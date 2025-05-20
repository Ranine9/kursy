// server.js

// Importowanie potrzebnych modułów
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1); // Ważne dla poprawnego działania secure cookies za reverse proxy

// --- Konfiguracja Połączenia z Bazą Danych PostgreSQL ---
if (!process.env.DATABASE_URL) {
    console.error('FATAL ERROR: Zmienna środowiskowa DATABASE_URL nie jest ustawiona!');
}
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) return console.error('Błąd połączenia z bazą danych PostgreSQL!', err.stack);
    if (client) {
        client.query('SELECT NOW()', (err, result) => {
            if (release) release(); 
            if (err) return console.error('Błąd podczas wykonywania zapytania testowego do bazy', err.stack);
            if (result && result.rows && result.rows.length > 0) {
                console.log('Pomyślnie połączono z PostgreSQL. Serwer czasu bazy danych:', result.rows[0].now);
            } else {
                console.log('Pomyślnie połączono z PostgreSQL, ale zapytanie testowe nie zwróciło oczekiwanych danych.');
            }
        });
    } else {
        console.error('Nie udało się uzyskać klienta z puli połączeń PostgreSQL.');
    }
});

async function initializeDatabase() {
    const client = await pool.connect(); // Użyjemy dedykowanego klienta dla transakcji DDL
    try {
        await client.query('BEGIN'); // Rozpocznij transakcję

        const createUserTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                -- Kolumna 'role' zostanie dodana poniżej przez ALTER TABLE, jeśli nie istnieje
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        // Najpierw utwórz tabelę users, jeśli nie istnieje (bez 'role' na tym etapie, aby uniknąć błędów, jeśli tabela już istnieje w starszej formie)
        await client.query(createUserTableQuery.replace("role VARCHAR(50) DEFAULT 'user' NOT NULL,", ""));
        console.log('Tabela "users" (wstępna struktura) sprawdzona/utworzona.');

        // Teraz dodaj kolumnę 'role', jeśli nie istnieje
        const alterUserTableQuery = `
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user' NOT NULL;
        `;
        await client.query(alterUserTableQuery);
        console.log('Kolumna "role" w tabeli "users" sprawdzona/dodana.');

        // Sprawdzenie, czy kolumna 'role' faktycznie istnieje
        const checkRoleColumnQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='users' AND column_name='role';
        `;
        const roleColumnCheck = await client.query(checkRoleColumnQuery);
        if (roleColumnCheck.rows.length > 0) {
            console.log('Potwierdzenie: Kolumna "role" istnieje w tabeli "users".');
        } else {
            console.error('KRYTYCZNY BŁĄD: Kolumna "role" NIE została pomyślnie dodana do tabeli "users"!');
            // Można rzucić błędem, aby zatrzymać dalszą inicjalizację, jeśli rola jest absolutnie krytyczna
            // throw new Error('Nie udało się dodać kolumny "role" do tabeli users.');
        }


        const createMaterialsTableQuery = `
            CREATE TABLE IF NOT EXISTS materials (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                category VARCHAR(100),
                price NUMERIC(10, 2) DEFAULT 0.00,
                file_url VARCHAR(1024), 
                cover_image_url VARCHAR(1024), 
                status VARCHAR(50) DEFAULT 'draft' NOT NULL, 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        const createUserMaterialsTableQuery = `
            CREATE TABLE IF NOT EXISTS user_materials (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                material_id INTEGER NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
                acquired_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, material_id)
            );
        `;
        const createUpdatedAtTriggerFunction = `
            CREATE OR REPLACE FUNCTION trigger_set_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        `;
        const applyUpdatedAtTriggerToMaterials = `
            DROP TRIGGER IF EXISTS set_timestamp_materials ON materials; 
            CREATE TRIGGER set_timestamp_materials
            BEFORE UPDATE ON materials
            FOR EACH ROW
            EXECUTE PROCEDURE trigger_set_timestamp();
        `;
        const addAdminUserIfNeeded = async () => {
            try {
                const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
                const adminPassword = process.env.ADMIN_PASSWORD || 'adminpassword';
                
                const res = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
                if (res.rows.length === 0) {
                    const salt = await bcrypt.genSalt(10);
                    const hashedPassword = await bcrypt.hash(adminPassword, salt);
                    await client.query(
                        'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)',
                        ['admin', adminEmail, hashedPassword, 'admin']
                    );
                    console.log(`Dodano domyślnego użytkownika admina: ${adminEmail}. Rola: admin.`);
                } else {
                    if (res.rows[0].role !== 'admin' && res.rows[0].email === adminEmail) {
                        await client.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', adminEmail]);
                        console.log(`Użytkownik ${adminEmail} już istniał, nadano rolę "admin".`);
                    }
                }
            } catch (dbError) {
                console.error("Błąd podczas dodawania/aktualizacji użytkownika admina:", dbError.message);
            }
        };
        const createSessionTableQuery = `
            CREATE TABLE IF NOT EXISTS "session" (
                "sid" varchar NOT NULL COLLATE "default",
                "sess" json NOT NULL,
                "expire" timestamp(6) NOT NULL,
                CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
            );
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
        `;
        
        await addAdminUserIfNeeded(); // Wywołaj to teraz, gdy kolumna 'role' na pewno jest
        
        await client.query(createMaterialsTableQuery);
        console.log('Tabela "materials" sprawdzona/utworzona.');
        
        await client.query(createUpdatedAtTriggerFunction);
        await client.query(applyUpdatedAtTriggerToMaterials);
        console.log('Trigger "updated_at" dla "materials" sprawdzony/utworzony.');

        await client.query(createUserMaterialsTableQuery);
        console.log('Tabela "user_materials" sprawdzona/utworzona.');

        await client.query(createSessionTableQuery);
        console.log('Tabela "session" sprawdzona/utworzona.');

        await client.query('COMMIT'); // Zatwierdź transakcję
        console.log('Inicjalizacja bazy danych zakończona pomyślnie.');

    } catch (err) {
        await client.query('ROLLBACK'); // Wycofaj transakcję w razie błędu
        console.error('Błąd podczas inicjalizacji bazy danych (transakcja wycofana):', err);
    } finally {
        client.release(); // Zwolnij klienta z puli
    }
}
initializeDatabase();

// --- Konfiguracja Nodemailer ---
// ... (bez zmian)
let transporter;
const emailHost = process.env.EMAIL_HOST;
const emailPort = parseInt(process.env.EMAIL_PORT || "587");
const emailUser = process.env.EMAIL_USER; 
const emailPass = process.env.EMAIL_PASS; 
const emailSenderAddress = process.env.EMAIL_SENDER_ADDRESS; 

console.log("Odczytane zmienne środowiskowe dla Nodemailer:");
console.log("  EMAIL_HOST:", emailHost ? emailHost.substring(0, 10) + "..." : "NIEUSTAWIONY");
console.log("  EMAIL_PORT:", emailPort);
console.log("  EMAIL_USER (Login SMTP):", emailUser ? emailUser.substring(0, 5) + "***" : "NIEUSTAWIONY");
console.log("  EMAIL_PASS (Klucz API SMTP):", emailPass ? "USTAWIONE (długość: " + emailPass.length + ")" : "NIEUSTAWIONE");
console.log("  EMAIL_SENDER_ADDRESS (Adres 'Od'):", emailSenderAddress || "NIEUSTAWIONY (użyje EMAIL_USER lub domyślnego)");


if (emailHost && emailUser && emailPass) {
    let transportOptions = {
        host: emailHost,
        port: emailPort,
        auth: {
            user: emailUser, 
            pass: emailPass, 
        },
        logger: true, 
        debug: true   
    };

    if (emailPort === 587) {
        transportOptions.secure = false; 
        transportOptions.requireTLS = true; 
        console.log("Konfiguracja Nodemailer dla portu 587 (STARTTLS): secure=false, requireTLS=true");
    } else if (emailPort === 465) {
        transportOptions.secure = true; 
        console.log("Konfiguracja Nodemailer dla portu 465 (SSL): secure=true");
    } else {
        console.log("Konfiguracja Nodemailer dla portu", emailPort, "(domyślne ustawienia secure)");
         transportOptions.secure = (emailPort === 465); 
    }
    
    console.log("Nodemailer auth object (login do SMTP):", JSON.stringify(transportOptions.auth, (key, value) => key === 'pass' ? '********' : value));

    transporter = nodemailer.createTransport(transportOptions);

    transporter.verify(function(error, success) {
        if (error) {
            console.error("Błąd weryfikacji konfiguracji Nodemailer:", error);
        } else {
            console.log("Nodemailer jest skonfigurowany i zweryfikowany pomyślnie.");
        }
    });
} else {
    console.warn("OSTRZEŻENIE: Brak pełnej konfiguracji SMTP (EMAIL_HOST, EMAIL_USER, EMAIL_PASS). Wysyłka maili będzie symulowana.");
    transporter = {
        sendMail: async (mailOptions) => {
            console.log("Symulacja wysyłki e-maila (konfiguracja SMTP niekompletna):");
            console.log("  OD:", mailOptions.from)
            console.log("  DO:", mailOptions.to);
            console.log("  TEMAT:", mailOptions.subject);
            return { messageId: "symulacja-" + Date.now() };
        }
    };
}

async function sendRegistrationEmail(userEmail, username) {
    const fromAddress = emailSenderAddress || emailUser || 'noreply@example.com';
    const mailOptions = {
        from: `"Platforma Materiałów" <${fromAddress}>`, 
        to: userEmail,
        subject: 'Witaj na Platformie! Potwierdzenie rejestracji', 
        text: `Witaj ${username},\n\nDziękujemy za rejestrację na naszej platformie z materiałami!\n\nPozdrawiamy,\nZespół Platformy`, 
        html: `<p>Witaj <strong>${username}</strong>,</p><p>Dziękujemy za rejestrację na naszej platformie z materiałami!</p><p>Pozdrawiamy,<br>Zespół Platformy</p>`, 
    };
    try {
        console.log(`Próba wysłania e-maila rejestracyjnego DO: ${userEmail} OD: ${fromAddress} (login SMTP: ${emailUser ? emailUser.substring(0,5) + '***' : 'NIEZNANY'})`);
        let info = await transporter.sendMail(mailOptions);
        console.log('Informacja o wysłaniu emaila z potwierdzeniem rejestracji: %s do %s', info.messageId, userEmail);
    } catch (error) {
        console.error('Błąd podczas wysyłania emaila z potwierdzeniem rejestracji:', error);
        if (error.response) {
            console.error('Odpowiedź serwera SMTP:', error.response);
        }
    }
}

// --- Konfiguracja aplikacji Express ---
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true }));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error('FATAL ERROR: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona! Sesje nie będą działać poprawnie.');
} else if (sessionSecret === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!' && process.env.NODE_ENV === 'production') {
    console.warn('UWAGA: Używasz domyślnego sekretu sesji w środowisku produkcyjnym! ZMIEŃ TO NATYCHMIAST na długi, losowy ciąg znaków w zmiennych środowiskowych Render!');
}

const sessionStore = new pgSession({
    pool: pool,
    tableName: 'session',
});
console.log('Magazyn sesji (pgSession) skonfigurowany.');

app.use(session({
    store: sessionStore,
    secret: sessionSecret || 'domyslny-sekret-na-wszelki-wypadek-dev-only',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24, 
        httpOnly: true,
        sameSite: 'lax'
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Middleware do logowania każdego żądania i stanu sesji
app.use((req, res, next) => {
    console.log(`-----------------------------------------------------`);
    console.log(`Przychodzące żądanie: ${req.method} ${req.url}`);
    console.log(`  ID Sesji z żądania (req.sessionID): ${req.sessionID}`);
    console.log(`  Zawartość sesji (req.session):`, JSON.stringify(req.session, null, 2));
    console.log(`  Ciasteczka (req.headers.cookie): ${req.headers.cookie}`);
    console.log(`-----------------------------------------------------`);
    next();
});

// --- Middleware autoryzacyjne ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    console.log(`  Użytkownik NIE jest uwierzytelniony (brak userId w sesji, SesjaID: ${req.sessionID}). Przekierowanie do /login z ${req.originalUrl}`);
    res.redirect('/login');
}

async function isAdmin(req, res, next) {
    if (!req.session.userId) {
        console.log('isAdmin: Brak userId w sesji. Użytkownik nie jest zalogowany.');
        return res.status(401).send('Brak autoryzacji - musisz być zalogowany.');
    }
    try {
        const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0 && result.rows[0].role === 'admin') {
            return next();
        } else {
            console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}) NIE ma roli "admin" (rola: ${result.rows.length > 0 ? result.rows[0].role : 'brak'}). Odmowa dostępu do ${req.originalUrl}`);
            return res.status(403).send('Brak uprawnień - tylko dla administratorów.');
        }
    } catch (error) {
        console.error("Błąd w middleware isAdmin:", error);
        return res.status(500).send('Błąd serwera podczas sprawdzania uprawnień.');
    }
}

// --- Definicje ścieżek (Routes) ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { username, email, password, 'confirm-password': confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).send('Wszystkie pola są wymagane!');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('Hasła nie są zgodne!');
    }

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existingUser.rows.length > 0) {
            if (existingUser.rows[0].email === email) {
                return res.status(400).send('Użytkownik o takim adresie email już istnieje!');
            }
            if (existingUser.rows[0].username === username) {
                return res.status(400).send('Użytkownik o takiej nazwie już istnieje!');
            }
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const insertUserQuery = 'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email';
        const newUserResult = await pool.query(insertUserQuery, [username, email, hashedPassword, 'user']);
        const newUser = newUserResult.rows[0];
        console.log('Nowy użytkownik zarejestrowany i zapisany do bazy:', newUser);

        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        req.session.role = 'user'; 
        
        req.session.save(async err => { 
            if (err) {
                console.error('Błąd podczas zapisywania sesji po rejestracji:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            await sendRegistrationEmail(newUser.email, newUser.username); 
            res.redirect('/dashboard');
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas rejestracji:", error);
        res.status(500).send('Wystąpił błąd serwera podczas rejestracji.');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email i hasło są wymagane!');
    }

    try {
        const result = await pool.query('SELECT id, username, email, password_hash, role FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role; 

        req.session.save(err => {
            if (err) {
                console.error('Błąd podczas zapisywania sesji po logowaniu:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            if (user.role === 'admin') {
                res.redirect('/admin/dashboard'); 
            } else {
                res.redirect('/dashboard'); 
            }
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas logowania:", error);
        res.status(500).send('Wystąpił błąd serwera podczas logowania.');
    }
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/user', isAuthenticated, (req, res) => {
    if (req.session.username && req.session.userId) {
        res.json({
            username: req.session.username,
            userId: req.session.userId,
            role: req.session.role 
        });
    } else {
        res.status(404).json({ error: 'User data not found in session' });
    }
});

app.get('/logout', (req, res) => {
    const username = req.session.username;
    const sessionID = req.sessionID;
    
    req.session.destroy(err => {
        if (err) {
            console.error(`Błąd podczas niszczenia sesji (ID: ${sessionID}) przy wylogowywaniu:`, err);
            return res.status(500).send('Nie udało się wylogować.');
        }
        res.clearCookie('connect.sid'); 
        res.redirect('/');
    });
});

// --- Ścieżki dla Panelu Administracyjnego ---
app.get('/admin/dashboard', isAuthenticated, isAdmin, (req, res) => {
    console.log(`Dostęp do /admin/dashboard udzielony dla admina: ${req.session.username}`);
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

app.get('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania listy użytkowników dla admina:", error);
        res.status(500).json({ error: 'Błąd serwera podczas pobierania użytkowników.' });
    }
});

app.put('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    const userId = parseInt(req.params.id); 
    const { username, email, role, password } = req.body; 

    if (!username || !email || !role) {
        return res.status(400).json({ message: 'Nazwa użytkownika, email i rola są wymagane.' });
    }
    if (role !== 'user' && role !== 'admin') {
        return res.status(400).json({ message: 'Nieprawidłowa rola. Dozwolone wartości: "user", "admin".' });
    }

    try {
        const conflictCheck = await pool.query(
            'SELECT id FROM users WHERE (email = $1 OR username = $2) AND id != $3',
            [email, username, userId]
        );
        if (conflictCheck.rows.length > 0) {
            return res.status(409).json({ message: 'Email lub nazwa użytkownika są już zajęte przez innego użytkownika.' });
        }

        let hashedPassword = null;
        if (password && password.trim() !== '') { 
            if (password.length < 6) { 
                 return res.status(400).json({ message: 'Nowe hasło musi mieć co najmniej 6 znaków.' });
            }
            const salt = await bcrypt.genSalt(10);
            hashedPassword = await bcrypt.hash(password, salt);
        }

        const updateFields = [];
        const values = [];
        let queryParamIndex = 1;

        updateFields.push(`username = $${queryParamIndex++}`);
        values.push(username);
        updateFields.push(`email = $${queryParamIndex++}`);
        values.push(email);
        updateFields.push(`role = $${queryParamIndex++}`);
        values.push(role);
        if (hashedPassword) {
            updateFields.push(`password_hash = $${queryParamIndex++}`);
            values.push(hashedPassword);
        }
        values.push(userId); 

        const updateUserQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${queryParamIndex} RETURNING id, username, email, role`;
        const result = await pool.query(updateUserQuery, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika o podanym ID.' });
        }
        res.json({ message: 'Dane użytkownika zaktualizowane pomyślnie.', user: result.rows[0] });
    } catch (error) {
        console.error(`Błąd podczas aktualizacji użytkownika ID: ${userId}:`, error);
        if (error.code === '23505') { 
            return res.status(409).json({ message: 'Email lub nazwa użytkownika są już zajęte.' });
        }
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji użytkownika.' });
    }
});

app.delete('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => {
    const userIdToDelete = parseInt(req.params.id);
    const adminUserId = req.session.userId; 

    if (userIdToDelete === adminUserId) {
        return res.status(403).json({ message: 'Administrator nie może usunąć własnego konta.' });
    }
    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, username', [userIdToDelete]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika o podanym ID.' });
        }
        res.json({ message: `Użytkownik "${result.rows[0].username}" (ID: ${result.rows[0].id}) został usunięty.` });
    } catch (error) {
        console.error(`Błąd podczas usuwania użytkownika ID: ${userIdToDelete}:`, error);
        res.status(500).json({ message: 'Błąd serwera podczas usuwania użytkownika.' });
    }
});

// API Endpoints dla materiałów (admin)
app.get('/api/admin/materials', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM materials ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania listy materiałów dla admina:", error);
        res.status(500).json({ error: 'Błąd serwera podczas pobierania materiałów.' });
    }
});

app.post('/api/admin/materials', isAuthenticated, isAdmin, async (req, res) => {
    const { title, description, category, price, file_url, cover_image_url, status } = req.body;
    if (!title) {
        return res.status(400).json({ message: 'Tytuł materiału jest wymagany.' });
    }
    if (!file_url) {
        return res.status(400).json({ message: 'Link do pliku (file_url) jest wymagany.' });
    }
    try {
        const insertMaterialQuery = `
            INSERT INTO materials (title, description, category, price, file_url, cover_image_url, status) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) 
            RETURNING *`;
        const values = [ title, description || null, category || null, price ? parseFloat(price) : 0.00, file_url, cover_image_url || null, status || 'draft' ];
        const result = await pool.query(insertMaterialQuery, values);
        res.status(201).json({ message: 'Materiał dodany pomyślnie.', material: result.rows[0] });
    } catch (error) {
        console.error("Błąd podczas tworzenia nowego materiału:", error);
        res.status(500).json({ message: 'Błąd serwera podczas tworzenia materiału.' });
    }
});

// === PUBLICZNE API Endpoints dla Materiałów ===
app.get('/api/materials', async (req, res) => {
    try {
        const result = await pool.query("SELECT id, title, description, category, price, cover_image_url, status FROM materials WHERE status = 'published' ORDER BY created_at DESC");
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania opublikowanych materiałów:", error);
        res.status(500).json({ error: 'Błąd serwera podczas pobierania materiałów.' });
    }
});

app.post('/api/materials/:id/acquire', isAuthenticated, async (req, res) => {
    const materialId = parseInt(req.params.id);
    const userId = req.session.userId;
    if (isNaN(materialId)) {
        return res.status(400).json({ message: 'Nieprawidłowe ID materiału.' });
    }
    try {
        const materialCheck = await pool.query("SELECT id, price FROM materials WHERE id = $1 AND status = 'published'", [materialId]);
        if (materialCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Materiał nie został znaleziony lub nie jest dostępny.' });
        }
        // const materialPrice = parseFloat(materialCheck.rows[0].price); // Na razie pomijamy płatności
        const existingAcquisition = await pool.query( 'SELECT * FROM user_materials WHERE user_id = $1 AND material_id = $2', [userId, materialId] );
        if (existingAcquisition.rows.length > 0) {
            return res.status(409).json({ message: 'Już posiadasz ten materiał.' });
        }
        await pool.query( 'INSERT INTO user_materials (user_id, material_id) VALUES ($1, $2)', [userId, materialId] );
        res.status(201).json({ message: 'Materiał został pomyślnie dodany do Twojego konta.' });
    } catch (error) {
        console.error(`Błąd podczas nabywania materiału ID: ${materialId} przez użytkownika ID: ${userId}:`, error);
        res.status(500).json({ message: 'Błąd serwera podczas próby nabycia materiału.' });
    }
});

app.get('/api/my-materials', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    try {
        const query = `
            SELECT m.id, m.title, m.description, m.category, m.cover_image_url, m.file_url, um.acquired_at
            FROM materials m
            JOIN user_materials um ON m.id = um.material_id
            WHERE um.user_id = $1
            ORDER BY um.acquired_at DESC;
        `;
        const result = await pool.query(query, [userId]);
        res.json(result.rows);
    } catch (error) {
        console.error(`Błąd podczas pobierania materiałów dla użytkownika ID: ${userId}:`, error);
        res.status(500).json({ error: 'Błąd serwera podczas pobierania Twoich materiałów.' });
    }
});

// --- Uruchomienie serwera ---
app.listen(PORT, () => {
    console.log(`Serwer uruchomiony na porcie ${PORT}`);
    if (!process.env.DATABASE_URL) console.warn('OSTRZEŻENIE: DATABASE_URL nie jest ustawiona.');
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!') console.warn('OSTRZEŻENIE: SESSION_SECRET nie jest ustawiona lub używa wartości domyślnej!');
    if (process.env.NODE_ENV !== 'production') console.warn('OSTRZEŻENIE: Aplikacja działa w trybie deweloperskim.');
    else console.log('Aplikacja działa w trybie produkcyjnym.');
    if (!emailHost || !emailUser || !emailPass) console.warn("OSTRZEŻENIE: Brak pełnej konfiguracji SMTP. Wysyłka maili będzie symulowana.");
    if (!emailSenderAddress && (emailHost && emailUser && emailPass)) console.warn("OSTRZEŻENIE: EMAIL_SENDER_ADDRESS nie jest ustawiona.");
    console.log('---');
    console.log('Ustawiono "trust proxy" na 1.');
    console.log('Magazyn sesji skonfigurowany do używania PostgreSQL.');
    console.log('Tabela "session" powinna być tworzona przy starcie serwera.');
    console.log('Pole "role" w tabeli "users" jest teraz dodawane/sprawdzane przy starcie.');
    console.log('Tabela "materials" jest teraz tworzona przy starcie serwera.');
    console.log('Tabela "user_materials" jest teraz tworzona przy starcie serwera.');
    console.log('Dodano publiczne API dla materiałów i API do zarządzania "Moje Materiały".');
    console.log('---');
});
