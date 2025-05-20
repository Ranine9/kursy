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
app.set('trust proxy', 1); 

// --- Konfiguracja Połączenia z Bazą Danych PostgreSQL ---
if (!process.env.DATABASE_URL) {
    console.error('FATAL ERROR: Zmienna środowiskowa DATABASE_URL nie jest ustawiona!');
    // W środowisku deweloperskim można by tu ustawić domyślny connection string,
    // ale w produkcji aplikacja powinna się zatrzymać lub logować krytyczny błąd.
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
    const client = await pool.connect(); 
    try {
        await client.query('BEGIN'); 

        const createUserTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                role VARCHAR(50) DEFAULT 'user' NOT NULL -- Dodano rolę od razu
            );
        `;
        await client.query(createUserTableQuery);
        console.log('Tabela "users" sprawdzona/utworzona.');

        // Sprawdzenie, czy kolumna 'role' istnieje, jeśli tabela była tworzona bez niej wcześniej
        // W nowej definicji jest już zawarta, więc ten krok jest bardziej dla kompatybilności wstecznej
        const checkRoleColumnQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='users' AND column_name='role';
        `;
        const roleColumnCheck = await client.query(checkRoleColumnQuery);
        if (roleColumnCheck.rows.length === 0) {
            // Jeśli kolumna 'role' nie istnieje (np. starsza baza danych), dodaj ją
            const alterUserTableQuery = `
                ALTER TABLE users
                ADD COLUMN role VARCHAR(50) DEFAULT 'user' NOT NULL;
            `;
            await client.query(alterUserTableQuery);
            console.log('Kolumna "role" została dodana do tabeli "users".');
        } else {
            console.log('Kolumna "role" już istnieje w tabeli "users".');
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
        await client.query(createMaterialsTableQuery);
        console.log('Tabela "materials" sprawdzona/utworzona.');
        
        const createUserMaterialsTableQuery = `
            CREATE TABLE IF NOT EXISTS user_materials (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                material_id INTEGER NOT NULL REFERENCES materials(id) ON DELETE CASCADE,
                acquired_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, material_id)
            );
        `;
        await client.query(createUserMaterialsTableQuery);
        console.log('Tabela "user_materials" sprawdzona/utworzona.');

        const createUpdatedAtTriggerFunction = `
            CREATE OR REPLACE FUNCTION trigger_set_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        `;
        await client.query(createUpdatedAtTriggerFunction);

        const applyUpdatedAtTriggerToMaterials = `
            DROP TRIGGER IF EXISTS set_timestamp_materials ON materials; 
            CREATE TRIGGER set_timestamp_materials
            BEFORE UPDATE ON materials
            FOR EACH ROW
            EXECUTE PROCEDURE trigger_set_timestamp();
        `;
        await client.query(applyUpdatedAtTriggerToMaterials);
        console.log('Trigger "updated_at" dla "materials" sprawdzony/utworzony.');
        
        const addAdminUserIfNeeded = async () => {
            try {
                const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
                const adminPassword = process.env.ADMIN_PASSWORD || 'adminpassword'; // Hasło powinno być silniejsze!
                
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
                    // Sprawdź, czy istniejący admin ma poprawną rolę
                    if (res.rows[0].role !== 'admin' && res.rows[0].email === adminEmail) {
                        await client.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', adminEmail]);
                        console.log(`Użytkownik ${adminEmail} już istniał, nadano/poprawiono rolę "admin".`);
                    }
                }
            } catch (dbError) {
                console.error("Błąd podczas dodawania/aktualizacji użytkownika admina:", dbError.message);
            }
        };
        await addAdminUserIfNeeded();
        
        const createSessionTableQuery = `
            CREATE TABLE IF NOT EXISTS "session" (
                "sid" varchar NOT NULL COLLATE "default",
                "sess" json NOT NULL,
                "expire" timestamp(6) NOT NULL
            ) WITH (OIDS=FALSE);
            ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
        `;
        // Powyższy kod dla tabeli sesji jest typowy dla connect-pg-simple
        await client.query(createSessionTableQuery);
        console.log('Tabela "session" sprawdzona/utworzona.');

        await client.query('COMMIT');
        console.log('Inicjalizacja bazy danych zakończona pomyślnie.');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Błąd podczas inicjalizacji bazy danych (transakcja wycofana):', err);
    } finally {
        client.release();
    }
}
initializeDatabase().catch(err => console.error("Nie udało się zainicjalizować bazy danych przy starcie:", err));


// --- Konfiguracja Nodemailer ---
let transporter;
const emailHost = process.env.EMAIL_HOST;
const emailPort = parseInt(process.env.EMAIL_PORT || "587"); // Domyślnie 587 dla STARTTLS
const emailUser = process.env.EMAIL_USER; // Login SMTP
const emailPass = process.env.EMAIL_PASS; // Hasło SMTP lub klucz API
const emailSenderAddress = process.env.EMAIL_SENDER_ADDRESS; // Adres "Od"

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
        logger: true, // Włącz logowanie dla Nodemailera
        debug: true   // Włącz debugowanie dla Nodemailera
    };

    // Ustawienia secure/TLS w zależności od portu
    if (emailPort === 587) {
        transportOptions.secure = false; // Dla STARTTLS secure jest false
        transportOptions.requireTLS = true; // Wymuś STARTTLS
        console.log("Konfiguracja Nodemailer dla portu 587 (STARTTLS): secure=false, requireTLS=true");
    } else if (emailPort === 465) {
        transportOptions.secure = true; // Dla SSL/TLS port 465 secure jest true
        console.log("Konfiguracja Nodemailer dla portu 465 (SSL): secure=true");
    } else {
        // Dla innych portów, pozwól Nodemailerowi zdecydować lub użyj domyślnych
        console.log("Konfiguracja Nodemailer dla portu", emailPort, "(domyślne ustawienia secure)");
         transportOptions.secure = (emailPort === 465); // Domyślnie true dla 465, false inaczej
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
            // console.log("  TREŚĆ (HTML):", mailOptions.html); // Można odkomentować dla pełniejszej symulacji
            return { messageId: "symulacja-" + Date.now() };
        }
    };
}

async function sendRegistrationEmail(userEmail, username) {
    const fromAddress = emailSenderAddress || emailUser || 'noreply@example.com'; // Użyj dedykowanego adresu 'Od' lub loginu SMTP
    const mailOptions = {
        from: `"Platforma Materiałów" <${fromAddress}>`, // Format: "Nazwa Wyświetlana <adres@email.com>"
        to: userEmail,
        subject: 'Witaj na Platformie! Potwierdzenie rejestracji', // Tytuł maila
        text: `Witaj ${username},\n\nDziękujemy za rejestrację na naszej platformie z materiałami!\n\nPozdrawiamy,\nZespół Platformy`, // Wersja tekstowa
        html: `<p>Witaj <strong>${username}</strong>,</p><p>Dziękujemy za rejestrację na naszej platformie z materiałami!</p><p>Pozdrawiamy,<br>Zespół Platformy</p>`, // Wersja HTML
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
app.use(bodyParser.json()); // Do parsowania JSON
app.use(bodyParser.urlencoded({ extended: true })); // Do parsowania danych formularzy

// Konfiguracja sesji
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error('FATAL ERROR: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona! Sesje nie będą działać poprawnie.');
    // process.exit(1); // Można rozważyć zatrzymanie aplikacji, jeśli sekret jest krytyczny
} else if (sessionSecret === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!' && process.env.NODE_ENV === 'production') {
    console.warn('UWAGA: Używasz domyślnego sekretu sesji w środowisku produkcyjnym! ZMIEŃ TO NATYCHMIAST na długi, losowy ciąg znaków w zmiennych środowiskowych Render!');
}

const sessionStore = new pgSession({
    pool: pool,                // Pula połączeń PostgreSQL
    tableName: 'session',      // Nazwa tabeli sesji
    // Można dodać inne opcje, np. errorLog
});
console.log('Magazyn sesji (pgSession) skonfigurowany.');

app.use(session({
    store: sessionStore,
    secret: sessionSecret || 'domyslny-sekret-na-wszelki-wypadek-dev-only', // Użyj zmiennej środowiskowej
    resave: false, // Nie zapisuj sesji, jeśli nie była modyfikowana
    saveUninitialized: false, // Nie twórz sesji, dopóki coś nie zostanie zapisane
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Używaj secure cookies w produkcji (HTTPS)
        maxAge: 1000 * 60 * 60 * 24, // Czas życia ciasteczka: 1 dzień
        httpOnly: true, // Ciasteczko niedostępne przez JavaScript po stronie klienta
        sameSite: 'lax' // Ochrona przed CSRF dla niektórych typów żądań
    }
}));

// Serwowanie plików statycznych z folderu 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Middleware do logowania każdego żądania i stanu sesji
app.use((req, res, next) => {
    console.log(`-----------------------------------------------------`);
    console.log(`Przychodzące żądanie: ${req.method} ${req.url}`);
    console.log(`  ID Sesji z żądania (req.sessionID): ${req.sessionID}`);
    console.log(`  Zawartość sesji (req.session):`, JSON.stringify(req.session, null, 2));
    // console.log(`  Ciasteczka (req.headers.cookie): ${req.headers.cookie}`); // Może być zbyt szczegółowe dla każdego logu
    console.log(`-----------------------------------------------------`);
    next();
});


// --- Middleware autoryzacyjne ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next(); // Użytkownik jest zalogowany, kontynuuj
    }
    // Użytkownik nie jest zalogowany
    console.log(`  Użytkownik NIE jest uwierzytelniony (brak userId w sesji, SesjaID: ${req.sessionID}). Przekierowanie do /login z ${req.originalUrl}`);
    // Jeśli to żądanie API, zwróć 401, w przeciwnym razie przekieruj
    if (req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ message: 'Brak autoryzacji. Musisz być zalogowany.' });
    }
    // Dla stron HTML, przekieruj do logowania z parametrem redirect, aby wrócić po zalogowaniu
    res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
}

async function isAdmin(req, res, next) {
    if (!req.session.userId) {
        console.log('isAdmin: Brak userId w sesji. Użytkownik nie jest zalogowany.');
        // Podobnie jak w isAuthenticated, rozróżnij odpowiedź dla API i stron HTML
        if (req.originalUrl.startsWith('/api/')) {
            return res.status(401).json({ message: 'Brak autoryzacji - musisz być zalogowany.'});
        }
        return res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
    }
    try {
        const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0 && result.rows[0].role === 'admin') {
            return next(); // Użytkownik jest adminem
        } else {
            console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}) NIE ma roli "admin" (rola: ${result.rows.length > 0 ? result.rows[0].role : 'brak'}). Odmowa dostępu do ${req.originalUrl}`);
            if (req.originalUrl.startsWith('/api/')) {
                return res.status(403).json({ message: 'Brak uprawnień - tylko dla administratorów.'});
            }
            // Dla stron HTML można przekierować do strony głównej lub panelu użytkownika
            return res.redirect('/dashboard.html?error=admin_required'); 
        }
    } catch (error) {
        console.error("Błąd w middleware isAdmin:", error);
        return res.status(500).json({ message: 'Błąd serwera podczas sprawdzania uprawnień.'});
    }
}

// --- Definicje ścieżek (Routes) ---

// Strony publiczne
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Rejestracja
app.post('/register', async (req, res) => {
    const { username, email, password, 'confirm-password': confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).json({ message: 'Wszystkie pola są wymagane!' }); 
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Hasła nie są zgodne!' });
    }
    if (password.length < 6) { 
        return res.status(400).json({ message: 'Hasło musi mieć co najmniej 6 znaków.' });
    }

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existingUser.rows.length > 0) {
            if (existingUser.rows[0].email === email) {
                return res.status(409).json({ message: 'Użytkownik o takim adresie email już istnieje!' }); 
            }
            if (existingUser.rows[0].username === username) {
                return res.status(409).json({ message: 'Użytkownik o takiej nazwie już istnieje!' });
            }
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const insertUserQuery = 'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role';
        const newUserResult = await pool.query(insertUserQuery, [username, email, hashedPassword, 'user']); 
        const newUser = newUserResult.rows[0];
        console.log('Nowy użytkownik zarejestrowany i zapisany do bazy:', newUser);

        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        req.session.role = newUser.role; 
        
        req.session.save(async err => { 
            if (err) {
                console.error('Błąd podczas zapisywania sesji po rejestracji:', err);
                return res.status(500).json({ message: 'Wystąpił błąd serwera podczas próby zapisania sesji.'});
            }
            await sendRegistrationEmail(newUser.email, newUser.username); 
            
            res.status(201).json({ 
                message: 'Rejestracja pomyślna!', 
                user: { id: newUser.id, username: newUser.username, role: newUser.role }, 
                redirectTo: '/dashboard.html' // Klient powinien obsłużyć to przekierowanie
            });
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas rejestracji:", error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas rejestracji.'});
    }
});

// Logowanie
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const redirectUrl = req.query.redirect || (req.session.role === 'admin' ? '/admin/dashboard.html' : '/dashboard.html');


    if (!email || !password) {
        return res.status(400).json({ message: 'Email i hasło są wymagane!' });
    }

    try {
        const result = await pool.query('SELECT id, username, email, password_hash, role FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Nieprawidłowy email lub hasło.' }); 
        }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Nieprawidłowy email lub hasło.' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role; 

        req.session.save(err => {
            if (err) {
                console.error('Błąd podczas zapisywania sesji po logowaniu:', err);
                return res.status(500).json({ message: 'Wystąpił błąd serwera podczas próby zapisania sesji.'});
            }
            
            let determinedRedirectTo = redirectUrl;
            // Jeśli loguje się admin, a redirectUrl nie jest panelem admina, przekieruj do panelu admina
            if (user.role === 'admin' && !redirectUrl.startsWith('/admin/')) {
                determinedRedirectTo = '/admin/dashboard.html';
            } else if (user.role !== 'admin' && redirectUrl.startsWith('/admin/')) {
                // Jeśli zwykły user próbuje wejść do admina przez redirect, kieruj do jego panelu
                determinedRedirectTo = '/dashboard.html';
            }


            res.status(200).json({ 
                message: 'Logowanie pomyślne!', 
                user: { id: user.id, username: user.username, role: user.role }, 
                redirectTo: determinedRedirectTo
            });
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas logowania:", error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas logowania.'});
    }
});


// Strony chronione
app.get('/dashboard.html', isAuthenticated, (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/material_gallery.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'material_gallery.html'));
});


// API dla danych użytkownika
app.get('/api/user', isAuthenticated, (req, res) => { 
    res.json({
        username: req.session.username,
        userId: req.session.userId,
        role: req.session.role 
    });
});

// Wylogowanie
app.get('/logout', (req, res) => {
    const username = req.session.username; 
    const sessionID = req.sessionID;
    
    req.session.destroy(err => {
        if (err) {
            console.error(`Błąd podczas niszczenia sesji (ID: ${sessionID}) dla użytkownika ${username} przy wylogowywaniu:`, err);
            return res.redirect('/?logoutError=true'); 
        }
        res.clearCookie('connect.sid'); 
        console.log(`Użytkownik ${username} (Sesja ID: ${sessionID}) wylogowany pomyślnie.`);
        res.redirect('/'); 
    });
});


// --- Ścieżki dla Panelu Administracyjnego ---
app.get('/admin/dashboard.html', isAuthenticated, isAdmin, (req, res) => { 
    console.log(`Dostęp do /admin/dashboard.html udzielony dla admina: ${req.session.username}`);
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

// API dla zarządzania użytkownikami (admin)
app.get('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania listy użytkowników dla admina:", error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania użytkowników.' });
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
        await pool.query('DELETE FROM user_materials WHERE user_id = $1', [userIdToDelete]);
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
        res.status(500).json({ message: 'Błąd serwera podczas pobierania materiałów.' });
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
        const values = [
            title,
            description || null,
            category || null,
            price ? parseFloat(price) : 0.00,
            file_url,
            cover_image_url || null,
            status || 'draft' 
        ];
        const result = await pool.query(insertMaterialQuery, values);
        res.status(201).json({ message: 'Materiał dodany pomyślnie.', material: result.rows[0] });
    } catch (error) {
        console.error("Błąd podczas tworzenia nowego materiału:", error);
        res.status(500).json({ message: 'Błąd serwera podczas tworzenia materiału.' });
    }
});

app.put('/api/admin/materials/:id', isAuthenticated, isAdmin, async (req, res) => {
    const materialId = parseInt(req.params.id);
    const { title, description, category, price, file_url, cover_image_url, status } = req.body;

    if (!title || !file_url) { 
        return res.status(400).json({ message: 'Tytuł oraz link do pliku (file_url) są wymagane.' });
    }
    const validStatuses = ['draft', 'published', 'archived'];
    if (status && !validStatuses.includes(status)) {
        return res.status(400).json({ message: `Nieprawidłowy status. Dozwolone wartości: ${validStatuses.join(', ')}.` });
    }

    try {
        const updateFields = [];
        const values = [];
        let queryParamIndex = 1;

        if (title !== undefined) { updateFields.push(`title = $${queryParamIndex++}`); values.push(title); }
        if (description !== undefined) { updateFields.push(`description = $${queryParamIndex++}`); values.push(description); }
        if (category !== undefined) { updateFields.push(`category = $${queryParamIndex++}`); values.push(category); }
        if (price !== undefined) { updateFields.push(`price = $${queryParamIndex++}`); values.push(price ? parseFloat(price) : 0.00); }
        if (file_url !== undefined) { updateFields.push(`file_url = $${queryParamIndex++}`); values.push(file_url); }
        if (cover_image_url !== undefined) { updateFields.push(`cover_image_url = $${queryParamIndex++}`); values.push(cover_image_url); }
        if (status !== undefined) { updateFields.push(`status = $${queryParamIndex++}`); values.push(status); }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ message: 'Brak danych do aktualizacji.' });
        }

        values.push(materialId); 

        const updateMaterialQuery = `UPDATE materials SET ${updateFields.join(', ')} WHERE id = $${queryParamIndex} RETURNING *`;
        const result = await pool.query(updateMaterialQuery, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Nie znaleziono materiału o podanym ID.' });
        }
        res.json({ message: 'Dane materiału zaktualizowane pomyślnie.', material: result.rows[0] });
    } catch (error) {
        console.error(`Błąd podczas aktualizacji materiału ID: ${materialId}:`, error);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji materiału.' });
    }
});

app.delete('/api/admin/materials/:id', isAuthenticated, isAdmin, async (req, res) => {
    const materialIdToDelete = parseInt(req.params.id);
    try {
        await pool.query('DELETE FROM user_materials WHERE material_id = $1', [materialIdToDelete]);
        const result = await pool.query('DELETE FROM materials WHERE id = $1 RETURNING id, title', [materialIdToDelete]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Nie znaleziono materiału o podanym ID.' });
        }
        res.json({ message: `Materiał "${result.rows[0].title}" (ID: ${result.rows[0].id}) został usunięty.` });
    } catch (error) {
        console.error(`Błąd podczas usuwania materiału ID: ${materialIdToDelete}:`, error);
        res.status(500).json({ message: 'Błąd serwera podczas usuwania materiału.' });
    }
});


// === PUBLICZNE API Endpoints dla Materiałów (dla zalogowanych użytkowników) ===

app.get('/api/materials', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, title, description, category, price, cover_image_url, status FROM materials WHERE status = 'published' ORDER BY created_at DESC"
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania opublikowanych materiałów (dla zalogowanych):", error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania materiałów.' });
    }
});

app.post('/api/materials/:id/acquire', isAuthenticated, async (req, res) => {
    const materialId = parseInt(req.params.id);
    const userId = req.session.userId;

    if (isNaN(materialId)) {
        return res.status(400).json({ message: 'Nieprawidłowe ID materiału.' });
    }

    try {
        const materialCheck = await pool.query(
            "SELECT id, title, price FROM materials WHERE id = $1 AND status = 'published'",
            [materialId]
        );
        if (materialCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Materiał nie został znaleziony lub nie jest dostępny.' });
        }
        const material = materialCheck.rows[0];

        const existingAcquisition = await pool.query(
            'SELECT * FROM user_materials WHERE user_id = $1 AND material_id = $2',
            [userId, materialId]
        );
        if (existingAcquisition.rows.length > 0) {
            return res.status(409).json({ message: `Już posiadasz materiał "${material.title}". Znajdziesz go w swoim panelu.` });
        }

        if (material.price > 0) {
            console.log(`Użytkownik ${userId} próbuje nabyć płatny materiał ${materialId} (${material.price} PLN) - logika płatności niezaimplementowana.`);
        }

        await pool.query(
            'INSERT INTO user_materials (user_id, material_id) VALUES ($1, $2)',
            [userId, materialId]
        );
        
        res.status(201).json({ message: `Materiał "${material.title}" został pomyślnie dodany do Twojego konta.` });

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
        res.status(500).json({ message: 'Błąd serwera podczas pobierania Twoich materiałów.' });
    }
});


// --- Uruchomienie serwera ---
app.listen(PORT, () => {
    console.log(`Serwer uruchomiony na porcie ${PORT}`);
    if (!process.env.DATABASE_URL) console.warn('OSTRZEŻENIE: DATABASE_URL nie jest ustawiona.');
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!') console.warn('OSTRZEŻENIE: SESSION_SECRET nie jest ustawiona lub używa wartości domyślnej!');
    if (process.env.NODE_ENV !== 'production') {
        console.warn('OSTRZEŻENIE: Aplikacja działa w trybie deweloperskim.');
    } else {
        console.log('Aplikacja działa w trybie produkcyjnym.');
    }
    if (!emailHost || !emailUser || !emailPass) console.warn("OSTRZEŻENIE: Brak pełnej konfiguracji SMTP. Wysyłka maili będzie symulowana.");
    if (!emailSenderAddress && (emailHost && emailUser && emailPass)) console.warn("OSTRZEŻENIE: EMAIL_SENDER_ADDRESS nie jest ustawiona, używany będzie login SMTP lub domyślny adres.");
    console.log('--- Podsumowanie konfiguracji ---');
    console.log('  Ustawiono "trust proxy" na 1.');
    console.log('  Magazyn sesji: PostgreSQL (tabela "session").');
    console.log('  Inicjalizacja bazy danych przy starcie (tabele: users, materials, user_materials, session).');
    console.log('  Dodano ścieżkę /material_gallery.html dla zalogowanych użytkowników.');
    console.log('  API /api/materials jest teraz chronione i wymaga zalogowania.');
    console.log('---');
});