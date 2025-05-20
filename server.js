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
    // W środowisku deweloperskim można by tu ustawić domyślny connection string, np. z dotenv
    // process.exit(1); // Zatrzymanie aplikacji, jeśli baza danych jest krytyczna
}
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Błąd połączenia z pulą bazy danych PostgreSQL!', err.stack);
        // Można rozważyć zatrzymanie aplikacji, jeśli połączenie z pulą jest niemożliwe
        // process.exit(1); 
        return;
    }
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

// --- Inicjalizacja Bazy Danych ---
async function initializeDatabase() {
    console.log('Rozpoczynanie inicjalizacji bazy danych...');
    const client = await pool.connect(); 
    console.log('Połączono klienta bazy danych na potrzeby inicjalizacji.');
    try {
        await client.query('BEGIN'); 
        console.log('Rozpoczęto transakcję inicjalizacji bazy danych.');

        // Tabela użytkowników
        const createUserTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                role VARCHAR(50) DEFAULT 'user' NOT NULL
            );
        `;
        await client.query(createUserTableQuery);
        console.log('Tabela "users" sprawdzona/utworzona.');

        // Tabela materiałów
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
        
        // Tabela łącząca użytkowników i materiały (nabyte materiały)
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

        // Trigger do aktualizacji `updated_at` w tabeli `materials`
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
        console.log('Funkcja triggera "trigger_set_timestamp" sprawdzona/utworzona.');

        const applyUpdatedAtTriggerToMaterials = `
            DROP TRIGGER IF EXISTS set_timestamp_materials ON materials; 
            CREATE TRIGGER set_timestamp_materials
            BEFORE UPDATE ON materials
            FOR EACH ROW
            EXECUTE PROCEDURE trigger_set_timestamp();
        `;
        await client.query(applyUpdatedAtTriggerToMaterials);
        console.log('Trigger "updated_at" dla "materials" sprawdzony/utworzony.');
        
        // Tabela ustawień aplikacji
        const createAppSettingsTableQuery = `
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key VARCHAR(255) PRIMARY KEY,
                setting_value TEXT,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(createAppSettingsTableQuery);
        console.log('Tabela "app_settings" sprawdzona/utworzona.');

        // Trigger do aktualizacji `updated_at` w tabeli `app_settings`
        const applyUpdatedAtTriggerToAppSettings = `
            DROP TRIGGER IF EXISTS set_timestamp_app_settings ON app_settings;
            CREATE TRIGGER set_timestamp_app_settings
            BEFORE UPDATE ON app_settings
            FOR EACH ROW
            EXECUTE PROCEDURE trigger_set_timestamp();
        `;
        await client.query(applyUpdatedAtTriggerToAppSettings);
        console.log('Trigger "updated_at" dla "app_settings" sprawdzony/utworzony.');


        // Domyślne ustawienia aplikacji (jeśli nie istnieją)
        const defaultSettings = [
            { key: 'siteName', value: 'Platforma Materiałów PRO' },
            { key: 'adminEmail', value: process.env.ADMIN_EMAIL || 'admin@example.com' },
            { key: 'maintenanceMode', value: 'false' },
            { key: 'maintenanceMessage', value: 'Strona jest obecnie w trybie konserwacji. Zapraszamy później!' },
            { key: 'itemsPerPageAdmin', value: '10' },
            { key: 'allowRegistration', value: 'true' },
            { key: 'defaultUserRole', value: 'user' },
            { key: 'defaultMaterialStatus', value: 'draft' },
            { key: 'failedLoginAttempts', value: '5' },
            { key: 'lockoutDuration', value: '15' } // w minutach
        ];

        console.log('Sprawdzanie/dodawanie domyślnych ustawień...');
        for (const setting of defaultSettings) {
            const res = await client.query('SELECT setting_value FROM app_settings WHERE setting_key = $1', [setting.key]);
            if (res.rows.length === 0) {
                await client.query('INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, $2)', [setting.key, setting.value]);
                console.log(`  Dodano domyślne ustawienie: ${setting.key} = ${setting.value}`);
            } else {
                console.log(`  Ustawienie ${setting.key} już istnieje.`);
            }
        }
        console.log('Zakończono sprawdzanie/dodawanie domyślnych ustawień.');
        
        // Dodanie użytkownika admina (jeśli nie istnieje)
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
                        console.log(`Użytkownik ${adminEmail} już istniał, nadano/poprawiono rolę "admin".`);
                    } else {
                        console.log(`Użytkownik admin ${adminEmail} już istnieje z poprawną rolą.`);
                    }
                }
            } catch (dbError) {
                console.error("Błąd podczas dodawania/aktualizacji użytkownika admina:", dbError.message);
            }
        };
        await addAdminUserIfNeeded();
        
        // Tabela sesji (dla connect-pg-simple)
        const createSessionTableSQL = `
            CREATE TABLE IF NOT EXISTS "session" (
                "sid" VARCHAR NOT NULL,
                "sess" JSON NOT NULL,
                "expire" TIMESTAMP(6) NOT NULL,
                CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
            );
        `;
        await client.query(createSessionTableSQL);
        console.log('Tabela "session" (z kluczem głównym zdefiniowanym inline) sprawdzona/utworzona.');

        const createSessionIndexSQL = `
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
        `;
        await client.query(createSessionIndexSQL);
        console.log('Indeks "IDX_session_expire" dla tabeli "session" sprawdzony/utworzony.');


        await client.query('COMMIT');
        console.log('Transakcja inicjalizacji bazy danych ZATWIERDZONA (COMMIT).');

    } catch (err) {
        console.error('Krytyczny błąd podczas inicjalizacji bazy danych, wykonywanie ROLLBACK...', err);
        await client.query('ROLLBACK');
        console.log('Transakcja inicjalizacji bazy danych WYCOFANA (ROLLBACK).');
        throw err; // Rzuć błąd dalej, aby został złapany przez startServer
    } finally {
        client.release();
        console.log('Zwolniono klienta bazy danych po inicjalizacji.');
    }
}


// --- Konfiguracja Nodemailer ---
let transporter;
const emailHost = process.env.EMAIL_HOST;
const emailPort = parseInt(process.env.EMAIL_PORT || "587"); // Domyślnie 587 dla STARTTLS
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
        logger: process.env.NODE_ENV !== 'production', // Loguj tylko w trybie deweloperskim
        debug: process.env.NODE_ENV !== 'production'   // Debuguj tylko w trybie deweloperskim
    };

    if (emailPort === 587) {
        transportOptions.secure = false; // Dla STARTTLS secure jest false
        transportOptions.requireTLS = true; // Wymuś STARTTLS
        console.log("Konfiguracja Nodemailer dla portu 587 (STARTTLS): secure=false, requireTLS=true");
    } else if (emailPort === 465) {
        transportOptions.secure = true; // Dla SSL secure jest true
        console.log("Konfiguracja Nodemailer dla portu 465 (SSL): secure=true");
    } else {
        // Dla innych portów, pozwól Nodemailerowi zdecydować lub ustaw domyślnie
        console.log("Konfiguracja Nodemailer dla portu", emailPort, "(domyślne ustawienia secure)");
         transportOptions.secure = (emailPort === 465); // Domyślnie secure=true tylko dla portu 465
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
            console.log("--- Symulacja wysyłki e-maila (konfiguracja SMTP niekompletna) ---");
            console.log("  OD:", mailOptions.from);
            console.log("  DO:", mailOptions.to);
            console.log("  TEMAT:", mailOptions.subject);
            console.log("  TREŚĆ (HTML):", mailOptions.html ? mailOptions.html.substring(0,100) + "..." : "Brak");
            console.log("--- Koniec symulacji ---");
            return { messageId: "symulacja-" + Date.now() };
        }
    };
}

async function sendEmail(to, subject, text, html) {
    const fromAddress = emailSenderAddress || emailUser || 'noreply@example.com';
    const mailOptions = {
        from: `"Platforma Materiałów" <${fromAddress}>`,
        to: to,
        subject: subject,
        text: text,
        html: html,
    };
    try {
        console.log(`Próba wysłania e-maila DO: ${to} OD: ${fromAddress} TEMAT: ${subject}`);
        let info = await transporter.sendMail(mailOptions);
        console.log('Informacja o wysłaniu emaila: %s do %s', info.messageId, to);
        return { success: true, info };
    } catch (error) {
        console.error(`Błąd podczas wysyłania emaila do ${to}:`, error);
        if (error.response) {
            console.error('Odpowiedź serwera SMTP:', error.response);
        }
        return { success: false, error };
    }
}

// --- Konfiguracja aplikacji Express ---
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error('FATAL ERROR: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona! Sesje nie będą działać poprawnie.');
} else if (sessionSecret === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!' && process.env.NODE_ENV === 'production') {
    console.warn('UWAGA: Używasz domyślnego sekretu sesji w środowisku produkcyjnym! ZMIEŃ TO NATYCHMIAST na długi, losowy ciąg znaków w zmiennych środowiskowych!');
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
        maxAge: 1000 * 60 * 60 * 24, // 1 dzień
        httpOnly: true, 
        sameSite: 'lax' 
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Middleware do logowania żądań (opcjonalne, ale pomocne)
app.use((req, res, next) => {
    console.log(`[REQ] ${new Date().toISOString()} | ${req.method} ${req.url} | SesjaID: ${req.sessionID} | UserID: ${req.session.userId || 'Niezalogowany'}`);
    next();
});


// --- Middleware autoryzacyjne ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next(); 
    }
    console.log(`  Użytkownik NIE jest uwierzytelniony (brak userId w sesji, SesjaID: ${req.sessionID}). Przekierowanie do /login z ${req.originalUrl}`);
    if (req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ message: 'Brak autoryzacji. Musisz być zalogowany.' });
    }
    res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
}

async function isAdmin(req, res, next) {
    if (!req.session.userId) {
        console.log('isAdmin: Brak userId w sesji. Użytkownik nie jest zalogowany.');
        if (req.originalUrl.startsWith('/api/')) {
            return res.status(401).json({ message: 'Brak autoryzacji - musisz być zalogowany.'});
        }
        return res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
    }
    try {
        const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0 && result.rows[0].role === 'admin') {
            return next(); 
        } else {
            console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}) NIE ma roli "admin" (rola: ${result.rows.length > 0 ? result.rows[0].role : 'brak'}). Odmowa dostępu do ${req.originalUrl}`);
            if (req.originalUrl.startsWith('/api/')) {
                return res.status(403).json({ message: 'Brak uprawnień - tylko dla administratorów.'});
            }
            // Przekieruj na dashboard użytkownika, jeśli próbuje wejść do /admin/* bez uprawnień
            return res.redirect('/dashboard.html?error=admin_required'); 
        }
    } catch (error) {
        console.error("Błąd w middleware isAdmin:", error);
        return res.status(500).json({ message: 'Błąd serwera podczas sprawdzania uprawnień.'});
    }
}

// --- Definicje ścieżek (Routes) ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

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
            // Wyślij email powitalny
            await sendEmail(
                newUser.email,
                'Witaj na Platformie Materiałów PRO!',
                `Witaj ${newUser.username},\n\nDziękujemy za rejestrację na naszej platformie Materiały PRO!\n\nPozdrawiamy,\nZespół Materiały PRO`,
                `<p>Witaj <strong>${newUser.username}</strong>,</p><p>Dziękujemy za rejestrację na naszej platformie Materiały PRO!</p><p>Pozdrawiamy,<br>Zespół Materiały PRO</p>`
            );
            
            res.status(201).json({ 
                message: 'Rejestracja pomyślna!', 
                user: { id: newUser.id, username: newUser.username, role: newUser.role }, 
                redirectTo: '/dashboard.html' 
            });
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas rejestracji:", error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas rejestracji.'});
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const redirectUrl = req.query.redirect; 

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
            
            let determinedRedirectTo = redirectUrl || (user.role === 'admin' ? '/admin_dashboard.html' : '/dashboard.html');
            if (user.role === 'admin' && (!redirectUrl || !redirectUrl.startsWith('/admin_dashboard.html'))) {
                determinedRedirectTo = '/admin_dashboard.html';
            } else if (user.role !== 'admin' && redirectUrl && redirectUrl.startsWith('/admin_dashboard.html')) {
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


app.get('/dashboard.html', isAuthenticated, (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/material_gallery.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'material_gallery.html'));
});


app.get('/api/user', isAuthenticated, (req, res) => { 
    res.json({
        username: req.session.username,
        userId: req.session.userId,
        role: req.session.role,
        email: req.session.email // Dodaj email do danych użytkownika w sesji, jeśli potrzebne
    });
});

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
app.get('/admin_dashboard.html', isAuthenticated, isAdmin, (req, res) => { 
    console.log(`Dostęp do /admin_dashboard.html udzielony dla admina: ${req.session.username}`);
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

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

// === API Endpoints dla Ustawień Administratora ===
app.get('/api/admin/settings', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT setting_key, setting_value FROM app_settings');
        const settings = result.rows.reduce((acc, row) => {
            // Konwersja wartości na odpowiednie typy, jeśli to konieczne
            if (row.setting_key === 'maintenanceMode' || row.setting_key === 'allowRegistration') {
                acc[row.setting_key] = (row.setting_value === 'true');
            } else if (['itemsPerPageAdmin', 'failedLoginAttempts', 'lockoutDuration'].includes(row.setting_key)) {
                acc[row.setting_key] = parseInt(row.setting_value, 10);
            }
            else {
                acc[row.setting_key] = row.setting_value;
            }
            return acc;
        }, {});

        // Dodaj informacje o konfiguracji SMTP (tylko informacyjnie, nie samo hasło)
        settings.smtpHost = process.env.EMAIL_HOST || 'Nie skonfigurowano';
        settings.smtpPort = parseInt(process.env.EMAIL_PORT || '0');
        settings.smtpUser = process.env.EMAIL_USER || 'Nie skonfigurowano';
        settings.smtpPassConfigured = !!process.env.EMAIL_PASS; // true jeśli hasło jest ustawione
        settings.smtpSender = process.env.EMAIL_SENDER_ADDRESS || settings.smtpUser || 'Nie skonfigurowano';
        settings.smtpSecure = (settings.smtpPort === 465); // Proste założenie, można ulepszyć

        res.json(settings);
    } catch (error) {
        console.error("Błąd podczas pobierania ustawień aplikacji:", error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania ustawień.' });
    }
});

app.post('/api/admin/settings', isAuthenticated, isAdmin, async (req, res) => {
    const settingsToUpdate = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const key in settingsToUpdate) {
            if (Object.prototype.hasOwnProperty.call(settingsToUpdate, key)) {
                // Pomijamy klucze związane z SMTP, które są tylko do odczytu z env
                if (key.startsWith('smtp')) continue;

                let valueToSave = settingsToUpdate[key];
                // Konwersja boolean na string dla bazy danych
                if (typeof valueToSave === 'boolean') {
                    valueToSave = valueToSave.toString();
                }

                const upsertQuery = `
                    INSERT INTO app_settings (setting_key, setting_value) 
                    VALUES ($1, $2) 
                    ON CONFLICT (setting_key) 
                    DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()
                `;
                await client.query(upsertQuery, [key, valueToSave]);
            }
        }
        await client.query('COMMIT');
        res.json({ message: 'Ustawienia zostały pomyślnie zaktualizowane.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Błąd podczas aktualizacji ustawień aplikacji:", error);
        res.status(500).json({ message: 'Błąd serwera podczas zapisywania ustawień.' });
    } finally {
        client.release();
    }
});

app.post('/api/admin/settings/test-smtp', isAuthenticated, isAdmin, async (req, res) => {
    try {
        // Pobierz email admina z ustawień lub zmiennej środowiskowej
        let adminEmailToTest = process.env.ADMIN_EMAIL; // Domyślnie z env
        const adminEmailSetting = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'adminEmail'");
        if (adminEmailSetting.rows.length > 0 && adminEmailSetting.rows[0].setting_value) {
            adminEmailToTest = adminEmailSetting.rows[0].setting_value;
        }
        
        if (!adminEmailToTest) {
            return res.status(400).json({ message: 'Adres email administratora nie jest skonfigurowany w ustawieniach ani w zmiennych środowiskowych.' });
        }

        if (!emailHost || !emailUser || !emailPass) {
             return res.status(400).json({ message: 'Konfiguracja SMTP (host, użytkownik, hasło) nie jest kompletna na serwerze.' });
        }

        const emailResult = await sendEmail(
            adminEmailToTest,
            'Testowa wiadomość SMTP z Panelu Admina',
            `Witaj,\n\nTo jest testowa wiadomość email wysłana z panelu administracyjnego Twojej platformy.\nJeśli ją otrzymałeś, konfiguracja SMTP działa poprawnie.\n\nPozdrawiamy,\nSystem MateriałyPRO\n\nCzas wysłania: ${new Date().toLocaleString('pl-PL')}`,
            `<p>Witaj,</p><p>To jest testowa wiadomość email wysłana z panelu administracyjnego Twojej platformy.</p><p>Jeśli ją otrzymałeś, konfiguracja SMTP działa poprawnie.</p><p>Pozdrawiamy,<br>System MateriałyPRO</p><p><i>Czas wysłania: ${new Date().toLocaleString('pl-PL')}</i></p>`
        );

        if (emailResult.success) {
            res.json({ message: `Testowy email został wysłany pomyślnie na adres ${adminEmailToTest}.` });
        } else {
            throw emailResult.error; // Rzuć błąd, aby został złapany przez catch
        }
    } catch (error) {
        console.error("Błąd podczas wysyłania testowego emaila SMTP:", error);
        res.status(500).json({ message: `Nie udało się wysłać testowego emaila. Błąd: ${error.message || 'Nieznany błąd SMTP'}` });
    }
});


// === PUBLICZNE API Endpoints dla Materiałów (dla zalogowanych użytkowników) ===

app.get('/api/materials', isAuthenticated, async (req, res) => {
    try {
        const queryText = "SELECT id, title, description, category, price, cover_image_url, status FROM materials WHERE status = 'published' ORDER BY created_at DESC";
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania opublikowanych materiałów:", error);
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

        // TODO: Dodać logikę płatności, jeśli material.price > 0
        if (material.price > 0) {
            console.log(`Użytkownik ${userId} próbuje nabyć płatny materiał ${materialId} (${material.price} PLN) - logika płatności niezaimplementowana.`);
            // return res.status(501).json({ message: 'Płatności nie są jeszcze zaimplementowane.' });
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
async function startServer() {
    try {
        await initializeDatabase(); // Poczekaj na zakończenie inicjalizacji bazy danych
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
            console.log('  Inicjalizacja bazy danych przy starcie (tabele: users, materials, user_materials, session, app_settings).');
            console.log('  Dodano endpointy API dla zarządzania ustawieniami aplikacji.');
            console.log('---');
        });
    } catch (error) {
        console.error("KRYTYCZNY BŁĄD: Nie udało się uruchomić serwera z powodu błędu inicjalizacji bazy danych.", error);
        process.exit(1); // Zakończ proces, jeśli inicjalizacja bazy danych się nie powiedzie
    }
}

startServer();
