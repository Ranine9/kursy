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
            console.log('Pomyślnie połączono z PostgreSQL. Serwer czasu bazy danych:', result.rows[0].now);
        });
    } else {
        console.error('Nie udało się uzyskać klienta z puli połączeń PostgreSQL.');
    }
});

async function initializeDatabase() {
    const createUserTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user' NOT NULL, -- Dodano pole roli, domyślnie 'user'
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    // Dodaj przykładowego admina, jeśli tabela jest pusta i go nie ma (tylko dla ułatwienia startu)
    // W produkcji role admina nadawaj w bezpieczniejszy sposób!
    const addAdminUserIfNeeded = async () => {
        try {
            const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
            const adminPassword = process.env.ADMIN_PASSWORD || 'adminpassword'; // Ustaw silne hasło w zmiennych środowiskowych!
            
            const res = await pool.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
            if (res.rows.length === 0) {
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(adminPassword, salt);
                await pool.query(
                    'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)',
                    ['admin', adminEmail, hashedPassword, 'admin']
                );
                console.log(`Dodano domyślnego użytkownika admina: ${adminEmail} (hasło: ${adminPassword} - ZMIEŃ JE!). Rola: admin.`);
                console.log("Pamiętaj, aby ustawić ADMIN_EMAIL i ADMIN_PASSWORD w zmiennych środowiskowych dla bezpieczeństwa.");
            } else {
                // Upewnij się, że istniejący użytkownik ma rolę admina, jeśli to ten sam email
                if (res.rows[0].role !== 'admin' && res.rows[0].email === adminEmail) {
                    await pool.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', adminEmail]);
                    console.log(`Użytkownik ${adminEmail} już istniał, nadano rolę "admin".`);
                }
            }
        } catch (dbError) {
            console.error("Błąd podczas dodawania/aktualizacji użytkownika admina:", dbError);
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
    try {
        await pool.query(createUserTableQuery);
        console.log('Tabela "users" sprawdzona/utworzona pomyślnie (z polem role).');
        await addAdminUserIfNeeded(); // Sprawdź i dodaj admina
        
        await pool.query(createSessionTableQuery);
        console.log('Tabela "session" sprawdzona/utworzona pomyślnie.');

    } catch (err) {
        console.error('Błąd podczas inicjalizacji bazy danych (tworzenia tabel):', err);
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
        from: `"Platforma KursyOnline" <${fromAddress}>`,
        to: userEmail,
        subject: 'Witaj w KursyOnline! Potwierdzenie rejestracji',
        text: `Witaj ${username},\n\nDziękujemy za rejestrację na platformie KursyOnline!\n\nPozdrawiamy,\nZespół KursyOnline`,
        html: `<p>Witaj <strong>${username}</strong>,</p><p>Dziękujemy za rejestrację na platformie KursyOnline!</p><p>Pozdrawiamy,<br>Zespół KursyOnline</p>`,
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
// ... (bodyParser, sessionStore, app.use(session(...)), static, middleware logujący żądania - bez zmian)
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
    // console.log('Middleware isAuthenticated - sprawdzanie sesji (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));
    if (req.session && req.session.userId) {
        // console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}, SesjaID: ${req.sessionID}) jest uwierzytelniony. Dostęp do ${req.originalUrl}`);
        return next();
    }
    console.log(`  Użytkownik NIE jest uwierzytelniony (brak userId w sesji, SesjaID: ${req.sessionID}). Przekierowanie do /login z ${req.originalUrl}`);
    res.redirect('/login');
}

async function isAdmin(req, res, next) {
    // console.log('Middleware isAdmin - sprawdzanie roli użytkownika (ID: ' + req.session.userId + ')');
    if (!req.session.userId) {
        console.log('isAdmin: Brak userId w sesji. Użytkownik nie jest zalogowany.');
        return res.status(401).send('Brak autoryzacji - musisz być zalogowany.');
    }
    try {
        const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0 && result.rows[0].role === 'admin') {
            // console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}) ma rolę "admin". Dostęp do ${req.originalUrl}`);
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
// ... (ścieżki /, /register, /login, /dashboard, /api/user, /logout - bez zmian)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    // console.log('POST /register, dane z formularza:', req.body);
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
                // console.log(`Próba rejestracji na istniejący email: ${email}`);
                return res.status(400).send('Użytkownik o takim adresie email już istnieje!');
            }
            if (existingUser.rows[0].username === username) {
                // console.log(`Próba rejestracji na istniejącą nazwę użytkownika: ${username}`);
                return res.status(400).send('Użytkownik o takiej nazwie już istnieje!');
            }
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Domyślnie rola to 'user', chyba że to pierwszy użytkownik - wtedy można by dać 'admin'
        // Ale na razie zostawiamy domyślną 'user' przy standardowej rejestracji.
        // Rola admina będzie nadawana ręcznie lub przez specjalny proces.
        const insertUserQuery = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email';
        const newUserResult = await pool.query(insertUserQuery, [username, email, hashedPassword]);
        const newUser = newUserResult.rows[0];
        console.log('Nowy użytkownik zarejestrowany i zapisany do bazy:', newUser);

        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        // console.log('Sesja ustawiona po rejestracji (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));
        
        req.session.save(async err => { 
            if (err) {
                console.error('Błąd podczas zapisywania sesji po rejestracji:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            // console.log('Sesja (ID: ' + req.sessionID + ') zapisana po rejestracji.');
            
            await sendRegistrationEmail(newUser.email, newUser.username); 
            
            // console.log('Przekierowanie do /dashboard po rejestracji i (próbie) wysłania emaila.');
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
    // console.log('POST /login, dane z formularza:', req.body);
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email i hasło są wymagane!');
    }

    try {
        const result = await pool.query('SELECT id, username, email, password_hash, role FROM users WHERE email = $1', [email]); // Pobieramy też rolę
        const user = result.rows[0];

        if (!user) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }
        // console.log(`Hasło poprawne dla użytkownika: ${user.username}`);

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role; // Zapisujemy rolę w sesji!
        // console.log('Sesja ustawiona po logowaniu (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));

        req.session.save(err => {
            if (err) {
                console.error('Błąd podczas zapisywania sesji po logowaniu:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            // console.log('Sesja (ID: ' + req.sessionID + ') zapisana po logowaniu.');
            if (user.role === 'admin') {
                res.redirect('/admin/dashboard'); // Przekieruj admina od razu do panelu admina
            } else {
                res.redirect('/dashboard'); // Zwykłego użytkownika do jego panelu
            }
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas logowania:", error);
        res.status(500).send('Wystąpił błąd serwera podczas logowania.');
    }
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    // console.log(`Serwowanie /dashboard dla użytkownika: ${req.session.username} (SesjaID: ${req.sessionID})`);
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/user', isAuthenticated, (req, res) => {
    // console.log(`Zapytanie do /api/user od użytkownika: ${req.session.username} (SesjaID: ${req.sessionID})`);
    if (req.session.username && req.session.userId) {
        res.json({
            username: req.session.username,
            userId: req.session.userId,
            role: req.session.role // Dodajemy rolę do odpowiedzi API
        });
    } else {
        // console.warn(`/api/user - brak danych użytkownika w sesji (SesjaID: ${req.sessionID}), mimo przejścia isAuthenticated.`);
        res.status(404).json({ error: 'User data not found in session' });
    }
});

app.get('/logout', (req, res) => {
    const username = req.session.username;
    const sessionID = req.sessionID;
    // console.log(`Próba wylogowania użytkownika: ${username || 'niezidentyfikowany'} (SesjaID: ${sessionID})`);
    
    req.session.destroy(err => {
        if (err) {
            console.error(`Błąd podczas niszczenia sesji (ID: ${sessionID}) przy wylogowywaniu:`, err);
            return res.status(500).send('Nie udało się wylogować.');
        }
        res.clearCookie('connect.sid'); 
        // console.log(`Użytkownik ${username || ''} wylogowany pomyślnie (SesjaID: ${sessionID}). Przekierowanie na /`);
        res.redirect('/');
    });
});

// --- Ścieżki dla Panelu Administracyjnego ---
app.get('/admin/dashboard', isAuthenticated, isAdmin, (req, res) => {
    console.log(`Dostęp do /admin/dashboard udzielony dla admina: ${req.session.username}`);
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

// API endpoint do pobierania listy użytkowników (tylko dla admina)
app.get('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        // Wykluczamy hasła z wyniku
        const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (error) {
        console.error("Błąd podczas pobierania listy użytkowników dla admina:", error);
        res.status(500).json({ error: 'Błąd serwera podczas pobierania użytkowników.' });
    }
});


// --- Uruchomienie serwera ---
// ... (logi startowe bez zmian)
app.listen(PORT, () => {
    console.log(`Serwer uruchomiony na porcie ${PORT}`);
    if (!process.env.DATABASE_URL) {
        console.warn('OSTRZEŻENIE: Zmienna środowiskowa DATABASE_URL nie jest ustawiona.');
    }
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!') {
        console.warn('OSTRZEŻENIE: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona lub używa wartości domyślnej!');
    }
    if (process.env.NODE_ENV !== 'production') {
        console.warn('OSTRZEŻENIE: Aplikacja działa w trybie deweloperskim.');
    } else {
        console.log('Aplikacja działa w trybie produkcyjnym.');
    }
    if (!emailHost || !emailUser || !emailPass) { 
        console.warn("OSTRZEŻENIE: Brak pełnej konfiguracji SMTP (EMAIL_HOST, EMAIL_USER, EMAIL_PASS). Wysyłka maili będzie symulowana.");
    }
    if (!emailSenderAddress && (emailHost && emailUser && emailPass)) {
        console.warn("OSTRZEŻENIE: Zmienna EMAIL_SENDER_ADDRESS nie jest ustawiona. Jako adres 'Od' zostanie użyty login SMTP (EMAIL_USER), co może powodować problemy z dostarczalnością lub błędy, jeśli nie jest to zweryfikowany nadawca w Brevo.");
    }
    console.log('---');
    console.log('Ustawiono "trust proxy" na 1.');
    console.log('Magazyn sesji skonfigurowany do używania PostgreSQL.');
    console.log('Tabela "session" powinna być tworzona przy starcie serwera.');
    console.log('Pole "role" dodane do tabeli "users".');
    console.log('---');
});
