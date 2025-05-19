// server.js

// Importowanie potrzebnych modułów
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg'); // Klient PostgreSQL
const pgSession = require('connect-pg-simple')(session); // Do przechowywania sesji w PostgreSQL

// Inicjalizacja aplikacji Express
const app = express();
const PORT = process.env.PORT || 3000;

// WAŻNE: Poinformuj Express, że działa za reverse proxy (np. na Render)
// To pozwala na poprawne działanie `secure: true` dla ciasteczek sesji.
app.set('trust proxy', 1); // Ufa pierwszemu proxy

// --- Konfiguracja Połączenia z Bazą Danych PostgreSQL ---
if (!process.env.DATABASE_URL) {
    console.error('FATAL ERROR: Zmienna środowiskowa DATABASE_URL nie jest ustawiona!');
    // process.exit(1); 
}
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('Błąd połączenia z bazą danych PostgreSQL!', err.stack);
    }
    if (client) {
        client.query('SELECT NOW()', (err, result) => {
            release();
            if (err) {
                return console.error('Błąd podczas wykonywania zapytania testowego do bazy', err.stack);
            }
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
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
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
        console.log('Tabela "users" sprawdzona/utworzona pomyślnie.');
        
        await pool.query(createSessionTableQuery);
        console.log('Tabela "session" sprawdzona/utworzona pomyślnie.');

    } catch (err) {
        console.error('Błąd podczas inicjalizacji bazy danych (tworzenia tabel):', err);
    }
}
initializeDatabase();

// --- Konfiguracja aplikacji Express ---
app.use(bodyParser.urlencoded({ extended: true }));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error('FATAL ERROR: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona! Sesje nie będą działać poprawnie.');
} else if (sessionSecret === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!' && process.env.NODE_ENV === 'production') {
    console.warn('UWAGA: Używasz domyślnego sekretu sesji w środowisku produkcyjnym! ZMIEŃ TO NATYCHMIAST na długi, losowy ciąg znaków w zmiennych środowiskowych Render!');
}

// Konfiguracja magazynu sesji w PostgreSQL
const sessionStore = new pgSession({
    pool: pool,
    tableName: 'session',
    // pruneSessionInterval: 60 // Co 60 sekund usuwaj wygasłe sesje z bazy
});
console.log('Magazyn sesji (pgSession) skonfigurowany.');

app.use(session({
    store: sessionStore,
    secret: sessionSecret || 'domyslny-sekret-na-wszelki-wypadek-dev-only', // Zapewnij fallback dla dev
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Ciasteczko wysyłane tylko przez HTTPS w produkcji
        maxAge: 1000 * 60 * 60 * 24, // 1 dzień
        httpOnly: true, // Zapobiega dostępowi do ciasteczka przez JavaScript po stronie klienta
        sameSite: 'lax' // Ochrona przed atakami CSRF
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


// --- Definicje ścieżek (Routes) ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    console.log('POST /register, dane z formularza:', req.body);
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
            // ... (obsługa istniejącego użytkownika bez zmian)
            if (existingUser.rows[0].email === email) {
                console.log(`Próba rejestracji na istniejący email: ${email}`);
                return res.status(400).send('Użytkownik o takim adresie email już istnieje!');
            }
            if (existingUser.rows[0].username === username) {
                console.log(`Próba rejestracji na istniejącą nazwę użytkownika: ${username}`);
                return res.status(400).send('Użytkownik o takiej nazwie już istnieje!');
            }
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const insertUserQuery = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username';
        const newUserResult = await pool.query(insertUserQuery, [username, email, hashedPassword]);
        const newUser = newUserResult.rows[0];
        console.log('Nowy użytkownik zarejestrowany i zapisany do bazy:', newUser);

        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        console.log('Sesja ustawiona po rejestracji (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));
        
        req.session.save(err => {
            if (err) {
                console.error('Błąd podczas zapisywania sesji po rejestracji:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            console.log('Sesja (ID: ' + req.sessionID + ') zapisana po rejestracji, przekierowanie do /dashboard');
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
    console.log('POST /login, dane z formularza:', req.body);
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email i hasło są wymagane!');
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }
        console.log(`Hasło poprawne dla użytkownika: ${user.username}`);

        req.session.userId = user.id;
        req.session.username = user.username;
        console.log('Sesja ustawiona po logowaniu (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));

        req.session.save(err => {
            if (err) {
                console.error('Błąd podczas zapisywania sesji po logowaniu:', err);
                return res.status(500).send('Wystąpił błąd serwera podczas próby zapisania sesji.');
            }
            console.log('Sesja (ID: ' + req.sessionID + ') zapisana po logowaniu, przekierowanie do /dashboard');
            res.redirect('/dashboard');
        });

    } catch (error) {
        console.error("Krytyczny błąd podczas logowania:", error);
        res.status(500).send('Wystąpił błąd serwera podczas logowania.');
    }
});

function isAuthenticated(req, res, next) {
    console.log('Middleware isAuthenticated - sprawdzanie sesji (ID: ' + req.sessionID + '):', JSON.stringify(req.session, null, 2));
    if (req.session && req.session.userId) {
        console.log(`  Użytkownik ${req.session.username} (ID: ${req.session.userId}, SesjaID: ${req.sessionID}) jest uwierzytelniony. Dostęp do ${req.originalUrl}`);
        return next();
    }
    console.log(`  Użytkownik NIE jest uwierzytelniony (brak userId w sesji, SesjaID: ${req.sessionID}). Przekierowanie do /login z ${req.originalUrl}`);
    res.redirect('/login');
}

app.get('/dashboard', isAuthenticated, (req, res) => {
    console.log(`Serwowanie /dashboard dla użytkownika: ${req.session.username} (SesjaID: ${req.sessionID})`);
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/user', isAuthenticated, (req, res) => {
    console.log(`Zapytanie do /api/user od użytkownika: ${req.session.username} (SesjaID: ${req.sessionID})`);
    if (req.session.username && req.session.userId) {
        res.json({
            username: req.session.username,
            userId: req.session.userId
        });
    } else {
        console.warn(`/api/user - brak danych użytkownika w sesji (SesjaID: ${req.sessionID}), mimo przejścia isAuthenticated.`);
        res.status(404).json({ error: 'User data not found in session' });
    }
});

app.get('/logout', (req, res) => {
    const username = req.session.username;
    const sessionID = req.sessionID;
    console.log(`Próba wylogowania użytkownika: ${username || 'niezidentyfikowany'} (SesjaID: ${sessionID})`);
    
    req.session.destroy(err => {
        if (err) {
            console.error(`Błąd podczas niszczenia sesji (ID: ${sessionID}) przy wylogowywaniu:`, err);
            return res.status(500).send('Nie udało się wylogować.');
        }
        res.clearCookie('connect.sid'); 
        console.log(`Użytkownik ${username || ''} wylogowany pomyślnie (SesjaID: ${sessionID}). Przekierowanie na /`);
        res.redirect('/');
    });
});

// --- Uruchomienie serwera ---
app.listen(PORT, () => {
    console.log(`Serwer uruchomiony na porcie ${PORT}`);
    // ... (reszta logów startowych bez zmian)
    if (!process.env.DATABASE_URL) {
        console.warn('OSTRZEŻENIE: Zmienna środowiskowa DATABASE_URL nie jest ustawiona. Aplikacja może nie działać poprawnie z bazą danych.');
    }
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'bardzo-tajny-sekret-do-zmiany-w-produkcji!') {
        console.warn('OSTRZEŻENIE: Zmienna środowiskowa SESSION_SECRET nie jest ustawiona lub używa wartości domyślnej. ZMIEŃ TO W PRODUKCJI!');
    }
    if (process.env.NODE_ENV !== 'production') {
        console.warn('OSTRZEŻENIE: Aplikacja działa w trybie deweloperskim (NODE_ENV nie jest ustawione na "production").');
    } else {
        console.log('Aplikacja działa w trybie produkcyjnym.');
    }
    console.log('---');
    console.log('Ustawiono "trust proxy" na 1.');
    console.log('Magazyn sesji skonfigurowany do używania PostgreSQL (connect-pg-simple).');
    console.log('Tabela "session" powinna być teraz tworzona przy starcie serwera, jeśli nie istnieje.');
    console.log('---');
});
