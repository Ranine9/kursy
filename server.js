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
    if (err) {
        console.error('Błąd połączenia z pulą bazy danych PostgreSQL!', err.stack);
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

        // Tabela materiałów - z nowymi polami is_featured i discount_price
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
                is_featured BOOLEAN DEFAULT FALSE,
                discount_price NUMERIC(10, 2) NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(createMaterialsTableQuery);
        console.log('Tabela "materials" (z is_featured, discount_price) sprawdzona/utworzona.');

        // Sprawdzenie i dodanie kolumn is_featured i discount_price, jeśli nie istnieją (dla istniejących tabel)
        const checkFeaturedColumnQuery = `SELECT column_name FROM information_schema.columns WHERE table_name='materials' AND column_name='is_featured';`;
        const featuredColumnCheck = await client.query(checkFeaturedColumnQuery);
        if (featuredColumnCheck.rows.length === 0) {
            await client.query('ALTER TABLE materials ADD COLUMN is_featured BOOLEAN DEFAULT FALSE;');
            console.log('Dodano kolumnę "is_featured" do tabeli "materials".');
        }

        const checkDiscountPriceColumnQuery = `SELECT column_name FROM information_schema.columns WHERE table_name='materials' AND column_name='discount_price';`;
        const discountPriceColumnCheck = await client.query(checkDiscountPriceColumnQuery);
        if (discountPriceColumnCheck.rows.length === 0) {
            await client.query('ALTER TABLE materials ADD COLUMN discount_price NUMERIC(10, 2) NULL;');
            console.log('Dodano kolumnę "discount_price" do tabeli "materials".');
        }
        
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

        // Trigger do aktualizacji `updated_at`
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

        const applyUpdatedAtTriggerToAppSettings = `
            DROP TRIGGER IF EXISTS set_timestamp_app_settings ON app_settings;
            CREATE TRIGGER set_timestamp_app_settings
            BEFORE UPDATE ON app_settings
            FOR EACH ROW
            EXECUTE PROCEDURE trigger_set_timestamp();
        `;
        await client.query(applyUpdatedAtTriggerToAppSettings);
        console.log('Trigger "updated_at" dla "app_settings" sprawdzony/utworzony.');

        // Domyślne ustawienia aplikacji
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
            { key: 'lockoutDuration', value: '15' }
        ];
        console.log('Sprawdzanie/dodawanie domyślnych ustawień...');
        for (const setting of defaultSettings) {
            const res = await client.query('SELECT setting_value FROM app_settings WHERE setting_key = $1', [setting.key]);
            if (res.rows.length === 0) {
                await client.query('INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, $2)', [setting.key, setting.value]);
                console.log(`  Dodano domyślne ustawienie: ${setting.key} = ${setting.value}`);
            }
        }
        console.log('Zakończono sprawdzanie/dodawanie domyślnych ustawień.');
        
        // Dodanie użytkownika admina
        const addAdminUserIfNeeded = async () => {
            try {
                const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
                const adminPassword = process.env.ADMIN_PASSWORD || 'adminpassword'; 
                const res = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
                if (res.rows.length === 0) {
                    const salt = await bcrypt.genSalt(10);
                    const hashedPassword = await bcrypt.hash(adminPassword, salt);
                    await client.query('INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)', ['admin', adminEmail, hashedPassword, 'admin']);
                    console.log(`Dodano domyślnego użytkownika admina: ${adminEmail}. Rola: admin.`);
                } else if (res.rows[0].role !== 'admin') {
                    await client.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', adminEmail]);
                    console.log(`Użytkownik ${adminEmail} już istniał, nadano/poprawiono rolę "admin".`);
                }
            } catch (dbError) { console.error("Błąd podczas dodawania/aktualizacji użytkownika admina:", dbError.message); }
        };
        await addAdminUserIfNeeded();
        
        // Tabela sesji
        const createSessionTableSQL = `
            CREATE TABLE IF NOT EXISTS "session" (
                "sid" VARCHAR NOT NULL,
                "sess" JSON NOT NULL,
                "expire" TIMESTAMP(6) NOT NULL,
                CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
            );
        `;
        await client.query(createSessionTableSQL);
        console.log('Tabela "session" sprawdzona/utworzona.');
        const createSessionIndexSQL = `CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");`;
        await client.query(createSessionIndexSQL);
        console.log('Indeks "IDX_session_expire" dla tabeli "session" sprawdzony/utworzony.');

        await client.query('COMMIT');
        console.log('Transakcja inicjalizacji bazy danych ZATWIERDZONA (COMMIT).');
    } catch (err) {
        console.error('Krytyczny błąd podczas inicjalizacji bazy danych, wykonywanie ROLLBACK...', err);
        await client.query('ROLLBACK');
        console.log('Transakcja inicjalizacji bazy danych WYCOFANA (ROLLBACK).');
        throw err;
    } finally {
        client.release();
        console.log('Zwolniono klienta bazy danych po inicjalizacji.');
    }
}

// --- Konfiguracja Nodemailer ---
let transporter;
const emailHost = process.env.EMAIL_HOST;
const emailPort = parseInt(process.env.EMAIL_PORT || "587");
const emailUser = process.env.EMAIL_USER; 
const emailPass = process.env.EMAIL_PASS; 
const emailSenderAddress = process.env.EMAIL_SENDER_ADDRESS; 

if (emailHost && emailUser && emailPass) {
    let transportOptions = {
        host: emailHost, port: emailPort, auth: { user: emailUser, pass: emailPass },
        logger: process.env.NODE_ENV !== 'production', debug: process.env.NODE_ENV !== 'production'
    };
    if (emailPort === 587) { transportOptions.secure = false; transportOptions.requireTLS = true; }
    else if (emailPort === 465) { transportOptions.secure = true; }
    else { transportOptions.secure = (emailPort === 465); }
    transporter = nodemailer.createTransport(transportOptions);
    transporter.verify((error) => {
        if (error) console.error("Błąd weryfikacji Nodemailer:", error);
        else console.log("Nodemailer skonfigurowany i zweryfikowany.");
    });
} else {
    console.warn("OSTRZEŻENIE: Brak pełnej konfiguracji SMTP. Wysyłka maili będzie symulowana.");
    transporter = { sendMail: async (o) => { console.log("Symulacja email:", o.to, o.subject); return { messageId: "sym-" + Date.now() }; } };
}

async function sendEmail(to, subject, text, html) {
    const from = emailSenderAddress || emailUser || 'noreply@example.com';
    try {
        let info = await transporter.sendMail({ from: `"Platforma Materiałów" <${from}>`, to, subject, text, html });
        console.log('Email wysłany: %s do %s', info.messageId, to);
        return { success: true, info };
    } catch (error) {
        console.error(`Błąd wysyłania emaila do ${to}:`, error);
        return { success: false, error };
    }
}

// --- Konfiguracja aplikacji Express ---
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 
const sessionSecret = process.env.SESSION_SECRET || 'domyslny-sekret-na-wszelki-wypadek-dev-only';
if (!process.env.SESSION_SECRET) console.error('FATAL ERROR: SESSION_SECRET nie jest ustawiona!');
const sessionStore = new pgSession({ pool: pool, tableName: 'session' });
app.use(session({
    store: sessionStore, secret: sessionSecret, resave: false, saveUninitialized: false, 
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24, httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
    console.log(`[REQ] ${new Date().toISOString()} | ${req.method} ${req.url} | SesjaID: ${req.sessionID} | UserID: ${req.session.userId || 'Niezalogowany'}`);
    next();
});

// --- Middleware autoryzacyjne ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) return next();
    if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ message: 'Brak autoryzacji.' });
    res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
}
async function isAdmin(req, res, next) {
    if (!req.session.userId) {
        if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ message: 'Brak autoryzacji.'});
        return res.redirect(`/login.html?redirect=${encodeURIComponent(req.originalUrl)}`);
    }
    try {
        const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length > 0 && result.rows[0].role === 'admin') return next();
        if (req.originalUrl.startsWith('/api/')) return res.status(403).json({ message: 'Brak uprawnień.'});
        return res.redirect('/dashboard.html?error=admin_required'); 
    } catch (error) {
        console.error("Błąd w isAdmin:", error);
        return res.status(500).json({ message: 'Błąd serwera.'});
    }
}

// --- Definicje ścieżek (Routes) ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.post('/register', async (req, res) => {
    const { username, email, password, 'confirm-password': confirmPassword } = req.body;
    if (!username || !email || !password || !confirmPassword || password !== confirmPassword || password.length < 6) {
        return res.status(400).json({ message: 'Niepoprawne dane formularza.' });
    }
    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (existingUser.rows.length > 0) return res.status(409).json({ message: 'Użytkownik o takim emailu lub nazwie już istnieje.' });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUserResult = await pool.query('INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, email, role', [username, email, hashedPassword, 'user']);
        const newUser = newUserResult.rows[0];
        req.session.userId = newUser.id; req.session.username = newUser.username; req.session.role = newUser.role; req.session.email = newUser.email;
        req.session.save(async err => {
            if (err) return res.status(500).json({ message: 'Błąd zapisu sesji.'});
            await sendEmail(newUser.email, 'Witaj na Platformie!', `Dziękujemy za rejestrację, ${newUser.username}!`, `<p>Dziękujemy za rejestrację, <strong>${newUser.username}</strong>!</p>`);
            res.status(201).json({ message: 'Rejestracja pomyślna!', user: newUser, redirectTo: '/dashboard.html' });
        });
    } catch (error) { console.error("Błąd /register:", error); res.status(500).json({ message: 'Błąd serwera.'}); }
});
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const redirectUrl = req.query.redirect;
    if (!email || !password) return res.status(400).json({ message: 'Email i hasło są wymagane.' });
    try {
        const result = await pool.query('SELECT id, username, email, password_hash, role FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: 'Nieprawidłowy email lub hasło.' });
        }
        req.session.userId = user.id; req.session.username = user.username; req.session.role = user.role; req.session.email = user.email; // Dodano email do sesji
        req.session.save(err => {
            if (err) return res.status(500).json({ message: 'Błąd zapisu sesji.'});
            let dest = redirectUrl || (user.role === 'admin' ? '/admin_dashboard.html' : '/dashboard.html');
            if (user.role === 'admin' && (!redirectUrl || !redirectUrl.startsWith('/admin_dashboard.html'))) dest = '/admin_dashboard.html';
            else if (user.role !== 'admin' && redirectUrl && redirectUrl.startsWith('/admin_dashboard.html')) dest = '/dashboard.html';
            res.status(200).json({ message: 'Logowanie pomyślne!', user, redirectTo: dest });
        });
    } catch (error) { console.error("Błąd /login:", error); res.status(500).json({ message: 'Błąd serwera.'}); }
});

app.get('/dashboard.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/material_gallery.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'material_gallery.html')));

app.get('/api/user', isAuthenticated, (req, res) => {
    // Zwracamy email z sesji, który został tam umieszczony podczas logowania
    res.json({ 
        username: req.session.username, 
        userId: req.session.userId, 
        role: req.session.role,
        email: req.session.email 
    });
});

// NOWE ENDPOINTY DLA PROFILU UŻYTKOWNIKA
app.put('/api/user/profile', isAuthenticated, async (req, res) => {
    const { email } = req.body;
    const userId = req.session.userId;

    if (!email || typeof email !== 'string' || !email.includes('@')) { // Prosta walidacja email
        return res.status(400).json({ message: 'Nieprawidłowy format adresu email.' });
    }

    try {
        // Sprawdź, czy nowy email nie jest już zajęty przez innego użytkownika
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email, userId]);
        if (emailCheck.rows.length > 0) {
            return res.status(409).json({ message: 'Ten adres email jest już używany przez inne konto.' });
        }

        const result = await pool.query('UPDATE users SET email = $1 WHERE id = $2 RETURNING email', [email, userId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }
        req.session.email = result.rows[0].email; // Zaktualizuj email w sesji
        req.session.save(err => {
            if (err) {
                console.error('Błąd zapisu sesji po aktualizacji profilu:', err);
                // Mimo wszystko, baza danych została zaktualizowana, więc można wysłać sukces
            }
            res.json({ message: 'Adres email został pomyślnie zaktualizowany.', email: result.rows[0].email });
        });
    } catch (error) {
        console.error(`Błąd podczas aktualizacji profilu użytkownika ID ${userId}:`, error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas aktualizacji profilu.' });
    }
});

app.put('/api/user/password', isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.session.userId;

    if (!currentPassword || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: 'Wszystkie pola są wymagane, a nowe hasło musi mieć co najmniej 6 znaków.' });
    }

    try {
        const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }
        const user = userResult.rows[0];

        const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Aktualne hasło jest nieprawidłowe.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedNewPassword, userId]);
        
        // Opcjonalnie: wyloguj użytkownika z innych sesji lub poinformuj o zmianie hasła
        res.json({ message: 'Hasło zostało pomyślnie zmienione.' });

    } catch (error) {
        console.error(`Błąd podczas zmiany hasła użytkownika ID ${userId}:`, error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas zmiany hasła.' });
    }
});


app.get('/logout', (req, res) => { /* bez zmian */ 
    req.session.destroy(err => {
        if (err) return res.redirect('/?logoutError=true');
        res.clearCookie('connect.sid'); res.redirect('/');
    });
});

// --- Ścieżki dla Panelu Administracyjnego (bez zmian w tej iteracji, poza tym co już było) ---
app.get('/admin_dashboard.html', isAuthenticated, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html')));
app.get('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    try {
        const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.put('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    const userId = parseInt(req.params.id); 
    const { username, email, role, password } = req.body; 
    if (!username || !email || !role || (role !== 'user' && role !== 'admin')) return res.status(400).json({ message: 'Niepoprawne dane.' });
    try {
        const conflictCheck = await pool.query('SELECT id FROM users WHERE (email = $1 OR username = $2) AND id != $3', [email, username, userId]);
        if (conflictCheck.rows.length > 0) return res.status(409).json({ message: 'Email lub nazwa użytkownika zajęte.' });
        let hashedPassword = null;
        if (password && password.trim() !== '') { 
            if (password.length < 6) return res.status(400).json({ message: 'Hasło za krótkie.' });
            hashedPassword = await bcrypt.hash(password, await bcrypt.genSalt(10));
        }
        const fields = ['username = $1', 'email = $2', 'role = $3'];
        const values = [username, email, role];
        if (hashedPassword) { fields.push(`password_hash = $${values.length + 1}`); values.push(hashedPassword); }
        values.push(userId);
        const query = `UPDATE users SET ${fields.join(', ')} WHERE id = $${values.length} RETURNING id, username, email, role`;
        const result = await pool.query(query, values);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        res.json({ message: 'Dane zaktualizowane.', user: result.rows[0] });
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.delete('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    const userIdToDelete = parseInt(req.params.id);
    if (userIdToDelete === req.session.userId) return res.status(403).json({ message: 'Nie można usunąć własnego konta.' });
    try {
        await pool.query('DELETE FROM user_materials WHERE user_id = $1', [userIdToDelete]);
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, username', [userIdToDelete]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        res.json({ message: `Użytkownik "${result.rows[0].username}" usunięty.` });
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

app.get('/api/admin/materials', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    try {
        const result = await pool.query('SELECT id, title, description, category, price, file_url, cover_image_url, status, is_featured, discount_price, created_at, updated_at FROM materials ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) { console.error("Błąd /api/admin/materials (GET):", error); res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.post('/api/admin/materials', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    const { title, description, category, price, file_url, cover_image_url, status, is_featured, discount_price } = req.body;
    if (!title || !file_url) return res.status(400).json({ message: 'Tytuł i link do pliku są wymagane.' });
    try {
        const query = `INSERT INTO materials (title, description, category, price, file_url, cover_image_url, status, is_featured, discount_price) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`; 
        const values = [title, description || null, category || null, price ? parseFloat(price) : 0.00, file_url, cover_image_url || null, status || 'draft', is_featured || false, discount_price ? parseFloat(discount_price) : null];
        const result = await pool.query(query, values);
        res.status(201).json({ message: 'Materiał dodany.', material: result.rows[0] });
    } catch (error) { console.error("Błąd /api/admin/materials (POST):", error); res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.put('/api/admin/materials/:id', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    const materialId = parseInt(req.params.id);
    const { title, description, category, price, file_url, cover_image_url, status, is_featured, discount_price } = req.body;
    if (!title || !file_url) return res.status(400).json({ message: 'Tytuł i link do pliku są wymagane.' });
    try {
        const fields = [], values = []; let idx = 1;
        if (title !== undefined) { fields.push(`title = $${idx++}`); values.push(title); }
        if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
        if (category !== undefined) { fields.push(`category = $${idx++}`); values.push(category); }
        if (price !== undefined) { fields.push(`price = $${idx++}`); values.push(price ? parseFloat(price) : 0.00); }
        if (file_url !== undefined) { fields.push(`file_url = $${idx++}`); values.push(file_url); }
        if (cover_image_url !== undefined) { fields.push(`cover_image_url = $${idx++}`); values.push(cover_image_url); }
        if (status !== undefined) { fields.push(`status = $${idx++}`); values.push(status); }
        if (is_featured !== undefined) { fields.push(`is_featured = $${idx++}`); values.push(is_featured); }
        if (discount_price !== undefined) { fields.push(`discount_price = $${idx++}`); values.push(discount_price ? parseFloat(discount_price) : null); }
        if (fields.length === 0) return res.status(400).json({ message: 'Brak danych do aktualizacji.' });
        values.push(materialId);
        const query = `UPDATE materials SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`;
        const result = await pool.query(query, values);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Nie znaleziono materiału.' });
        res.json({ message: 'Materiał zaktualizowany.', material: result.rows[0] });
    } catch (error) { console.error(`Błąd /api/admin/materials/:id (PUT) dla ID ${materialId}:`, error); res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.delete('/api/admin/materials/:id', isAuthenticated, isAdmin, async (req, res) => { /* bez zmian */ 
    const materialIdToDelete = parseInt(req.params.id);
    try {
        await pool.query('DELETE FROM user_materials WHERE material_id = $1', [materialIdToDelete]);
        const result = await pool.query('DELETE FROM materials WHERE id = $1 RETURNING id, title', [materialIdToDelete]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Nie znaleziono materiału.' });
        res.json({ message: `Materiał "${result.rows[0].title}" usunięty.` });
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

// API Endpoints dla Ustawień Administratora (bez zmian)
app.get('/api/admin/settings', isAuthenticated, isAdmin, async (req, res) => { /* ... */ 
    try {
        const result = await pool.query('SELECT setting_key, setting_value FROM app_settings');
        const settings = result.rows.reduce((acc, row) => {
            if (row.setting_key === 'maintenanceMode' || row.setting_key === 'allowRegistration') acc[row.setting_key] = (row.setting_value === 'true');
            else if (['itemsPerPageAdmin', 'failedLoginAttempts', 'lockoutDuration'].includes(row.setting_key)) acc[row.setting_key] = parseInt(row.setting_value, 10);
            else acc[row.setting_key] = row.setting_value;
            return acc;
        }, {});
        settings.smtpHost = process.env.EMAIL_HOST || 'Nie skonfigurowano';
        settings.smtpPort = parseInt(process.env.EMAIL_PORT || '0');
        settings.smtpUser = process.env.EMAIL_USER || 'Nie skonfigurowano';
        settings.smtpPassConfigured = !!process.env.EMAIL_PASS;
        settings.smtpSender = process.env.EMAIL_SENDER_ADDRESS || settings.smtpUser || 'Nie skonfigurowano';
        settings.smtpSecure = (settings.smtpPort === 465);
        res.json(settings);
    } catch (error) { console.error("Błąd /api/admin/settings (GET):", error); res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.post('/api/admin/settings', isAuthenticated, isAdmin, async (req, res) => { /* ... */ 
    const settingsToUpdate = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const key in settingsToUpdate) {
            if (Object.prototype.hasOwnProperty.call(settingsToUpdate, key) && !key.startsWith('smtp')) {
                let valueToSave = typeof settingsToUpdate[key] === 'boolean' ? settingsToUpdate[key].toString() : settingsToUpdate[key];
                await client.query('INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, $2) ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()', [key, valueToSave]);
            }
        }
        await client.query('COMMIT');
        res.json({ message: 'Ustawienia zaktualizowane.' });
    } catch (error) { await client.query('ROLLBACK'); console.error("Błąd /api/admin/settings (POST):", error); res.status(500).json({ message: 'Błąd serwera.' });
    } finally { client.release(); }
});
app.post('/api/admin/settings/test-smtp', isAuthenticated, isAdmin, async (req, res) => { /* ... */ 
    try {
        let adminEmailToTest = process.env.ADMIN_EMAIL;
        const adminEmailSetting = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'adminEmail'");
        if (adminEmailSetting.rows.length > 0 && adminEmailSetting.rows[0].setting_value) adminEmailToTest = adminEmailSetting.rows[0].setting_value;
        if (!adminEmailToTest) return res.status(400).json({ message: 'Brak emaila admina.' });
        if (!emailHost || !emailUser || !emailPass) return res.status(400).json({ message: 'Niekompletna konfiguracja SMTP.' });
        const emailResult = await sendEmail(adminEmailToTest, 'Test SMTP', 'Testowa wiadomość SMTP.', '<p>Testowa wiadomość SMTP.</p>');
        if (emailResult.success) res.json({ message: `Testowy email wysłany na ${adminEmailToTest}.` });
        else throw emailResult.error;
    } catch (error) { console.error("Błąd /api/admin/settings/test-smtp:", error); res.status(500).json({ message: `Błąd wysyłki: ${error.message || 'Błąd SMTP'}` }); }
});

// === PUBLICZNE API Endpoints dla Materiałów (bez zmian) ===
app.get('/api/materials', isAuthenticated, async (req, res) => { /* ... */ 
    try {
        const queryText = "SELECT id, title, description, category, price, cover_image_url, status, is_featured, discount_price, created_at FROM materials WHERE status = 'published' ORDER BY created_at DESC";
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (error) { console.error("Błąd /api/materials (GET):", error); res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.post('/api/materials/:id/acquire', isAuthenticated, async (req, res) => { /* ... */ 
    const materialId = parseInt(req.params.id);
    const userId = req.session.userId;
    if (isNaN(materialId)) return res.status(400).json({ message: 'Nieprawidłowe ID.' });
    try {
        const materialCheck = await pool.query("SELECT id, title, price FROM materials WHERE id = $1 AND status = 'published'", [materialId]);
        if (materialCheck.rows.length === 0) return res.status(404).json({ message: 'Materiał niedostępny.' });
        const material = materialCheck.rows[0];
        const existingAcquisition = await pool.query('SELECT * FROM user_materials WHERE user_id = $1 AND material_id = $2', [userId, materialId]);
        if (existingAcquisition.rows.length > 0) return res.status(409).json({ message: `Już posiadasz "${material.title}".` });
        if (material.price > 0) console.log(`Nabywanie płatnego materiału ${materialId} - płatności niezaimplementowane.`);
        await pool.query('INSERT INTO user_materials (user_id, material_id) VALUES ($1, $2)', [userId, materialId]);
        res.status(201).json({ message: `Materiał "${material.title}" dodany do konta.` });
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});
app.get('/api/my-materials', isAuthenticated, async (req, res) => { /* ... */ 
    const userId = req.session.userId;
    try {
        const query = `SELECT m.id, m.title, m.description, m.category, m.cover_image_url, m.file_url, um.acquired_at FROM materials m JOIN user_materials um ON m.id = um.material_id WHERE um.user_id = $1 ORDER BY um.acquired_at DESC;`;
        const result = await pool.query(query, [userId]);
        res.json(result.rows);
    } catch (error) { res.status(500).json({ message: 'Błąd serwera.' }); }
});

// --- Uruchomienie serwera ---
async function startServer() {
    try {
        await initializeDatabase();
        app.listen(PORT, () => {
            console.log(`Serwer uruchomiony na porcie ${PORT}`);
            console.log(`NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
            console.log('--- Serwer gotowy ---');
        });
    } catch (error) {
        console.error("KRYTYCZNY BŁĄD STARTU SERWERA:", error);
        process.exit(1);
    }
}

startServer();
