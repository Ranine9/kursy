// server.js

// Importowanie potrzebnych modułów
const express = require('express'); // Framework do tworzenia aplikacji webowych
const bodyParser = require('body-parser'); // Do parsowania danych z formularzy HTML
const path = require('path'); // Do pracy ze ścieżkami plików
const session = require('express-session'); // Do zarządzania sesjami użytkowników
const bcrypt = require('bcryptjs'); // Do hashowania haseł

// Inicjalizacja aplikacji Express
const app = express();
const PORT = process.env.PORT || 3000; // Port, na którym serwer będzie nasłuchiwał (ważne dla Render)

// --- Konfiguracja aplikacji ---

// Użyj body-parsera do odczytywania danych z formularzy (application/x-www-form-urlencoded)
app.use(bodyParser.urlencoded({ extended: true }));

// Skonfiguruj sesje
// WAŻNE: W produkcji 'secret' powinien być długim, losowym ciągiem znaków i przechowywanym bezpiecznie (np. w zmiennych środowiskowych)
app.use(session({
    secret: 'bardzo-tajny-sekret-do-zmiany-w-produkcji!', // ZMIEŃ TO!
    resave: false, // Nie zapisuj sesji, jeśli nie była modyfikowana
    saveUninitialized: false, // Nie twórz sesji, dopóki coś nie zostanie w niej zapisane
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Używaj bezpiecznych ciasteczek (HTTPS) w produkcji
        maxAge: 1000 * 60 * 60 * 24 // Czas życia ciasteczka sesji (np. 1 dzień)
    }
}));

// Serwowanie plików statycznych (HTML, CSS, JS z frontendu) z folderu 'public'
// __dirname to bieżący katalog, w którym znajduje się server.js
app.use(express.static(path.join(__dirname, 'public')));

// --- "Baza danych" w pamięci (TYLKO DO CELÓW DEMONSTRACYJNYCH!) ---
// W prawdziwej aplikacji tutaj byłoby połączenie z bazą danych (np. PostgreSQL, MongoDB)
let users = []; // Tablica do przechowywania zarejestrowanych użytkowników
let userIdCounter = 1; // Prosty licznik ID użytkowników

// --- Definicje ścieżek (Routes) ---

// Strona główna - przekierowuje do index.html z folderu public
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ścieżka do strony rejestracji (GET) - serwuje plik register.html
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Obsługa formularza rejestracji (POST)
app.post('/register', async (req, res) => {
    const { username, email, password, 'confirm-password': confirmPassword } = req.body;

    // Prosta walidacja (w realnej aplikacji byłaby bardziej rozbudowana)
    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).send('Wszystkie pola są wymagane!');
    }
    if (password !== confirmPassword) {
        return res.status(400).send('Hasła nie są zgodne!');
    }
    if (users.find(user => user.email === email)) {
        return res.status(400).send('Użytkownik o takim adresie email już istnieje!');
    }
    if (users.find(user => user.username === username)) {
        return res.status(400).send('Użytkownik o takiej nazwie już istnieje!');
    }

    try {
        // Hashowanie hasła przed zapisem
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = {
            id: userIdCounter++,
            username,
            email,
            password: hashedPassword // Zapisujemy zahashowane hasło
        };
        users.push(newUser);
        console.log('Nowy użytkownik zarejestrowany:', newUser); // Logowanie na serwerze
        console.log('Wszyscy użytkownicy:', users);

        // Po udanej rejestracji, automatycznie zaloguj użytkownika i przekieruj do panelu
        req.session.userId = newUser.id;
        req.session.username = newUser.username;
        res.redirect('/dashboard');

    } catch (error) {
        console.error("Błąd podczas hashowania hasła:", error);
        res.status(500).send('Wystąpił błąd serwera podczas rejestracji.');
    }
});

// Ścieżka do strony logowania (GET) - serwuje plik login.html
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Obsługa formularza logowania (POST)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email i hasło są wymagane!');
    }

    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(400).send('Nieprawidłowy email lub hasło.'); // Ogólny komunikat dla bezpieczeństwa
    }

    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Nieprawidłowy email lub hasło.');
        }

        // Ustawienie sesji po pomyślnym logowaniu
        req.session.userId = user.id;
        req.session.username = user.username;
        console.log(`Użytkownik ${user.username} zalogowany.`);

        res.redirect('/dashboard'); // Przekierowanie do panelu użytkownika

    } catch (error) {
        console.error("Błąd podczas porównywania hasła:", error);
        res.status(500).send('Wystąpił błąd serwera podczas logowania.');
    }
});

// Middleware sprawdzający, czy użytkownik jest zalogowany
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next(); // Użytkownik jest zalogowany, kontynuuj
    }
    res.redirect('/login'); // Użytkownik nie jest zalogowany, przekieruj do logowania
}

// Ścieżka do panelu użytkownika (GET) - wymaga zalogowania
// Używamy middleware `isAuthenticated`
app.get('/dashboard', isAuthenticated, (req, res) => {
    // Tutaj moglibyśmy przekazać dane użytkownika do szablonu,
    // ale ponieważ serwujemy statyczny HTML, musielibyśmy go modyfikować po stronie klienta
    // lub użyć systemu szablonów (np. EJS, Handlebars)
    // Na razie po prostu serwujemy plik dashboard.html
    // Nazwę użytkownika można by wstrzyknąć przez JavaScript na froncie, pobierając ją np. z API
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Ścieżka do pobrania danych zalogowanego użytkownika (API endpoint)
app.get('/api/user', isAuthenticated, (req, res) => {
    // Zwracamy tylko bezpieczne dane, nigdy hasła!
    res.json({
        userId: req.session.userId,
        username: req.session.username
    });
});


// Obsługa wylogowania (GET lub POST)
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Błąd podczas niszczenia sesji:', err);
            return res.status(500).send('Nie udało się wylogować.');
        }
        console.log('Użytkownik wylogowany.');
        res.clearCookie('connect.sid'); // Nazwa ciasteczka sesji może zależeć od konfiguracji
        res.redirect('/'); // Przekierowanie na stronę główną
    });
});


// --- Uruchomienie serwera ---
app.listen(PORT, () => {
    console.log(`Serwer uruchomiony na porcie ${PORT}`);
    console.log(`Przejdź do http://localhost:${PORT} w przeglądarce.`);
    console.log('---');
    console.log('Pamiętaj, że to jest BARDZO UPROSZCZONY backend.');
    console.log('W prawdziwej aplikacji potrzebujesz:');
    console.log('  - Prawdziwej bazy danych (np. PostgreSQL na Render).');
    console.log('  - Bezpieczniejszego zarządzania sekretami sesji.');
    console.log('  - Rozbudowanej walidacji danych wejściowych.');
    console.log('  - Lepszej obsługi błędów.');
    console.log('  - Być może systemu szablonów (np. EJS) jeśli chcesz dynamicznie generować HTML na serwerze.');
    console.log('---');
});
