const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

// Добавляем поле password в таблицу users, если его еще нет
db.serialize(() => {
    db.run(`ALTER TABLE users ADD COLUMN password TEXT`, (err) => {
        // Игнорируем ошибку, если колонка уже существует
        if (err && !err.message.includes('duplicate column')) {
            console.log('Ошибка при добавлении колонки password:', err.message);
        }
    });
});

// Создание таблицы products (если еще не создана)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        article TEXT UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        price DECIMAL(10,2),
        quantity INTEGER,
        supplier TEXT,
        category TEXT,
        image_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Получить все товары
app.get("/products", (req, res) => {
    db.all("SELECT * FROM products", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Получить товары по категории
app.get("/products/category/:category", (req, res) => {
    const category = req.params.category;
    db.all("SELECT * FROM products WHERE category = ?", [category], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Поиск товаров
app.get("/products/search/:query", (req, res) => {
    const query = `%${req.params.query}%`;
    db.all("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?", 
        [query, query], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Добавить товар
app.post("/products", (req, res) => {
    const { article, name, description, price, quantity, supplier, category, image_url } = req.body;
    db.run("INSERT INTO products (article, name, description, price, quantity, supplier, category, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [article, name, description, price, quantity, supplier, category, image_url],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
});

// Остальные маршруты для users...
app.get("/users", (req, res) => {
    db.all("SELECT * FROM users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post("/users", (req, res) => {
    const { fio, email, phone, role_id } = req.body;
    db.run("INSERT INTO users (fio, email, phone, role_id) VALUES (?, ?, ?, ?)",
        [fio, email, phone, role_id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
});

// Регистрация пользователя
app.post("/auth/register", (req, res) => {
    const { fio, email, phone, password } = req.body;
    
    // Валидация
    if (!fio || !email || !password) {
        return res.status(400).json({ error: "ФИО, email и пароль обязательны" });
    }
    
    // Проверка формата email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Неверный формат email" });
    }
    
    // Проверка длины пароля
    if (password.length < 6) {
        return res.status(400).json({ error: "Пароль должен содержать минимум 6 символов" });
    }
    
    // Проверяем, существует ли пользователь с таким email
    db.get("SELECT id FROM users WHERE email = ?", [email], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (row) {
            return res.status(400).json({ error: "Пользователь с таким email уже существует" });
        }
        
        // Получаем role_id для обычного пользователя (customer = 1)
        db.get("SELECT id FROM roles WHERE name = 'customer'", [], (err, roleRow) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            const roleId = roleRow ? roleRow.id : 1; // По умолчанию 1, если роли нет
            
            // Хешируем пароль
            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).json({ error: "Ошибка при хешировании пароля" });
                }
                
                db.run("INSERT INTO users (fio, email, phone, password, role_id) VALUES (?, ?, ?, ?, ?)",
                    [fio, email, phone || null, hashedPassword, roleId],
                    function(err) {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        res.json({ 
                            success: true, 
                            message: "Регистрация успешна",
                            userId: this.lastID 
                        });
                    }
                );
            });
        });
    });
});

// Авторизация пользователя
app.post("/auth/login", (req, res) => {
    const { email, password } = req.body;
    
    // Валидация
    if (!email || !password) {
        return res.status(400).json({ error: "Email и пароль обязательны" });
    }
    
    // Ищем пользователя по email
    db.get("SELECT id, fio, email, phone, password, role_id FROM users WHERE email = ?", 
        [email], 
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            if (!user) {
                return res.status(401).json({ error: "Неверный email или пароль" });
            }
            
            // Проверяем пароль с помощью bcrypt
            bcrypt.compare(password, user.password, (err, isValid) => {
                if (err) {
                    return res.status(500).json({ error: "Ошибка при проверке пароля" });
                }
                
                if (!isValid) {
                    return res.status(401).json({ error: "Неверный email или пароль" });
                }
                
                // Возвращаем данные пользователя (без пароля)
                const { password: _, ...userWithoutPassword } = user;
                res.json({ 
                    success: true, 
                    message: "Авторизация успешна",
                    user: userWithoutPassword 
                });
            });
        }
    );
});

app.listen(3000, () => {
    console.log("Сервер запущен: http://localhost:3000");
});