const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

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

app.listen(3000, () => {
    console.log("Сервер запущен: http://localhost:3000");
});