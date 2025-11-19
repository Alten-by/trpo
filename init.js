const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./database.db");

const DEFAULT_ROLES = ["customer", "supplier", "admin"];
const DEFAULT_REQUEST_STATUSES = [
    "Заявка оформлена, ожидайте отгрузки",
    "Заявка на рассмотрении, ожидайте"
];

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )`);

    DEFAULT_ROLES.forEach((role) => {
        db.run(`INSERT OR IGNORE INTO roles (name) VALUES (?)`, [role]);
    });

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fio TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password TEXT,
        company_name TEXT DEFAULT NULL,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS statuses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT
    )`);

    DEFAULT_REQUEST_STATUSES.forEach((status) => {
        db.run(`INSERT OR IGNORE INTO statuses (name) VALUES (?)`, [status]);
    });

    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        article TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        supplier TEXT,
        min_stock INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        status_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        total_sum REAL NOT NULL,
        description TEXT,
        recipient_name TEXT,
        delivery_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(status_id) REFERENCES statuses(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS request_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price_per_unit REAL NOT NULL,
        FOREIGN KEY(request_id) REFERENCES requests(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id),
        UNIQUE(user_id, product_id)
    )`);
});

db.close();
