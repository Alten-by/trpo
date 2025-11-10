const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./database.db");

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fio TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS statuses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        article TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        supplier TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        status_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        total_sum REAL NOT NULL,
        description TEXT,
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
});

db.close();
