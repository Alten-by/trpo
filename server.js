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
            
            const storedPassword = user.password || "";
            const isHashed = typeof storedPassword === "string" && storedPassword.startsWith("$2");

            const respondWithUser = () => {
                const { password: _, ...userWithoutPassword } = user;
                res.json({
                    success: true,
                    message: "Авторизация успешна",
                    user: userWithoutPassword
                });
            };

            const handleLegacyPassword = () => {
                if (storedPassword === password) {
                    bcrypt.hash(password, 10, (hashErr, newHash) => {
                        if (!hashErr) {
                            db.run("UPDATE users SET password = ? WHERE id = ?", [newHash, user.id], () => {
                                user.password = newHash;
                                respondWithUser();
                            });
                        } else {
                            respondWithUser();
                        }
                    });
                } else {
                    return res.status(401).json({ error: "Неверный email или пароль" });
                }
            };

            if (!storedPassword) {
                return res.status(401).json({ error: "Пароль для этого пользователя не задан. Обновите пароль через регистрацию." });
            }

            if (!isHashed) {
                return handleLegacyPassword();
            }

            // Проверяем пароль с помощью bcrypt
            bcrypt.compare(password, storedPassword, (compareErr, isValid) => {
                if (compareErr) {
                    return res.status(500).json({ error: "Ошибка при проверке пароля" });
                }
                
                if (!isValid) {
                    return res.status(401).json({ error: "Неверный email или пароль" });
                }
                
                respondWithUser();
            });
        }
    );
});

// Создание таблицы cart_items, если её еще нет
db.serialize(() => {
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

// Получить корзину пользователя
app.get("/api/cart", (req, res) => {
    const { user_id } = req.query;
    
    if (!user_id) {
        return res.status(400).json({ error: "user_id обязателен" });
    }
    
    // Получаем корзину с полной информацией о товарах
    db.all(`
        SELECT 
            ci.product_id as id,
            ci.quantity,
            p.name,
            p.price,
            p.image_url as image,
            p.article,
            p.category
        FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.user_id = ?
        ORDER BY ci.created_at DESC
    `, [user_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        // Преобразуем результат в нужный формат
        const cart = rows.map(row => ({
            id: row.id,
            name: row.name,
            price: Number(row.price) || 0,
            image: row.image || null,
            quantity: Number(row.quantity) || 1,
            article: row.article,
            category: row.category
        }));
        
        res.json(cart);
    });
});

// Добавить товар в корзину или обновить количество
app.post("/api/cart", (req, res) => {
    const { user_id, product_id, quantity } = req.body;
    
    if (!user_id || !product_id) {
        return res.status(400).json({ error: "user_id и product_id обязательны" });
    }
    
    const qty = Math.max(1, Number(quantity) || 1);
    
    // Проверяем, существует ли товар
    db.get("SELECT id FROM products WHERE id = ?", [product_id], (err, product) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (!product) {
            return res.status(404).json({ error: "Товар не найден" });
        }
        
        // Проверяем, есть ли уже этот товар в корзине
        db.get("SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?", 
            [user_id, product_id], 
            (err, existingItem) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                if (existingItem) {
                    // Обновляем количество (добавляем к существующему)
                    const newQuantity = existingItem.quantity + qty;
                    db.run(
                        "UPDATE cart_items SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        [newQuantity, existingItem.id],
                        function(err) {
                            if (err) {
                                return res.status(500).json({ error: err.message });
                            }
                            res.json({ success: true, message: "Количество обновлено", quantity: newQuantity });
                        }
                    );
                } else {
                    // Добавляем новый товар
                    db.run(
                        "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                        [user_id, product_id, qty],
                        function(err) {
                            if (err) {
                                return res.status(500).json({ error: err.message });
                            }
                            res.json({ success: true, message: "Товар добавлен в корзину", id: this.lastID });
                        }
                    );
                }
            }
        );
    });
});

// Обновить количество товара в корзине
app.put("/api/cart/:productId", (req, res) => {
    const { productId } = req.params;
    const { user_id, quantity } = req.body;
    
    if (!user_id) {
        return res.status(400).json({ error: "user_id обязателен" });
    }
    
    const qty = Math.max(1, Number(quantity) || 1);
    
    db.run(
        "UPDATE cart_items SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND product_id = ?",
        [qty, user_id, productId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: "Товар не найден в корзине" });
            }
            
            res.json({ success: true, message: "Количество обновлено", quantity: qty });
        }
    );
});

// Удалить товар из корзины
app.delete("/api/cart/:productId", (req, res) => {
    const { productId } = req.params;
    const { user_id } = req.query;
    
    if (!user_id) {
        return res.status(400).json({ error: "user_id обязателен" });
    }
    
    db.run(
        "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
        [user_id, productId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: "Товар не найден в корзине" });
            }
            
            res.json({ success: true, message: "Товар удалён из корзины" });
        }
    );
});

// Очистить корзину пользователя
app.delete("/api/cart", (req, res) => {
    const { user_id } = req.query;
    
    if (!user_id) {
        return res.status(400).json({ error: "user_id обязателен" });
    }
    
    db.run("DELETE FROM cart_items WHERE user_id = ?", [user_id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        res.json({ success: true, message: "Корзина очищена", deleted: this.changes });
    });
});

app.listen(3000, () => {
    console.log("Сервер запущен: http://localhost:3000");
});