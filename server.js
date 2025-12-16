const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

const REQUIRED_ROLES = ["customer", "supplier", "admin"];
const REQUEST_STATUSES = {
    PENDING: "Заявка на рассмотрении, ожидайте",
    READY: "Заявка оформлена, ожидайте отгрузки",
    SHIPPED: "Отгружено",
    DECLINED: "Откланена"
};
const DEFAULT_COMPANY_NAME = "LocalStore";
const ADMIN_USER = {
    email: "toture11gg@gmail.com",
    fio: "Главный администратор",
    phone: null,
    company_name: DEFAULT_COMPANY_NAME,
    password: "Admin123!"
};

function addColumnIfMissing(tableName, columnName, definition) {
    db.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`, (err) => {
        if (err && !err.message.includes("duplicate column")) {
            console.log(`Ошибка при добавлении колонки ${columnName}:`, err.message);
        }
    });
}

function seedRoles() {
    REQUIRED_ROLES.forEach((role) => {
        db.run(`INSERT OR IGNORE INTO roles (name) VALUES (?)`, [role]);
    });
}

function seedRequestStatuses() {
    const desiredStatuses = Object.values(REQUEST_STATUSES);
    desiredStatuses.forEach((statusName) => {
        db.run(`INSERT OR IGNORE INTO statuses (name) VALUES (?)`, [statusName]);
    });

    const renames = [
        ["Заявка отклонена", REQUEST_STATUSES.DECLINED],
        ["Заявка оформлена, ожидайте отгрузки", REQUEST_STATUSES.READY],
        ["Заявка на рассмотрении, ожидайте", REQUEST_STATUSES.PENDING],
        ["Новая", REQUEST_STATUSES.PENDING]
    ];

    renames.forEach(([from, to]) => {
        db.run(`UPDATE statuses SET name = ? WHERE name = ?`, [to, from]);
    });
}

function getStatusId(statusName, callback) {
    db.get(`SELECT id FROM statuses WHERE name = ?`, [statusName], (err, row) => {
        if (err) {
            return callback(err);
        }
        callback(null, row ? row.id : null);
    });
}

function getRoleId(roleName, callback) {
    db.get(`SELECT id FROM roles WHERE name = ?`, [roleName], (err, row) => {
        if (err) {
            return callback(err);
        }
        callback(null, row ? row.id : null);
    });
}

function ensureAdminUser() {
    getRoleId("admin", (roleErr, adminRoleId) => {
        if (roleErr || !adminRoleId) {
            console.error("Не удалось получить роль администратора:", roleErr ? roleErr.message : "роль не найдена");
            return;
        }

        db.get(`SELECT id, role_id FROM users WHERE email = ?`, [ADMIN_USER.email], (err, existingUser) => {
            if (err) {
                console.error("Ошибка при поиске администратора:", err.message);
                return;
            }

            if (!existingUser) {
                bcrypt.hash(ADMIN_USER.password, 10, (hashErr, hashedPassword) => {
                    if (hashErr) {
                        console.error("Ошибка при создании администратора:", hashErr.message);
                        return;
                    }

                    db.run(
                        `INSERT INTO users (fio, email, phone, password, role_id, company_name) VALUES (?, ?, ?, ?, ?, ?)`,
                        [ADMIN_USER.fio, ADMIN_USER.email, ADMIN_USER.phone, hashedPassword, adminRoleId, ADMIN_USER.company_name],
                        (insertErr) => {
                            if (insertErr) {
                                console.error("Ошибка при добавлении администратора:", insertErr.message);
                            } else {
                                console.log(`Администратор создан: ${ADMIN_USER.email}`);
                            }
                        }
                    );
                });
            } else if (existingUser.role_id !== adminRoleId) {
                db.run(`UPDATE users SET role_id = ? WHERE id = ?`, [adminRoleId, existingUser.id], (updateErr) => {
                    if (updateErr) {
                        console.error("Ошибка при обновлении роли администратора:", updateErr.message);
                    }
                });
            }
        });
    });
}

function requireAdmin(adminId, res, onSuccess) {
    if (!adminId) {
        return res.status(400).json({ error: "adminId обязателен" });
    }

    db.get(
        `SELECT u.id FROM users u
         JOIN roles r ON r.id = u.role_id
         WHERE u.id = ? AND r.name = 'admin'`,
        [adminId],
        (err, adminRow) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (!adminRow) {
                return res.status(403).json({ error: "Доступ запрещен" });
            }

            onSuccess();
        }
    );
}

function requireSupplier(supplierId, res, onSuccess) {
    if (!supplierId) {
        return res.status(400).json({ error: "supplierId обязателен" });
    }

    db.get(
        `SELECT u.id, u.company_name FROM users u
         JOIN roles r ON r.id = u.role_id
         WHERE u.id = ? AND r.name = 'supplier'`,
        [supplierId],
        (err, supplierRow) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (!supplierRow) {
                return res.status(403).json({ error: "Доступ запрещен. Требуется роль поставщика" });
            }

            onSuccess(supplierRow);
        }
    );
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )`);

    seedRoles();

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fio TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password TEXT,
        company_name TEXT,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )`);

    addColumnIfMissing("users", "password", "TEXT");
    addColumnIfMissing("users", "company_name", "TEXT");
    addColumnIfMissing("products", "created_at", "DATETIME");
    addColumnIfMissing("products", "min_stock", "INTEGER DEFAULT 0");

    db.run(`CREATE TABLE IF NOT EXISTS statuses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT
    )`);

    seedRequestStatuses();

    // Создание таблицы products (если еще не создана)
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
    addColumnIfMissing("requests", "recipient_name", "TEXT");
    addColumnIfMissing("requests", "delivery_address", "TEXT");
    addColumnIfMissing("requests", "created_at", "DATETIME");

    db.run(`CREATE TABLE IF NOT EXISTS request_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price_per_unit REAL NOT NULL,
        FOREIGN KEY(request_id) REFERENCES requests(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )`);

    // Создание таблицы cart_items (если ещё не создана)
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

    ensureAdminUser();
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
    const { article, name, description, price, quantity, supplier, category, image_url, min_stock } = req.body;

    if (!article) {
        return res.status(400).json({ error: "Артикул обязателен" });
    }

    db.get("SELECT id FROM products WHERE article = ?", [article], (err, existingProduct) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (existingProduct) {
            return res.status(400).json({ error: "Товар с таким артикулом уже существует" });
        }

        const normalizedMinStock = Number.isFinite(Number(min_stock)) && Number(min_stock) >= 0
            ? Math.floor(Number(min_stock))
            : 0;

        db.run(
            "INSERT INTO products (article, name, description, price, quantity, supplier, category, image_url, min_stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [article, name, description, price, quantity, supplier, category, image_url, normalizedMinStock],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ id: this.lastID });
            }
        );
    });
});

// Поставщик: получить свои товары
app.get("/supplier/products", (req, res) => {
    const supplierId = Number(req.query.supplierId);

    requireSupplier(supplierId, res, (supplier) => {
        db.all(
            "SELECT * FROM products WHERE supplier = ? ORDER BY COALESCE(created_at, '1970-01-01') DESC, id DESC",
            [supplier.company_name],
            (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json(rows);
            }
        );
    });
});

// Поставщик: создать товар
app.post("/supplier/products", (req, res) => {
    const supplierId = Number(req.body.supplierId);
    const { article, name, description, price, quantity, category, image_url, min_stock } = req.body;

    if (!article || !name || !price || quantity === undefined) {
        return res.status(400).json({ error: "Артикул, название, цена и количество обязательны" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        db.get(
            "SELECT id FROM products WHERE article = ?",
            [article],
            (err, existingProduct) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (existingProduct) {
                    return res.status(400).json({ error: "Товар с таким артикулом уже существует" });
                }

                const normalizedMinStock = Number.isFinite(Number(min_stock)) && Number(min_stock) >= 0
                    ? Math.floor(Number(min_stock))
                    : 0;

                db.run(
                    "INSERT INTO products (article, name, description, price, quantity, supplier, category, image_url, min_stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [article, name, description, price, quantity, supplier.company_name, category || null, image_url || null, normalizedMinStock],
                    function(err) {
                        if (err) {
                            if (err.message.includes("UNIQUE constraint")) {
                                return res.status(400).json({ error: "Товар с таким артикулом уже существует" });
                            }
                            return res.status(500).json({ error: err.message });
                        }
                        res.json({ 
                            success: true, 
                            id: this.lastID,
                            message: "Товар успешно создан"
                        });
                    }
                );
            }
        );
    });
});

// Поставщик: получить один свой товар
app.get("/supplier/products/:productId", (req, res) => {
    const supplierId = Number(req.query.supplierId);
    const productId = Number(req.params.productId);

    console.log(`GET /supplier/products/${productId}?supplierId=${supplierId}`);

    if (!supplierId || isNaN(supplierId)) {
        return res.status(400).json({ error: "supplierId обязателен и должен быть числом" });
    }

    if (!productId || isNaN(productId)) {
        return res.status(400).json({ error: "productId обязателен и должен быть числом" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        db.get(
            "SELECT * FROM products WHERE id = ? AND supplier = ?",
            [productId, supplier.company_name],
            (err, product) => {
                if (err) {
                    console.error('Ошибка БД:', err);
                    return res.status(500).json({ error: err.message });
                }

                if (!product) {
                    return res.status(404).json({ error: "Товар не найден или не принадлежит вам" });
                }

                res.json(product);
            }
        );
    });
});

// Поставщик: обновить свой товар
app.put("/supplier/products/:productId", (req, res) => {
    const supplierId = Number(req.body.supplierId);
    const productId = Number(req.params.productId);
    const { article, name, description, price, quantity, category, image_url, min_stock } = req.body;

    if (!productId) {
        return res.status(400).json({ error: "productId обязателен" });
    }

    if (!article || !name || !price || quantity === undefined) {
        return res.status(400).json({ error: "Артикул, название, цена и количество обязательны" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        // Проверяем, что товар принадлежит этому поставщику
        db.get(
            "SELECT id FROM products WHERE id = ? AND supplier = ?",
            [productId, supplier.company_name],
            (err, product) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (!product) {
                    return res.status(404).json({ error: "Товар не найден или не принадлежит вам" });
                }

                // Проверяем, не занят ли новый артикул другим товаром
                db.get(
                    "SELECT id FROM products WHERE article = ? AND id != ?",
                    [article, productId],
                    (err2, existingProduct) => {
                        if (err2) {
                            return res.status(500).json({ error: err2.message });
                        }

                        if (existingProduct) {
                            return res.status(400).json({ error: "Товар с таким артикулом уже существует" });
                        }

                        // Обновляем товар
                        const normalizedMinStock = Number.isFinite(Number(min_stock)) && Number(min_stock) >= 0
                            ? Math.floor(Number(min_stock))
                            : 0;

                        db.run(
                            "UPDATE products SET article = ?, name = ?, description = ?, price = ?, quantity = ?, category = ?, image_url = ?, min_stock = ? WHERE id = ?",
                            [article, name, description || null, price, quantity, category || null, image_url || null, normalizedMinStock, productId],
                            function(updateErr) {
                                if (updateErr) {
                                    return res.status(500).json({ error: updateErr.message });
                                }

                                res.json({
                                    success: true,
                                    message: "Товар успешно обновлен"
                                });
                            }
                        );
                    }
                );
            }
        );
    });
});

// Поставщик: удалить свой товар
app.delete("/supplier/products/:productId", (req, res) => {
    const supplierId = Number(req.query.supplierId);
    const productId = Number(req.params.productId);

    if (!productId) {
        return res.status(400).json({ error: "productId обязателен" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        // Проверяем, что товар принадлежит этому поставщику
        db.get(
            "SELECT id FROM products WHERE id = ? AND supplier = ?",
            [productId, supplier.company_name],
            (err, product) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (!product) {
                    return res.status(404).json({ error: "Товар не найден или не принадлежит вам" });
                }

                db.run("DELETE FROM products WHERE id = ?", [productId], function(deleteErr) {
                    if (deleteErr) {
                        return res.status(500).json({ error: deleteErr.message });
                    }

                    res.json({
                        success: true,
                        message: "Товар успешно удален"
                    });
                });
            }
        );
    });
});

// Остальные маршруты для users...
app.get("/users", (req, res) => {
    db.all(
        `SELECT u.id, u.fio, u.email, u.phone, u.company_name, u.role_id, r.name AS role_name
         FROM users u
         LEFT JOIN roles r ON r.id = u.role_id
         ORDER BY u.id`,
        [],
        (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const users = rows.map((row) => ({
            id: row.id,
            fio: row.fio,
            email: row.email,
            phone: row.phone,
            company_name: row.company_name,
            role_id: row.role_id,
            role: row.role_name
        }));
        res.json(users);
    });
});

app.post("/users", (req, res) => {
    const { fio, email, phone, role_id, company_name } = req.body;
    db.run("INSERT INTO users (fio, email, phone, role_id, company_name) VALUES (?, ?, ?, ?, ?)",
        [fio, email, phone, role_id, company_name || null],
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
                
                db.run("INSERT INTO users (fio, email, phone, password, role_id, company_name) VALUES (?, ?, ?, ?, ?, ?)",
                    [fio, email, phone || null, hashedPassword, roleId, null],
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
    db.get(
        `SELECT u.id, u.fio, u.email, u.phone, u.password, u.role_id, u.company_name, r.name AS role_name
         FROM users u
         LEFT JOIN roles r ON r.id = u.role_id
         WHERE u.email = ?`,
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
                const userPayload = {
                    id: user.id,
                    fio: user.fio,
                    email: user.email,
                    phone: user.phone,
                    role_id: user.role_id,
                    company_name: user.company_name,
                    role: user.role_name || "customer"
                };
                res.json({
                    success: true,
                    message: "Авторизация успешна",
                    user: userPayload
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

// Админ: получить список пользователей
app.get("/admin/users", (req, res) => {
    const adminId = Number(req.query.adminId);

    requireAdmin(adminId, res, () => {
        db.all(
            `SELECT u.id, u.fio, u.email, u.phone, u.company_name, u.role_id, r.name AS role_name
             FROM users u
             LEFT JOIN roles r ON r.id = u.role_id
             ORDER BY u.id`,
            [],
            (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                const users = rows.map((row) => ({
                    id: row.id,
                    fio: row.fio,
                    email: row.email,
                    phone: row.phone,
                    company_name: row.company_name,
                    role_id: row.role_id,
                    role: row.role_name || "customer"
                }));

                res.json(users);
            }
        );
    });
});

// Админ: обновить название компании поставщика
app.put("/admin/users/:userId/company", (req, res) => {
    const adminId = Number(req.body.adminId);
    const userId = Number(req.params.userId);
    const { companyName } = req.body;

    if (!userId) {
        return res.status(400).json({ error: "userId обязателен" });
    }

    requireAdmin(adminId, res, () => {
        db.get(
            `SELECT u.id, r.name AS role_name
             FROM users u
             LEFT JOIN roles r ON r.id = u.role_id
             WHERE u.id = ?`,
            [userId],
            (err, targetUser) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (!targetUser) {
                    return res.status(404).json({ error: "Пользователь не найден" });
                }

                if (targetUser.role_name !== "supplier") {
                    return res.status(400).json({ error: "Пользователь не является поставщиком" });
                }

                const normalizedCompany = companyName && companyName.toString().trim() 
                    ? companyName.toString().trim() 
                    : DEFAULT_COMPANY_NAME;

                // Сначала получаем старое название компании
                db.get(
                    `SELECT company_name FROM users WHERE id = ?`,
                    [userId],
                    (err, oldUser) => {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        if (!oldUser) {
                            return res.status(404).json({ error: "Пользователь не найден" });
                        }

                        const oldCompanyName = oldUser.company_name;

                        // Обновляем название компании в users
                        db.run(
                            `UPDATE users SET company_name = ? WHERE id = ?`,
                            [normalizedCompany, userId],
                            function(updateErr) {
                                if (updateErr) {
                                    return res.status(500).json({ error: updateErr.message });
                                }

                                if (this.changes === 0) {
                                    return res.status(400).json({ error: "Изменения не были применены" });
                                }

                                // Обновляем supplier во всех товарах этого поставщика
                                if (oldCompanyName && oldCompanyName !== normalizedCompany) {
                                    db.run(
                                        `UPDATE products SET supplier = ? WHERE supplier = ?`,
                                        [normalizedCompany, oldCompanyName],
                                        (productUpdateErr) => {
                                            if (productUpdateErr) {
                                                console.error('Ошибка обновления товаров:', productUpdateErr);
                                            }
                                        }
                                    );
                                }

                                res.json({
                                    success: true,
                                    userId,
                                    companyName: normalizedCompany
                                });
                            }
                        );
                    }
                );
            }
        );
    });
});

// Админ: переключить статус поставщика
app.put("/admin/users/:userId/supplier", (req, res) => {
    const adminId = Number(req.body.adminId);
    const userId = Number(req.params.userId);
    const { isSupplier, companyName } = req.body;

    if (!userId) {
        return res.status(400).json({ error: "userId обязателен" });
    }

    const supplierFlag = isSupplier === true || isSupplier === "true" || isSupplier === 1 || isSupplier === "1";

    requireAdmin(adminId, res, () => {
        db.get(
            `SELECT u.id, r.name AS role_name
             FROM users u
             LEFT JOIN roles r ON r.id = u.role_id
             WHERE u.id = ?`,
            [userId],
            (err, targetUser) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (!targetUser) {
                    return res.status(404).json({ error: "Пользователь не найден" });
                }

                if (targetUser.role_name === "admin") {
                    return res.status(400).json({ error: "Нельзя изменять статус администратора" });
                }

                if (adminId === userId) {
                    return res.status(400).json({ error: "Нельзя изменить собственный статус" });
                }

                const targetRoleName = supplierFlag ? "supplier" : "customer";
                getRoleId(targetRoleName, (roleErr, targetRoleId) => {
                    if (roleErr || !targetRoleId) {
                        return res.status(500).json({ error: "Не удалось получить роль" });
                    }

                    const normalizedCompany = supplierFlag
                        ? (companyName && companyName.toString().trim()) || DEFAULT_COMPANY_NAME
                        : null;

                    // Получаем старое название компании перед обновлением
                    db.get(
                        `SELECT company_name FROM users WHERE id = ?`,
                        [userId],
                        (err, oldUser) => {
                            if (err) {
                                return res.status(500).json({ error: err.message });
                            }

                            const oldCompanyName = oldUser?.company_name;

                            db.run(
                                `UPDATE users SET role_id = ?, company_name = ? WHERE id = ?`,
                                [targetRoleId, normalizedCompany, userId],
                                function(updateErr) {
                                    if (updateErr) {
                                        return res.status(500).json({ error: updateErr.message });
                                    }

                                    if (this.changes === 0) {
                                        return res.status(400).json({ error: "Изменения не были применены" });
                                    }

                                    // Обновляем supplier во всех товарах, если изменилось название компании
                                    if (supplierFlag && oldCompanyName && oldCompanyName !== normalizedCompany) {
                                        db.run(
                                            `UPDATE products SET supplier = ? WHERE supplier = ?`,
                                            [normalizedCompany, oldCompanyName],
                                            (productUpdateErr) => {
                                                if (productUpdateErr) {
                                                    console.error('Ошибка обновления товаров:', productUpdateErr);
                                                }
                                            }
                                        );
                                    }

                                    res.json({
                                        success: true,
                                        userId,
                                        isSupplier: supplierFlag,
                                        companyName: normalizedCompany || undefined
                                    });
                                }
                            );
                        }
                    );
                });
            }
        );
    });
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
                    const newQuantity = (Number(existingItem.quantity) || 0) + qty;
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

app.post("/requests/checkout", (req, res) => {
    const { userId, recipientName, deliveryAddress } = req.body;

    if (!userId) {
        return res.status(400).json({ error: "userId обязателен" });
    }

    const trimmedRecipient = (recipientName || "").toString().trim();
    const trimmedAddress = (deliveryAddress || "").toString().trim();

    if (!trimmedAddress) {
        return res.status(400).json({ error: "Адрес доставки обязателен" });
    }

    db.get("SELECT id, fio FROM users WHERE id = ?", [userId], (userErr, user) => {
        if (userErr) {
            return res.status(500).json({ error: userErr.message });
        }

        if (!user) {
            return res.status(404).json({ error: "Пользователь не найден" });
        }

        db.all(
            `SELECT ci.product_id, ci.quantity AS requested_qty, p.quantity AS stock_qty, p.price, p.name
             FROM cart_items ci
             JOIN products p ON p.id = ci.product_id
             WHERE ci.user_id = ?`,
            [userId],
            (cartErr, cartItems) => {
                if (cartErr) {
                    return res.status(500).json({ error: cartErr.message });
                }

                if (!cartItems || cartItems.length === 0) {
                    return res.status(400).json({ error: "Корзина пуста" });
                }

                getStatusId(REQUEST_STATUSES.READY, (readyErr, readyStatusId) => {
                    if (readyErr || !readyStatusId) {
                        return res.status(500).json({ error: "Не удалось получить статус 'Оформлена'" });
                    }

                    getStatusId(REQUEST_STATUSES.PENDING, (pendingErr, pendingStatusId) => {
                        if (pendingErr || !pendingStatusId) {
                            return res.status(500).json({ error: "Не удалось получить статус 'На рассмотрении'" });
                        }

                        const finalRecipient = trimmedRecipient || user.fio || "Получатель";
                        const createdRequests = [];

                        db.serialize(() => {
                            db.run("BEGIN TRANSACTION");

                            const processItem = (index = 0) => {
                                if (index >= cartItems.length) {
                                    db.run(
                                        "DELETE FROM cart_items WHERE user_id = ?",
                                        [userId],
                                        (deleteErr) => {
                                            if (deleteErr) {
                                                db.run("ROLLBACK");
                                                return res.status(500).json({ error: deleteErr.message });
                                            }

                                            db.run("COMMIT", (commitErr) => {
                                                if (commitErr) {
                                                    db.run("ROLLBACK");
                                                    return res.status(500).json({ error: commitErr.message });
                                                }

                                                res.json({
                                                    success: true,
                                                    message: `Создано ${createdRequests.length} заявок`,
                                                    requests: createdRequests
                                                });
                                            });
                                        }
                                    );
                                    return;
                                }

                                const item = cartItems[index];
                                const requestedQty = Number(item.requested_qty) || 0;
                                const unitPrice = Number(item.price) || 0;
                                const stockQtyRaw = Number(item.stock_qty);
                                const stockQty = Number.isFinite(stockQtyRaw) ? Math.max(0, stockQtyRaw) : 0;
                                const isoDate = new Date().toISOString();

                                if (requestedQty <= 0) {
                                    // Пропускаем некорректные позиции
                                    return processItem(index + 1);
                                }

                                const createRequest = (statusId, statusName, qty, deductQty, done) => {
                                    const totalSum = unitPrice * qty;
                                    db.run(
                                        `INSERT INTO requests (user_id, status_id, date, total_sum, description, recipient_name, delivery_address, created_at)
                                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                                        [
                                            userId,
                                            statusId,
                                            isoDate,
                                            totalSum,
                                            item.name ? `Товар: ${item.name}` : null,
                                            finalRecipient,
                                            trimmedAddress,
                                            isoDate
                                        ],
                                        function(insertErr) {
                                            if (insertErr) {
                                                db.run("ROLLBACK");
                                                return res.status(500).json({ error: insertErr.message });
                                            }

                                            const requestId = this.lastID;
                                            db.run(
                                                `INSERT INTO request_items (request_id, product_id, quantity, price_per_unit)
                                                 VALUES (?, ?, ?, ?)`,
                                                [requestId, item.product_id, qty, unitPrice],
                                                (itemErr) => {
                                                    if (itemErr) {
                                                        db.run("ROLLBACK");
                                                        return res.status(500).json({ error: itemErr.message });
                                                    }

                                                    const finalizeItem = () => {
                                                        createdRequests.push({
                                                            requestId,
                                                            productId: item.product_id,
                                                            productName: item.name,
                                                            quantity: qty,
                                                            inStock: statusName === REQUEST_STATUSES.READY,
                                                            status: statusName
                                                        });
                                                        done();
                                                    };

                                                    if (deductQty > 0) {
                                                        db.run(
                                                            "UPDATE products SET quantity = quantity - ? WHERE id = ?",
                                                            [deductQty, item.product_id],
                                                            (updateErr) => {
                                                                if (updateErr) {
                                                                    db.run("ROLLBACK");
                                                                    return res.status(500).json({ error: updateErr.message });
                                                                }
                                                                finalizeItem();
                                                            }
                                                        );
                                                    } else {
                                                        finalizeItem();
                                                    }
                                                }
                                            );
                                        }
                                    );
                                };

                                // Логика разбиения заявки:
                                // 1) Если товара достаточно -> одна заявка READY на всё количество
                                // 2) Если товара мало, но > 0 -> одна заявка READY на доступное количество и вторая PENDING на остаток
                                // 3) Если товара нет -> одна заявка PENDING на всё количество
                                if (stockQty >= requestedQty && stockQty > 0) {
                                    // Всё в наличии
                                    createRequest(readyStatusId, REQUEST_STATUSES.READY, requestedQty, requestedQty, () => {
                                        processItem(index + 1);
                                    });
                                } else if (stockQty > 0 && stockQty < requestedQty) {
                                    const readyQty = stockQty;
                                    const pendingQty = requestedQty - stockQty;

                                    // Сначала часть, которая есть на складе
                                    createRequest(readyStatusId, REQUEST_STATUSES.READY, readyQty, readyQty, () => {
                                        // Затем часть, которая ждёт поставщика
                                        createRequest(pendingStatusId, REQUEST_STATUSES.PENDING, pendingQty, 0, () => {
                                            processItem(index + 1);
                                        });
                                    });
                                } else {
                                    // На складе нет, вся заявка ждёт поставщика
                                    createRequest(pendingStatusId, REQUEST_STATUSES.PENDING, requestedQty, 0, () => {
                                        processItem(index + 1);
                                    });
                                }
                            };

                            processItem();
                        });
                    });
                });
            }
        );
    });
});

app.get("/requests", (req, res) => {
    const userId = Number(req.query.userId);

    if (!userId) {
        return res.status(400).json({ error: "userId обязателен" });
    }

    db.all(
        `SELECT r.id AS requestId,
                r.date,
                r.total_sum,
                r.description,
                r.recipient_name,
                r.delivery_address,
                s.name AS status,
                ri.product_id,
                p.name AS productName,
                ri.quantity,
                ri.price_per_unit
         FROM requests r
         LEFT JOIN statuses s ON s.id = r.status_id
         LEFT JOIN request_items ri ON ri.request_id = r.id
         LEFT JOIN products p ON p.id = ri.product_id
         WHERE r.user_id = ?
         ORDER BY r.date DESC, r.id DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            const requests = rows.map((row) => ({
                requestId: row.requestId,
                date: row.date,
                total_sum: Number(row.total_sum) || 0,
                description: row.description,
                recipientName: row.recipient_name,
                deliveryAddress: row.delivery_address,
                status: row.status,
                productId: row.product_id,
                productName: row.productName,
                quantity: row.quantity,
                pricePerUnit: row.price_per_unit
            }));

            res.json(requests);
        }
    );
});

app.get("/supplier/requests", (req, res) => {
    const supplierId = Number(req.query.supplierId);

    requireSupplier(supplierId, res, (supplier) => {
        db.all(
            `SELECT 
                r.id AS requestId,
                r.date,
                r.total_sum,
                r.description,
                r.recipient_name,
                r.delivery_address,
                s.name AS status,
                ri.quantity,
                ri.price_per_unit,
                p.name AS product_name,
                u.fio AS customer_name
             FROM requests r
             JOIN request_items ri ON ri.request_id = r.id
             JOIN products p ON p.id = ri.product_id
             JOIN users u ON u.id = r.user_id
             LEFT JOIN statuses s ON s.id = r.status_id
             WHERE p.supplier = ?
             ORDER BY r.date DESC, r.id DESC`,
            [supplier.company_name],
            (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                const result = rows.map((row) => ({
                    requestId: row.requestId,
                    date: row.date,
                    total_sum: Number(row.total_sum) || 0,
                    description: row.description,
                    recipientName: row.recipient_name,
                    deliveryAddress: row.delivery_address,
                    status: row.status,
                    quantity: row.quantity,
                    pricePerUnit: row.price_per_unit,
                    productName: row.product_name,
                    customerName: row.customer_name
                }));

                res.json(result);
            }
        );
    });
});

app.put("/supplier/requests/:requestId/status", (req, res) => {
    const requestId = Number(req.params.requestId);
    const supplierId = Number(req.body.supplierId);
    const newStatus = (req.body.status || "").toString().trim();

    if (!requestId || !supplierId) {
        return res.status(400).json({ error: "requestId и supplierId обязательны" });
    }

    if (!newStatus || !Object.values(REQUEST_STATUSES).includes(newStatus)) {
        return res.status(400).json({ error: "Некорректный статус" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        db.get(
            `SELECT p.supplier
             FROM request_items ri
             JOIN products p ON p.id = ri.product_id
             WHERE ri.request_id = ?`,
            [requestId],
            (err, row) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (!row) {
                    return res.status(404).json({ error: "Заявка не найдена" });
                }

                if (row.supplier !== supplier.company_name) {
                    return res.status(403).json({ error: "Заявка не принадлежит вам" });
                }

                getStatusId(newStatus, (statusErr, statusId) => {
                    if (statusErr || !statusId) {
                        return res.status(500).json({ error: "Не удалось найти статус" });
                    }

                    db.run(
                        `UPDATE requests SET status_id = ? WHERE id = ?`,
                        [statusId, requestId],
                        function(updateErr) {
                            if (updateErr) {
                                return res.status(500).json({ error: updateErr.message });
                            }

                            if (this.changes === 0) {
                                return res.status(400).json({ error: "Изменения не применены" });
                            }

                            res.json({
                                success: true,
                                requestId,
                                status: newStatus
                            });
                        }
                    );
                });
            }
        );
    });
});

app.delete("/requests/:requestId", (req, res) => {
    const requestId = Number(req.params.requestId);
    const userId = Number(req.query.userId);

    if (!requestId || !userId) {
        return res.status(400).json({ error: "requestId и userId обязательны" });
    }

    db.get(
        `SELECT r.id, s.name AS status
         FROM requests r
         LEFT JOIN statuses s ON s.id = r.status_id
         WHERE r.id = ? AND r.user_id = ?`,
        [requestId, userId],
        (err, request) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (!request) {
                return res.status(404).json({ error: "Заявка не найдена" });
            }

            if (request.status !== REQUEST_STATUSES.DECLINED) {
                return res.status(400).json({ error: "Можно удалить только отклонённые заявки" });
            }

            db.serialize(() => {
                db.run("BEGIN TRANSACTION");

                db.run(
                    "DELETE FROM request_items WHERE request_id = ?",
                    [requestId],
                    (itemsErr) => {
                        if (itemsErr) {
                            db.run("ROLLBACK");
                            return res.status(500).json({ error: itemsErr.message });
                        }

                        db.run(
                            "DELETE FROM requests WHERE id = ?",
                            [requestId],
                            (deleteErr) => {
                                if (deleteErr) {
                                    db.run("ROLLBACK");
                                    return res.status(500).json({ error: deleteErr.message });
                                }

                                db.run("COMMIT", (commitErr) => {
                                    if (commitErr) {
                                        db.run("ROLLBACK");
                                        return res.status(500).json({ error: commitErr.message });
                                    }

                                    res.json({ success: true, message: "Заявка удалена" });
                                });
                            }
                        );
                    }
                );
            });
        }
    );
});

// Изменить email (логин) пользователя
app.put("/auth/profile/email", (req, res) => {
    const { userId, newEmail, password } = req.body;
    
    // Валидация
    if (!userId || !newEmail || !password) {
        return res.status(400).json({ error: "userId, newEmail и password обязательны" });
    }
    
    // Проверка формата email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(newEmail)) {
        return res.status(400).json({ error: "Неверный формат email" });
    }
    
    // Получаем пользователя
    db.get("SELECT id, email, password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (!user) {
            return res.status(404).json({ error: "Пользователь не найден" });
        }
        
        // Проверяем, что новый email отличается от текущего
        if (user.email === newEmail) {
            return res.status(400).json({ error: "Новый email совпадает с текущим" });
        }
        
        // Проверяем пароль
        const storedPassword = user.password || "";
        const isHashed = typeof storedPassword === "string" && storedPassword.startsWith("$2");
        
        const verifyPassword = (callback) => {
            if (!storedPassword) {
                return callback(false);
            }
            
            if (!isHashed) {
                // Старый формат пароля (plain text)
                return callback(storedPassword === password);
            }
            
            // Проверяем пароль с помощью bcrypt
            bcrypt.compare(password, storedPassword, (compareErr, isValid) => {
                if (compareErr) {
                    return callback(false);
                }
                callback(isValid);
            });
        };
        
        verifyPassword((isValid) => {
            if (!isValid) {
                return res.status(401).json({ error: "Неверный пароль" });
            }
            
            // Проверяем, не занят ли новый email другим пользователем
            db.get("SELECT id FROM users WHERE email = ? AND id != ?", [newEmail, userId], (err, existingUser) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                if (existingUser) {
                    return res.status(400).json({ error: "Пользователь с таким email уже существует" });
                }
                
                // Обновляем email
                db.run("UPDATE users SET email = ? WHERE id = ?", [newEmail, userId], function(err) {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    
                    res.json({
                        success: true,
                        message: "Email успешно изменен",
                        newEmail: newEmail
                    });
                });
            });
        });
    });
});

// Изменить пароль пользователя
app.put("/auth/profile/password", (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;
    
    // Валидация
    if (!userId || !currentPassword || !newPassword) {
        return res.status(400).json({ error: "userId, currentPassword и newPassword обязательны" });
    }
    
    // Проверка длины нового пароля
    if (newPassword.length < 6) {
        return res.status(400).json({ error: "Пароль должен содержать минимум 6 символов" });
    }
    
    // Проверяем, что новый пароль отличается от текущего
    if (currentPassword === newPassword) {
        return res.status(400).json({ error: "Новый пароль должен отличаться от текущего" });
    }
    
    // Получаем пользователя
    db.get("SELECT id, password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        if (!user) {
            return res.status(404).json({ error: "Пользователь не найден" });
        }
        
        // Проверяем текущий пароль
        const storedPassword = user.password || "";
        const isHashed = typeof storedPassword === "string" && storedPassword.startsWith("$2");
        
        const verifyPassword = (callback) => {
            if (!storedPassword) {
                return callback(false);
            }
            
            if (!isHashed) {
                // Старый формат пароля (plain text)
                return callback(storedPassword === currentPassword);
            }
            
            // Проверяем пароль с помощью bcrypt
            bcrypt.compare(currentPassword, storedPassword, (compareErr, isValid) => {
                if (compareErr) {
                    return callback(false);
                }
                callback(isValid);
            });
        };
        
        verifyPassword((isValid) => {
            if (!isValid) {
                return res.status(401).json({ error: "Неверный текущий пароль" });
            }
            
            // Хешируем новый пароль
            bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).json({ error: "Ошибка при хешировании пароля" });
                }
                
                // Обновляем пароль
                db.run("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, userId], function(err) {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    
                    res.json({
                        success: true,
                        message: "Пароль успешно изменен"
                    });
                });
            });
        });
    });
});

app.listen(3000, () => {
    console.log("Сервер запущен: http://localhost:3000");
});