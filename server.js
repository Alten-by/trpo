const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

const REQUIRED_ROLES = ["customer", "supplier", "admin"];
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    const { article, name, description, price, quantity, supplier, category, image_url } = req.body;
    db.run("INSERT INTO products (article, name, description, price, quantity, supplier, category, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [article, name, description, price, quantity, supplier, category, image_url],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
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
    const { article, name, description, price, quantity, category, image_url } = req.body;

    if (!article || !name || !price || quantity === undefined) {
        return res.status(400).json({ error: "Артикул, название, цена и количество обязательны" });
    }

    requireSupplier(supplierId, res, (supplier) => {
        db.run(
            "INSERT INTO products (article, name, description, price, quantity, supplier, category, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [article, name, description, price, quantity, supplier.company_name, category || null, image_url || null],
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
    const { article, name, description, price, quantity, category, image_url } = req.body;

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
                        db.run(
                            "UPDATE products SET article = ?, name = ?, description = ?, price = ?, quantity = ?, category = ?, image_url = ? WHERE id = ?",
                            [article, name, description || null, price, quantity, category || null, image_url || null, productId],
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

                        res.json({
                            success: true,
                            userId,
                            companyName: normalizedCompany
                        });
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

                            res.json({
                                success: true,
                                userId,
                                isSupplier: supplierFlag,
                                companyName: normalizedCompany || undefined
                            });
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