const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    crypto.randomBytes(48).toString("hex");

if (!process.env.JWT_SECRET) {
    console.warn(
        "⚠️  JWT_SECRET non défini : un secret aléatoire a été généré " +
        "pour cette instance. Les sessions seront invalidées à chaque " +
        "redémarrage. Définis JWT_SECRET en production."
    );
}

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error(
        "❌ DATABASE_URL manquant. VaultBridge a besoin d'une base " +
        "PostgreSQL (ex : Neon, Supabase, ou Render Postgres — toutes " +
        "ont un tier gratuit). Définis la variable d'environnement " +
        "DATABASE_URL et redémarre."
    );
    process.exit(1);
}

const PUBLIC_PATH = path.join(__dirname, "public");

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl:
        process.env.PGSSL === "disable"
            ? false
            : { rejectUnauthorized: false }
});

async function initSchema() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            vault_salt TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS vault_entries (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            icon TEXT NOT NULL DEFAULT '🔐',
            name TEXT NOT NULL,
            login TEXT NOT NULL,
            password_cipher TEXT NOT NULL,
            iv TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_vault_entries_user_id
        ON vault_entries(user_id);
    `);
}

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"],
                formAction: ["'self'"]
            }
        },
        crossOriginEmbedderPolicy: false
    })
);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Trop de tentatives. Réessayez dans quelques minutes." }
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Trop de requêtes. Ralentissez un peu." }
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(PUBLIC_PATH));
app.use("/api/", apiLimiter);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email) {
    return typeof email === "string" && EMAIL_REGEX.test(email) && email.length <= 254;
}

function isValidLength(value, min, max) {
    return typeof value === "string" && value.length >= min && value.length <= max;
}
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", 12);

async function authenticate(req, res, next) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Authentification requise."
        });
    }

    const token = header.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded || !decoded.sub) {
            return res.status(401).json({
                error: "Session invalide."
            });
        }

        const result = await pool.query("SELECT id FROM users WHERE id = $1", [decoded.sub]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: "Ce compte n'existe plus."
            });
        }

        req.userId = decoded.sub;

        next();
    } catch (error) {
        return res.status(401).json({
            error: "Session invalide ou expirée."
        });
    }
}

app.get("/api", async (req, res) => {
    let dbOk = true;

    try {
        await pool.query("SELECT 1");
    } catch (error) {
        dbOk = false;
    }

    res.json({
        ok: true,
        message: "VaultBridge API fonctionne.",
        version: "1.0.0",
        database: dbOk ? "connected" : "unreachable"
    });
});

app.post("/api/register", authLimiter, async (req, res) => {
    try {
        const { name, email, password } = req.body || {};

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "Nom, email et mot de passe requis."
            });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const normalizedName = String(name).trim();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({
                error: "Adresse email invalide."
            });
        }

        if (!isValidLength(normalizedName, 1, 100)) {
            return res.status(400).json({
                error: "Le nom doit contenir entre 1 et 100 caractères."
            });
        }

        if (!isValidLength(String(password), 8, 128)) {
            return res.status(400).json({
                error: "Le mot de passe doit contenir entre 8 et 128 caractères."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const vaultSalt = crypto.randomBytes(16).toString("base64");
        const userId = crypto.randomUUID();

        try {
            await pool.query(
                `INSERT INTO users (id, name, email, password_hash, vault_salt)
                 VALUES ($1, $2, $3, $4, $5)`,
                [userId, normalizedName, normalizedEmail, passwordHash, vaultSalt]
            );
        } catch (error) {
            if (error.code === "23505") { // unique_violation
                return res.status(409).json({
                    error: "Un compte existe déjà avec cette adresse."
                });
            }
            throw error;
        }

        const token = jwt.sign(
            { sub: userId },
            JWT_SECRET,
            { expiresIn: "12h" }
        );

        return res.status(201).json({
            token,
            user: {
                id: userId,
                name: normalizedName,
                email: normalizedEmail
            },
            vaultSalt
        });

    } catch (error) {
        console.error("Erreur inscription :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.post("/api/login", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({
                error: "Email et mot de passe requis."
            });
        }

        const normalizedEmail = String(email).trim().toLowerCase();

        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [normalizedEmail]
        );

        const user = result.rows[0] || null;
        const hashToCheck = user ? user.password_hash : DUMMY_HASH;
        const valid = await bcrypt.compare(password, hashToCheck);

        if (!user || !valid) {
            return res.status(401).json({
                error: "Email ou mot de passe incorrect."
            });
        }

        const token = jwt.sign(
            { sub: user.id },
            JWT_SECRET,
            { expiresIn: "12h" }
        );

        return res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            },
            vaultSalt: user.vault_salt
        });

    } catch (error) {
        console.error("Erreur connexion :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.get("/api/account", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, name, email, created_at FROM users WHERE id = $1",
            [req.userId]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({
                error: "Compte introuvable."
            });
        }

        return res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            createdAt: user.created_at
        });
    } catch (error) {
        console.error("Erreur lecture compte :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.delete("/api/account", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            "DELETE FROM users WHERE id = $1 RETURNING id",
            [req.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "Compte introuvable."
            });
        }

        return res.json({
            ok: true,
            message: "Compte supprimé."
        });
    } catch (error) {
        console.error("Erreur suppression compte :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.get("/api/vault", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, icon, name, login AS user, password_cipher AS "passwordCipher",
                    iv, created_at AS "createdAt"
             FROM vault_entries
             WHERE user_id = $1
             ORDER BY created_at ASC`,
            [req.userId]
        );

        return res.json(result.rows);
    } catch (error) {
        console.error("Erreur lecture coffre :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.post("/api/vault", authenticate, async (req, res) => {
    try {
        const {
            icon,
            name,
            user,
            passwordCipher,
            iv
        } = req.body || {};

        if (!name || !user || !passwordCipher || !iv) {
            return res.status(400).json({
                error: "Champs manquants."
            });
        }

        if (
            !isValidLength(String(name), 1, 200) ||
            !isValidLength(String(user), 1, 200) ||
            !isValidLength(String(passwordCipher), 1, 10000) ||
            !isValidLength(String(iv), 1, 200)
        ) {
            return res.status(400).json({
                error: "Un ou plusieurs champs dépassent la longueur autorisée."
            });
        }

        const entryId = crypto.randomUUID();

        const cleanIcon =
            typeof icon === "string" && icon.trim()
                ? icon.trim().slice(0, 4)
                : "🔐";

        const result = await pool.query(
            `INSERT INTO vault_entries
                (id, user_id, icon, name, login, password_cipher, iv)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, icon, name, login AS user,
                       password_cipher AS "passwordCipher", iv,
                       created_at AS "createdAt"`,
            [
                entryId,
                req.userId,
                cleanIcon,
                String(name).trim(),
                String(user).trim(),
                String(passwordCipher),
                String(iv)
            ]
        );

        return res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Erreur ajout entrée :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.delete("/api/vault/:id", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `DELETE FROM vault_entries
             WHERE id = $1 AND user_id = $2
             RETURNING id`,
            [req.params.id, req.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "Entrée introuvable."
            });
        }

        return res.json({ ok: true });
    } catch (error) {
        console.error("Erreur suppression entrée :", error);

        return res.status(500).json({
            error: "Erreur interne du serveur."
        });
    }
});

app.use((req, res, next) => {
    if (req.method !== "GET") {
        return next();
    }

    if (req.path.startsWith("/api/")) {
        return res.status(404).json({
            error: "Route API introuvable."
        });
    }

    const indexPath = path.join(PUBLIC_PATH, "index.html");

    return res.sendFile(indexPath, error => {
        if (error) {
            res.status(404).send(
                "VaultBridge : index.html introuvable."
            );
        }
    });
});

app.use((err, req, res, next) => {
    console.error("Erreur serveur :", err);

    if (res.headersSent) {
        return next(err);
    }

    return res.status(500).json({
        error: "Erreur interne du serveur."
    });
});

initSchema()
    .then(() => {
        app.listen(PORT, () => {
            console.log("");
            console.log("======================================");
            console.log("       VAULTBRIDGE SERVER");
            console.log("======================================");
            console.log(`Serveur  : http://localhost:${PORT}`);
            console.log(`API      : http://localhost:${PORT}/api`);
            console.log("Base de données : PostgreSQL — schéma prêt");
            console.log("======================================");
            console.log("");
        });
    })
    .catch(error => {
        console.error("❌ Impossible d'initialiser la base :", error);
        process.exit(1);
    });