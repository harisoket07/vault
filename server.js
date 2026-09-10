/**
 * VaultBridge — server.js
 * ------------------------------------------------------------
 * Backend Express pour VaultBridge
 *
 * - Mots de passe de comptes hashés avec bcrypt (facteur 12)
 * - Coffre chiffré côté navigateur (AES-GCM 256 + PBKDF2)
 *   Le serveur ne voit jamais les mots de passe du coffre en clair.
 * - Sessions JWT avec expiration contrôlée
 * - Persistance dans PostgreSQL (Neon / Supabase / Render) via DATABASE_URL
 * - Compatible Express 5
 *
 * SÉCURITÉ EN COUCHES :
 *   1. Proxy configuré avant les rate-limiters (anti-spoofing IP)
 *   2. CSP stricte avec NONCE PAR REQUÊTE pour le script inline
 *      (pas de 'unsafe-inline' sur scriptSrc — le HTML n'a pas besoin
 *      d'être modifié, le nonce est injecté à la volée au moment du
 *      rendu de index.html)
 *   3. En-têtes HTTP stricts (Helmet, HSTS, Permissions-Policy, etc.)
 *   4. Anti-cache sur toutes les routes /api/
 *   5. Limiteur de débit par IP et par IP+compte
 *   6. Anti-brute-force PERSISTÉ EN BASE par compte (failed_login_attempts /
 *      next_attempt_at) — survit aux redémarrages et fonctionne quel que
 *      soit le nombre d'instances déployées (contrairement à un tracker
 *      en mémoire, qui se contourne en changeant d'IP ou en tapant sur
 *      une autre instance)
 *   7. CAPTCHA (Cloudflare Turnstile) obligatoire à l'inscription ET
 *      après plusieurs échecs de connexion, vérifié dans tous les cas
 *      (aucun moyen de l'omettre en ne fournissant pas le champ)
 *   8. Validation stricte des entrées + UUID sur tous les paramètres d'URL
 *   9. Suppression de compte : mot de passe obligatoire et vérifié
 *      systématiquement (jamais de bypass possible)
 *
 * Dépendances à installer :
 *   npm install express pg bcryptjs jsonwebtoken helmet express-rate-limit
 *
 * Variables d'environnement :
 *   DATABASE_URL          → obligatoire (chaîne de connexion Postgres)
 *   JWT_SECRET            → fortement recommandé en production
 *   JWT_EXPIRES_IN        → optionnel (défaut "4h")
 *   TRUST_PROXY           → "true"/"1" ou valeur express (ex: "loopback")
 *   TURNSTILE_SECRET_KEY  → optionnel — active le CAPTCHA
 *   TURNSTILE_SITE_KEY    → optionnel — sitekey publique correspondante
 *   PGSSL                 → "disable" pour désactiver SSL Postgres (local)
 *   NODE_ENV              → "production" active trust proxy par défaut
 */

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

/* ============================================================
   🔒 SÉCURITÉ — CONFIGURATION PROXY (DOIT ÊTRE AU TOUT DÉBUT)
   ------------------------------------------------------------
   Si déployé derrière un reverse proxy (Render, Fly.io, Cloudflare,
   Nginx, Heroku), express doit faire confiance au proxy pour lire
   req.ip correctement. En local, on ne fait pas confiance aveuglément
   pour éviter le spoofing d'en-tête X-Forwarded-For.
============================================================ */
const trustProxyEnv = process.env.TRUST_PROXY;
if (trustProxyEnv === "true" || trustProxyEnv === "1") {
    app.set("trust proxy", 1);
} else if (trustProxyEnv) {
    app.set("trust proxy", trustProxyEnv);
} else if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    crypto.randomBytes(48).toString("hex");

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "4h";

if (!process.env.JWT_SECRET) {
    console.warn(
        "⚠️  JWT_SECRET non défini : un secret aléatoire a été généré " +
        "pour cette instance. Les sessions seront invalidées à chaque " +
        "redémarrage. Définis JWT_SECRET en production."
    );
}

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL && require.main === module) {
    console.error(
        "❌ DATABASE_URL manquant. VaultBridge a besoin d'une base " +
        "PostgreSQL (ex : Neon, Supabase, ou Render Postgres — toutes " +
        "ont un tier gratuit). Définis la variable d'environnement " +
        "DATABASE_URL et redémarre."
    );
    process.exit(1);
}

const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || null;
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "0x4AAAAAAEvLrQJ9GrveT-pT";

if (!TURNSTILE_SECRET_KEY) {
    console.warn(
        "⚠️  TURNSTILE_SECRET_KEY non défini — le CAPTCHA est désactivé. " +
        "Le délai progressif par compte reste actif. Pour l'activer, " +
        "crée une clé gratuite sur https://dash.cloudflare.com/ (Turnstile)."
    );
}

const PUBLIC_PATH = path.join(__dirname, "public");
const INDEX_HTML_PATH = path.join(PUBLIC_PATH, "index.html");

/* ============================================================
   🔒 SÉCURITÉ — RENDU DE index.html AVEC NONCE CSP INJECTÉ
   ------------------------------------------------------------
   Plutôt que d'autoriser 'unsafe-inline' pour les scripts (ce qui
   annule une grande partie de la protection CSP contre le XSS), on
   injecte un nonce unique par requête dans les balises <script>
   qui n'ont pas d'attribut src (donc le script inline de l'app),
   sans toucher aux <script src="..."> externes (Three.js, Turnstile)
   qui sont déjà couverts par les domaines autorisés.
   Le fichier index.html n'a besoin d'aucune modification.
============================================================ */

let cachedIndexTemplate = null;

function loadIndexTemplate() {
    if (cachedIndexTemplate === null) {
        cachedIndexTemplate = fs.readFileSync(INDEX_HTML_PATH, "utf8");
    }
    return cachedIndexTemplate;
}

function renderIndexHtml(nonce) {
    const template = loadIndexTemplate();
    // Injecte nonce="..." uniquement sur les balises <script> SANS src=
    return template.replace(/<script(?![^>]*\bsrc=)([^>]*)>/gi, (match, attrs) => {
        return `<script nonce="${nonce}"${attrs}>`;
    });
}

function sendIndexHtml(req, res) {
    try {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(renderIndexHtml(res.locals.cspNonce));
    } catch (error) {
        console.error("Erreur rendu index.html :", error);
        res.status(404).send("VaultBridge : index.html introuvable.");
    }
}

/* ============================================================
   🔒 SÉCURITÉ — PARAMÈTRES ANTI-BRUTE-FORCE PAR COMPTE
   ------------------------------------------------------------
   BACKOFF_SCHEDULE[n] = délai en secondes imposé après le n-ième
   échec consécutif sur un compte. Persisté en base (colonnes
   failed_login_attempts / next_attempt_at) : reste efficace même
   avec plusieurs instances du serveur ou après un redémarrage,
   contrairement à un compteur gardé uniquement en mémoire.
============================================================ */

const BACKOFF_SCHEDULE = [0, 0, 0, 5, 15, 30, 60, 120, 300];
const CAPTCHA_THRESHOLD = 3;

function computeBackoffSeconds(failedAttempts) {
    const idx = Math.min(Math.max(0, failedAttempts), BACKOFF_SCHEDULE.length - 1);
    return BACKOFF_SCHEDULE[idx];
}

/* ============================================================
   🔒 SÉCURITÉ — VÉRIFICATION CAPTCHA (Cloudflare Turnstile)
   ------------------------------------------------------------
   Dégradation propre : si TURNSTILE_SECRET_KEY n'est pas configurée,
   cette fonction laisse toujours passer (le délai progressif reste
   la seule protection) plutôt que de bloquer une instance mal
   configurée. Sinon, un token absent ou invalide est TOUJOURS rejeté
   — impossible de la contourner en omettant simplement le champ.
============================================================ */

async function verifyCaptcha(token, remoteIp) {
    if (!TURNSTILE_SECRET_KEY) return true;
    if (!token || typeof token !== "string") return false;

    try {
        const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                secret: TURNSTILE_SECRET_KEY,
                response: token,
                remoteip: remoteIp || ""
            })
        });

        const data = await response.json();
        return data.success === true;
    } catch (error) {
        console.error("Erreur vérification CAPTCHA :", error.message);
        return false; // en cas de doute, on bloque plutôt que de laisser passer
    }
}

/* ============================================================
   BASE DE DONNÉES POSTGRESQL
============================================================ */

const isLocalDb = Boolean(
    DATABASE_URL && (
        DATABASE_URL.includes("localhost") ||
        DATABASE_URL.includes("127.0.0.1") ||
        DATABASE_URL.includes("sslmode=disable")
    )
);

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl:
        process.env.PGSSL === "disable" || (isLocalDb && process.env.PGSSL !== "require")
            ? false
            : { rejectUnauthorized: false }
});

pool.on("error", (err) => {
    console.error("⚠️ Erreur inattendue du pool PostgreSQL :", err.message);
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

    // 🔒 Colonnes du délai progressif par compte — persistées en base
    // pour rester efficaces quel que soit le nombre d'instances du
    // serveur ou après un redémarrage.
    await pool.query(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
    `);
    await pool.query(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
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

/* ============================================================
   🔒 SÉCURITÉ — EN-TÊTES HTTP & CSP AVEC NONCE
============================================================ */

app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
    next();
});

app.use((req, res, next) => {
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                // Pas de 'unsafe-inline' : le script inline de l'app utilise
                // le nonce généré par requête (voir renderIndexHtml). Les
                // scripts externes (Three.js, Turnstile) restent listés
                // explicitement par domaine.
                scriptSrc: [
                    "'self'",
                    `'nonce-${res.locals.cspNonce}'`,
                    "https://cdnjs.cloudflare.com",
                    "https://challenges.cloudflare.com"
                ],
                // 'unsafe-inline' reste nécessaire pour styleSrc : l'app
                // utilise des attributs style="" inline sur certains
                // éléments. Risque bien moindre que pour les scripts.
                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com"
                ],
                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com",
                    "data:"
                ],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'", "https://challenges.cloudflare.com"],
                frameSrc: ["https://challenges.cloudflare.com"],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"],
                formAction: ["'self'"]
            }
        },
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: { policy: "same-origin" },
        crossOriginResourcePolicy: { policy: "same-origin" },
        referrerPolicy: { policy: "strict-origin-when-cross-origin" }
    })(req, res, next);
});

app.use((req, res, next) => {
    res.setHeader(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()"
    );
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    next();
});

/* ============================================================
   🔒 SÉCURITÉ — LIMITATION DE DÉBIT (RATE LIMITING)
============================================================ */

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { error: "Trop de tentatives depuis cette adresse. Réessayez plus tard." }
});

const ipAccountLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    validate: { keyGeneratorIpFallback: false },
    keyGenerator: (req) => {
        const email = String((req.body && req.body.email) || "").trim().toLowerCase();
        return `${req.ip}:${email}`;
    },
    message: { error: "Trop de tentatives sur ce compte depuis cette adresse. Réessayez plus tard." }
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Trop de requêtes. Ralentissez un peu." }
});

/* ============================================================
   MIDDLEWARE & CACHE-CONTROL POUR L'API
============================================================ */

app.use(express.json({ limit: "500kb" }));

// Erreur de parsing JSON → 400 propre plutôt que 500
app.use((err, req, res, next) => {
    if (err && err.type === "entity.parse.failed") {
        return res.status(400).json({ error: "Corps de requête JSON invalide." });
    }
    next(err);
});

// index:false pour que express.static ne serve jamais index.html
// directement (sans nonce injecté) — nos routes dédiées s'en chargent.
app.use(express.static(PUBLIC_PATH, { index: false }));

app.use("/api", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
});

app.use("/api/", apiLimiter);

/* ============================================================
   🔒 SÉCURITÉ — VALIDATION DES ENTRÉES
============================================================ */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isValidEmail(email) {
    return typeof email === "string" && EMAIL_REGEX.test(email) && email.length <= 254;
}

function isValidLength(value, min, max) {
    return typeof value === "string" && value.length >= min && value.length <= max;
}

function isValidUuid(value) {
    return typeof value === "string" && UUID_REGEX.test(value);
}

// Hash factice utilisé pour égaliser le temps de réponse quand l'email
// n'existe pas — jamais utilisé pour un vrai compte.
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", 12);

/* ============================================================
   AUTHENTIFICATION JWT
============================================================ */

async function authenticate(req, res, next) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Authentification requise." });
    }

    const token = header.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded || !decoded.sub || !isValidUuid(decoded.sub)) {
            return res.status(401).json({ error: "Session invalide." });
        }

        const result = await pool.query("SELECT id FROM users WHERE id = $1", [decoded.sub]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Ce compte n'existe plus." });
        }

        req.userId = decoded.sub;
        next();
    } catch (error) {
        return res.status(401).json({ error: "Session invalide ou expirée." });
    }
}

/* ============================================================
   ROUTE DE STATUT API
============================================================ */

app.get("/api", async (req, res) => {
    let dbOk = true;

    try {
        await pool.query("SELECT 1");
    } catch {
        dbOk = false;
    }

    res.json({
        ok: true,
        message: "VaultBridge API opérationnelle.",
        version: "1.2.0",
        database: dbOk ? "connected" : "unreachable",
        captchaEnabled: Boolean(TURNSTILE_SECRET_KEY),
        turnstileSiteKey: TURNSTILE_SITE_KEY
    });
});

/* ============================================================
   INSCRIPTION
   🔒 Le CAPTCHA est vérifié dès que TURNSTILE_SECRET_KEY est
   configurée, sans condition sur la présence du champ dans le body
   (verifyCaptcha rejette déjà un token absent) — impossible à
   contourner en omettant simplement captchaToken.
============================================================ */

app.post("/api/register", authLimiter, async (req, res) => {
    try {
        const { name, email, password, captchaToken } = req.body || {};

        if (!name || !email || !password) {
            return res.status(400).json({ error: "Nom, email et mot de passe requis." });
        }

        if (TURNSTILE_SECRET_KEY) {
            const captchaOk = await verifyCaptcha(captchaToken, req.ip);
            if (!captchaOk) {
                return res.status(400).json({ error: "Vérification anti-robot requise ou invalide." });
            }
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const normalizedName = String(name).trim();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({ error: "Adresse email invalide." });
        }

        if (!isValidLength(normalizedName, 1, 100)) {
            return res.status(400).json({ error: "Le nom doit contenir entre 1 et 100 caractères." });
        }

        if (!isValidLength(String(password), 8, 128)) {
            return res.status(400).json({ error: "Le mot de passe maître doit contenir entre 8 et 128 caractères." });
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
                return res.status(409).json({ error: "Un compte existe déjà avec cette adresse email." });
            }
            throw error;
        }

        const token = jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        return res.status(201).json({
            token,
            user: { id: userId, name: normalizedName, email: normalizedEmail },
            vaultSalt
        });
    } catch (error) {
        console.error("Erreur inscription :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   CONNEXION
   🔒 SÉCURITÉ — protection en couches :
     - authLimiter + ipAccountLimiter (par IP, et par IP+compte)
     - délai progressif PERSISTÉ EN BASE par compte, indépendant de
       l'IP de l'attaquant (colonnes failed_login_attempts /
       next_attempt_at) — ne se contourne pas en changeant d'IP
     - CAPTCHA obligatoire après CAPTCHA_THRESHOLD échecs
     - remise à zéro complète après un succès
   Le timing de bcrypt.compare reste égalisé (vrai hash ou hash
   factice) pour ne pas révéler par le délai de réponse si l'email
   existe.
============================================================ */

app.post("/api/login", authLimiter, ipAccountLimiter, async (req, res) => {
    try {
        const { email, password, captchaToken } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({ error: "Email et mot de passe requis." });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const captchaActive = Boolean(TURNSTILE_SECRET_KEY);

        const result = await pool.query("SELECT * FROM users WHERE email = $1", [normalizedEmail]);
        let user = result.rows[0] || null;

        // Lever une échéance de délai déjà dépassée avant de continuer.
        if (user && user.next_attempt_at && new Date(user.next_attempt_at) <= new Date()) {
            await pool.query("UPDATE users SET next_attempt_at = NULL WHERE id = $1", [user.id]);
            user.next_attempt_at = null;
        }

        // Délai progressif encore actif : on bloque avant même de
        // vérifier le mot de passe (le message révèle déjà l'état du
        // compte, donc ce court-circuit n'ajoute pas de fuite d'info
        // supplémentaire par rapport au 401 générique ci-dessous).
        if (user && user.next_attempt_at && new Date(user.next_attempt_at) > new Date()) {
            const secondsLeft = Math.max(1, Math.ceil((new Date(user.next_attempt_at) - new Date()) / 1000));
            return res.status(429).json({
                error: `Trop de tentatives. Réessayez dans ${secondsLeft} seconde(s).`,
                captchaRequired: captchaActive && (user.failed_login_attempts || 0) >= CAPTCHA_THRESHOLD
            });
        }

        // CAPTCHA requis après plusieurs échecs sur ce compte.
        const captchaNeeded = captchaActive && Boolean(user) && (user.failed_login_attempts || 0) >= CAPTCHA_THRESHOLD;

        if (captchaNeeded) {
            const captchaOk = await verifyCaptcha(captchaToken, req.ip);
            if (!captchaOk) {
                return res.status(400).json({
                    error: "Vérification anti-robot requise ou invalide.",
                    captchaRequired: true
                });
            }
        }

        const hashToCheck = user ? user.password_hash : DUMMY_HASH;
        const valid = await bcrypt.compare(password, hashToCheck);

        if (!user || !valid) {
            let captchaRequiredNext = false;

            if (user) {
                const attempts = (user.failed_login_attempts || 0) + 1;
                const delaySeconds = computeBackoffSeconds(attempts);
                const nextAttemptAt = delaySeconds > 0 ? new Date(Date.now() + delaySeconds * 1000) : null;

                await pool.query(
                    "UPDATE users SET failed_login_attempts = $1, next_attempt_at = $2 WHERE id = $3",
                    [attempts, nextAttemptAt, user.id]
                );

                captchaRequiredNext = captchaActive && attempts >= CAPTCHA_THRESHOLD;
            }

            return res.status(401).json({
                error: "Email ou mot de passe incorrect.",
                captchaRequired: captchaRequiredNext
            });
        }

        // Succès : réinitialisation complète.
        if (user.failed_login_attempts > 0 || user.next_attempt_at) {
            await pool.query(
                "UPDATE users SET failed_login_attempts = 0, next_attempt_at = NULL WHERE id = $1",
                [user.id]
            );
        }

        const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        return res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email },
            vaultSalt: user.vault_salt
        });
    } catch (error) {
        console.error("Erreur connexion :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   INFORMATIONS DU COMPTE
============================================================ */

app.get("/api/account", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, name, email, created_at FROM users WHERE id = $1",
            [req.userId]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: "Compte introuvable." });
        }

        return res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            createdAt: user.created_at
        });
    } catch (error) {
        console.error("Erreur lecture compte :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   SUPPRESSION DU COMPTE
   🔒 Mot de passe obligatoire ET vérifié systématiquement — aucun
   chemin ne permet de supprimer le compte sans lui.
============================================================ */

app.delete("/api/account", authenticate, async (req, res) => {
    try {
        const { password } = req.body || {};

        if (!password || typeof password !== "string") {
            return res.status(400).json({ error: "Mot de passe requis pour confirmer la suppression." });
        }

        const userRes = await pool.query(
            "SELECT password_hash FROM users WHERE id = $1",
            [req.userId]
        );

        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: "Compte introuvable." });
        }

        const valid = await bcrypt.compare(password, userRes.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: "Mot de passe incorrect." });
        }

        const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Compte introuvable." });
        }

        return res.json({ ok: true, message: "Compte supprimé définitivement." });
    } catch (error) {
        console.error("Erreur suppression compte :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   RÉCUPÉRER LE COFFRE
============================================================ */

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
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   AJOUTER UNE ENTRÉE AU COFFRE
============================================================ */

app.post("/api/vault", authenticate, async (req, res) => {
    try {
        const { icon, name, user, passwordCipher, iv } = req.body || {};

        if (!name || !user || !passwordCipher || !iv) {
            return res.status(400).json({
                error: "Nom de service, identifiant, chiffrement et vecteur d'initialisation requis."
            });
        }

        if (
            !isValidLength(String(name), 1, 200) ||
            !isValidLength(String(user), 1, 200) ||
            !isValidLength(String(passwordCipher), 1, 10000) ||
            !isValidLength(String(iv), 1, 200)
        ) {
            return res.status(400).json({ error: "Un ou plusieurs champs dépassent la longueur autorisée." });
        }

        const entryId = crypto.randomUUID();
        const cleanIcon = typeof icon === "string" && icon.trim() ? icon.trim().slice(0, 8) : "🔐";

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
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   MODIFIER UNE ENTRÉE DU COFFRE
============================================================ */

app.put("/api/vault/:id", authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidUuid(id)) {
            return res.status(400).json({ error: "Identifiant d'accès invalide." });
        }

        const { icon, name, user, passwordCipher, iv } = req.body || {};

        if (!name || !user || !passwordCipher || !iv) {
            return res.status(400).json({ error: "Champs obligatoires manquants." });
        }

        if (
            !isValidLength(String(name), 1, 200) ||
            !isValidLength(String(user), 1, 200) ||
            !isValidLength(String(passwordCipher), 1, 10000) ||
            !isValidLength(String(iv), 1, 200)
        ) {
            return res.status(400).json({ error: "Un ou plusieurs champs dépassent la longueur autorisée." });
        }

        const cleanIcon = typeof icon === "string" && icon.trim() ? icon.trim().slice(0, 8) : "🔐";

        const result = await pool.query(
            `UPDATE vault_entries
             SET icon = $1, name = $2, login = $3, password_cipher = $4, iv = $5
             WHERE id = $6 AND user_id = $7
             RETURNING id, icon, name, login AS user,
                       password_cipher AS "passwordCipher", iv,
                       created_at AS "createdAt"`,
            [cleanIcon, String(name).trim(), String(user).trim(), String(passwordCipher), String(iv), id, req.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Entrée introuvable ou vous n'avez pas l'autorisation de la modifier." });
        }

        return res.json(result.rows[0]);
    } catch (error) {
        console.error("Erreur modification entrée :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   SUPPRIMER UNE ENTRÉE DU COFFRE
============================================================ */

app.delete("/api/vault/:id", authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidUuid(id)) {
            return res.status(400).json({ error: "Identifiant d'accès invalide." });
        }

        const result = await pool.query(
            `DELETE FROM vault_entries WHERE id = $1 AND user_id = $2 RETURNING id`,
            [id, req.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Entrée introuvable." });
        }

        return res.json({ ok: true });
    } catch (error) {
        console.error("Erreur suppression entrée :", error);
        return res.status(500).json({ error: "Erreur interne du serveur." });
    }
});

/* ============================================================
   ROUTES SPA — servent index.html avec le nonce CSP injecté
============================================================ */

app.get(["/", "/index.html"], (req, res) => {
    sendIndexHtml(req, res);
});

app.use((req, res, next) => {
    if (req.method !== "GET") {
        return next();
    }

    if (req.path.startsWith("/api/")) {
        return res.status(404).json({ error: "Route API introuvable." });
    }

    sendIndexHtml(req, res);
});

/* ============================================================
   GESTION CENTRALE DES ERREURS
============================================================ */

app.use((err, req, res, next) => {
    console.error("Erreur serveur non gérée :", err);

    if (res.headersSent) {
        return next(err);
    }

    return res.status(500).json({ error: "Erreur interne du serveur." });
});

/* ============================================================
   DÉMARRAGE DU SERVEUR
============================================================ */

if (require.main === module) {
    initSchema()
        .then(() => {
            app.listen(PORT, () => {
                console.log("");
                console.log("======================================");
                console.log("       VAULTBRIDGE SECURE SERVER      ");
                console.log("======================================");
                console.log(`Serveur   : http://localhost:${PORT}`);
                console.log(`API       : http://localhost:${PORT}/api`);
                console.log("Base SQL  : PostgreSQL (schéma initialisé)");
                console.log(`CAPTCHA   : ${TURNSTILE_SECRET_KEY ? "Activé" : "Désactivé (délai progressif seul)"}`);
                console.log("======================================");
                console.log("");
            });
        })
        .catch(error => {
            console.error("❌ Impossible d'initialiser la base de données :", error);
            process.exit(1);
        });
}

module.exports = { app, pool, initSchema };