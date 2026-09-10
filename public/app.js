/**
 * VaultBridge — app.js
 * ------------------------------------------------------------
 * Client application for VaultBridge:
 * - End-to-end client-side encryption (Web Crypto PBKDF2 + AES-256-GCM)
 * - In-memory key management (never written to disk, localStorage, or cookies)
 * - Clipboard auto-clearing after 30 seconds for credential protection
 * - Automatic inactivity lock after 15 minutes
 * - Complete zero-residue DOM sanitization upon logout or lock
 * - Real-time password health & reuse audit
 * - Interactive 3D Three.js digital vault visualization
 */

(function () {
    "use strict";

    /* =========================================================
       STATE MANAGEMENT (KEPT IN MEMORY ONLY)
    ========================================================= */
    const API_BASE = "";
    let authToken = null;
    let currentUser = null;
    let vaultSalt = null;
    let vaultKey = null;      // CryptoKey (extractable: false)
    let vaultData = [];       // Array of decrypted objects in memory
    let selectedVaultId = null;
    let activeFilter = "all"; // 'all' | 'strong' | 'weak' | 'reused'
    let editingEntryId = null;

    let captchaEnabledOnServer = false;
    let turnstileSiteKey = "0x4AAAAAAEvLrQJ9GrveT-pT";
    let loginCaptchaRequired = false;
    let loginWidgetId = null;
    let registerWidgetId = null;

    // Security auto-lock (15 minutes = 900 seconds)
    const INACTIVITY_TIMEOUT_SEC = 15 * 60;
    let secondsUntilLock = INACTIVITY_TIMEOUT_SEC;
    let inactivityInterval = null;
    let clipboardClearTimeout = null;

    /* =========================================================
       API CLIENT WITH ERROR HANDLING
    ========================================================= */
    async function apiFetch(path, options = {}) {
        const headers = {
            "Content-Type": "application/json",
            ...(options.headers || {})
        };

        if (authToken) {
            headers.Authorization = "Bearer " + authToken;
        }

        const response = await fetch(API_BASE + path, {
            ...options,
            headers
        });

        let body = null;
        try {
            body = await response.json();
        } catch {
            body = null;
        }

        if (!response.ok) {
            const err = new Error(
                (body && body.error) || "Une erreur est survenue lors de la communication avec le serveur."
            );
            err.status = response.status;
            err.data = body;
            throw err;
        }

        return body;
    }

    /* =========================================================
       SECURITY: INACTIVITY AUTO-LOCK SYSTEM
    ========================================================= */
    function resetInactivityTimer() {
        secondsUntilLock = INACTIVITY_TIMEOUT_SEC;
        updateInactivityDisplay();
    }

    function updateInactivityDisplay() {
        const el = document.getElementById("inactivity-timer");
        if (!el) return;
        const mins = Math.floor(secondsUntilLock / 60);
        const secs = secondsUntilLock % 60;
        el.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    }

    function startInactivityMonitor() {
        stopInactivityMonitor();
        resetInactivityTimer();
        inactivityInterval = setInterval(() => {
            if (!authToken) return;
            secondsUntilLock--;
            updateInactivityDisplay();

            if (secondsUntilLock <= 0) {
                lockVaultDueToInactivity();
            }
        }, 1000);

        // Activity listeners
        const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
        events.forEach(ev => window.addEventListener(ev, resetInactivityTimer, { passive: true }));
    }

    function stopInactivityMonitor() {
        if (inactivityInterval) {
            clearInterval(inactivityInterval);
            inactivityInterval = null;
        }
    }

    function lockVaultDueToInactivity() {
        if (!authToken) return;
        // Purge decrypted keys from memory
        vaultKey = null;
        vaultData = [];
        selectedVaultId = null;

        // Wipe sensitive DOM nodes
        wipeSensitiveDOM();

        // Show lock screen modal
        const lockModal = document.getElementById("lock-modal");
        if (lockModal) {
            document.getElementById("lock-password").value = "";
            lockModal.classList.add("active");
            document.getElementById("lock-password").focus();
        }
        showToast("🔒 Coffre verrouillé par mesure d'inactivité", "warning");
    }

    /* =========================================================
       SECURITY: CLIPBOARD AUTO-CLEAR (30 SECONDS)
    ========================================================= */
    function copyToClipboardSecure(text, successMsg = "✓ Copié dans le presse-papier") {
        if (!text) return;

        const performCopy = (val) => {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                return navigator.clipboard.writeText(val);
            } else {
                const ta = document.createElement("textarea");
                ta.value = val;
                ta.style.position = "fixed";
                ta.style.opacity = "0";
                document.body.appendChild(ta);
                ta.select();
                const ok = document.execCommand("copy");
                document.body.removeChild(ta);
                return ok ? Promise.resolve() : Promise.reject(new Error("execCommand failed"));
            }
        };

        performCopy(text)
            .then(() => {
                showToast(successMsg);

                // Schedule auto-clear in 30 seconds
                if (clipboardClearTimeout) clearTimeout(clipboardClearTimeout);
                clipboardClearTimeout = setTimeout(() => {
                    performCopy("").then(() => {
                        showToast("🛡️ Presse-papier nettoyé automatiquement", "warning");
                    }).catch(() => {});
                }, 30000);
            })
            .catch(() => {
                showToast("Échec de la copie", "error");
            });
    }

    /* =========================================================
       SECURITY: ZERO-RESIDUE DOM & MEMORY WIPING
    ========================================================= */
    function wipeSensitiveDOM() {
        const vaultItems = document.getElementById("vault-items");
        if (vaultItems) vaultItems.innerHTML = "";

        const vaultDetail = document.getElementById("vault-detail");
        if (vaultDetail) {
            vaultDetail.innerHTML = `
                <div class="empty-state-view">
                    <div class="empty-state-icon">◈</div>
                    <h3>Coffre verrouillé ou vide</h3>
                    <p>Déverrouillez votre coffre pour consulter vos accès.</p>
                </div>
            `;
        }

        const searchInput = document.getElementById("search");
        if (searchInput) searchInput.value = "";

        // Clear all form password fields
        document.querySelectorAll('input[type="password"]').forEach(input => {
            input.value = "";
        });
    }

    /* =========================================================
       CLIENT-SIDE ENCRYPTION (Web Crypto API)
       PBKDF2 (150,000 iter, SHA-256) -> AES-256-GCM
    ========================================================= */
    function bufToB64(buf) {
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function b64ToBuf(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    async function deriveVaultKey(password, saltB64) {
        const baseKey = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: b64ToBuf(saltB64),
                iterations: 150000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false, // Key is non-extractable from JS memory
            ["encrypt", "decrypt"]
        );
    }

    async function encryptForVault(plaintext) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            vaultKey,
            new TextEncoder().encode(plaintext)
        );

        return {
            passwordCipher: bufToB64(cipherBuf),
            iv: bufToB64(iv.buffer)
        };
    }

    async function decryptFromVault(cipherB64, ivB64) {
        const plainBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64ToBuf(ivB64) },
            vaultKey,
            b64ToBuf(cipherB64)
        );

        return new TextDecoder().decode(plainBuf);
    }

    /* =========================================================
       PASSWORD ENTROPY & STRENGTH ANALYZER
    ========================================================= */
    function calculateEntropyAndStrength(password) {
        if (!password || typeof password !== "string") {
            return { score: 0, label: "faible", bits: 0 };
        }

        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

        const bits = Math.round(password.length * Math.log2(Math.max(2, pool)));

        let score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;
        if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;

        let label = "faible";
        if (score >= 5 || bits >= 75) {
            label = "fort";
        } else if (score >= 3 || bits >= 45) {
            label = "moyen";
        }

        return { score, label, bits };
    }

    /* =========================================================
       XSS PROTECTION / SANITIZATION
    ========================================================= */
    function escapeHtml(value) {
        if (value === null || value === undefined) return "";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    /* =========================================================
       TURNSTILE HELPERS
    ========================================================= */
    function renderTurnstileWidget(selector) {
        if (typeof turnstile === "undefined") return null;
        const container = document.querySelector(selector);
        if (!container) return null;
        try {
            return turnstile.render(selector, {
                sitekey: turnstileSiteKey,
                theme: "dark"
            });
        } catch (e) {
            console.warn("Turnstile render error on " + selector, e);
            return null;
        }
    }

    function ensureRegisterTurnstile() {
        if (!captchaEnabledOnServer) return;
        const wrapper = document.getElementById("register-turnstile-wrapper");
        if (wrapper) wrapper.style.display = "flex";
        if (typeof turnstile !== "undefined" && registerWidgetId === null) {
            registerWidgetId = renderTurnstileWidget("#register-turnstile");
        }
    }

    function ensureLoginTurnstile() {
        const wrapper = document.getElementById("login-turnstile-wrapper");
        if (wrapper) wrapper.style.display = "flex";
        if (typeof turnstile !== "undefined") {
            if (loginWidgetId === null) {
                loginWidgetId = renderTurnstileWidget("#login-turnstile");
            } else {
                resetTurnstile("#login-turnstile", loginWidgetId);
            }
        }
    }

    function getTurnstileToken(selector, widgetId) {
        const el = document.querySelector(selector);
        if (el) {
            const input = el.querySelector('input[name="cf-turnstile-response"]') ||
                          el.closest("form")?.querySelector('input[name="cf-turnstile-response"]');
            if (input && input.value) return input.value;
        }
        if (typeof turnstile !== "undefined") {
            try {
                if (widgetId !== null && widgetId !== undefined) {
                    const res = turnstile.getResponse(widgetId);
                    if (res) return res;
                }
                return turnstile.getResponse(selector) || "";
            } catch {
                return "";
            }
        }
        return "";
    }

    function resetTurnstile(selector, widgetId) {
        const el = document.querySelector(selector);
        if (el) {
            const input = el.querySelector('input[name="cf-turnstile-response"]') ||
                          el.closest("form")?.querySelector('input[name="cf-turnstile-response"]');
            if (input) input.value = "";
        }
        if (typeof turnstile !== "undefined") {
            try {
                if (widgetId !== null && widgetId !== undefined) {
                    turnstile.reset(widgetId);
                } else {
                    turnstile.reset(selector);
                }
            } catch {}
        }
    }

    window.onloadTurnstileCallback = function () {
        if (captchaEnabledOnServer) {
            const regForm = document.getElementById("register-form");
            if (regForm && regForm.style.display !== "none") {
                ensureRegisterTurnstile();
            }
        }
    };

    async function checkServerStatus() {
        try {
            const info = await apiFetch("/api");
            captchaEnabledOnServer = Boolean(info && info.captchaEnabled);
            if (info && info.turnstileSiteKey) {
                turnstileSiteKey = info.turnstileSiteKey;
            }
            const regForm = document.getElementById("register-form");
            if (captchaEnabledOnServer && regForm && regForm.style.display !== "none") {
                ensureRegisterTurnstile();
            }
        } catch {
            captchaEnabledOnServer = false;
        }
    }

    /* =========================================================
       AUTHENTICATION UI & MODE SWITCHING
    ========================================================= */
    const authScreen = document.getElementById("auth-screen");
    const appContainer = document.getElementById("app");
    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");
    const loginTab = document.getElementById("login-tab");
    const registerTab = document.getElementById("register-tab");
    const authTitle = document.getElementById("auth-title");
    const authMessage = document.getElementById("auth-message");

    function setAuthMode(mode) {
        authMessage.textContent = "";
        if (mode === "login") {
            loginForm.style.display = "block";
            registerForm.style.display = "none";
            loginTab.classList.add("active");
            registerTab.classList.remove("active");
            authTitle.textContent = "Connexion";
        } else {
            loginForm.style.display = "none";
            registerForm.style.display = "block";
            loginTab.classList.remove("active");
            registerTab.classList.add("active");
            authTitle.textContent = "Créer un compte";
            ensureRegisterTurnstile();
        }
    }

    if (loginTab) loginTab.onclick = () => setAuthMode("login");
    if (registerTab) registerTab.onclick = () => setAuthMode("register");

    // Password visibility toggle
    document.querySelectorAll(".toggle-password-btn").forEach(button => {
        button.addEventListener("click", () => {
            const targetId = button.dataset.target;
            const input = document.getElementById(targetId);
            if (!input) return;
            const isPassword = input.type === "password";
            input.type = isPassword ? "text" : "password";
            button.textContent = isPassword ? "🙈" : "👁";
        });
    });

    // Registration password strength indicator
    const regPasswordInput = document.getElementById("register-password");
    if (regPasswordInput) {
        regPasswordInput.addEventListener("input", (e) => {
            const val = e.target.value;
            const { score, label } = calculateEntropyAndStrength(val);
            const seg1 = document.getElementById("reg-seg-1");
            const seg2 = document.getElementById("reg-seg-2");
            const seg3 = document.getElementById("reg-seg-3");
            const seg4 = document.getElementById("reg-seg-4");
            const labelEl = document.getElementById("reg-strength-label");

            [seg1, seg2, seg3, seg4].forEach(s => {
                if (s) s.className = "strength-segment";
            });

            if (!val) {
                if (labelEl) labelEl.textContent = "Entrez un mot de passe";
                return;
            }

            if (score <= 2) {
                if (seg1) seg1.classList.add("active-weak");
                if (labelEl) labelEl.textContent = "Faible";
            } else if (score <= 3) {
                if (seg1) seg1.classList.add("active-fair");
                if (seg2) seg2.classList.add("active-fair");
                if (labelEl) labelEl.textContent = "Moyen";
            } else if (score <= 4) {
                if (seg1) seg1.classList.add("active-good");
                if (seg2) seg2.classList.add("active-good");
                if (seg3) seg3.classList.add("active-good");
                if (labelEl) labelEl.textContent = "Bon";
            } else {
                if (seg1) seg1.classList.add("active-strong");
                if (seg2) seg2.classList.add("active-strong");
                if (seg3) seg3.classList.add("active-strong");
                if (seg4) seg4.classList.add("active-strong");
                if (labelEl) labelEl.textContent = "Excellent";
            }
        });
    }

    /* =========================================================
       REGISTRATION HANDLER
    ========================================================= */
    if (registerForm) {
        registerForm.addEventListener("submit", async event => {
            event.preventDefault();
            const name = document.getElementById("register-name").value.trim();
            const email = document.getElementById("register-email").value.trim().toLowerCase();
            const password = document.getElementById("register-password").value;
            const confirm = document.getElementById("register-confirm").value;
            authMessage.textContent = "";

            if (password.length < 8) {
                authMessage.textContent = "Le mot de passe maître doit contenir au moins 8 caractères.";
                return;
            }

            if (password !== confirm) {
                authMessage.textContent = "Les mots de passe ne correspondent pas.";
                return;
            }

            let captchaToken = "";
            if (captchaEnabledOnServer && registerWidgetId !== null) {
                captchaToken = getTurnstileToken("#register-turnstile", registerWidgetId);
                if (!captchaToken) {
                    authMessage.textContent = "Veuillez compléter la vérification anti-robot.";
                    return;
                }
            }

            const submitBtn = document.getElementById("register-submit");
            submitBtn.disabled = true;

            try {
                const result = await apiFetch("/api/register", {
                    method: "POST",
                    body: JSON.stringify({ name, email, password, captchaToken })
                });

                authToken = result.token;
                currentUser = result.user;
                vaultSalt = result.vaultSalt;
                vaultKey = await deriveVaultKey(password, vaultSalt);
                vaultData = [];

                showApp(currentUser);
                showToast("✓ Compte créé avec succès ! Bienvenue.");
            } catch (error) {
                authMessage.textContent = error.message;
                resetTurnstile("#register-turnstile", registerWidgetId);
            } finally {
                submitBtn.disabled = false;
            }
        });
    }

    /* =========================================================
       LOGIN HANDLER
    ========================================================= */
    if (loginForm) {
        loginForm.addEventListener("submit", async event => {
            event.preventDefault();
            const email = document.getElementById("login-email").value.trim().toLowerCase();
            const password = document.getElementById("login-password").value;
            authMessage.textContent = "";

            let captchaToken = "";
            if (loginCaptchaRequired) {
                captchaToken = getTurnstileToken("#login-turnstile", loginWidgetId);
                if (!captchaToken) {
                    authMessage.textContent = "Veuillez compléter la vérification anti-robot.";
                    return;
                }
            }

            const submitBtn = document.getElementById("login-submit");
            submitBtn.disabled = true;

            try {
                const result = await apiFetch("/api/login", {
                    method: "POST",
                    body: JSON.stringify({ email, password, captchaToken })
                });

                authToken = result.token;
                currentUser = result.user;
                vaultSalt = result.vaultSalt;
                vaultKey = await deriveVaultKey(password, vaultSalt);

                await loadVaultFromServer();

                loginCaptchaRequired = false;
                const loginWrapper = document.getElementById("login-turnstile-wrapper");
                if (loginWrapper) loginWrapper.style.display = "none";

                showApp(currentUser);
                showToast("✓ Connexion réussie au coffre");
            } catch (error) {
                authMessage.textContent = error.message;
                if (error.data && error.data.captchaRequired) {
                    loginCaptchaRequired = true;
                    ensureLoginTurnstile();
                } else if (loginWidgetId !== null) {
                    resetTurnstile("#login-turnstile", loginWidgetId);
                }
            } finally {
                submitBtn.disabled = false;
            }
        });
    }

    /* =========================================================
       VAULT LOADING & CLIENT DECRYPTION
    ========================================================= */
    async function loadVaultFromServer() {
        const entries = await apiFetch("/api/vault");
        vaultData = [];

        for (const entry of entries) {
            let password = "";
            try {
                password = await decryptFromVault(entry.passwordCipher, entry.iv);
            } catch (err) {
                console.warn("Échec du déchiffrement pour l'accès :", entry.id);
                password = "[Erreur de déchiffrement]";
            }

            const { label: strength, bits: entropy } = calculateEntropyAndStrength(password);

            vaultData.push({
                id: entry.id,
                icon: entry.icon || "🔐",
                name: entry.name,
                user: entry.user,
                password,
                strength,
                entropy,
                createdAt: entry.createdAt
            });
        }
    }

    /* =========================================================
       APP DISPLAY, NAVIGATION & LOGOUT
    ========================================================= */
    function showApp(account) {
        authScreen.style.display = "none";
        appContainer.classList.add("visible");

        const sidebarUserEl = document.getElementById("sidebar-user");
        if (sidebarUserEl) sidebarUserEl.textContent = account.email;

        const avatarEl = document.getElementById("user-avatar-initials");
        if (avatarEl) {
            const initial = (account.name || account.email || "U").charAt(0).toUpperCase();
            avatarEl.textContent = initial;
        }

        goToPage("home");
        renderVault();
        updateDashboardMetrics();
        startInactivityMonitor();
    }

    function logout() {
        stopInactivityMonitor();

        authToken = null;
        currentUser = null;
        vaultSalt = null;
        vaultKey = null;
        vaultData = [];
        selectedVaultId = null;
        editingEntryId = null;
        loginCaptchaRequired = false;

        const loginWrapper = document.getElementById("login-turnstile-wrapper");
        if (loginWrapper) loginWrapper.style.display = "none";

        wipeSensitiveDOM();

        appContainer.classList.remove("visible");
        authScreen.style.display = "grid";

        if (loginForm) loginForm.reset();
        if (registerForm) registerForm.reset();

        resetTurnstile("#login-turnstile", loginWidgetId);
        resetTurnstile("#register-turnstile", registerWidgetId);

        setAuthMode("login");
        showToast("✓ Déconnexion effectuée. Le coffre est sécurisé.");
    }

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) logoutBtn.addEventListener("click", logout);

    const quickLockBtn = document.getElementById("quick-lock-btn");
    if (quickLockBtn) quickLockBtn.addEventListener("click", lockVaultDueToInactivity);

    /* Unlock Modal Handler */
    const unlockForm = document.getElementById("unlock-form");
    if (unlockForm) {
        unlockForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const password = document.getElementById("lock-password").value;
            const unlockBtn = document.getElementById("unlock-submit");
            unlockBtn.disabled = true;

            try {
                if (!vaultSalt) {
                    logout();
                    return;
                }

                const derivedKey = await deriveVaultKey(password, vaultSalt);
                // Verify key by testing with the server
                vaultKey = derivedKey;
                await loadVaultFromServer();

                document.getElementById("lock-modal").classList.remove("active");
                document.getElementById("lock-password").value = "";
                startInactivityMonitor();
                renderVault();
                updateDashboardMetrics();
                showToast("✓ Coffre déverrouillé");
            } catch {
                showToast("Mot de passe incorrect", "error");
            } finally {
                unlockBtn.disabled = false;
            }
        });
    }

    /* =========================================================
       NAVIGATION BETWEEN PAGES
    ========================================================= */
    const navButtons = document.querySelectorAll(".nav-item-btn");
    const pages = document.querySelectorAll(".page");
    const pageTitle = document.getElementById("page-title");
    const titles = {
        home: "Accueil",
        vault: "Mon coffre",
        dashboard: "Centre de sécurité"
    };

    function goToPage(pageName) {
        pages.forEach(sec => sec.classList.remove("active"));
        const targetPage = document.getElementById(pageName);
        if (targetPage) targetPage.classList.add("active");

        navButtons.forEach(btn => {
            btn.classList.toggle("active", btn.dataset.page === pageName);
        });

        if (pageTitle) pageTitle.textContent = titles[pageName] || "VaultBridge";

        if (pageName === "vault") {
            renderVault();
        } else if (pageName === "dashboard") {
            updateDashboardMetrics();
        }
    }

    document.querySelectorAll("[data-page]").forEach(button => {
        button.addEventListener("click", () => goToPage(button.dataset.page));
    });

    /* =========================================================
       PASSWORD HEALTH & REUSE DETECTION
    ========================================================= */
    function getPasswordReuseCounts() {
        const counts = {};
        vaultData.forEach(entry => {
            if (entry.password && entry.password !== "[Erreur de déchiffrement]") {
                counts[entry.password] = (counts[entry.password] || 0) + 1;
            }
        });
        return counts;
    }

    /* =========================================================
       VAULT RENDERING & FILTERING
    ========================================================= */
    const vaultItemsContainer = document.getElementById("vault-items");
    const vaultDetailContainer = document.getElementById("vault-detail");

    function getFilteredVaultData() {
        const reuseCounts = getPasswordReuseCounts();
        let list = [...vaultData];

        if (activeFilter === "strong") {
            list = list.filter(e => e.strength === "fort");
        } else if (activeFilter === "weak") {
            list = list.filter(e => e.strength === "faible");
        } else if (activeFilter === "reused") {
            list = list.filter(e => (reuseCounts[e.password] || 0) > 1);
        }

        const query = (document.getElementById("search")?.value || "").toLowerCase().trim();
        if (query) {
            list = list.filter(e =>
                (e.name || "").toLowerCase().includes(query) ||
                (e.user || "").toLowerCase().includes(query)
            );
        }

        return list;
    }

    function renderVault() {
        if (!vaultItemsContainer) return;
        const filtered = getFilteredVaultData();
        vaultItemsContainer.innerHTML = "";

        // Update badge count
        const badgeCount = document.getElementById("vault-badge-count");
        if (badgeCount) badgeCount.textContent = vaultData.length;

        if (filtered.length === 0) {
            vaultItemsContainer.innerHTML = `
                <div style="padding: 30px; text-align: center; color: var(--text-dim); font-size: 0.85rem;">
                    Aucun accès trouvé.
                </div>
            `;
            return;
        }

        const reuseCounts = getPasswordReuseCounts();

        filtered.forEach(entry => {
            const isReused = (reuseCounts[entry.password] || 0) > 1;
            const isSelected = selectedVaultId === entry.id;

            const card = document.createElement("button");
            card.className = `vault-item-card ${isSelected ? "selected" : ""}`;
            card.innerHTML = `
                <span class="vault-item-icon">${escapeHtml(entry.icon)}</span>
                <div class="vault-item-meta">
                    <strong>${escapeHtml(entry.name)}</strong>
                    <small>${escapeHtml(entry.user)}</small>
                </div>
                ${isReused ? '<span class="strength-tag faible" title="Mot de passe réutilisé">🔁 Réutilisé</span>' : ''}
                <span class="strength-tag ${entry.strength}">${entry.strength}</span>
            `;

            card.onclick = () => {
                selectedVaultId = entry.id;
                renderVault();
                renderVaultDetail(entry);
            };

            vaultItemsContainer.appendChild(card);
        });

        // If something was already selected, update detail
        if (selectedVaultId) {
            const currentSelected = vaultData.find(e => e.id === selectedVaultId);
            if (currentSelected) renderVaultDetail(currentSelected);
        }
    }

    function renderVaultDetail(entry) {
        if (!vaultDetailContainer) return;
        let passwordVisible = false;
        const reuseCounts = getPasswordReuseCounts();
        const isReused = (reuseCounts[entry.password] || 0) > 1;

        function render() {
            vaultDetailContainer.innerHTML = `
                <div class="detail-header-card">
                    <div class="detail-brand-info">
                        <div class="detail-hero-icon">${escapeHtml(entry.icon)}</div>
                        <div class="detail-title-block">
                            <h3>${escapeHtml(entry.name)}</h3>
                            <small>Identifiant : ${escapeHtml(entry.user)}</small>
                        </div>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center;">
                        ${isReused ? '<span class="strength-tag faible">⚠️ Mot de passe réutilisé</span>' : ''}
                        <span class="strength-tag ${entry.strength}">${entry.strength}</span>
                    </div>
                </div>

                <div class="detail-fields-group">
                    <div class="detail-field-box">
                        <div class="detail-field-label">SERVICE / APPLICATION</div>
                        <div class="detail-field-content">
                            <span class="detail-field-value">${escapeHtml(entry.name)}</span>
                            <div class="detail-field-actions">
                                <button class="icon-btn" id="copy-service-btn">⧉ Copier</button>
                            </div>
                        </div>
                    </div>

                    <div class="detail-field-box">
                        <div class="detail-field-label">IDENTIFIANT / EMAIL</div>
                        <div class="detail-field-content">
                            <span class="detail-field-value">${escapeHtml(entry.user)}</span>
                            <div class="detail-field-actions">
                                <button class="icon-btn" id="copy-user-btn">⧉ Copier</button>
                            </div>
                        </div>
                    </div>

                    <div class="detail-field-box">
                        <div class="detail-field-label">MOT DE PASSE CHIFFRÉ (AES-GCM)</div>
                        <div class="detail-field-content">
                            <span class="detail-field-value" style="font-family: var(--font-mono)">
                                ${passwordVisible ? escapeHtml(entry.password) : "••••••••••••••••"}
                            </span>
                            <div class="detail-field-actions">
                                <button class="icon-btn" id="toggle-pwd-btn">
                                    ${passwordVisible ? "🙈 Masquer" : "👁 Afficher"}
                                </button>
                                <button class="icon-btn" id="copy-pwd-btn">⧉ Copier</button>
                            </div>
                        </div>
                    </div>

                    <div class="detail-security-audit-box">
                        <div class="audit-meta-row">
                            <span>Robustesse cryptographique</span>
                            <strong>${entry.entropy || 0} bits d'entropie (${entry.strength})</strong>
                        </div>
                        <div class="strength-bar-track">
                            <div class="strength-segment active-${entry.strength === 'fort' ? 'strong' : entry.strength === 'moyen' ? 'fair' : 'weak'}"></div>
                            <div class="strength-segment ${entry.strength !== 'faible' ? 'active-' + (entry.strength === 'fort' ? 'strong' : 'fair') : ''}"></div>
                            <div class="strength-segment ${entry.strength === 'fort' ? 'active-strong' : ''}"></div>
                        </div>
                    </div>
                </div>

                <div class="detail-footer-actions">
                    <div class="left-actions">
                        <button class="primary-btn" id="main-copy-btn">
                            ⚡ Copier le mot de passe
                        </button>
                        <button class="secondary-btn" id="edit-entry-btn">
                            ✏️ Modifier
                        </button>
                    </div>
                    <div class="right-actions">
                        <button class="danger-btn" id="delete-entry-btn">
                            🗑️ Supprimer
                        </button>
                    </div>
                </div>
            `;

            // Event bindings
            document.getElementById("toggle-pwd-btn").onclick = () => {
                passwordVisible = !passwordVisible;
                render();
            };

            document.getElementById("copy-service-btn").onclick = () => {
                copyToClipboardSecure(entry.name, "✓ Nom du service copié");
            };

            document.getElementById("copy-user-btn").onclick = () => {
                copyToClipboardSecure(entry.user, "✓ Identifiant copié");
            };

            document.getElementById("copy-pwd-btn").onclick = () => {
                copyToClipboardSecure(entry.password, "✓ Mot de passe copié (nettoyage auto dans 30s)");
            };

            document.getElementById("main-copy-btn").onclick = () => {
                copyToClipboardSecure(entry.password, "✓ Mot de passe copié (nettoyage auto dans 30s)");
            };

            document.getElementById("edit-entry-btn").onclick = () => {
                openEditModal(entry);
            };

            document.getElementById("delete-entry-btn").onclick = async () => {
                if (!confirm(`Supprimer définitivement l'accès "${entry.name}" ?`)) return;
                try {
                    await apiFetch(`/api/vault/${entry.id}`, { method: "DELETE" });
                    vaultData = vaultData.filter(item => item.id !== entry.id);
                    selectedVaultId = null;
                    renderVault();
                    updateDashboardMetrics();

                    vaultDetailContainer.innerHTML = `
                        <div class="empty-state-view">
                            <div class="empty-state-icon" style="color:var(--state-success);border-color:var(--state-success-border)">✓</div>
                            <h3>Accès supprimé avec succès</h3>
                            <p>Les données ont été effacées de votre coffre chiffré.</p>
                        </div>
                    `;
                    showToast("✓ Accès supprimé du coffre");
                } catch (error) {
                    showToast(error.message, "error");
                }
            };
        }

        render();
    }

    /* Filter pills listener */
    document.querySelectorAll(".filter-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            activeFilter = pill.dataset.filter || "all";
            renderVault();
        });
    });

    /* Search input listener */
    const searchInput = document.getElementById("search");
    const searchClearBtn = document.getElementById("search-clear");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            if (searchClearBtn) {
                searchClearBtn.classList.toggle("visible", Boolean(e.target.value));
            }
            renderVault();
        });
    }

    if (searchClearBtn) {
        searchClearBtn.addEventListener("click", () => {
            if (searchInput) searchInput.value = "";
            searchClearBtn.classList.remove("visible");
            renderVault();
            if (searchInput) searchInput.focus();
        });
    }

    /* Keyboard shortcuts */
    window.addEventListener("keydown", (e) => {
        // Press '/' or Ctrl+K to search
        if ((e.key === "/" && document.activeElement.tagName !== "INPUT") || (e.ctrlKey && e.key === "k")) {
            e.preventDefault();
            goToPage("vault");
            if (searchInput) searchInput.focus();
        }
        // Esc closes active modals
        if (e.key === "Escape") {
            document.querySelectorAll(".modal-overlay.active").forEach(m => m.classList.remove("active"));
        }
    });

    /* =========================================================
       CRYPTOGRAPHICALLY SECURE PASSWORD GENERATOR
    ========================================================= */
    function generateAdvancedPassword(options = {}) {
        const length = options.length || 20;
        const useUpper = options.uppercase !== false;
        const useLower = options.lowercase !== false;
        const useDigits = options.digits !== false;
        const useSymbols = options.symbols !== false;
        const avoidAmbiguous = options.avoidAmbiguous === true;

        let upperChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        let lowerChars = "abcdefghijkmnopqrstuvwxyz";
        let digitChars = "23456789";
        let symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        if (!avoidAmbiguous) {
            upperChars += "IO";
            lowerChars += "l";
            digitChars += "01";
        }

        let charPool = "";
        const guaranteed = [];

        if (useUpper) {
            charPool += upperChars;
            guaranteed.push(upperChars[getRandomInt(upperChars.length)]);
        }
        if (useLower) {
            charPool += lowerChars;
            guaranteed.push(lowerChars[getRandomInt(lowerChars.length)]);
        }
        if (useDigits) {
            charPool += digitChars;
            guaranteed.push(digitChars[getRandomInt(digitChars.length)]);
        }
        if (useSymbols) {
            charPool += symbolChars;
            guaranteed.push(symbolChars[getRandomInt(symbolChars.length)]);
        }

        if (charPool.length === 0) {
            charPool = lowerChars + digitChars;
        }

        const remainingLength = Math.max(0, length - guaranteed.length);
        const randomValues = new Uint32Array(remainingLength);
        crypto.getRandomValues(randomValues);

        const passwordArray = [...guaranteed];
        for (let i = 0; i < remainingLength; i++) {
            passwordArray.push(charPool[randomValues[i] % charPool.length]);
        }

        // Fisher-Yates shuffle
        for (let i = passwordArray.length - 1; i > 0; i--) {
            const j = getRandomInt(i + 1);
            const temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }

        return passwordArray.join("");
    }

    function getRandomInt(max) {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0] % max;
    }

    /* Generator Modal & Interactive Controls */
    const generatorModal = document.getElementById("generator-modal");
    const genLengthSlider = document.getElementById("gen-length-slider");
    const genLengthVal = document.getElementById("gen-length-val");
    const genOutputEl = document.getElementById("gen-output-text");
    const genEntropyBadge = document.getElementById("gen-entropy-badge");

    function updateGeneratorUI() {
        if (!genLengthSlider) return;
        const length = parseInt(genLengthSlider.value, 10);
        if (genLengthVal) genLengthVal.textContent = length;

        const options = {
            length,
            uppercase: document.getElementById("gen-opt-upper")?.checked ?? true,
            lowercase: document.getElementById("gen-opt-lower")?.checked ?? true,
            digits: document.getElementById("gen-opt-digits")?.checked ?? true,
            symbols: document.getElementById("gen-opt-symbols")?.checked ?? true,
            avoidAmbiguous: document.getElementById("gen-opt-ambiguous")?.checked ?? false
        };

        const pwd = generateAdvancedPassword(options);
        if (genOutputEl) genOutputEl.textContent = pwd;

        const { label, bits } = calculateEntropyAndStrength(pwd);
        if (genEntropyBadge) {
            genEntropyBadge.textContent = `${bits} bits • ${label}`;
            genEntropyBadge.className = `strength-tag ${label}`;
        }
    }

    if (genLengthSlider) {
        genLengthSlider.addEventListener("input", updateGeneratorUI);
    }
    document.querySelectorAll(".generator-checkbox").forEach(cb => {
        cb.addEventListener("change", updateGeneratorUI);
    });

    const regenBtn = document.getElementById("gen-regenerate-btn");
    if (regenBtn) regenBtn.addEventListener("click", updateGeneratorUI);

    const genCopyBtn = document.getElementById("gen-copy-btn");
    if (genCopyBtn) {
        genCopyBtn.addEventListener("click", () => {
            const pwd = genOutputEl?.textContent;
            if (pwd) copyToClipboardSecure(pwd, "✓ Mot de passe généré copié");
        });
    }

    const openGenModalBtn = document.getElementById("generate-password");
    if (openGenModalBtn) {
        openGenModalBtn.addEventListener("click", () => {
            updateGeneratorUI();
            if (generatorModal) generatorModal.classList.add("active");
        });
    }

    const quickGenBtn = document.getElementById("quick-generate");
    if (quickGenBtn) {
        quickGenBtn.addEventListener("click", () => {
            const pwd = generateAdvancedPassword({ length: 22 });
            copyToClipboardSecure(pwd, "✓ Mot de passe fort (22 car.) copié");
        });
    }

    const closeGenModalBtn = document.getElementById("close-generator-modal");
    if (closeGenModalBtn && generatorModal) {
        closeGenModalBtn.addEventListener("click", () => {
            generatorModal.classList.remove("active");
        });
    }

    /* =========================================================
       ADD / EDIT ENTRY MODAL
    ========================================================= */
    const entryModal = document.getElementById("add-modal");
    const entryForm = document.getElementById("add-form");
    const entryModalTitle = document.getElementById("entry-modal-title");
    const openAddModalBtn = document.getElementById("open-add-modal");
    const closeAddModalBtn = document.getElementById("close-add-modal");

    function openAddModal() {
        editingEntryId = null;
        if (entryModalTitle) entryModalTitle.textContent = "Ajouter un accès au coffre";
        if (entryForm) entryForm.reset();
        const iconInput = document.getElementById("add-icon");
        if (iconInput) iconInput.value = "🔐";
        updateIconPickerSelected("🔐");
        if (entryModal) entryModal.classList.add("active");
    }

    function openEditModal(entry) {
        editingEntryId = entry.id;
        if (entryModalTitle) entryModalTitle.textContent = "Modifier l'accès";
        document.getElementById("add-name").value = entry.name;
        document.getElementById("add-user").value = entry.user;
        document.getElementById("add-password").value = entry.password;
        document.getElementById("add-icon").value = entry.icon || "🔐";
        updateIconPickerSelected(entry.icon || "🔐");
        if (entryModal) entryModal.classList.add("active");
    }

    function updateIconPickerSelected(icon) {
        document.querySelectorAll(".icon-preset-btn").forEach(btn => {
            btn.classList.toggle("selected", btn.dataset.icon === icon);
        });
    }

    document.querySelectorAll(".icon-preset-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const icon = btn.dataset.icon || "🔐";
            const iconInput = document.getElementById("add-icon");
            if (iconInput) iconInput.value = icon;
            updateIconPickerSelected(icon);
        });
    });

    if (openAddModalBtn) openAddModalBtn.onclick = openAddModal;
    if (closeAddModalBtn && entryModal) {
        closeAddModalBtn.onclick = () => entryModal.classList.remove("active");
    }

    // Inline generator in entry modal
    const inlineGenBtn = document.getElementById("modal-inline-gen-btn");
    if (inlineGenBtn) {
        inlineGenBtn.addEventListener("click", () => {
            const pwd = generateAdvancedPassword({ length: 20 });
            const pwdInput = document.getElementById("add-password");
            if (pwdInput) {
                pwdInput.value = pwd;
                pwdInput.type = "text";
                showToast("✓ Mot de passe fort généré pour ce compte");
            }
        });
    }

    if (entryForm) {
        entryForm.addEventListener("submit", async event => {
            event.preventDefault();
            const name = document.getElementById("add-name").value.trim();
            const user = document.getElementById("add-user").value.trim();
            const password = document.getElementById("add-password").value;
            const icon = document.getElementById("add-icon").value.trim() || "🔐";
            const submitBtn = entryForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;

            try {
                const { passwordCipher, iv } = await encryptForVault(password);

                if (editingEntryId) {
                    // PUT /api/vault/:id
                    const updated = await apiFetch(`/api/vault/${editingEntryId}`, {
                        method: "PUT",
                        body: JSON.stringify({ icon, name, user, passwordCipher, iv })
                    });

                    const index = vaultData.findIndex(item => item.id === editingEntryId);
                    const { label: strength, bits: entropy } = calculateEntropyAndStrength(password);
                    if (index !== -1) {
                        vaultData[index] = {
                            id: updated.id,
                            icon: updated.icon,
                            name: updated.name,
                            user: updated.user,
                            password,
                            strength,
                            entropy,
                            createdAt: updated.createdAt
                        };
                    }
                    showToast("✓ Accès mis à jour avec succès");
                } else {
                    // POST /api/vault
                    const entry = await apiFetch("/api/vault", {
                        method: "POST",
                        body: JSON.stringify({ icon, name, user, passwordCipher, iv })
                    });

                    const { label: strength, bits: entropy } = calculateEntropyAndStrength(password);
                    vaultData.push({
                        id: entry.id,
                        icon: entry.icon,
                        name: entry.name,
                        user: entry.user,
                        password,
                        strength,
                        entropy,
                        createdAt: entry.createdAt
                    });
                    selectedVaultId = entry.id;
                    showToast("✓ Nouvel accès ajouté au coffre chiffré");
                }

                renderVault();
                updateDashboardMetrics();
                entryModal.classList.remove("active");
                entryForm.reset();
            } catch (error) {
                showToast(error.message, "error");
            } finally {
                submitBtn.disabled = false;
            }
        });
    }

    /* =========================================================
       SECURITY DASHBOARD & METRICS
    ========================================================= */
    function updateDashboardMetrics() {
        const total = vaultData.length;
        const reuseCounts = getPasswordReuseCounts();

        const strongCount = vaultData.filter(i => i.strength === "fort").length;
        const weakCount = vaultData.filter(i => i.strength === "faible").length;
        const reusedCount = vaultData.filter(i => (reuseCounts[i.password] || 0) > 1).length;

        // Metric cards
        const elTotal = document.getElementById("stat-total");
        const elStrong = document.getElementById("stat-strong");
        const elAlert = document.getElementById("stat-alert");
        const elReused = document.getElementById("stat-reused");

        if (elTotal) elTotal.textContent = total;
        if (elStrong) elStrong.textContent = strongCount;
        if (elAlert) elAlert.textContent = weakCount;
        if (elReused) elReused.textContent = reusedCount;

        // Security score calculation
        let score = 100;
        if (total === 0) {
            score = 0;
        } else {
            const weakPenalty = (weakCount / total) * 45;
            const reusePenalty = (reusedCount / total) * 35;
            score = Math.max(0, Math.min(100, Math.round(100 - weakPenalty - reusePenalty)));
        }

        const scoreTextEl = document.getElementById("security-score-val");
        if (scoreTextEl) scoreTextEl.textContent = `${score}%`;

        // SVG Radial arc
        const circle = document.getElementById("score-progress-circle");
        if (circle) {
            const radius = circle.r.baseVal.value;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference - (score / 100) * circumference;
            circle.style.strokeDasharray = `${circumference} ${circumference}`;
            circle.style.strokeDashoffset = offset;

            if (score >= 80) {
                circle.style.stroke = "var(--state-success)";
            } else if (score >= 50) {
                circle.style.stroke = "var(--state-warning)";
            } else {
                circle.style.stroke = "var(--state-danger)";
            }
        }

        // Weak passwords list in dashboard
        const weakListEl = document.getElementById("dashboard-weak-list");
        if (weakListEl) {
            const weakEntries = vaultData.filter(e => e.strength === "faible");
            if (weakEntries.length === 0) {
                weakListEl.innerHTML = `<div style="color:var(--state-success);padding:10px;font-size:0.85rem;">✓ Aucun mot de passe faible détecté. Excellent !</div>`;
            } else {
                weakListEl.innerHTML = weakEntries.map(e => `
                    <div class="audit-issue-row">
                        <div>
                            <strong>${escapeHtml(e.name)}</strong>
                            <small style="color:var(--text-dim);display:block;">${escapeHtml(e.user)}</small>
                        </div>
                        <button class="icon-btn" onclick="window.VaultApp.openEdit('${e.id}')">Renforcer ⚡</button>
                    </div>
                `).join("");
            }
        }

        // Reused passwords list in dashboard
        const reusedListEl = document.getElementById("dashboard-reused-list");
        if (reusedListEl) {
            const reusedEntries = vaultData.filter(e => (reuseCounts[e.password] || 0) > 1);
            if (reusedEntries.length === 0) {
                reusedListEl.innerHTML = `<div style="color:var(--state-success);padding:10px;font-size:0.85rem;">✓ Aucun mot de passe n'est réutilisé sur plusieurs services.</div>`;
            } else {
                reusedListEl.innerHTML = reusedEntries.map(e => `
                    <div class="audit-issue-row">
                        <div>
                            <strong>${escapeHtml(e.name)}</strong>
                            <small style="color:var(--state-danger);display:block;">Mot de passe dupliqué</small>
                        </div>
                        <button class="icon-btn" onclick="window.VaultApp.openEdit('${e.id}')">Changer ⚡</button>
                    </div>
                `).join("");
            }
        }
    }

    /* =========================================================
       DELETE ACCOUNT MODAL
    ========================================================= */
    const deleteAccountModal = document.getElementById("delete-account-modal");
    const openDeleteBtn = document.getElementById("open-delete-account-modal");
    const closeDeleteBtn = document.getElementById("close-delete-account-modal");
    const confirmDeleteBtn = document.getElementById("confirm-delete-account");

    if (openDeleteBtn && deleteAccountModal) {
        openDeleteBtn.onclick = () => {
            document.getElementById("delete-account-password").value = "";
            deleteAccountModal.classList.add("active");
        };
    }

    if (closeDeleteBtn && deleteAccountModal) {
        closeDeleteBtn.onclick = () => deleteAccountModal.classList.remove("active");
    }

    if (confirmDeleteBtn) {
        confirmDeleteBtn.onclick = async () => {
            const password = document.getElementById("delete-account-password").value;
            if (!password) {
                showToast("Mot de passe maître requis", "error");
                return;
            }

            confirmDeleteBtn.disabled = true;
            try {
                await apiFetch("/api/account", {
                    method: "DELETE",
                    body: JSON.stringify({ password })
                });

                deleteAccountModal.classList.remove("active");
                logout();
                showToast("✓ Compte et coffre supprimés définitivement.");
            } catch (error) {
                showToast(error.message, "error");
            } finally {
                confirmDeleteBtn.disabled = false;
            }
        };
    }

    /* =========================================================
       TOAST NOTIFICATION ENGINE
    ========================================================= */
    let toastTimer = null;
    function showToast(message, type = "success") {
        const toast = document.getElementById("toast");
        if (!toast) return;

        let icon = "✓";
        if (type === "error") icon = "✕";
        if (type === "warning") icon = "⚠️";

        toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
        toast.className = "";
        if (type === "error") toast.classList.add("error");
        if (type === "warning") toast.classList.add("warning");
        toast.classList.add("show");

        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            toast.classList.remove("show");
        }, 3200);
    }

    /* =========================================================
       THREE.JS DIGITAL VAULT VISUALIZATION
    ========================================================= */
    function initThreeVaultVisualization() {
        const container = document.getElementById("three-container");
        if (!container || typeof THREE === "undefined") return;

        try {
            const scene = new THREE.Scene();
            const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
            camera.position.set(0, 1, 8.8);

            const renderer = new THREE.WebGLRenderer({
                antialias: true,
                alpha: true,
                powerPreference: "high-performance"
            });
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
            container.appendChild(renderer.domElement);

            // Lights
            scene.add(new THREE.AmbientLight(0x0c1e3d, 2.5));
            const blueLight = new THREE.PointLight(0x3b82f6, 6, 30);
            blueLight.position.set(4, 5, 5);
            scene.add(blueLight);

            const cyanLight = new THREE.PointLight(0x00f0ff, 5, 30);
            cyanLight.position.set(-4, 2, 4);
            scene.add(cyanLight);

            // Digital Vault Group
            const vaultGroup = new THREE.Group();
            scene.add(vaultGroup);

            // Vault Body
            const bodyGeo = new THREE.BoxGeometry(3.1, 3.4, 2.3);
            const bodyMat = new THREE.MeshStandardMaterial({
                color: 0x091224,
                metalness: 0.85,
                roughness: 0.25
            });
            const vaultBody = new THREE.Mesh(bodyGeo, bodyMat);
            vaultGroup.add(vaultBody);

            // Glowing Wireframe Edges
            const edgeLines = new THREE.LineSegments(
                new THREE.EdgesGeometry(bodyGeo),
                new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.65 })
            );
            vaultGroup.add(edgeLines);

            // Vault Door
            const doorMat = new THREE.MeshStandardMaterial({
                color: 0x0f1d38,
                metalness: 0.9,
                roughness: 0.2
            });
            const door = new THREE.Mesh(new THREE.BoxGeometry(2.5, 2.9, 0.2), doorMat);
            door.position.z = 1.2;
            vaultGroup.add(door);

            // Electronic Dial Ring
            const dialMat = new THREE.MeshStandardMaterial({
                color: 0x00f0ff,
                emissive: 0x005577,
                metalness: 0.8,
                roughness: 0.2
            });
            const dial = new THREE.Mesh(new THREE.TorusGeometry(0.68, 0.08, 16, 64), dialMat);
            dial.position.z = 1.34;
            vaultGroup.add(dial);

            // Rotating Cyber Rings around Vault
            const rings = [];
            [2.2, 2.9, 3.6].forEach((rad, idx) => {
                const ring = new THREE.Mesh(
                    new THREE.TorusGeometry(rad, 0.016, 6, 80),
                    new THREE.MeshBasicMaterial({
                        color: idx === 0 ? 0x00f0ff : idx === 1 ? 0x3b82f6 : 0x6366f1,
                        transparent: true,
                        opacity: 0.4
                    })
                );
                ring.rotation.x = Math.random() * Math.PI;
                ring.rotation.y = Math.random() * Math.PI;
                vaultGroup.add(ring);
                rings.push(ring);
            });

            // Particles
            const particleCount = 450;
            const pos = new Float32Array(particleCount * 3);
            for (let i = 0; i < particleCount * 3; i++) {
                pos[i] = (Math.random() - 0.5) * 22;
            }
            const partGeo = new THREE.BufferGeometry();
            partGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
            const particles = new THREE.Points(
                partGeo,
                new THREE.PointsMaterial({ color: 0x00f0ff, size: 0.04, transparent: true, opacity: 0.55 })
            );
            scene.add(particles);

            // Mouse parallax
            let mouseX = 0, mouseY = 0;
            window.addEventListener("mousemove", (e) => {
                mouseX = e.clientX / window.innerWidth - 0.5;
                mouseY = e.clientY / window.innerHeight - 0.5;
            }, { passive: true });

            function resize() {
                const w = container.clientWidth || 650;
                const h = container.clientHeight || 650;
                camera.aspect = w / h;
                camera.updateProjectionMatrix();
                renderer.setSize(w, h, false);
            }
            window.addEventListener("resize", resize);
            resize();

            const clock = new THREE.Clock();
            function animate() {
                requestAnimationFrame(animate);
                const t = clock.getElapsedTime();

                // Gentle rotation & hover tracking
                const targetY = mouseX * 0.35 + Math.sin(t * 0.4) * 0.15;
                const targetX = mouseY * 0.2 + Math.cos(t * 0.3) * 0.05;
                vaultGroup.rotation.y += (targetY - vaultGroup.rotation.y) * 0.04;
                vaultGroup.rotation.x += (targetX - vaultGroup.rotation.x) * 0.04;

                rings[0].rotation.z += 0.008;
                rings[1].rotation.x += 0.006;
                rings[2].rotation.y += 0.009;

                particles.rotation.y = t * 0.015;

                renderer.render(scene, camera);
            }
            animate();
        } catch (e) {
            console.warn("Three.js initialization failed :", e);
        }
    }

    // Expose global helper for dashboard inline buttons
    window.VaultApp = {
        openEdit: (id) => {
            const entry = vaultData.find(e => e.id === id);
            if (entry) {
                goToPage("vault");
                selectedVaultId = entry.id;
                renderVault();
                renderVaultDetail(entry);
                openEditModal(entry);
            }
        }
    };

    // Initialize application
    checkServerStatus();
    initThreeVaultVisualization();

})();
