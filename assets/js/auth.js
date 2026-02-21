/**
 * AUTH — Composable authentication gate.
 * Same pattern as TALK/SHOP: one include, one script, frontmatter-controlled.
 *
 * Reads CANON.json. If privacy: PRIVATE, gates the page behind GitHub OAuth.
 * Frontmatter: auth: true|required
 *
 * Usage:
 *   page frontmatter: auth: true
 *   {% include AUTH.html %}
 *   <script src="/assets/js/auth.js"></script>
 *   <script>AUTH.init();</script>
 *
 * AUTH | CANONIC | 2026
 */
var AUTH = (function () {
    'use strict';

    var API = 'https://api.canonic.org';
    var KEY = 'canonic_session_token';
    var _user = null;

    // ── Storage ─────────────────────────────────────────
    function getToken() {
        try { return localStorage.getItem(KEY); } catch (_) { return null; }
    }
    function setToken(t) {
        try { localStorage.setItem(KEY, t); } catch (_) {}
    }
    function clearToken() {
        try { localStorage.removeItem(KEY); } catch (_) {}
    }

    // ── OAuth exchange ──────────────────────────────────
    async function exchange(code) {
        var redirect = window.location.origin + window.location.pathname;
        try {
            var res = await fetch(API + '/auth/github', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code, redirect_uri: redirect })
            });
            if (!res.ok) {
                var err = await res.json().catch(function () { return {}; });
                return { error: err.error || ('HTTP ' + res.status) };
            }
            var data = await res.json();
            var token = data.session_token || data.access_token;
            if (token) {
                setToken(token);
                return { user: data.user, name: data.name, avatar_url: data.avatar_url };
            }
            return { error: 'No token in response' };
        } catch (e) {
            return { error: e.message || 'Network error' };
        }
    }

    // ── Session validation ──────────────────────────────
    async function validate() {
        var token = getToken();
        if (!token) return null;
        try {
            var res = await fetch(API + '/auth/session', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            if (res.ok) {
                var data = await res.json();
                if (data.user) return data;
            }
            if (token.startsWith('gho_')) {
                var gh = await fetch('https://api.github.com/user', {
                    headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' }
                });
                if (gh.ok) {
                    var u = await gh.json();
                    return { user: u.login, name: u.name, avatar_url: u.avatar_url };
                }
            }
            clearToken();
            return null;
        } catch (_) { clearToken(); return null; }
    }

    // ── Reader check ────────────────────────────────────
    function authorized(user, readers) {
        if (!readers || readers.length === 0) return true;
        var gh = (user.user || user.login || '').toLowerCase();
        for (var i = 0; i < readers.length; i++) {
            if (readers[i].toLowerCase() === gh) return true;
        }
        return false;
    }

    // ── Login prompt ────────────────────────────────────
    function loginUrl() {
        return 'https://github.com/login/oauth/authorize?client_id=Ov23libAbRu20g5MLTLJ' +
            '&redirect_uri=' + encodeURIComponent(window.location.origin + window.location.pathname) +
            '&scope=read:user';
    }

    function showLogin(msg) {
        document.body.classList.add('auth-gated');
        var gate = document.getElementById('authGate');
        if (!gate) return;
        gate.innerHTML =
            '<div class="auth-box">' +
            '<div style="font-size:48px;margin-bottom:16px;">&#128274;</div>' +
            '<h2>PRIVATE</h2>' +
            (msg ? '<p class="auth-error">' + msg + '</p>' : '') +
            '<p>This dashboard requires GitHub authentication.</p>' +
            '<a class="auth-btn" href="' + loginUrl() + '">Sign in with GitHub</a>' +
            '</div>';
    }

    // ── Reveal ──────────────────────────────────────────
    function reveal(user) {
        _user = user;
        document.body.classList.remove('auth-gated');
        var gate = document.getElementById('authGate');
        if (gate) gate.innerHTML = '';
    }

    // ── Init ────────────────────────────────────────────
    async function init() {
        var mode = document.getElementById('authGate');
        var authMode = mode ? mode.getAttribute('data-mode') : 'gate';

        // Load CANON.json for this scope
        var canon;
        try {
            var res = await fetch('./CANON.json');
            canon = await res.json();
        } catch (_) {
            // No CANON.json — if auth: required, still gate
            if (authMode === 'required') {
                canon = { privacy: 'PRIVATE', readers: [] };
            } else {
                return;
            }
        }

        if (authMode !== 'required' && (!canon.privacy || canon.privacy !== 'PRIVATE')) return;

        // Page is PRIVATE — gate immediately
        document.body.classList.add('auth-gated');

        // Handle OAuth callback (?code= in URL)
        var params = new URLSearchParams(window.location.search);
        var code = params.get('code');
        if (code) {
            params.delete('code');
            params.delete('state');
            var clean = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
            window.history.replaceState({}, '', clean);

            var result = await exchange(code);
            if (result && result.error) {
                showLogin(result.error);
                return;
            }
            if (result && result.user && authorized(result, canon.readers)) {
                reveal(result);
                return;
            }
            showLogin(result && result.user ? 'Access denied for ' + result.user + '.' : 'Authentication failed.');
            return;
        }

        // Check existing session
        var session = await validate();
        if (session && authorized(session, canon.readers)) {
            reveal(session);
            return;
        }
        if (session) clearToken();
        showLogin();
    }

    // ── Public API ──────────────────────────────────────
    return {
        init: init,
        user: function () { return _user; },
        sessionToken: function () { return getToken(); }
    };
})();
