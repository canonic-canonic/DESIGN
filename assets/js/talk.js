/**
 * TALK — Unified Fleet Conversation Service
 * inherits: CHAT + INTEL
 *
 * CANON.json is the SINGLE SOURCE OF TRUTH.
 * No hardcoded fallbacks. No ungoverned prompts.
 * MUST read CANON.json. 255 compliance enforced.
 *
 * Usage:
 *   <script src="/base/talk.js"></script>
 *   <script>TALK.init();</script>
 *
 * CANON.json contract:
 *   { scope, systemPrompt, welcome, placeholder, disclaimer }
 *
 * HTML contract (flexible — supports multiple ID patterns):
 *   Overlay: #talkOverlay OR #chatOverlay
 *   Messages: #talkMessages
 *   Input: #talkChatInput
 *   Send: #talkSend
 *   Bar: #talkInput OR #searchInput
 *   Intel: #talkIntelTimeline
 *
 * API: https://api.canonic.org/chat (Cloudflare Workers)
 *
 * TALK | CANONIC | 2026-02-12
 */

const TALK = {
    api: 'https://api.canonic.org/chat',
    messages: [],
    scope: null,
    system: null,
    governed: false,
    intelLedger: [],
    canon: null,
    plugins: [],
    currentProvider: 'auto',
    providers: {
        auto:      'https://api.canonic.org/chat',
        anthropic: 'https://anthropic.canonic.org/chat',
        runpod:    'https://runpod.canonic.org/chat',
        vastai:    'https://vast.canonic.org/chat',
        openai:    'https://openai.canonic.org/chat',
        deepseek:  'https://deepseek.canonic.org/chat'
    },

    // ── Initialize ──────────────────────────────────────────────────
    init(config) {
        config = config || {};
        if (config.api) this.api = config.api;

        // Wire event listeners — support multiple DOM patterns
        var talkInput = document.getElementById('talkInput') || document.getElementById('searchInput');
        var chatInput = document.getElementById('talkChatInput');
        var sendBtn = document.getElementById('talkSend');

        if (talkInput) {
            talkInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') TALK.open();
            });
        }
        if (chatInput) {
            chatInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') TALK.send();
            });
        }
        if (sendBtn) {
            sendBtn.addEventListener('click', function() { TALK.send(); });
        }
        document.addEventListener('keydown', function(e) {
            var overlay = document.getElementById('talkOverlay') || document.getElementById('chatOverlay');
            if (e.key === 'Escape' && overlay && overlay.classList.contains('open')) {
                TALK.close();
            }
        });

        // CANON.json is REQUIRED — load governance, then INTEL, then optional plugins.
        this.loadCanon().then(function() {
            TALK.loadIntel();
            TALK.initPlugins();
            TALK.loadCoinBadge();
        });
    },

    // ── Plugins (optional, governed by CANON.json flags) ────────────
    // Plugin map: CANON.json boolean flag → script path.
    // Dynamic loading: if CANON.json declares `"omics": true` and the page hasn't
    // already loaded the script, TALK loads it at runtime.
    PLUGIN_MAP: {
        mcode:  '/plugins/mcode.js',
        trials: '/plugins/trials.js',
        omics:  '/plugins/omics.js'
    },

    loadScript(src) {
        return new Promise(function(resolve) {
            var s = document.createElement('script');
            s.src = src;
            s.onload = resolve;
            s.onerror = resolve; // fail-closed: missing plugin must not break TALK
            document.head.appendChild(s);
        });
    },

    async initPlugins() {
        // No hardcoded behavior. Plugins must be explicitly enabled by CANON.json.
        this.plugins = [];
        if (!this.canon) return;

        // Discover which plugins CANON.json enables and dynamically load missing ones.
        var names = Object.keys(this.PLUGIN_MAP);
        var toLoad = [];
        for (var i = 0; i < names.length; i++) {
            if (!this.canon[names[i]]) continue;
            var globalName = names[i].toUpperCase();
            // Skip if the page already loaded the script (e.g., CUSTOM layout <script> tags).
            try {
                if (typeof window !== 'undefined' && typeof window[globalName] !== 'undefined') continue;
            } catch {}
            toLoad.push(this.loadScript(this.PLUGIN_MAP[names[i]]));
        }

        // Wait for any dynamic script loads to complete.
        if (toLoad.length) await Promise.allSettled(toLoad);

        // Discover loaded plugins from window globals.
        for (var j = 0; j < names.length; j++) {
            if (!this.canon[names[j]]) continue;
            var gName = names[j].toUpperCase();
            var plugin = null;
            try {
                if (typeof window !== 'undefined' && typeof window[gName] !== 'undefined') {
                    plugin = window[gName];
                }
            } catch {}
            if (plugin) this.plugins.push(plugin);
        }

        // Initialize plugins. Fail-closed: plugin failures must not break TALK.
        for (var k = 0; k < this.plugins.length; k++) {
            var p = this.plugins[k];
            try {
                if (p && typeof p.init === 'function') p.init(this);
            } catch (e) {
                console.warn('[TALK] plugin init failed:', e);
            }
        }
    },

	    // ── Load CANON.json — REQUIRED governance source ────────────────
	    async loadCanon() {
	        try {
	            // Optional inheritance chain. Governed and explicit: no hardcoded defaults.
	            // Child scopes may add but should not weaken (min/max principle).
	            const MAX_INHERIT_DEPTH = 6;

	            const validateInheritsPath = (p) => {
	                if (!p || typeof p !== 'string') throw new Error('CANON.json inherits must be a string');
	                if (p.indexOf('://') !== -1) throw new Error('CANON.json inherits must be relative (no scheme)');
	                if (p[0] === '/') throw new Error('CANON.json inherits must be relative (no absolute path)');
	                return p;
	            };

	            const mergeCanon = (parent, child) => {
	                parent = parent || {};
	                child = child || {};
	                var out = {};
	                for (var k in parent) out[k] = parent[k];
	                for (var k2 in child) {
	                    var pv = parent[k2];
	                    var cv = child[k2];
	                    // Min/max: booleans are monotonic (parent=true cannot be disabled downstream).
	                    if (typeof pv === 'boolean' && typeof cv === 'boolean') out[k2] = (pv || cv);
	                    else out[k2] = cv;
	                }
	                return out;
	            };

	            const loadCanonFile = async (path) => {
	                var res = await fetch(path);
	                if (!res.ok) throw new Error(path + ' ' + res.status);
	                return await res.json();
	            };

	            const loadCanonRec = async (path, depth, seen) => {
	                depth = depth || 0;
	                seen = seen || {};
	                if (depth > MAX_INHERIT_DEPTH) throw new Error('CANON.json inherits too deep');
	                if (seen[path]) throw new Error('CANON.json inherits cycle');
	                seen[path] = true;

	                var child = await loadCanonFile(path);
	                var inherits = child && child.inherits;
	                if (!inherits) return child;

	                var list = Array.isArray(inherits) ? inherits : [inherits];
	                var merged = {};
	                for (var i = 0; i < list.length; i++) {
	                    var p = validateInheritsPath(list[i]);
	                    var parent = await loadCanonRec(p, depth + 1, seen);
	                    merged = mergeCanon(merged, parent);
	                }
	                return mergeCanon(merged, child);
	            };

	            var canon = await loadCanonRec('./CANON.json');

	            // MUST have systemPrompt
	            if (!canon.systemPrompt) throw new Error('CANON.json missing systemPrompt');

            this.canon = canon;
            this.system = canon.systemPrompt;
            this.scope = canon.scope || canon.name || 'CANONIC';
            this.notify = Array.isArray(canon.notify) ? canon.notify : [];
            this.governed = true;

            // Welcome message
            if (canon.welcome) {
                var el = document.getElementById('talkMessages');
                if (el && !el.children.length) {
                    var div = document.createElement('div');
                    div.className = 'message assistant';
                    var textDiv = document.createElement('div');
                    textDiv.innerHTML = this.md(canon.welcome);
                    div.appendChild(textDiv);
                    el.appendChild(div);
                }
            }

            this.applyCanonUI(canon);

        } catch(e) {
            // UNGOVERNED — refuse to operate with generic prompt
            this.governed = false;
            this.system = null;
            this.scope = 'UNGOVERNED';
            document.documentElement.setAttribute('data-talk', 'ungoverned');
            var el = document.getElementById('talkMessages');
            if (el) {
                var div = document.createElement('div');
                div.className = 'message error';
                var textDiv = document.createElement('div');
                textDiv.textContent = 'MAGIC VIOLATION — CANON.json missing or invalid. TALK requires governed context. ' + e.message;
                div.appendChild(textDiv);
                el.appendChild(div);
            }
        }
    },


    applyCanonUI(canon) {
        var scopeText = String(canon.scope || canon.name || 'CANONIC').toUpperCase() + ' TALK';
        document.querySelectorAll('.talk-scope').forEach(function (el) {
            el.textContent = scopeText;
        });

        var placeholder = canon.placeholder || ('Ask ' + String(canon.scope || canon.name || 'CANONIC') + '...');
        [document.getElementById('talkChatInput'), document.getElementById('talkInput'), document.getElementById('searchInput')]
            .forEach(function (inp) { if (inp) inp.placeholder = placeholder; });

        document.documentElement.setAttribute('data-talk', 'governed');

        // Quick actions: CANON.json array → tappable chips above chat input
        if (Array.isArray(canon.quickActions) && canon.quickActions.length) {
            this.renderQuickActions(canon.quickActions);
        }
    },

    // ── Quick Actions — prefill buttons driven by CANON.json ─────────
    renderQuickActions(actions) {
        var inputArea = document.querySelector('.input-area');
        if (!inputArea) return;

        // Don't duplicate
        if (document.getElementById('talkQuickActions')) return;

        var container = document.createElement('div');
        container.id = 'talkQuickActions';
        container.style.cssText = 'display:flex;gap:0.5rem;padding:0.5rem 1rem;overflow-x:auto;flex-shrink:0;flex-wrap:wrap;';

        for (var i = 0; i < actions.length; i++) {
            var qa = actions[i];
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'talk-qa';
            btn.textContent = (qa.icon || '') + ' ' + qa.label;
            btn.setAttribute('data-msg', qa.message || '');
            btn.addEventListener('click', (function(msg) {
                return function() {
                    var input = document.getElementById('talkChatInput');
                    if (!input) return;
                    input.value = msg;
                    input.focus();
                    // Auto-send if message is complete (no trailing space)
                    if (msg && msg.charAt(msg.length - 1) !== ' ') {
                        if (TALK.governed && TALK.send) TALK.send();
                    }
                };
            })(qa.message || ''));
            container.appendChild(btn);
        }

        inputArea.parentNode.insertBefore(container, inputArea);

        // Inject quick-action styles if not already present
        if (!document.getElementById('talkQAStyles')) {
            var style = document.createElement('style');
            style.id = 'talkQAStyles';
            style.textContent = '.talk-qa{display:inline-flex;align-items:center;gap:.25rem;padding:.375rem .75rem;border:1px solid var(--border,#e5e5e5);border-radius:999px;background:var(--glass,rgba(255,255,255,.8));color:var(--fg,#374151);font-size:.8125rem;font-weight:500;cursor:pointer;transition:all .15s;white-space:nowrap;flex-shrink:0}.talk-qa:hover{border-color:var(--accent,#f97316);color:var(--accent,#f97316);background:rgba(var(--accent-rgb,249,115,22),.08);transform:translateY(-1px)}.talk-qa:active{transform:translateY(0) scale(.97)}';
            document.head.appendChild(style);
        }
    },

    // ── Overlay Control ─────────────────────────────────────────────
    open() {
        var overlay = document.getElementById('talkOverlay') || document.getElementById('chatOverlay');
        var barInput = document.getElementById('talkInput') || document.getElementById('searchInput');
        var chatInput = document.getElementById('talkChatInput');
        if (!overlay) return;

        overlay.classList.add('open');
        if (barInput && barInput.value.trim()) {
            if (chatInput) chatInput.value = barInput.value;
            barInput.value = '';
            setTimeout(function() { TALK.send(); }, 50);
        }
        setTimeout(function() { if (chatInput) chatInput.focus(); }, 100);
    },

    close() {
        var overlay = document.getElementById('talkOverlay') || document.getElementById('chatOverlay');
        if (overlay) overlay.classList.remove('open');
        var barInput = document.getElementById('talkInput') || document.getElementById('searchInput');
        if (barInput) barInput.focus();
    },

    // ── Markdown Parser (XSS-safe, full typesetting) ──────────────────
    md(text) {
        var escaped = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        var codeBlocks = [];
        escaped = escaped.replace(/```(\w*)\n([\s\S]*?)```/g, function(m, lang, code) {
            codeBlocks.push('<pre><code' + (lang ? ' class="lang-' + lang + '"' : '') + '>' + code.trimEnd() + '</code></pre>');
            return '\x00CODE' + (codeBlocks.length - 1) + '\x00';
        });

        var html = escaped
            .replace(/^### (.+)$/gm, '<h4>$1</h4>')
            .replace(/^## (.+)$/gm, '<h3>$1</h3>')
            .replace(/^# (.+)$/gm, '<h2>$1</h2>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.+?)\*/g, '<em>$1</em>')
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');

        html = html
            .replace(/---/g, '\u2014')
            .replace(/--/g, '\u2013')
            .replace(/\.\.\./g, '\u2026')
            .replace(/"([^"]+)"/g, '\u201c$1\u201d')
            .replace(/'([^']+)'/g, '\u2018$1\u2019');

        var lines = html.split('\n');
        var result = [];
        var inList = false;
        var listType = null;
        var inBlockquote = false;
        var inTable = false;
        var tableHeader = false;

        var closeTable = function() {
            if (inTable) { result.push('</tbody></table>'); inTable = false; tableHeader = false; }
        };

        var parseTableRow = function(line, tag) {
            var cells = line.replace(/^\|/, '').replace(/\|$/, '').split('|');
            var row = '<tr>';
            for (var c = 0; c < cells.length; c++) {
                row += '<' + tag + '>' + cells[c].trim() + '</' + tag + '>';
            }
            return row + '</tr>';
        };

        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];

            var codeMatch = line.match(/^\x00CODE(\d+)\x00$/);
            if (codeMatch) {
                if (inList) { result.push('</' + listType + '>'); inList = false; listType = null; }
                if (inBlockquote) { result.push('</blockquote>'); inBlockquote = false; }
                closeTable();
                result.push(codeBlocks[parseInt(codeMatch[1])]);
                continue;
            }

            if (/^[-*_]{3,}$/.test(line.trim())) {
                if (inList) { result.push('</' + listType + '>'); inList = false; listType = null; }
                if (inBlockquote) { result.push('</blockquote>'); inBlockquote = false; }
                closeTable();
                result.push('<hr>');
                continue;
            }

            // Table rows: lines containing | with content
            var isTableRow = /^\|.+\|$/.test(line.trim());
            var isSeparator = /^\|[\s:]*[-\u2014]+[\s:]*(\|[\s:]*[-\u2014]+[\s:]*)*\|$/.test(line.trim());

            if (isTableRow) {
                if (inList) { result.push('</' + listType + '>'); inList = false; listType = null; }
                if (inBlockquote) { result.push('</blockquote>'); inBlockquote = false; }

                if (isSeparator) {
                    // Separator row — marks transition from header to body
                    if (inTable) { tableHeader = true; }
                    continue;
                }

                if (!inTable) {
                    // First row — open table, treat as header
                    result.push('<table><thead>');
                    result.push(parseTableRow(line, 'th'));
                    result.push('</thead><tbody>');
                    inTable = true;
                    tableHeader = true;
                } else {
                    result.push(parseTableRow(line, 'td'));
                }
                continue;
            } else {
                closeTable();
            }

            var bqMatch = line.match(/^&gt;\s?(.*)$/);
            if (bqMatch) {
                if (inList) { result.push('</' + listType + '>'); inList = false; listType = null; }
                if (!inBlockquote) { result.push('<blockquote>'); inBlockquote = true; }
                if (bqMatch[1].trim()) result.push('<p>' + bqMatch[1] + '</p>');
                continue;
            } else if (inBlockquote) {
                result.push('</blockquote>');
                inBlockquote = false;
            }

            var ulMatch = line.match(/^[-*]\s+(.+)$/);
            var olMatch = line.match(/^\d+\.\s+(.+)$/);

            if (ulMatch || olMatch) {
                var newType = ulMatch ? 'ul' : 'ol';
                if (!inList) {
                    result.push('<' + newType + '>');
                    inList = true;
                    listType = newType;
                } else if (listType !== newType) {
                    result.push('</' + listType + '><' + newType + '>');
                    listType = newType;
                }
                result.push('<li>' + (ulMatch || olMatch)[1] + '</li>');
            } else {
                if (inList) { result.push('</' + listType + '>'); inList = false; listType = null; }
                if (line.trim()) {
                    result.push(line.indexOf('<h') === 0 ? line : '<p>' + line + '</p>');
                }
            }
        }
        if (inList) result.push('</' + listType + '>');
        if (inBlockquote) result.push('</blockquote>');
        closeTable();
        return result.join('');
    },

    // ── Scrolling ───────────────────────────────────────────────────
    isNearBottom(el) {
        return el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    },

    scrollToBottom(el) {
        el.scrollTo({ top: el.scrollHeight, behavior: 'auto' });
    },

    // ── Typing Animation ────────────────────────────────────────────
    async typeMessage(rawText, element, container) {
        var wasNearBottom = container ? this.isNearBottom(container) : true;
        var words = rawText.split(/(\s+)/g).filter(function(w) { return w; });
        var displayed = '';
        element.classList.add('typing');

        for (var i = 0; i < words.length; i++) {
            displayed += words[i];
            element.innerHTML = this.md(displayed);
            if (container && (wasNearBottom || this.isNearBottom(container))) {
                this.scrollToBottom(container);
            }
            var word = words[i].trim();
            if (!word) continue;
            var delay = 20 + Math.random() * 12;
            if (/[.?!]$/.test(word)) delay += 80;
            if (/[,:]$/.test(word)) delay += 40;
            await new Promise(function(r) { setTimeout(r, delay); });
        }
        element.classList.remove('typing');
        // RUNNER: inject action buttons after typing completes
        if (this.scope === 'RUNNER') this.injectTaskActions(element);
    },

    // ── Add Message ─────────────────────────────────────────────────
    add(content, role) {
        var el = document.getElementById('talkMessages');
        if (!el) return null;

        var div = document.createElement('div');
        div.className = 'message ' + role;

        var textDiv = document.createElement('div');
        if (role === 'assistant' && content && content.indexOf('Thinking') === -1) {
            textDiv.innerHTML = this.md(content);
            // RUNNER: inject action buttons for task IDs
            if (this.scope === 'RUNNER') this.injectTaskActions(textDiv);
        } else {
            textDiv.textContent = content;
        }

        div.appendChild(textDiv);
        el.appendChild(div);
        el.scrollTop = el.scrollHeight;
        return div;
    },

    // RUNNER: convert task IDs in assistant messages into clickable action buttons
    injectTaskActions(el) {
        // Find all text nodes containing task IDs like [TB6D2C9719CF3] or TB6D2C9719CF3
        var html = el.innerHTML;
        // Add claim/complete buttons after task ID references
        html = html.replace(/\[?(T[A-F0-9]{12,})\]?/g, function(match, taskId) {
            return match +
                ' <button class="runner-action" onclick="TALK.sendAction(\'claim ' + taskId + '\')" ' +
                'style="font-size:11px;padding:2px 8px;margin:0 2px;border:1px solid #f97316;color:#f97316;background:transparent;border-radius:4px;cursor:pointer;font-weight:600;"' +
                '>Claim</button>' +
                '<button class="runner-action" onclick="TALK.sendAction(\'complete ' + taskId + '\')" ' +
                'style="font-size:11px;padding:2px 8px;margin:0 2px;border:1px solid #22c55e;color:#22c55e;background:transparent;border-radius:4px;cursor:pointer;font-weight:600;"' +
                '>Done</button>';
        });
        el.innerHTML = html;
    },

    // Send a task action through chat
    sendAction(text) {
        var input = document.getElementById('talkChatInput') || document.getElementById('talkInput');
        if (input) {
            input.value = text;
            this.send();
        }
    },

    // ── INTEL Ledger ────────────────────────────────────────────────
    async loadIntel() {
        // Static LEARNING.json — the governed source
        try {
            var res = await fetch('./LEARNING.json');
            if (res.ok) {
                var data = await res.json();
                this.intelLedger = data.ledger || [];
                this.renderIntel();
            }
        } catch(e) { /* LEARNING.json unavailable */ }
    },

    renderIntel() {
        var el = document.getElementById('talkIntelTimeline');
        if (!el || !this.intelLedger.length) return;

        el.innerHTML = '<div style="font-size:10px;font-weight:600;color:var(--fg-secondary,#6b7280);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">INTEL Ledger</div>' +
            this.intelLedger.map(function(e) {
                return '<div style="display:flex;gap:8px;font-size:11px;padding:4px 0;border-bottom:1px solid var(--border,#e5e7eb);">' +
                    '<span style="color:var(--fg-secondary,#6b7280);font-family:\'SF Mono\',Monaco,monospace;white-space:nowrap;">' + e.date + '</span>' +
                    '<span style="color:var(--fg,#374151);">' + e.text + '</span></div>';
            }).join('');
    },

    // ── COIN Badge — live balance in header ─────────────────────────
    async loadCoinBadge() {
        var badge = document.getElementById('runnerCoinBadge');
        if (!badge) return; // Only RUNNER pages have this element

        // Handle Stripe checkout return
        var params = new URLSearchParams(window.location.search);
        if (params.get('checkout') === 'success') {
            this.add('Credits purchase confirmed! Your balance will update shortly.', 'assistant');
            history.replaceState({}, '', window.location.pathname);
        }

        var API = 'https://api.canonic.org';

        // Wait for AUTH to complete (resolves race between AUTH.init and TALK.init).
        // GOV: COIN/CANON.md — resolve github → VAULT principal → governed balance.
        if (typeof AUTH !== 'undefined') {
            if (AUTH.ready) {
                await AUTH.ready();
            } else if (AUTH.user && !AUTH.user()) {
                // Fallback: AUTH.ready() not available (old auth.js) — poll for completion.
                for (var _i = 0; _i < 20 && !AUTH.user(); _i++) {
                    await new Promise(function(r) { setTimeout(r, 250); });
                }
            }
        }
        var authUser = (typeof AUTH !== 'undefined' && AUTH.user) ? AUTH.user() : null;

        // If AUTH has a GitHub identity, always register/resolve via VAULT principal.
        // This ensures governed balance even if localStorage has a stale anonymous userId.
        if (authUser && authUser.user) {
            try {
                var res = await fetch(API + '/runner/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: authUser.name || authUser.user, github: authUser.user, role: 'Requester' })
                });
                if (res.ok) {
                    var data = await res.json();
                    var uid = data.user && data.user.id;
                    if (uid) localStorage.setItem('runner_user_id', uid);
                    if (data.principal) localStorage.setItem('runner_principal', data.principal);
                    this.renderCoinBadge(badge, data.balance || 0);
                    return;
                }
            } catch(e) { /* fall through */ }
        }

        // No AUTH — use existing localStorage userId or create anonymous user.
        var userId = localStorage.getItem('runner_user_id');
        if (!userId) {
            try {
                var res = await fetch(API + '/runner/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: 'RUNNER User', role: 'Requester' })
                });
                if (res.ok) {
                    var data = await res.json();
                    userId = data.user && data.user.id;
                    if (userId) localStorage.setItem('runner_user_id', userId);
                    this.renderCoinBadge(badge, data.balance || 0);
                }
            } catch(e) { /* silent */ }
            return;
        }

        // Existing anonymous user — fetch KV balance
        try {
            var res = await fetch(API + '/runner/balance?user_id=' + encodeURIComponent(userId));
            if (res.ok) {
                var data = await res.json();
                this.renderCoinBadge(badge, data.balance || 0);
            }
        } catch(e) { /* silent */ }
    },

    renderCoinBadge(badge, balance) {
        badge.textContent = balance + ' Credits';
        badge.classList.remove('loading');
        badge.style.cursor = 'pointer';
        this.coinBalance = balance;
        this.userId = localStorage.getItem('runner_user_id');
        badge.title = 'Click to buy Credits';
        badge.onclick = function() { TALK.buyCoin(); };
    },

    // Governed credit packs — COIN/CANON.md § Credit Packs
    CREDIT_PACKS: [
        { coin: 25, price: 25, label: '25 Credits', badge: 'Starter' },
        { coin: 50, price: 50, label: '50 Credits', badge: 'Popular' },
        { coin: 100, price: 95, label: '100 Credits', badge: 'Save 5%' },
        { coin: 250, price: 225, label: '250 Credits', badge: 'Save 10%' },
        { coin: 500, price: 425, label: '500 Credits', badge: 'Best Value' }
    ],

    _ensurePackStyles() {
        if (document.getElementById('talkPackStyles')) return;
        var s = document.createElement('style');
        s.id = 'talkPackStyles';
        s.textContent =
            '.talk-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:flex;align-items:center;justify-content:center;padding:1rem;}' +
            '.talk-modal{background:var(--card,#fff);border-radius:1rem;padding:1.5rem;max-width:28rem;width:100%;border:1px solid var(--border,#e5e7eb);}' +
            '.talk-modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;}' +
            '.talk-modal-header h3{margin:0;font-size:1.125rem;}' +
            '.talk-modal-close{background:none;border:none;font-size:1.5rem;cursor:pointer;color:var(--fg,#374151);padding:0 0.25rem;}' +
            '.talk-pack-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(8rem,1fr));gap:0.75rem;}' +
            '.talk-pack{display:flex;flex-direction:column;align-items:center;gap:0.25rem;padding:1rem 0.75rem;background:var(--bg,#f9fafb);border:2px solid var(--border,#e5e7eb);border-radius:0.75rem;cursor:pointer;transition:border-color 0.15s,transform 0.15s;}' +
            '.talk-pack:hover{border-color:#f97316;transform:translateY(-2px);}' +
            '.talk-pack-badge{font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:#f97316;background:rgba(249,115,22,0.1);padding:0.125rem 0.5rem;border-radius:999px;}' +
            '.talk-pack-amount{font-size:1.75rem;font-weight:800;color:var(--text,#111);line-height:1;}' +
            '.talk-pack-label{font-size:0.7rem;font-weight:600;color:var(--fg-secondary,#6b7280);text-transform:uppercase;letter-spacing:0.1em;}' +
            '.talk-pack-price{font-size:0.9rem;font-weight:700;color:var(--text,#111);}';
        document.head.appendChild(s);
    },

    buyCoin() {
        var userId = this.userId || localStorage.getItem('runner_user_id');
        if (!userId) { this.add('Sign in first to buy Credits.', 'error'); return; }

        this._ensurePackStyles();
        var self = this;
        var overlay = document.createElement('div');
        overlay.className = 'talk-modal-overlay';
        overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
        var html = '<div class="talk-modal">' +
            '<div class="talk-modal-header"><h3>Buy Credits</h3><button class="talk-modal-close" onclick="this.closest(\'.talk-modal-overlay\').remove()">&times;</button></div>' +
            '<p style="margin:0 0 1rem;font-size:0.85rem;color:var(--fg-secondary,#6b7280);">Credits power every task. Pick a pack:</p>' +
            '<div class="talk-pack-grid">';
        for (var i = 0; i < this.CREDIT_PACKS.length; i++) {
            var p = this.CREDIT_PACKS[i];
            html += '<button class="talk-pack" data-coin="' + p.coin + '">' +
                '<span class="talk-pack-badge">' + p.badge + '</span>' +
                '<span class="talk-pack-amount">' + p.coin + '</span>' +
                '<span class="talk-pack-label">CREDITS</span>' +
                '<span class="talk-pack-price">$' + p.price + '</span>' +
                '</button>';
        }
        html += '</div></div>';
        overlay.innerHTML = html;
        document.body.appendChild(overlay);
        var packs = overlay.querySelectorAll('.talk-pack');
        for (var j = 0; j < packs.length; j++) {
            packs[j].addEventListener('click', function() {
                var coin = parseInt(this.getAttribute('data-coin'));
                overlay.remove();
                self._checkout(coin);
            });
        }
    },

    async _checkout(coins) {
        var userId = this.userId || localStorage.getItem('runner_user_id');
        try {
            var res = await fetch('https://api.canonic.org/runner/checkout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: userId,
                    amount_coin: coins,
                    success_url: window.location.origin + window.location.pathname + '?checkout=success',
                    cancel_url: window.location.origin + window.location.pathname + '?checkout=cancel'
                })
            });
            var data = await res.json();
            if (data.url) {
                window.location.href = data.url;
            } else {
                this.add('Checkout error: ' + (data.error || 'unknown'), 'error');
            }
        } catch(e) {
            this.add('Checkout failed. Try again.', 'error');
        }
    },

    // ── Send Message ────────────────────────────────────────────────
    async send() {
        // Refuse if ungoverned
        if (!this.governed || !this.system) {
            this.add('MAGIC VIOLATION — Cannot send. CANON.json not loaded. This TALK is ungoverned.', 'error');
            return;
        }

        var input = document.getElementById('talkChatInput');
        if (!input) return;

        var text = input.value.trim();
        if (!text) return;
        input.value = '';

        // Optional plugin hook: beforeSend (e.g., mCODE extraction + state attach)
        // Await supports async plugins (OMICS live API). Sync plugins resolve immediately.
        var config = {};
        for (var i = 0; i < this.plugins.length; i++) {
            var p = this.plugins[i];
            try {
                if (p && p.hooks && typeof p.hooks.beforeSend === 'function') {
                    var out = await p.hooks.beforeSend({ text: text, config: config, talk: this });
                    if (out && typeof out.text === 'string') text = out.text;
                }
            } catch (e) {
                console.warn('[TALK] plugin beforeSend failed:', e);
            }
        }

        this.add(text, 'user');
        this.messages.push({ role: 'user', content: text });

        var typing = this.add('Thinking...', 'assistant');
        var msgContainer = document.getElementById('talkMessages');

        try {
            // Ensure live governed UI data is available to the model even if the server
            // does not explicitly forward `config` into the LLM context.
            var sys = this.system;
            try {
                if (config && config.trials) {
                    sys += '\n\nLIVE_TRIALS_CONTEXT (from ClinicalTrials.gov panel, governed):\n' + JSON.stringify(config.trials);
                    sys += '\n\nRules: Treat LIVE_TRIALS_CONTEXT as the only trial list you can see right now. If the user asks for a specific institution/location and the context is not filtered, ask for ZIP/city/radius and explain the limitation.';
                }
                if (config && config.omics) {
                    sys += '\n\nLIVE_OMICS_CONTEXT (from NCBI E-utilities + PharmGKB, governed):\n' + JSON.stringify(config.omics);
                    sys += '\n\nRules: Treat LIVE_OMICS_CONTEXT as live database results. Cite accession numbers. Declare evidence tier (GOLD/SILVER/BRONZE) for each finding. If context is empty for a queried entity, state that no results were found rather than hallucinating.';
                }
            } catch {}

            var authHeaders = { 'Content-Type': 'application/json' };
            try {
                var sessionToken = (typeof AUTH !== 'undefined' && AUTH.sessionToken) ? AUTH.sessionToken() : null;
                if (sessionToken) authHeaders['Authorization'] = 'Bearer ' + sessionToken;
            } catch (_) {}

            var res = await fetch(this.api, {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({
                    message: text,
                    history: this.messages.slice(-10),
                    system: sys,
                    scope: this.scope,
                    config: config
                })
            });

            if (!res.ok) throw new Error('API ' + res.status);

            var data = await res.json();
            if (typing) typing.remove();

            var reply = data.message || data.text ||
                (data.content && data.content[0] && data.content[0].text) ||
                'Could not process that.';

            // Optional plugin hook: afterReceive (e.g., mCODE extraction from assistant reply)
            for (var j = 0; j < this.plugins.length; j++) {
                var p2 = this.plugins[j];
                try {
                    if (p2 && p2.hooks && typeof p2.hooks.afterReceive === 'function') {
                        var out2 = p2.hooks.afterReceive({ reply: reply, config: config, talk: this, response: data });
                        if (out2 && typeof out2.reply === 'string') reply = out2.reply;
                    }
                } catch (e) {
                    console.warn('[TALK] plugin afterReceive failed:', e);
                }
            }

            // Session chain: persist provider metadata for BAKEOFF evidence
            if (data.trace_id) {
                try {
                    var chainKey = 'canonic_session_chain_' + (this.scope || 'UNGOVERNED');
                    var chain = JSON.parse(localStorage.getItem(chainKey) || '[]');
                    chain.push({
                        trace_id: data.trace_id,
                        provider_used: data.provider_used || '',
                        scope: data.scope || this.scope,
                        elapsed_ms: data.elapsed_ms || 0,
                        ts: new Date().toISOString()
                    });
                    if (chain.length > 500) chain.splice(0, chain.length - 500);
                    localStorage.setItem(chainKey, JSON.stringify(chain));
                } catch (ce) { /* localStorage unavailable */ }
            }

            var msgEl = this.add('', 'assistant');
            var textEl = msgEl ? (msgEl.querySelector('div') || msgEl.firstChild) : null;
            if (textEl) {
                await this.typeMessage(reply, textEl, msgContainer);
            } else {
                this.add(reply, 'assistant');
            }
            this.messages.push({ role: 'assistant', content: reply });

            // LEDGER: persist conversation turn server-side (GOV: TALK/CANON.md)
            // Fire-and-forget — ledger failure must not break chat
            try {
                var ledgerHeaders = { 'Content-Type': 'application/json' };
                try {
                    var ledgerToken = (typeof AUTH !== 'undefined' && AUTH.sessionToken) ? AUTH.sessionToken() : null;
                    if (ledgerToken) ledgerHeaders['Authorization'] = 'Bearer ' + ledgerToken;
                } catch (_) {}
                fetch('https://api.canonic.org/talk/ledger', {
                    method: 'POST',
                    headers: ledgerHeaders,
                    body: JSON.stringify({
                        scope: this.scope || 'UNGOVERNED',
                        user_message: text,
                        assistant_message: reply,
                        trace_id: data.trace_id || null,
                        provider_used: data.provider_used || null,
                        elapsed_ms: data.elapsed_ms || null,
                        notify: this.notify || []
                    })
                }).catch(function() {});
            } catch (le) { /* ledger write must not break chat */ }
        } catch (e) {
            if (typing) typing.remove();
            this.add('Connection issue. Try again in a moment.', 'error');
        }

        input.focus();
    },

    // BAKEOFF: switch provider mid-session (frictionless)
    switchProvider(provider) {
        var p = String(provider || 'auto').toLowerCase();
        if (!this.providers[p]) p = 'auto';
        var prev = this.currentProvider;
        this.currentProvider = p;
        this.api = this.providers[p];

        // Record switch event in session chain
        try {
            var chainKey = 'canonic_session_chain_' + (this.scope || 'UNGOVERNED');
            var chain = JSON.parse(localStorage.getItem(chainKey) || '[]');
            chain.push({
                event: 'switch',
                from: prev,
                to: p,
                scope: this.scope,
                ts: new Date().toISOString()
            });
            if (chain.length > 500) chain.splice(0, chain.length - 500);
            localStorage.setItem(chainKey, JSON.stringify(chain));
        } catch (e) { /* localStorage unavailable */ }

        // Update UI indicator
        var dot = document.querySelector('.talk-dot');
        if (dot) dot.setAttribute('data-provider', p);
        var label = document.getElementById('talkProviderLabel');
        if (label) label.textContent = p.toUpperCase();

        this.add('Switched to ' + p.toUpperCase() + '.', 'system');
    },

    // BAKEOFF evidence: return session chain for a given scope
    getSessionChain(scope) {
        var key = 'canonic_session_chain_' + (scope || this.scope || 'UNGOVERNED');
        try { return JSON.parse(localStorage.getItem(key) || '[]'); }
        catch (e) { return []; }
    }
};
