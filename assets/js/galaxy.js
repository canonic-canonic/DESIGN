/**
 * galaxy.js — GALAXY · Distributed Compute
 *
 * Loads galaxy.json → vis-network.
 * Full gov tree: branches visible, leaves click-to-explode.
 * ORGs = stars. SERVICES = icons. USERS = names.
 *
 * MAGIC 255 | CANONIC | 2026-02
 */

var GALAXY = (function () {
    'use strict';

    var network = null;
    var galaxy = null;
    var nodeMap = {};
    var nodeDS = null;
    var edgeDS = null;
    var _collapseAll = null;
    var _authUser = null;

    // ── AUTH ────────────────────────────────────────────────
    var AUTH_API = 'https://api.canonic.org';

    async function validateGalaxyAuth() {
        var token = null;
        try { token = localStorage.getItem('canonic_session_token'); } catch (_) {}
        if (!token) return null;
        try {
            var res = await fetch(AUTH_API + '/auth/session', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            if (!res.ok) return null;
            return await res.json();
        } catch (_) { return null; }
    }

    function canSeeNode(n) {
        if (!n.privacy || n.privacy !== 'PRIVATE') return true;
        if (!_authUser) return false;
        var readers = n.readers || [];
        if (readers.length === 0) return !!_authUser; // ORG member default
        if (readers.indexOf('*') !== -1) return true;
        if (readers.indexOf(_authUser.user) !== -1) return true;
        return false;
    }

    // ── FORMATTING ───────────────────────────────────────
    function titleCase(s) {
        return s.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function hexToRgba(hex, alpha) {
        if (!hex || hex.charAt(0) !== '#') return 'rgba(100,116,139,' + alpha + ')';
        var r = parseInt(hex.slice(1, 3), 16);
        var g = parseInt(hex.slice(3, 5), 16);
        var b = parseInt(hex.slice(5, 7), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
    }

    // ── TIER ─────────────────────────────────────────────
    function tierFor(bits) {
        if (bits >= 255) return { name: 'MAGIC', color: '#00ff88', badge: '\u2726' };
        if (bits >= 127) return { name: 'AGENT', color: '#2997ff', badge: '\u25C6' };
        if (bits >= 63)  return { name: 'ENTERPRISE', color: '#bf5af2', badge: 'E' };
        if (bits >= 43)  return { name: 'BUSINESS', color: '#ff9f0a', badge: 'B' };
        if (bits >= 35)  return { name: 'COMMUNITY', color: '#fbbf24', badge: 'C' };
        return { name: 'NONE', color: '#ff453a', badge: '\u2014' };
    }

    // ── CANONICAL ICON MAPPING ───────────────────────────
    var SERVICE_ICONS = {
        CANONIC:     '\uf3ed',  HADLEYLAB:   '\uf0c3',
        MAMMOCHAT:   '\uf4be',  ONCOCHAT:    '\uf610',
        MEDCHAT:     '\uf0f1',  FINCHAT:     '\uf155',
        LAWCHAT:     '\uf24e',  TALK:        '\uf086',
        HEALTH:      '\uf21e',  EMAIL:       '\uf0e0',
        IMESSAGE:    '\uf4ad',  LINKEDIN:    '\uf0c1',
        CALENDAR:    '\uf073',  BLOG:        '\uf1ea',
        BOOK:        '\uf02d',  PAPER:       '\uf15c',
        DECK:        '\uf1fe',  DEAL:        '\uf2b5',
        SHOP:        '\uf07a',  VAULT:       '\uf023',
        PATENT:      '\uf0e3',  PLAYBOOKS:   '\uf46d',
        VITAE:       '\uf2bb',  BAKEOFF:     '\uf091',
        RUNPOD:      '\uf233',  VASTAI:      '\uf233',
        CHAT:        '\uf075',  MAGIC:       '\uf0d0',
        GALAXY:      '\uf005',  SERVICES:    '\uf1b3',
        LEARNING:    '\uf19d',  FOUNDATION:  '\uf19c',
        INDUSTRIES:  '\uf275',  DEXTER:      '\uf1b3',
        USERS:       '\uf0c0',  COMPLIANCE:  '\uf058',
        SURFACE:     '\uf108',  PROGRAMMING: '\uf121',
        MED:         '\uf21e',  ONCO:        '\uf610',
        DEALS:       '\uf2b5',  PATENTS:     '\uf0e3',
        BOOKS:       '\uf02d',  DECKS:       '\uf1fe',
        ORGS:        '\uf1ad',  REGULATORY:  '\uf0e3',
        HORIZONTAL:  '\uf0c9',  VERTICALS:   '\uf0dc',
    };

    var CATEGORY_ICONS = {
        SERVICES: '\uf0c0', RUNTIME: '\uf013', GOVERNANCE: '\uf19c',
        KNOWLEDGE: '\uf02d', COMMERCE: '\uf07a', OPERATIONS: '\uf0e8',
        CONTENT: '\uf15c', SCOPE: '\uf111',
    };

    // ── CATEGORY COLORS — from canonverse visual language ──
    var CATEGORY_COLORS = {
        KERNEL:     '#ff0088',
        RUNTIME:    '#00ff88',
        OPERATIONS: '#2997ff',
        COMMERCE:   '#ff9f0a',
        KNOWLEDGE:  '#bf5af2',
        GOVERNANCE: '#ffd60a',
        SERVICES:   '#ec4899',
        CONTENT:    '#a78bfa',
        ORG:        '#64748b',
    };

    function colorFor(n) {
        // Priority: explicit node color > flagship color > category color > default
        if (n.color && n.color !== '#64748b') return n.color;
        if (FLAGSHIPS[n.label]) return FLAGSHIPS[n.label].color;
        return CATEGORY_COLORS[n.category] || '#64748b';
    }

    function iconFor(n) {
        return SERVICE_ICONS[n.label] || CATEGORY_ICONS[n.category] || '\uf111';
    }

    // ── FLAGSHIPS — promoted services with brand identity ──
    var FLAGSHIPS = {
        MAMMOCHAT:  { color: '#ec4899', url: 'https://hadleylab.org/TALKS/MAMMOCHAT/', icon: '\uf4be' },
        CARIBCHAT:  { color: '#f97316', url: 'https://hadleylab.org/TALKS/CARIBCHAT/', icon: '\uf086' },
        ONCOCHAT:   { color: '#3b82f6', url: 'https://hadleylab.org/TALKS/ONCOCHAT/',  icon: '\uf610' },
        MEDCHAT:    { color: '#00ff88', url: 'https://hadleylab.org/TALKS/MEDCHAT/',    icon: '\uf0f1' },
        LAWCHAT:    { color: '#94a3b8', url: 'https://hadleylab.org/TALKS/LAWCHAT/',    icon: '\uf24e' },
        FINCHAT:    { color: '#ff9f0a', url: 'https://hadleylab.org/TALKS/FINCHAT/',    icon: '\uf155' },
        DEV:        { color: '#22d3ee', url: 'https://hadleylab.org/TALKS/DEV/',        icon: '\uf121' },
        NONA:       { color: '#4ade80', url: 'https://hadleylab.org/TALKS/NONA/',       icon: '\uf07a' },
        RUNNER:     { color: '#f59e0b', url: 'https://hadleylab.org/TALKS/RUNNER/',    icon: '\uf0e8' },
        VITAE:      { color: '#bf5af2', url: 'https://hadleylab.org/SERVICES/VITAE/',   icon: '\uf2bb' },
        STAR:       { color: '#ffd60a', url: 'https://hadleylab.org/SERVICES/STAR/',    icon: '\uf005' },
    };

    // ── TIER SHADOW (ambient glow from visual language contract) ──
    function tierShadow(bits) {
        var b = (typeof bits === 'number') ? bits : 0;
        if (b >= 255) return { enabled: true, color: '#00ff88', size: 20, x: 0, y: 0 };
        if (b >= 127) return { enabled: true, color: '#2997ff', size: 12, x: 0, y: 0 };
        if (b >= 63)  return { enabled: true, color: '#bf5af2', size: 8, x: 0, y: 0 };
        if (b >= 43)  return { enabled: true, color: '#ff9f0a', size: 4, x: 0, y: 0 };
        return { enabled: false };
    }

    // ── FEDERATION — external orgs in the compute network ──
    // Canonical direct mapping from VITAE.md (all 38 users audited)
    var FEDERATION = {
        // Healthcare systems
        ADVENTHEALTH: { label: 'ADVENTHEALTH', color: '#0ea5e9', icon: '\uf0f8' },  // hospital
        ELCAMINO:     { label: 'EL CAMINO',    color: '#34d399', icon: '\uf0f8' },  // hospital
        HOWARD:       { label: 'HOWARD',       color: '#a855f7', icon: '\uf19d' },  // graduation-cap
        // Universities
        UCF:          { label: 'UCF',          color: '#fbbf24', icon: '\uf19d' },  // graduation-cap
        UCSF:         { label: 'UCSF',         color: '#2997ff', icon: '\uf19d' },  // graduation-cap
        MALTA:        { label: 'MALTA',         color: '#f97316', icon: '\uf19d' },  // graduation-cap
        // Tech + industry
        BEDASOFTWARE: { label: 'BEDASOFTWARE', color: '#22d3ee', icon: '\uf121' },  // code
        VERILY:       { label: 'VERILY',       color: '#4ade80', icon: '\uf0c3' },  // flask (Alphabet)
        NUMEDII:      { label: 'NUMEDII',      color: '#e879f9', icon: '\uf0c3' },  // flask
        MAMMOSIGHT:   { label: 'MAMMOSIGHT',   color: '#fb923c', icon: '\uf610' },  // x-ray
        ICARO:        { label: 'ICARO',         color: '#f43f5e', icon: '\uf3ed' },  // gem
        QUALHEALTH:   { label: 'QUAL HEALTH',  color: '#a3e635', icon: '\uf21e' },  // heartbeat
        CELERITAS:    { label: 'CELERITAS',     color: '#38bdf8', icon: '\uf544' },  // robot
        ATOM:         { label: 'ATOM',          color: '#c084fc', icon: '\uf5d2' },  // atom
        // Legal + professional
        SLONIMLAW:    { label: 'SLONIM LAW',   color: '#94a3b8', icon: '\uf24e' },  // gavel
        LOZALOZA:     { label: 'LOZA & LOZA',  color: '#94a3b8', icon: '\uf0e3' },  // balance-scale
        WIDERMAN:     { label: 'WIDERMAN',     color: '#94a3b8', icon: '\uf0e3' },  // balance-scale
        // Government + services
        ORANGECO:     { label: 'ORANGE CO',    color: '#fb923c', icon: '\uf19c' },  // university
        JPCAPITAL:    { label: 'JP CAPITAL',   color: '#fbbf24', icon: '\uf1ad' },  // building
        ABOPM:        { label: 'ABOPM',        color: '#14b8a6', icon: '\uf0f1' },  // stethoscope
    };

    // User → external org (last path segment → federation key)
    // fatima-boukrim + isabella-johnston = CANONIC (already governance ORG)
    var USER_ORGS = {
        // AdventHealth (Orlando)
        'rob-purinton':           'ADVENTHEALTH',
        'rob-herzog':             'ADVENTHEALTH',
        'alyssa-tanaka':          'ADVENTHEALTH',
        // UCF College of Medicine
        'deborah-german':         'UCF',
        'david-metcalf':          'UCF',
        'elena-cyrus':            'UCF',
        'jane-gibson':            'UCF',
        'mariana-dangiolo':       'UCF',
        'mubarak-shah':           'UCF',
        // UCSF / Bakar Institute
        'atul-butte':             'UCSF',
        'marina-sirota':          'UCSF',
        'rima-arnaout':           'UCSF',
        'ted-goldstein':          'UCSF',
        // Howard University
        'alex-evans':             'HOWARD',
        'robin-williams':         'HOWARD',
        'terrence-fullum':        'HOWARD',
        // El Camino Health
        'minh-nguyen':            'ELCAMINO',
        'shyamali':               'ELCAMINO',
        // University of Malta
        'neville-calleja':        'MALTA',
        // BedaSoftware
        'ir4y':                   'BEDASOFTWARE',
        'yana':                   'BEDASOFTWARE',
        // Tech + industry
        'andrew-trister':         'VERILY',
        'gini-deshpande':         'NUMEDII',
        'junaid-kalia':           'MAMMOSIGHT',
        'mike-miller':            'ICARO',
        'beau-norgeot':           'QUALHEALTH',
        'geoff-seyon':            'CELERITAS',
        'avinash-boodoosingh':    'ATOM',
        'afsana-akter':           'MAMMOSIGHT',
        // Legal + professional
        'david-slonim':           'SLONIMLAW',
        'gabe-fitch':             'LOZALOZA',
        'mark-malek':             'WIDERMAN',
        // Government + services
        'kunal-patel':            'ORANGECO',
        'jason-palinkas':         'JPCAPITAL',
        'anil-bajnath':           'ABOPM',
        'maria-hupp':             'SLONIMLAW',
    };

    function userKey(userId) {
        var parts = userId.split('/');
        return parts[parts.length - 1];
    }

    // ── COMPLIANCE RING SVG ──────────────────────────────
    // dims: optional array of 8 dimension names; missing_dims: which are missing
    var MAGIC_DIMS = ['GOV', 'OPS', 'DATA', 'COIN', 'INTEL', 'CHAT', 'LANG', 'SPEC'];

    function ringHTML(bits, sz, missing_dims) {
        sz = sz || 90;
        var cx = sz / 2, pct = Math.min(bits / 255, 1);
        var tier = tierFor(bits);
        var svg = '<svg width="' + sz + '" height="' + sz + '" viewBox="0 0 ' + sz + ' ' + sz + '">';

        // 8-segment mode when missing_dims provided and < 8 missing
        if (missing_dims && missing_dims.length > 0 && missing_dims.length < 8) {
            var r = sz * 0.40, w = 6;
            var gap = 0.06; // radians gap between segments
            var segAngle = (2 * Math.PI - 8 * gap) / 8;
            var missingSet = {};
            missing_dims.forEach(function (d) { missingSet[d] = true; });
            MAGIC_DIMS.forEach(function (dim, i) {
                var startAngle = -Math.PI / 2 + i * (segAngle + gap);
                var endAngle = startAngle + segAngle;
                var x1 = cx + r * Math.cos(startAngle);
                var y1 = cx + r * Math.sin(startAngle);
                var x2 = cx + r * Math.cos(endAngle);
                var y2 = cx + r * Math.sin(endAngle);
                var filled = !missingSet[dim];
                svg += '<path d="M ' + x1 + ' ' + y1 + ' A ' + r + ' ' + r + ' 0 0 1 ' + x2 + ' ' + y2 + '"'
                    + ' fill="none" stroke="' + (filled ? tier.color : '#333') + '"'
                    + ' stroke-width="' + w + '" stroke-linecap="round"'
                    + ' opacity="' + (filled ? 0.8 : 0.25) + '"/>';
            });
        } else {
            // Classic 3-ring mode
            [{ r: sz * 0.47, w: 4, o: 0.15 }, { r: sz * 0.40, w: 5, o: 0.35 }, { r: sz * 0.33, w: 6, o: 0.70 }].forEach(function (t) {
                var c = 2 * Math.PI * t.r;
                svg += '<circle cx="' + cx + '" cy="' + cx + '" r="' + t.r + '" fill="none" stroke="' + tier.color + '" stroke-width="' + t.w + '" opacity="' + t.o + '" stroke-dasharray="' + (c * pct) + ' ' + c + '" stroke-linecap="round" transform="rotate(-90 ' + cx + ' ' + cx + ')"/>';
            });
        }
        svg += '<text x="' + cx + '" y="' + cx + '" text-anchor="middle" dominant-baseline="central" fill="#fff" font-size="' + (sz * 0.22) + '" font-weight="700">' + bits + '</text></svg>';
        return svg;
    }

    // ── DETAIL PANEL — Quick Look ────────────────────────
    function buildBreadcrumb(node) {
        var parts = [];
        var cur = node;
        var seen = {};
        while (cur) {
            if (seen[cur.id]) break;
            seen[cur.id] = true;
            if (canSeeNode(cur)) parts.unshift(cur);
            if (cur.parent && nodeMap[cur.parent]) {
                cur = nodeMap[cur.parent];
            } else break;
        }
        if (parts.length <= 1) return '';
        var html = '<div class="dp-breadcrumb">';
        parts.forEach(function (p, i) {
            if (i > 0) html += '<span class="dp-breadcrumb-sep">\u203a</span>';
            if (p.id !== node.id) {
                html += '<a href="#" onclick="GALAXY.focusScope(\'' + p.id + '\');return false">' + p.label + '</a>';
            } else {
                html += '<span style="color:var(--fg)">' + p.label + '</span>';
            }
        });
        html += '</div>';
        return html;
    }

    function showDetail(node) {
        var panel = document.getElementById('detailPanel');
        if (!panel) return;
        var name = node.kind === 'USER' ? titleCase(node.label.toLowerCase()) : node.label;
        var flagship = FLAGSHIPS[node.label];
        var accentColor = flagship ? flagship.color : (node.color || 'transparent');
        var html = '<div class="dp-header" style="border-top:3px solid ' + accentColor + '"><span class="dp-name" style="color:' + (node.color || '#f5f5f7') + '">' + name + '</span><button class="dp-close" onclick="GALAXY.closeDetail()">\u00d7</button></div>';
        // Breadcrumb
        html += buildBreadcrumb(node);
        // Compliance ring — THE PRODUCT (principals also get rings)
        if (node.kind !== 'USER' || node.principal) {
            var nodeBits = (typeof node.bits === 'number') ? node.bits : 0;
            var tierInfo = tierFor(nodeBits);
            html += '<div class="dp-ring">' + ringHTML(nodeBits, 140, node.missing_dims) + '</div>';
            html += '<div class="dp-tier" style="color:' + tierInfo.color + '">' + tierInfo.badge + ' ' + tierInfo.name + '</div>';

            // Missing dimensions
            if (node.missing_dims && node.missing_dims.length > 0 && node.missing_dims.length < 8) {
                html += '<div class="dp-intel"><div class="dp-intel-label">MISSING DIMENSIONS</div><div class="dp-dims">';
                node.missing_dims.forEach(function (d) { html += '<span class="dp-dim-missing">' + d + '</span>'; });
                html += '</div></div>';
            }

            // Next tier
            if (node.next_tier) {
                html += '<div class="dp-intel"><div class="dp-intel-label">NEXT TIER</div><div class="dp-intel-value">' + node.next_tier + ' <span style="opacity:0.5">(+' + node.next_tier_gap + ' bits)</span></div></div>';
            }

            // INTEL summary — THE SERVICE
            if (node.intel_summary) {
                html += '<div class="dp-intel"><div class="dp-intel-label">INTEL</div><div class="dp-intel-value" style="font-size:11px;line-height:1.5">' + node.intel_summary + '</div></div>';
            } else if (node.has_intel === false && node.kind !== 'USER' && nodeBits < 255) {
                html += '<div class="dp-intel"><div class="dp-intel-label">INTEL</div><div class="dp-intel-value" style="color:#ff453a;font-size:11px">MISSING — LANG dimension blocked</div></div>';
            }

            // ROADMAP NOW
            if (node.roadmap_now) {
                html += '<div class="dp-intel"><div class="dp-intel-label">ROADMAP NOW</div><div class="dp-intel-value" style="font-size:11px;line-height:1.5">' + node.roadmap_now + '</div></div>';
            }

            // LEARNING patterns
            if (node.learning_count) {
                html += '<div class="dp-intel"><div class="dp-intel-label">LEARNING</div><div class="dp-intel-value">' + node.learning_count + ' patterns</div></div>';
            }
        }
        html += '<div class="dp-meta">';
        html += '<div class="dp-row"><span class="dp-label">Kind</span><span class="dp-value" style="color:' + (node.color || '#f5f5f7') + '">' + node.kind + '</span></div>';
        html += '<div class="dp-row"><span class="dp-label">Category</span><span class="dp-value">' + (node.category || '') + '</span></div>';
        if (node.children > 0) html += '<div class="dp-row"><span class="dp-label">Children</span><span class="dp-value">' + node.children + '</span></div>';
        // Show federation org for users
        if (node.kind === 'USER') {
            var key = userKey(node.id);
            var fedKey = USER_ORGS[key];
            if (fedKey) {
                var fed = FEDERATION[fedKey];
                html += '<div class="dp-row"><span class="dp-label">Organization</span><span class="dp-value" style="color:' + fed.color + '">' + fed.label + '</span></div>';
            }
        }
        html += '</div>';

        // For federation orgs, show their members
        var isFed = (node.id || '').indexOf('fed:') === 0;
        if (isFed) {
            var fedKey = node.id.replace('fed:', '');
            var members = galaxy.nodes.filter(function (n) {
                return n.kind === 'USER' && USER_ORGS[userKey(n.id)] === fedKey && canSeeNode(n);
            });
            if (members.length) {
                html += '<div class="dp-section"><div class="dp-section-title">Members (' + members.length + ')</div><div class="dp-inheritors">';
                members.forEach(function (m) {
                    html += '<span class="dp-child" style="border-color:' + (node.color || '#f5f5f7') + ';color:' + (node.color || '#f5f5f7') + '" onclick="GALAXY.focusScope(\'' + m.id + '\')">' + titleCase(m.label.toLowerCase()) + '</span>';
                });
                html += '</div></div>';
            }
        }

        var kids = galaxy.nodes.filter(function (c) { return c.parent === node.id && canSeeNode(c); });
        if (kids.length) {
            html += '<div class="dp-section"><div class="dp-section-title">Contains (' + kids.length + ')</div><div class="dp-inheritors">';
            kids.slice(0, 20).forEach(function (c) {
                var cname = c.kind === 'USER' ? titleCase(c.label.toLowerCase()) : c.label;
                html += '<span class="dp-child" style="border-color:' + c.color + ';color:' + c.color + '" onclick="GALAXY.focusScope(\'' + c.id + '\')">' + cname + '</span>';
            });
            if (kids.length > 20) html += '<span class="dp-child" style="border-color:#86868b;color:#86868b">+' + (kids.length - 20) + ' more</span>';
            html += '</div></div>';
        }
        // Flagship launch button
        if (flagship) {
            html += '<a class="dp-launch" href="' + flagship.url + '">Open ' + node.label + ' \u2192</a>';
        }

        panel.innerHTML = html;
        panel.classList.add('open');
    }

    function closeDetail() {
        var panel = document.getElementById('detailPanel');
        if (panel) panel.classList.remove('open');
    }

    // ── SEARCH / SPOTLIGHT ──────────────────────────────
    function handleSearch(query) {
        if (!galaxy) return;
        var q = query.toLowerCase().trim();
        var resultsEl = document.getElementById('spotlightResults');
        if (!resultsEl) return;
        if (!q) {
            resultsEl.innerHTML = '<div class="spotlight-empty">Type to search scopes, services, users...</div>';
            if (network) network.setSelection({ nodes: [], edges: [] });
            return;
        }
        var allNodes = galaxy.nodes.slice();
        Object.keys(FEDERATION).forEach(function (key) {
            allNodes.push({ id: 'fed:' + key, label: FEDERATION[key].label, kind: 'ORG', color: FEDERATION[key].color });
        });
        var matches = allNodes.filter(function (n) {
            if (!canSeeNode(n)) return false;
            return n.label.toLowerCase().indexOf(q) >= 0
                || (n.kind || '').toLowerCase().indexOf(q) >= 0
                || (n.category || '').toLowerCase().indexOf(q) >= 0
                || (n.tier || '').toLowerCase().indexOf(q) >= 0;
        });
        // Sort: flagships first, then by bits descending
        matches.sort(function (a, b) {
            var aF = FLAGSHIPS[a.label] ? 1 : 0;
            var bF = FLAGSHIPS[b.label] ? 1 : 0;
            if (aF !== bF) return bF - aF;
            return (b.bits || 0) - (a.bits || 0);
        });
        matches = matches.slice(0, 10);

        if (matches.length === 0) {
            resultsEl.innerHTML = '<div class="spotlight-empty">No results for "' + q + '"</div>';
            return;
        }

        var html = '';
        matches.forEach(function (m) {
            var tier = tierFor(m.bits || 0);
            var flagship = FLAGSHIPS[m.label];
            var bgColor = flagship ? flagship.color : (m.color || '#64748b');
            var displayName = m.kind === 'USER' ? titleCase(m.label.toLowerCase()) : m.label;
            // Path context for disambiguation
            var pathCtx = '';
            if (m.id && m.id.indexOf('/') >= 0) {
                var parts = m.id.split('/');
                // Show last 2-3 path segments before the label
                var ctxParts = parts.slice(0, -1).slice(-2);
                pathCtx = ctxParts.join(' › ');
            }
            html += '<div class="spotlight-row" onclick="GALAXY.focusScope(\'' + m.id + '\');GALAXY.closeSpotlight()">';
            html += '<div class="spotlight-row-icon" style="background:' + hexToRgba(bgColor, 0.2) + ';color:' + bgColor + '"><i class="fas" style="font-size:14px">&#x' + iconFor(m).charCodeAt(0).toString(16) + ';</i></div>';
            html += '<div class="spotlight-row-info"><div class="spotlight-row-name" style="color:' + (m.color || '#f5f5f7') + '">' + displayName + '</div>';
            if (pathCtx) html += '<div style="font-family:var(--mono);font-size:9px;color:var(--dim);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + pathCtx + '</div>';
            html += '</div>';
            html += '<span class="spotlight-row-kind">' + (m.kind || 'SCOPE') + '</span>';
            if (typeof m.bits === 'number') html += '<span class="spotlight-row-bits" style="color:' + tier.color + '">' + m.bits + '</span>';
            html += '</div>';
        });
        resultsEl.innerHTML = html;
    }

    function openSpotlight() {
        var el = document.getElementById('spotlight');
        if (!el) return;
        el.style.display = '';
        requestAnimationFrame(function () {
            el.classList.add('open');
            var input = document.getElementById('spotlightInput');
            if (input) { input.value = ''; input.focus(); }
            var resultsEl = document.getElementById('spotlightResults');
            if (resultsEl) resultsEl.innerHTML = '<div class="spotlight-empty">Type to search scopes, services, users...</div>';
        });
    }

    function closeSpotlight() {
        var el = document.getElementById('spotlight');
        if (!el) return;
        el.classList.remove('open');
        setTimeout(function () { el.style.display = 'none'; }, 200);
    }

    function focusScope(id) {
        var node = nodeMap[id];
        if (!node) return;
        if (nodeDS.get(id)) {
            network.focus(id, { scale: 2.5, animation: { duration: 600, easingFunction: 'easeInOutCubic' } });
        }
        showDetail(node);
        // Close intel panel when focusing a scope
        var ip = document.getElementById('intelPanel');
        if (ip) ip.classList.remove('open');
    }

    // ── BUILD GRAPH ──────────────────────────────────────
    function buildGraph(container) {
        var FA = '"Font Awesome 5 Free"';

        // Index
        galaxy.nodes.forEach(function (n) { nodeMap[n.id] = n; });

        // ── Build edge lookups from galaxy.json ──
        var inheritsTo = {};
        var clusterEdges = [];
        var domainEdges = [];
        (galaxy.edges || []).forEach(function (e) {
            if (e.kind === 'INHERITS') inheritsTo[e.from] = e.to;
            else if (e.kind === 'CLUSTER') clusterEdges.push(e);
            else if (e.kind === 'DOMAINS') domainEdges.push(e);
        });

        // Resolve governance ORG via INHERITS chain (not filesystem)
        function govOrg(node) {
            var cur = node, seen = {};
            while (cur) {
                if (seen[cur.id]) return null;
                seen[cur.id] = true;
                if (cur.kind === 'ORG') return cur.id;
                // Prefer INHERITS edge, fall back to parent
                var next = inheritsTo[cur.id] || cur.parent;
                if (!next) return null;
                cur = nodeMap[next];
            }
            return null;
        }

        // ── Classify: branches + users (visible) vs leaves (hidden) ──
        var branches = [];
        var users = [];
        var leaves = [];
        galaxy.nodes.forEach(function (n) {
            if (n.kind === 'ORG' || (n.children && n.children > 0)) {
                branches.push(n);
            } else if (n.kind === 'USER') {
                users.push(n);  // always visible, orbit ORG
            } else {
                leaves.push(n);
            }
        });

        var branchSet = new Set(branches.map(function (b) { return b.id; }));

        // Map leaves to nearest branch ancestor (filesystem)
        var hiddenLeaves = {};
        leaves.forEach(function (n) {
            var pid = n.parent;
            while (pid && !branchSet.has(pid)) {
                var p = nodeMap[pid];
                if (!p) break;
                pid = p.parent;
            }
            if (pid && branchSet.has(pid)) {
                if (!hiddenLeaves[pid]) hiddenLeaves[pid] = [];
                hiddenLeaves[pid].push(n);
            }
        });

        // ── Disambiguate duplicate labels among branches ──
        var labelCounts = {};
        branches.forEach(function (n) {
            labelCounts[n.label] = (labelCounts[n.label] || 0) + 1;
        });
        var STRUCTURAL_LABELS = { SERVICES: 1, TALK: 1, LEARNING: 1, FOUNDATION: 1, MAGIC: 1, SHOP: 1 };

        function disambiguatedLabel(n) {
            // Prefix structural duplicates with parent name for clarity
            if ((labelCounts[n.label] > 1 || STRUCTURAL_LABELS[n.label]) && n.parent) {
                var parent = nodeMap[n.parent];
                if (parent && parent.label && parent.label !== n.label) {
                    return parent.label + '/' + n.label;
                }
            }
            return n.label;
        }

        // ── Build branch nodes ──
        function makeBranchNode(n) {
            // Auth-aware: hide PRIVATE nodes the user cannot see
            if (n.privacy === 'PRIVATE' && !canSeeNode(n)) return null;

            var leafCount = hiddenLeaves[n.id] ? hiddenLeaves[n.id].length : 0;
            var label = disambiguatedLabel(n);
            if (leafCount > 0) label += '\n+' + leafCount;
            // Mark PRIVATE scopes the user CAN see with a lock indicator
            var isPrivateVisible = n.privacy === 'PRIVATE' && canSeeNode(n);
            if (isPrivateVisible) label = '\uf023 ' + label; // lock icon prefix

            var nodeBits = (typeof n.bits === 'number') ? n.bits : 0;

            if (n.kind === 'ORG') {
                return {
                    id: n.id, label: label, shape: 'icon',
                    icon: { face: FA, weight: '900', code: iconFor(n), size: 52, color: n.color },
                    font: { color: n.color, size: 14, vadjust: 8, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                    shadow: tierShadow(nodeBits),
                    mass: 4
                };
            }

            // Principal flagship — governors render as icons with tier glow
            if (n.principal) {
                return {
                    id: n.id, label: titleCase(label.toLowerCase()), shape: 'icon',
                    icon: { face: FA, weight: '900', code: '\uf505', size: 32, color: n.color || '#ec4899' },
                    font: { color: n.color || '#ec4899', size: 11, vadjust: 5, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                    shadow: tierShadow(nodeBits),
                    mass: 1.5
                };
            }

            // Flagship promotion — larger, glowing, heavier
            var flagship = FLAGSHIPS[n.label];
            if (flagship) {
                return {
                    id: n.id, label: label, shape: 'icon',
                    icon: { face: FA, weight: '900', code: flagship.icon, size: 44, color: flagship.color },
                    font: { color: flagship.color, size: 12, vadjust: 6, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                    shadow: { enabled: true, color: flagship.color, size: 30, x: 0, y: 0 },
                    mass: 2.5
                };
            }

            // Compliance-driven sizing (16-44px range)
            var size = 16 + (nodeBits / 255) * 28;
            var nodeColor = colorFor(n);
            if (isPrivateVisible) nodeColor = '#ffd60a';

            return {
                id: n.id, label: label, shape: 'icon',
                icon: { face: FA, weight: '900', code: iconFor(n), size: size, color: nodeColor },
                font: { color: isPrivateVisible ? '#ffd60a' : nodeColor, size: 9, vadjust: 4, multi: true, face: 'SF Mono, Menlo, monospace' },
                shadow: tierShadow(nodeBits),
                mass: 0.8 + (nodeBits / 255) * 1.5
            };
        }

        var nodes = branches.map(makeBranchNode).filter(function (n) { return n !== null; });

        // Add user nodes (orbit their ORG via governance)
        users.forEach(function (n) {
            nodes.push({
                id: n.id, label: titleCase(n.label.toLowerCase()), shape: 'box',
                margin: { top: 5, bottom: 5, left: 8, right: 8 },
                color: { background: 'rgba(255,255,255,0.03)', border: 'rgba(255,255,255,0.1)',
                         highlight: { background: 'rgba(255,255,255,0.08)', border: '#00ff88' } },
                font: { color: 'rgba(255,255,255,0.65)', size: 9, face: 'SF Mono, Menlo, monospace' },
                borderWidth: 1, mass: 0.3
            });
        });

        // ── Build tree edges between branches ──
        var edges = [];
        var eid = 0;
        branches.forEach(function (n) {
            if (!n.parent) return;
            var pid = n.parent;
            while (pid && !branchSet.has(pid)) {
                var p = nodeMap[pid];
                if (!p) break;
                pid = p.parent;
            }
            if (!pid || !branchSet.has(pid)) return;
            var parent = nodeMap[pid];
            var c = parent ? (parent.color || '#64748b') : '#64748b';
            edges.push({
                id: 'e' + (eid++), from: pid, to: n.id,
                color: { color: hexToRgba(c, 0.12), highlight: hexToRgba(c, 0.5), hover: hexToRgba(c, 0.3) },
                width: n.parent === pid ? 1.5 : 1,
                smooth: { type: 'continuous' }
            });
        });

        // ── User → ORG edges ──
        // Federated users orbit their federation org (primary).
        // Non-federated users (Canonic-native) orbit governance ORG.
        users.forEach(function (n) {
            var key = userKey(n.id);
            if (USER_ORGS[key]) return;  // handled by federation edges below
            var orgId = govOrg(n);
            if (!orgId) return;
            edges.push({
                id: 'u' + (eid++), from: orgId, to: n.id,
                color: { color: 'rgba(255,255,255,0.06)', highlight: 'rgba(255,255,255,0.25)' },
                width: 0.5, smooth: { type: 'continuous' }
            });
        });

        // ── Federation ORG nodes ──
        Object.keys(FEDERATION).forEach(function (key) {
            var fed = FEDERATION[key];
            var fedId = 'fed:' + key;
            var fedNode = { id: fedId, kind: 'ORG', label: fed.label, color: fed.color, category: 'FEDERATION', children: 0 };
            nodeMap[fedId] = fedNode;
            nodes.push({
                id: fedId, label: fed.label, shape: 'icon',
                icon: { face: FA, weight: '900', code: fed.icon, size: 40, color: fed.color },
                font: { color: fed.color, size: 12, vadjust: 6, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                shadow: { enabled: true, color: fed.color, size: 20, x: 0, y: 0 },
                mass: 2
            });
        });

        // ── Federation → HADLEYLAB bridge (you brought them in) ──
        Object.keys(FEDERATION).forEach(function (key) {
            var fed = FEDERATION[key];
            var fedId = 'fed:' + key;
            edges.push({
                id: 'fbr:' + key, from: 'hadleylab-canonic/DEXTER', to: fedId,
                color: { color: hexToRgba(fed.color, 0.10), highlight: hexToRgba(fed.color, 0.4) },
                width: 1, dashes: [6, 10],
                smooth: { type: 'curvedCW', roundness: 0.2 }
            });
        });

        // ── User → Federation ORG edges (primary attractor) ──
        users.forEach(function (n) {
            var key = userKey(n.id);
            var fedKey = USER_ORGS[key];
            if (!fedKey) return;
            var fedId = 'fed:' + fedKey;
            var fedColor = FEDERATION[fedKey].color;
            edges.push({
                id: 'fed:' + (eid++), from: fedId, to: n.id,
                color: { color: hexToRgba(fedColor, 0.25), highlight: hexToRgba(fedColor, 0.6) },
                width: 1.5,
                smooth: { type: 'continuous' }
            });
        });

        // Bridge between ORGs
        var orgs = branches.filter(function (n) { return n.kind === 'ORG'; });
        for (var i = 0; i < orgs.length; i++) {
            for (var j = i + 1; j < orgs.length; j++) {
                edges.push({
                    id: 'bridge' + i + j, from: orgs[i].id, to: orgs[j].id,
                    label: 'DISTRIBUTED COMPUTE',
                    font: { color: 'rgba(255,255,255,0.12)', size: 8, face: 'SF Mono, Menlo, monospace', strokeWidth: 0 },
                    color: { color: 'rgba(255,255,255,0.05)', highlight: 'rgba(255,255,255,0.25)' },
                    width: 2, dashes: [8, 12],
                    smooth: { type: 'curvedCW', roundness: 0.15 }
                });
            }
        }

        // ── CLUSTER edges (domain affinity between ORGs) ──
        var nodeIdSet = new Set(nodes.map(function (n) { return n.id; }));
        clusterEdges.forEach(function (ce) {
            if (!nodeIdSet.has(ce.from) || !nodeIdSet.has(ce.to)) return;
            var w = ce.weight || 1;
            edges.push({
                id: 'cluster:' + ce.from + ':' + ce.to,
                from: ce.from, to: ce.to,
                color: { color: 'rgba(0,255,136,0.08)', highlight: 'rgba(0,255,136,0.35)' },
                width: Math.min(w * 1.5, 5),
                dashes: [4, 8],
                smooth: { type: 'curvedCW', roundness: 0.25 },
                title: 'CLUSTER: ' + (ce.domains || []).join(', ')
            });
        });

        // ── DOMAINS edges (ORG → industry vertical) ──
        domainEdges.forEach(function (de) {
            if (!nodeIdSet.has(de.from) || !nodeIdSet.has(de.to)) return;
            edges.push({
                id: 'domain:' + de.from + ':' + de.to,
                from: de.from, to: de.to,
                color: { color: 'rgba(191,90,242,0.10)', highlight: 'rgba(191,90,242,0.4)' },
                width: 1, dashes: [2, 6],
                smooth: { type: 'curvedCCW', roundness: 0.3 }
            });
        });

        nodeDS = new vis.DataSet(nodes);
        edgeDS = new vis.DataSet(edges);

        network = new vis.Network(container, { nodes: nodeDS, edges: edgeDS }, {
            physics: {
                barnesHut: {
                    gravitationalConstant: -18000,
                    centralGravity: 0.08,
                    springLength: 280,
                    springConstant: 0.02,
                    damping: 0.4,
                    avoidOverlap: 0.6
                },
                maxVelocity: 80,
                minVelocity: 0.3,
                stabilization: { iterations: 800, updateInterval: 25 }
            },
            nodes: { shape: 'dot' },
            edges: { arrows: { to: { enabled: false } }, smooth: { forceDirection: 'none' } },
            interaction: { hover: true, tooltipDelay: 150, zoomView: true, dragView: true, zoomSpeed: 0.08 }
        });

        // ── Expand / Collapse ──
        var expanded = {};

        function makeLeafVis(leaf, parentId) {
            if (leaf.kind === 'USER') {
                return {
                    id: leaf.id, label: titleCase(leaf.label.toLowerCase()), shape: 'box',
                    margin: { top: 5, bottom: 5, left: 8, right: 8 },
                    color: { background: 'rgba(255,255,255,0.03)', border: 'rgba(255,255,255,0.1)',
                             highlight: { background: 'rgba(255,255,255,0.08)', border: '#00ff88' } },
                    font: { color: 'rgba(255,255,255,0.65)', size: 9, face: 'SF Mono, Menlo, monospace' },
                    borderWidth: 1, mass: 0.3
                };
            }
            if (leaf.kind === 'SERVICE') {
                return {
                    id: leaf.id, label: leaf.label, shape: 'icon',
                    icon: { face: FA, weight: '900', code: iconFor(leaf), size: 20, color: colorFor(leaf) },
                    font: { color: '#86868b', size: 8, vadjust: 3, face: 'SF Mono, Menlo, monospace' },
                    mass: 0.5
                };
            }
            // SCOPE, DEAL, VERTICAL → text
            return {
                id: leaf.id, label: leaf.label, shape: 'text',
                font: { color: hexToRgba(leaf.color || '#64748b', 0.5), size: 9, face: 'SF Mono, Menlo, monospace' },
                mass: 0.3
            };
        }

        function expandBranch(branchId) {
            if (!hiddenLeaves[branchId] || expanded[branchId]) return;
            expanded[branchId] = true;

            var n = nodeMap[branchId];
            if (n) nodeDS.update({ id: branchId, label: n.label });

            hiddenLeaves[branchId].forEach(function (leaf) {
                nodeDS.add(makeLeafVis(leaf, branchId));
                edgeDS.add({
                    id: 'leaf:' + leaf.id, from: branchId, to: leaf.id,
                    color: { color: hexToRgba(leaf.color || '#64748b', 0.08) },
                    width: 0.5, smooth: { type: 'continuous' }
                });
            });
        }

        function collapseBranch(branchId) {
            if (!expanded[branchId]) return;
            expanded[branchId] = false;
            var n = nodeMap[branchId];
            if (n) nodeDS.update({ id: branchId, label: n.label + '\n+' + hiddenLeaves[branchId].length });
            hiddenLeaves[branchId].forEach(function (leaf) {
                try { nodeDS.remove(leaf.id); } catch (e) {}
                try { edgeDS.remove('leaf:' + leaf.id); } catch (e) {}
            });
        }

        function collapseAll() {
            Object.keys(expanded).forEach(function (id) {
                if (expanded[id]) collapseBranch(id);
            });
        }
        _collapseAll = collapseAll;

        // ── Click ──
        network.on('click', function (params) {
            if (params.nodes.length === 1) {
                var nid = params.nodes[0];
                var node = nodeMap[nid];

                // Toggle expand if it's a branch with leaves
                if (hiddenLeaves[nid]) {
                    if (expanded[nid]) {
                        collapseBranch(nid);
                    } else {
                        expandBranch(nid);
                        network.focus(nid, { scale: 2.0, animation: { duration: 600, easingFunction: 'easeInOutCubic' } });
                    }
                }
                if (node) showDetail(node);
            } else {
                closeDetail();
            }
        });

        network.on('doubleClick', function (params) {
            if (params.nodes.length === 1) {
                network.focus(params.nodes[0], { scale: 3.5, animation: { duration: 800, easingFunction: 'easeInOutCubic' } });
            }
        });
    }

    // ── HUD — Rich Information Meter ─────────────────────
    function renderHUD() {
        var hud = document.getElementById('hud');
        if (!hud) return;
        var users = 0, svcs = 0, orgs = 0, scopes = 0, totalBits = 0, bitCount = 0, healthCount = 0;
        galaxy.nodes.forEach(function (n) {
            if (!canSeeNode(n)) return;
            if (n.kind === 'USER') users++;
            else if (n.kind === 'SERVICE') svcs++;
            else if (n.kind === 'ORG') orgs++;
            else scopes++;
            if (typeof n.bits === 'number' && n.kind !== 'USER') {
                totalBits += n.bits;
                bitCount++;
                if (n.bits >= 35) healthCount++; // ≥ COMMUNITY tier
            }
        });
        orgs += Object.keys(FEDERATION).length;
        var avgBits = bitCount > 0 ? Math.round(totalBits / bitCount) : 0;
        var avgTier = tierFor(avgBits);
        var healthPct = bitCount > 0 ? Math.round((healthCount / bitCount) * 100) : 0;

        var html = ringHTML(avgBits, 100);
        html += '<div class="hud-bits-display" style="color:' + avgTier.color + '">' + avgBits + ' / 255</div>';
        html += '<div class="hud-label" style="color:' + avgTier.color + '">' + avgTier.badge + ' ' + avgTier.name + '</div>';
        html += '<div class="hud-divider"></div>';
        html += '<div class="hud-stats-grid">';
        html += '<div class="hud-stat"><span class="hud-stat-val">' + users + '</span> USER</div>';
        html += '<div class="hud-stat"><span class="hud-stat-val">' + orgs + '</span> ORGS</div>';
        html += '<div class="hud-stat"><span class="hud-stat-val">' + svcs + '</span> SRVCS</div>';
        html += '<div class="hud-stat"><span class="hud-stat-val">' + scopes + '</span> SCOPES</div>';
        html += '</div>';
        html += '<div class="hud-divider"></div>';
        html += '<div class="hud-health">';
        html += '<div class="hud-health-label">FLEET HEALTH</div>';
        html += '<div class="hud-health-bar"><div class="hud-health-fill" style="width:' + healthPct + '%;background:' + avgTier.color + '"></div></div>';
        html += '</div>';

        hud.innerHTML = html;
        // Dynamic border glow in tier color
        hud.style.borderColor = hexToRgba(avgTier.color, 0.3);
        hud.style.boxShadow = '0 0 16px ' + hexToRgba(avgTier.color, 0.15) + ', var(--shadow)';
    }

    // ── DOCK — Render flagship app icons ────────────────
    function renderDock() {
        var container = document.getElementById('dockApps');
        if (!container) return;
        var html = '';
        Object.keys(FLAGSHIPS).forEach(function (key) {
            var f = FLAGSHIPS[key];
            html += '<a class="dock-app" href="' + f.url + '" title="' + key + '" style="background:' + hexToRgba(f.color, 0.2) + '">';
            html += '<i class="fas" style="color:' + f.color + '">&#x' + f.icon.charCodeAt(0).toString(16) + ';</i>';
            html += '<span class="dock-app-label">' + key + '</span>';
            html += '</a>';
        });
        container.innerHTML = html;
    }

    // ── LEGEND — interactive category filter ───────────────
    var _activeCat = null;

    function renderLegend() {
        var el = document.getElementById('galaxyLegend');
        if (!el) return;
        var cats = ['KERNEL', 'RUNTIME', 'OPERATIONS', 'COMMERCE', 'KNOWLEDGE', 'GOVERNANCE', 'SERVICES', 'CONTENT', 'ORG'];
        var html = '';
        cats.forEach(function (cat) {
            html += '<div class="legend-cat" data-cat="' + cat + '" onclick="GALAXY.filterCategory(\'' + cat + '\')">';
            html += '<span class="legend-dot" style="background:' + CATEGORY_COLORS[cat] + '"></span>';
            html += cat;
            html += '</div>';
        });
        html += '<div class="legend-edges">';
        html += '<span style="color:rgba(255,255,255,0.3)">━</span> inherits &nbsp;';
        html += '<span style="color:rgba(255,255,255,0.2)">╌</span> cluster &nbsp;';
        html += '<span style="color:rgba(255,255,255,0.1)">┈</span> domains';
        html += '</div>';
        el.innerHTML = html;
    }

    function filterCategory(cat) {
        if (!nodeDS || !network) return;
        var legendEl = document.getElementById('galaxyLegend');

        if (_activeCat === cat) {
            // Toggle off — show all
            _activeCat = null;
            nodeDS.forEach(function (visNode) {
                var data = nodeMap[visNode.id];
                if (!data) return;
                nodeDS.update({ id: visNode.id, opacity: 1.0 });
            });
            if (legendEl) {
                legendEl.querySelectorAll('.legend-cat').forEach(function (el) {
                    el.classList.remove('active', 'dimmed');
                });
            }
            return;
        }

        _activeCat = cat;
        nodeDS.forEach(function (visNode) {
            var data = nodeMap[visNode.id];
            if (!data) return;
            var nodeCat = data.category || (data.kind === 'ORG' ? 'ORG' : 'SCOPE');
            var match = (nodeCat === cat) || (data.kind === cat);
            nodeDS.update({ id: visNode.id, opacity: match ? 1.0 : 0.12 });
        });

        if (legendEl) {
            legendEl.querySelectorAll('.legend-cat').forEach(function (el) {
                var elCat = el.getAttribute('data-cat');
                el.classList.toggle('active', elCat === cat);
                el.classList.toggle('dimmed', elCat !== cat);
            });
        }
    }

    // ── INTEL TASK MANAGER ──────────────────────────────────
    function renderIntelPanel() {
        var body = document.getElementById('intelBody');
        if (!body || !galaxy) return;

        // Collect actionable scopes: non-USER, bits < 255, has next_tier
        var tasks = galaxy.nodes.filter(function (n) {
            return canSeeNode(n) && n.kind !== 'USER' && typeof n.bits === 'number' && n.bits < 255 && n.bits > 0 && n.next_tier;
        });

        // Sort by gap ascending (smallest gap = most actionable)
        tasks.sort(function (a, b) { return (a.next_tier_gap || 999) - (b.next_tier_gap || 999); });

        // Limit to top 30
        tasks = tasks.slice(0, 30);

        if (tasks.length === 0) {
            body.innerHTML = '<div style="padding:20px;text-align:center;color:#86868b;font-size:11px;">ALL SCOPES AT MAGIC 255</div>';
            return;
        }

        var html = '';
        tasks.forEach(function (n) {
            var tier = tierFor(n.bits);
            var action = n.roadmap_now || (n.missing_dims && n.missing_dims.length > 0 ? 'Add: ' + n.missing_dims.join(', ') : 'Increase compliance');
            var gapLabel = n.next_tier ? '+' + n.next_tier_gap + ' → ' + n.next_tier : '';

            html += '<div class="intel-row" onclick="GALAXY.focusScope(\'' + n.id + '\')">';
            html += '<span class="intel-bits" style="color:' + tier.color + '">' + n.bits + '</span>';
            html += '<div class="intel-info">';
            html += '<div class="intel-scope" style="color:' + (n.color || '#f5f5f7') + '">' + n.label + '</div>';
            html += '<div class="intel-action">' + action + '</div>';
            html += '</div>';
            if (gapLabel) html += '<span class="intel-gap">' + gapLabel + '</span>';
            html += '</div>';
        });

        body.innerHTML = html;
    }

    // ── TRANSFORM SCOPES → GALAXY ─────────────────────────
    function transformScopes(scopes) {
        var childCount = {};
        scopes.forEach(function (s) {
            if (s.inherits) {
                childCount[s.inherits] = (childCount[s.inherits] || 0) + 1;
            }
        });

        var nodes = [];
        var edges = [];

        scopes.forEach(function (s) {
            var kind = 'SCOPE';
            if (s.category === 'ORG') kind = 'ORG';
            else if (s.category === 'SERVICES') kind = 'SERVICE';

            nodes.push({
                id: s.id,
                label: s.label,
                kind: kind,
                parent: s.inherits || null,
                children: childCount[s.id] || 0,
                color: s.color,
                category: s.category,
                bits: s.bits,
                source: s.source,
                repo: s.repo
            });

            if (s.inherits) {
                edges.push({ from: s.id, to: s.inherits, kind: 'INHERITS' });
            }
        });

        return { nodes: nodes, edges: edges };
    }

    // ── INIT ─────────────────────────────────────────────
    async function init(el) {
        // Validate auth session before building (affects node visibility)
        _authUser = await validateGalaxyAuth();

        var res = await fetch('../galaxy.json');
        var raw = await res.json();
        galaxy = Array.isArray(raw) ? transformScopes(raw) : raw;

        // Merge auth-gated private nodes if authenticated
        if (_authUser && galaxy.api_base) {
            try {
                var authRes = await fetch(galaxy.api_base + '/galaxy/auth', {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('canonic_session_token') }
                });
                if (authRes.ok) {
                    var priv = await authRes.json();
                    if (priv.nodes) galaxy.nodes = galaxy.nodes.concat(priv.nodes);
                    if (priv.edges) galaxy.edges = galaxy.edges.concat(priv.edges);
                }
            } catch (_) {}
        }

        var container = el || document.getElementById('galaxy');
        if (!container) return;
        buildGraph(container);
        renderHUD();
        renderIntelPanel();

        // Dismiss loading spinner + cinematic zoom after stabilization
        var loaderDismissed = false;
        function dismissLoader() {
            if (loaderDismissed) return;
            loaderDismissed = true;
            var loader = document.getElementById('galaxyLoader');
            if (loader) loader.classList.add('hidden');
            // Cinematic zoom-in: start wide, ease into the galaxy
            if (network) {
                network.moveTo({ scale: 0.5, animation: false });
                setTimeout(function () {
                    network.fit({ animation: { duration: 1800, easingFunction: 'easeInOutCubic' } });
                }, 100);
            }
        }
        if (network) {
            network.once('stabilizationIterationsDone', dismissLoader);
        }
        setTimeout(dismissLoader, 3000);

        renderDock();
        renderLegend();

        // Spotlight search
        var spotlightInput = document.getElementById('spotlightInput');
        if (spotlightInput) {
            spotlightInput.addEventListener('input', function () { handleSearch(this.value); });
            spotlightInput.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') { closeSpotlight(); }
            });
        }
        // Cmd+K / Ctrl+K opens spotlight
        document.addEventListener('keydown', function (e) {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                openSpotlight();
                return;
            }
            if (e.key === 'Escape') {
                var spotEl = document.getElementById('spotlight');
                if (spotEl && spotEl.classList.contains('open')) {
                    closeSpotlight();
                    return;
                }
                if (_collapseAll) _collapseAll();
                closeDetail();
                if (network) network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
            }
        });

        // Auto-hide nav on galaxy interaction
        var nav = document.querySelector('.nav');
        if (nav && document.body.classList.contains('galaxy-page')) {
            var hideTimer = null;
            function hideNav() { nav.classList.add('nav-hidden'); }
            function showNav() { nav.classList.remove('nav-hidden'); clearTimeout(hideTimer); }
            // Hide after 3s idle on load
            hideTimer = setTimeout(hideNav, 3000);
            // Hide when interacting with canvas
            container.addEventListener('pointerdown', function () {
                hideNav();
                clearTimeout(hideTimer);
            });
            // Show when pointer enters top 60px zone
            document.addEventListener('pointermove', function (e) {
                if (e.clientY < 60) showNav();
            });
            // Show on touch at top of screen
            document.addEventListener('touchstart', function (e) {
                var t = e.touches[0];
                if (t && t.clientY < 60) showNav();
            }, { passive: true });
            // Re-hide after 4s if no interaction with nav
            nav.addEventListener('pointerleave', function () {
                hideTimer = setTimeout(hideNav, 4000);
            });
            nav.addEventListener('pointerenter', function () {
                clearTimeout(hideTimer);
            });
        }
    }

    return { init: init, closeDetail: closeDetail, focusScope: focusScope, openSpotlight: openSpotlight, closeSpotlight: closeSpotlight, filterCategory: filterCategory, auth: function () { return _authUser; } };
})();
