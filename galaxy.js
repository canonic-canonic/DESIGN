/**
 * galaxy.js — GALAXY · CANONIC ∩ MAGIC
 *
 * Loads galaxy.json → vis-network.
 * Dual drawers: left (INTEL), right (DETAIL).
 * Control panel: brand + score + tier pills (top-left).
 * Category legend (top-right). Search bar (bottom center).
 *
 * MAGIC 255 | CANONIC | 2026-03
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
    var _leftOpen = false;
    var _rightOpen = false;
    var _searchOpen = false;
    var _selectedNodeId = null;
    var _viewMode = 'finder';  // 'finder' | 'graph'
    var _finderPath = [];       // breadcrumb stack of node IDs
    var _graphBuilt = false;
    var _talkMode = false;

    // ── AUTH (sourced from compiled galaxy.json — no hardcoding) ──
    var AUTH_API = '';

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
        if (readers.length === 0) return !!_authUser;
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

    function formatCoin(n) {
        return (n || 0).toLocaleString();
    }

    // ── LAUNCH URL RESOLVER ──
    // Vanity domains built dynamically from HTTP.json domains table.
    // Subdomain targets (e.g. omicschat.hadleylab.org) map to the scope label.
    // Fleet roots (hadleylab.org, canonic.org, gorunner.pro) map to ORG labels.
    var _vanityDomains = {};
    var _httpConfig = null;

    function buildVanityMap(http) {
        _httpConfig = http;
        // Fleet roots → ORG labels
        var fleet = http.fleet || {};
        Object.keys(fleet).forEach(function (repo) {
            var domain = fleet[repo];
            var label = repo.replace('.github.io', '').replace(/\//g, '-').toUpperCase();
            // e.g. hadleylab-canonic.github.io → HADLEYLAB, canonic-canonic.github.io → CANONIC
            if (label.indexOf('-CANONIC') > 0) label = label.replace('-CANONIC', '');
            _vanityDomains[label] = 'https://' + domain;
        });
        // Domain entries → scope labels from target path
        // Priority: .ai > other TLD vanity > subdomain
        (http.domains || []).forEach(function (d) {
            var domain = d.domain;
            var target = d.target || '';
            var parts = target.replace(/\/$/, '').split('/');
            var scopeName = (parts[parts.length - 1] || '').toUpperCase();
            if (!scopeName) return;
            var isAI = domain.endsWith('.ai');
            var isVanity = domain.split('.').length === 2;
            var existing = _vanityDomains[scopeName];
            if (!existing || isAI || (isVanity && !existing.endsWith('.ai'))) {
                _vanityDomains[scopeName] = 'https://' + domain;
            }
        });
    }

    function launchUrl(node) {
        if (!node) return '';
        var label = node.label || '';
        if (_vanityDomains[label]) return _vanityDomains[label];
        // TALK channels → hadleylab.org/talks/{channel}/
        if (node.talk && node.talk.channels && node.talk.channels.length > 0) {
            var channel = node.talk.channels[0].toLowerCase();
            return 'https://hadleylab.org/talks/' + channel + '/';
        }
        // Fleet path fallback → hadleylab.org/{fleet_path}
        if (node.fleet_path) {
            return 'https://hadleylab.org/' + node.fleet_path.toLowerCase() + '/';
        }
        return '';
    }

    // ── TIER (sourced from compiled galaxy.json tiers — no hardcoding) ──
    var _compiledTiers = [];

    function tierFor(bits) {
        for (var i = 0; i < _compiledTiers.length; i++) {
            if (bits >= _compiledTiers[i].threshold) return _compiledTiers[i];
        }
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
        INDUSTRIES:  '\uf275',  USERS:       '\uf0c0',
        COMPLIANCE:  '\uf058',  SURFACE:     '\uf108',
        PROGRAMMING: '\uf121',  MED:         '\uf21e',
        ONCO:        '\uf610',  DEALS:       '\uf2b5',
        PATENTS:     '\uf0e3',  BOOKS:       '\uf02d',
        DECKS:       '\uf1fe',  ORGS:        '\uf1ad',
        REGULATORY:  '\uf0e3',  HORIZONTAL:  '\uf0c9',
        VERTICALS:   '\uf0dc',  CARIBCHAT:   '\uf57d',
        COIN:        '\uf51e',  RUNNER:      '\uf544',
        OMICSCHAT:   '\uf471',  NONA:        '\uf1b0',
        STAR:        '\uf005',  DEV:         '\uf121',
    };

    var CATEGORY_ICONS = {
        SERVICES: '\uf0c0', RUNTIME: '\uf013', GOVERNANCE: '\uf19c',
        KNOWLEDGE: '\uf02d', COMMERCE: '\uf07a', OPERATIONS: '\uf0e8',
        CONTENT: '\uf15c', SCOPE: '\uf111',
    };

    function iconFor(n) {
        return SERVICE_ICONS[n.label] || CATEGORY_ICONS[n.category] || '\uf111';
    }

    // ── TIER SHADOW ──────────────────────────────────────
    function tierShadow(bits) {
        var b = (typeof bits === 'number') ? bits : 0;
        if (b >= 255) return { enabled: true, color: '#00ff88', size: 20, x: 0, y: 0 };
        if (b >= 127) return { enabled: true, color: '#2997ff', size: 12, x: 0, y: 0 };
        if (b >= 63)  return { enabled: true, color: '#bf5af2', size: 8, x: 0, y: 0 };
        if (b >= 43)  return { enabled: true, color: '#ff9f0a', size: 4, x: 0, y: 0 };
        return { enabled: false };
    }

    // ── FEDERATION (discovered from compiled galaxy.json — no hardcoding) ──
    var FEDERATION = {};   // populated from galaxy.federation[]
    var USER_ORGS = {};    // populated from node.organization field

    function buildFederationFromData() {
        // Build federation registry from compiled galaxy.json
        if (galaxy.federation) {
            galaxy.federation.forEach(function (f) {
                var key = f.label.toUpperCase().replace(/[^A-Z0-9]/g, '');
                FEDERATION[key] = { label: f.label, color: f.color || '#64748b', icon: '\uf1ad' };
            });
        }
        // Build user-org map from node.organization field on USER nodes
        galaxy.nodes.forEach(function (n) {
            if (n.kind === 'USER' && n.organization) {
                var key = userKey(n.id);
                var orgKey = n.organization.toUpperCase().replace(/[^A-Z0-9]/g, '');
                USER_ORGS[key] = orgKey;
                // Auto-create federation entry if not already present
                if (!FEDERATION[orgKey]) {
                    FEDERATION[orgKey] = { label: n.organization, color: '#64748b', icon: '\uf1ad' };
                }
            }
        });
    }

    function userKey(userId) {
        var parts = userId.split('/');
        return parts[parts.length - 1];
    }

    // ── COMPLIANCE RING SVG ──────────────────────────────
    function ringHTML(bits, sz, hideText) {
        sz = sz || 90;
        var cx = sz / 2, pct = Math.min(bits / 255, 1);
        // Tier-aware ring color
        var ringColor = '#00ff88';
        if (bits < 43) ringColor = '#ff453a';
        else if (bits < 63) ringColor = '#ff9f0a';
        else if (bits < 127) ringColor = '#bf5af2';
        else if (bits < 255) ringColor = '#2997ff';

        var svg = '<svg width="' + sz + '" height="' + sz + '" viewBox="0 0 ' + sz + ' ' + sz + '">';
        // Background track
        [{ r: sz * 0.47, w: 4 }, { r: sz * 0.40, w: 5 }, { r: sz * 0.33, w: 6 }].forEach(function (t) {
            svg += '<circle cx="' + cx + '" cy="' + cx + '" r="' + t.r + '" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="' + t.w + '"/>';
        });
        // Filled arcs
        [{ r: sz * 0.47, w: 4, o: 0.2 }, { r: sz * 0.40, w: 5, o: 0.45 }, { r: sz * 0.33, w: 6, o: 0.85 }].forEach(function (t) {
            var c = 2 * Math.PI * t.r;
            svg += '<circle cx="' + cx + '" cy="' + cx + '" r="' + t.r + '" fill="none" stroke="' + ringColor + '" stroke-width="' + t.w + '" opacity="' + t.o + '" stroke-dasharray="' + (c * pct) + ' ' + c + '" stroke-linecap="round" transform="rotate(-90 ' + cx + ' ' + cx + ')"/>';
        });
        if (!hideText) {
            svg += '<text x="' + cx + '" y="' + cx + '" text-anchor="middle" dominant-baseline="central" fill="' + ringColor + '" font-size="' + (sz * 0.22) + '" font-weight="700" font-family="SF Mono, Menlo, monospace">' + bits + '</text>';
        }
        svg += '</svg>';
        return svg;
    }

    // ── DETAIL (renders into tab content) ─────
    function renderDetailHTML(node) {
        var name = node.kind === 'USER' ? titleCase(node.label.toLowerCase()) : node.label;
        var html = '<div class="dp-header"><span class="dp-name" style="color:' + (node.color || '#f5f5f7') + '">' + name + '</span></div>';

        if (node.kind !== 'USER' || node.principal) {
            var nodeBits = (typeof node.bits === 'number') ? node.bits : 0;
            var tierInfo = tierFor(nodeBits);
            html += '<div class="dp-ring">';
            var nodeUrl = launchUrl(node);
            if (nodeUrl) {
                html += '<a href="' + nodeUrl + '" target="_blank" class="dp-ring-launch" title="' + node.label + '">';
                html += ringHTML(nodeBits, 140, true);
                html += '<div class="dp-rocket">\ud83d\ude80</div>';
                html += '</a>';
            } else {
                html += ringHTML(nodeBits, 140);
            }
            html += '</div>';
            html += '<div class="dp-tier" style="color:' + tierInfo.color + '">' + tierInfo.badge + ' ' + tierInfo.name + ' <span style="opacity:0.4;font-weight:400">\u00b7 ' + nodeBits + '/255</span></div>';

            // SCORE (composite governance + economy) with progress bar
            if (typeof node.score === 'number' && node.score > 0) {
                var scoreColor = tierFor(node.score).color;
                html += '<div class="dp-intel"><div class="dp-intel-label" style="color:' + scoreColor + '">SCORE</div>';
                html += '<div class="dp-intel-value" style="font-size:20px;font-weight:700;color:' + scoreColor + '">' + node.score + ' <span style="opacity:0.3;font-size:11px;font-weight:400">/ 255</span></div>';
                html += '<div class="dp-score-bar"><div class="dp-score-fill" style="width:' + Math.round(node.score / 255 * 100) + '%;background:linear-gradient(90deg,' + scoreColor + ',#fff)"></div></div>';
                html += '</div>';
            }

            // Missing dimensions (with fix buttons)
            if (node.missing_dims && node.missing_dims.length > 0 && node.missing_dims.length < 8) {
                html += '<div class="dp-intel"><div class="dp-intel-label">MISSING DIMENSIONS</div><div class="dp-dims">';
                node.missing_dims.forEach(function (d) {
                    html += '<span class="dp-dim-fix" onclick="event.stopPropagation(); GALAXY.fixDim(\'' + node.id + '\',\'' + d + '\')">' + d + ' <i class="fas fa-wrench" style="font-size:8px;margin-left:2px"></i></span>';
                });
                html += '</div>';
                html += '<button type="button" class="dp-fix-all" onclick="GALAXY.fixScope(\'' + node.id + '\')"><i class="fas fa-tools"></i> FIX ALL (' + node.missing_dims.length + ' gaps)</button>';
                html += '</div>';
            }

            // Next tier
            if (node.next_tier) {
                html += '<div class="dp-intel"><div class="dp-intel-label">NEXT TIER</div><div class="dp-intel-value">' + node.next_tier + ' <span style="opacity:0.5">(+' + node.next_tier_gap + ' bits)</span></div></div>';
            }

            // INTEL summary
            if (node.intel_summary) {
                html += '<div class="dp-intel"><div class="dp-intel-label">INTEL</div><div class="dp-intel-value" style="font-size:11px;line-height:1.5">' + node.intel_summary + '</div></div>';
            } else if (node.has_intel === false && node.kind !== 'USER' && nodeBits < 255) {
                html += '<div class="dp-intel"><div class="dp-intel-label">INTEL</div><div class="dp-intel-value" style="color:#ff453a;font-size:11px">MISSING</div></div>';
            }

            // ROADMAP NOW
            if (node.roadmap_now) {
                html += '<div class="dp-intel"><div class="dp-intel-label">ROADMAP NOW</div><div class="dp-intel-value" style="font-size:11px;line-height:1.5">' + node.roadmap_now + '</div></div>';
            }

            // LEARNING patterns (expanded, not just count)
            if (node.learning && node.learning.length > 0) {
                html += '<div class="dp-intel"><div class="dp-intel-label">LEARNING (' + node.learning.length + ')</div>';
                node.learning.slice(0, 5).forEach(function (p) {
                    html += '<div class="dp-learning-row"><span class="dp-learning-signal">' + p.signal + '</span><span class="dp-learning-pattern">' + p.pattern + '</span><span class="dp-learning-date">' + p.date + '</span></div>';
                });
                html += '</div>';
            } else if (node.learning_count) {
                html += '<div class="dp-intel"><div class="dp-intel-label">LEARNING</div><div class="dp-intel-value">' + node.learning_count + ' patterns</div></div>';
            }

            // COIN (economy)
            if (node.wallet) {
                html += '<div class="dp-intel"><div class="dp-intel-label" style="color:#ffd60a">ECONOMY</div>';
                html += '<div class="dp-intel-value" style="font-size:18px;font-weight:700;color:#ffd60a;text-shadow:0 0 12px rgba(255,214,10,0.3)">' + formatCoin(node.wallet.balance) + ' <span style="opacity:0.4;font-size:10px;font-weight:400">COIN</span></div>';
                html += '<div style="display:flex;gap:12px;margin-top:4px">';
                html += '<span style="font-family:var(--mono);font-size:10px;color:#86868b">' + node.wallet.events + ' events</span>';
                if (node.wallet.last_close) {
                    html += '<span style="font-family:var(--mono);font-size:10px;color:#86868b">close ' + node.wallet.last_close + '</span>';
                }
                html += '</div></div>';
            }

            // TALK (chat activity)
            if (node.talk && node.talk.sessions > 0) {
                html += '<div class="dp-intel"><div class="dp-intel-label" style="color:#2997ff">TALK</div>';
                html += '<div class="dp-intel-value" style="font-size:16px;font-weight:700;color:#2997ff">' + node.talk.sessions + ' <span style="opacity:0.4;font-size:10px;font-weight:400">sessions</span></div>';
                if (node.talk.channels && node.talk.channels.length > 0) {
                    html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">';
                    node.talk.channels.forEach(function (ch) {
                        html += '<span style="font-family:var(--mono);font-size:9px;padding:2px 6px;border-radius:4px;background:rgba(41,151,255,0.1);color:#2997ff;border:1px solid rgba(41,151,255,0.15)">' + ch + '</span>';
                    });
                    html += '</div>';
                }
                // Launch button for TALK services
                var lUrl = launchUrl(node);
                if (lUrl) {
                    html += '<a class="dp-launch" href="' + lUrl + '" target="_blank">\ud83d\ude80 ' + node.label + '</a>';
                }
                html += '</div>';
            }
        }

        html += '<div class="dp-meta">';
        html += '<div class="dp-row"><span class="dp-label">Kind</span><span class="dp-value" style="color:' + (node.color || '#f5f5f7') + '">' + node.kind + '</span></div>';
        html += '<div class="dp-row"><span class="dp-label">Category</span><span class="dp-value">' + (node.category || '') + '</span></div>';
        if (node.children > 0) html += '<div class="dp-row"><span class="dp-label">Children</span><span class="dp-value">' + node.children + '</span></div>';
        if (node.kind === 'USER') {
            var key = userKey(node.id);
            var fedKey = USER_ORGS[key];
            if (fedKey) {
                var fed = FEDERATION[fedKey];
                html += '<div class="dp-row"><span class="dp-label">Organization</span><span class="dp-value" style="color:' + fed.color + '">' + fed.label + '</span></div>';
            }
        }
        html += '</div>';

        // Federation members
        var isFed = (node.id || '').indexOf('fed:') === 0;
        if (isFed) {
            var fedKey2 = node.id.replace('fed:', '');
            var members = galaxy.nodes.filter(function (n) {
                return n.kind === 'USER' && USER_ORGS[userKey(n.id)] === fedKey2;
            });
            if (members.length) {
                html += '<div class="dp-section"><div class="dp-section-title">Members (' + members.length + ')</div><div class="dp-inheritors">';
                members.forEach(function (m) {
                    html += '<span class="dp-child" style="border-color:' + (node.color || '#f5f5f7') + ';color:' + (node.color || '#f5f5f7') + '" onclick="GALAXY.focusScope(\'' + m.id + '\')">' + titleCase(m.label.toLowerCase()) + '</span>';
                });
                html += '</div></div>';
            }
        }

        var kids = galaxy.nodes.filter(function (c) { return c.parent === node.id; });
        if (kids.length) {
            html += '<div class="dp-section"><div class="dp-section-title">Contains (' + kids.length + ')</div><div class="dp-inheritors">';
            kids.slice(0, 20).forEach(function (c) {
                var cname = c.kind === 'USER' ? titleCase(c.label.toLowerCase()) : c.label;
                html += '<span class="dp-child" style="border-color:' + c.color + ';color:' + c.color + '" onclick="GALAXY.focusScope(\'' + c.id + '\')">' + cname + '</span>';
            });
            if (kids.length > 20) html += '<span class="dp-child" style="border-color:#86868b;color:#86868b">+' + (kids.length - 20) + ' more</span>';
            html += '</div></div>';
        }
        return html;
    }

    function showDetail(node) {
        _selectedNodeId = node.id;
        renderControlPanel();
        openRightDrawer();
    }

    function closeDetail() {
        _selectedNodeId = null;
        renderControlPanel();
        closeRightDrawer();
    }

    function clearScope() {
        _selectedNodeId = null;
        renderControlPanel();
    }

    // ── DRAWER MANAGEMENT ─────────────────────────────
    function openLeftDrawer() {
        var el = document.getElementById('leftDrawer');
        if (!el || !galaxy) return;
        closeSearch();
        el.innerHTML = '<div class="ld-header"><span class="ld-title">INTEL</span><button class="ld-close" onclick="GALAXY.closeLeft()">&times;</button></div>' + renderIntelTab();
        el.classList.add('open');
        _leftOpen = true;
    }

    function closeLeftDrawer() {
        var el = document.getElementById('leftDrawer');
        if (el) el.classList.remove('open');
        _leftOpen = false;
    }

    function toggleLeft() {
        if (_leftOpen) closeLeftDrawer();
        else openLeftDrawer();
    }

    function openRightDrawer() {
        var el = document.getElementById('rightDrawer');
        if (!el) return;
        closeSearch();
        if (_selectedNodeId && nodeMap[_selectedNodeId]) {
            el.innerHTML = renderDetailHTML(nodeMap[_selectedNodeId]);
        } else {
            el.innerHTML = '<div style="padding:24px;text-align:center;color:#86868b;font-size:11px;font-family:var(--mono)">Click a node to view details</div>';
        }
        el.classList.add('open');
        _rightOpen = true;
    }

    function closeRightDrawer() {
        var el = document.getElementById('rightDrawer');
        if (el) el.classList.remove('open');
        _rightOpen = false;
    }

    function toggleRight() {
        if (_rightOpen) closeRightDrawer();
        else openRightDrawer();
    }

    // ── MASTER SCORE (floating game HUD) ──────────────────
    // Category colors from GALAXY.md spec
    var CATEGORY_COLORS = {
        KERNEL: '#ff0088', RUNTIME: '#00ff88', OPERATIONS: '#2997ff',
        COMMERCE: '#ff9f0a', KNOWLEDGE: '#bf5af2', GOVERNANCE: '#ffd60a',
        SERVICES: '#ec4899', CONTENT: '#a78bfa', ORG: '#64748b'
    };

    function renderControlPanel() {
        var el = document.getElementById('controlPanel');
        if (!el || !galaxy) return;

        // Interactively scoped: show selected node or master
        var scoped = _selectedNodeId ? nodeMap[_selectedNodeId] : null;
        var bits, balance, tier, label;
        if (scoped) {
            bits = scoped.bits || 0;
            balance = scoped.wallet ? scoped.wallet.balance : 0;
            tier = tierFor(bits);
            label = scoped.label;
        } else {
            var master = galaxy.master;
            bits = master ? master.bits : 0;
            balance = master ? master.wallet_balance : (galaxy.stats ? galaxy.stats.total_coin : 0);
            tier = tierFor(bits);
            label = '';
        }

        var tierClass = bits >= 255 ? ' unicorn-text' : '';
        var html = '';

        // Close scope button
        if (scoped) {
            html += '<button class="cp-close" onclick="GALAXY.clearScope()" title="Back to master">&times;</button>';
        }

        // Personal identity (when authenticated) or brand fallback
        if (_authUser && _authUser.avatar_url) {
            html += '<div class="cp-identity">';
            html += '<img class="cp-avatar" src="' + _authUser.avatar_url + '" alt="">';
            html += '<div class="cp-identity-info">';
            var displayName = _authUser.name || _authUser.login || 'Governor';
            html += '<div class="cp-greeting">' + displayName.split(' ')[0] + '</div>';
            html += '<div class="cp-username">@' + (_authUser.login || '') + '</div>';
            html += '</div></div>';
        } else {
            html += '<div class="cp-brand">';
            html += '<div class="cp-brand-title">CANONIC</div>';
            html += '<div class="cp-brand-sub">\u2229 MAGIC</div>';
            html += '</div>';
        }

        // Score: ring + tier + coin
        html += '<div class="cp-score">';
        html += '<div class="cp-ring" onclick="GALAXY.toggleLeft()" title="Open INTEL">';
        html += ringHTML(bits, 48, true);
        html += '<span class="cp-bits">' + bits + '</span>';
        html += '</div>';
        html += '<div class="cp-stats">';
        html += '<div class="cp-tier' + tierClass + '" style="' + (tierClass ? '' : 'color:' + tier.color) + '">' + tier.badge + ' ' + tier.name + '</div>';
        html += '<a class="cp-coin" href="https://hadleylab.org/timeline/" target="_blank" title="Open Wallet"><i class="fas fa-coins"></i> ' + formatCoin(balance) + '</a>';
        if (label) {
            html += '<div class="cp-scope-label">' + label + '</div>';
        }
        html += '</div></div>';

        // View toggle (stable across both views)
        var finderActive = _viewMode === 'finder' ? ' active' : '';
        var graphActive = _viewMode === 'graph' ? ' active' : '';
        html += '<div class="cp-divider"></div>';
        html += '<div class="cp-view-toggle">';
        html += '<span class="fc-toggle-btn' + finderActive + '" onclick="GALAXY.setView(\'finder\')"><i class="fas fa-th-list"></i> Finder</span>';
        html += '<span class="fc-toggle-btn' + graphActive + '" onclick="GALAXY.setView(\'graph\')"><i class="fas fa-project-diagram"></i> Graph</span>';
        html += '</div>';

        // Breadcrumb (Finder only)
        if (_viewMode === 'finder' && _finderPath.length > 0) {
            html += '<div class="cp-breadcrumb">';
            html += '<span class="cp-crumb" onclick="GALAXY.navigateToRoot()"><i class="fas fa-home" style="font-size:9px"></i></span>';
            _finderPath.forEach(function (nid, i) {
                var n = nodeMap[nid];
                if (!n) return;
                html += ' <span style="opacity:.3">/</span> ';
                if (i === _finderPath.length - 1) {
                    html += '<span class="cp-crumb cp-crumb-current">' + n.label + '</span>';
                } else {
                    html += '<span class="cp-crumb" onclick="GALAXY.navigateToBreadcrumb(' + i + ')">' + n.label + '</span>';
                }
            });
            html += '</div>';
        }

        // Graph-only: fleet stats + tier pills (hidden in Finder)
        if (_viewMode === 'graph') {
            var st = galaxy.stats || {};
            var userCount = st.user_count || 0;
            var orgCount = st.org_count || 0;
            var svcCount = st.svc_count || 0;
            var scopeCount = st.scope_count || 0;
            var healthPct = st.fleet_health_pct || 0;

            html += '<div class="cp-divider"></div>';
            html += '<div class="cp-fleet-stats">';
            html += '<span class="cp-fleet-stat' + (_activeFilter === 'kind:USER' ? ' active' : '') + '" onclick="GALAXY.filterKind(\'USER\')" title="Filter users"><span class="cp-fleet-num">' + userCount + '</span> USER</span>';
            html += '<span class="cp-fleet-stat' + (_activeFilter === 'kind:ORG' ? ' active' : '') + '" onclick="GALAXY.filterKind(\'ORG\')" title="Filter orgs"><span class="cp-fleet-num">' + orgCount + '</span> ORGS</span>';
            html += '</div>';
            html += '<div class="cp-fleet-stats">';
            html += '<span class="cp-fleet-stat' + (_activeFilter === 'kind:SERVICE' ? ' active' : '') + '" onclick="GALAXY.filterKind(\'SERVICE\')" title="Filter services"><span class="cp-fleet-num">' + svcCount + '</span> SRVCS</span>';
            html += '<span class="cp-fleet-stat' + (_activeFilter === 'kind:SCOPE' ? ' active' : '') + '" onclick="GALAXY.filterKind(\'SCOPE\')" title="Filter scopes"><span class="cp-fleet-num">' + scopeCount + '</span> SCOPES</span>';
            html += '</div>';

            var healthColor = healthPct >= 90 ? '#22c55e' : healthPct >= 70 ? '#eab308' : '#ef4444';
            html += '<div class="cp-health" onclick="GALAXY.filterHealthy(false)" title="Fleet health">';
            html += '<div class="cp-health-label">FLEET HEALTH</div>';
            html += '<div class="cp-health-bar"><div class="cp-health-fill" style="width:' + healthPct + '%;background:' + healthColor + '"></div></div>';
            html += '</div>';

            var tierCounts = {};
            _compiledTiers.forEach(function (t) { tierCounts[t.name] = 0; });
            galaxy.nodes.forEach(function (n) {
                if (n.kind !== 'USER' && typeof n.bits === 'number') {
                    var t = tierFor(n.bits);
                    if (tierCounts[t.name] !== undefined) tierCounts[t.name]++;
                    else tierCounts[t.name] = 1;
                }
            });

            html += '<div class="cp-divider"></div>';
            html += '<div class="cp-filters">';
            _compiledTiers.forEach(function (t) {
                var cnt = tierCounts[t.name] || 0;
                if (cnt > 0) {
                    var active = _activeFilter === 'tier:' + t.name ? ' active' : '';
                    html += '<span class="filter-pill' + active + '" style="color:' + t.color + ';border-color:' + hexToRgba(t.color, 0.4) + '" onclick="GALAXY.filterTier(\'' + t.name + '\')">' + t.badge + ' ' + t.name + ' <span style="opacity:0.5;font-size:8px">' + cnt + '</span></span>';
                }
            });
            html += '</div>';
        }

        el.innerHTML = html;
    }

    function renderCatLegend() {
        var el = document.getElementById('catLegend');
        if (!el || !galaxy) return;
        // Hide in Finder mode (graph-only affordance)
        if (_viewMode === 'finder') { el.style.display = 'none'; return; }
        el.style.display = '';

        var catCounts = {};
        galaxy.nodes.forEach(function (n) {
            if (n.category) catCounts[n.category] = (catCounts[n.category] || 0) + 1;
        });

        var html = '';
        Object.keys(CATEGORY_COLORS).forEach(function (cat) {
            if (!catCounts[cat]) return;
            var active = _activeFilter === cat ? ' active' : '';
            html += '<span class="cat-dot' + active + '" onclick="GALAXY.filterCategory(\'' + cat + '\')">';
            html += '<span class="cat-dot-circle" style="background:' + CATEGORY_COLORS[cat] + ';color:' + CATEGORY_COLORS[cat] + '"></span>';
            html += cat;
            html += '</span>';
        });

        el.innerHTML = html;
    }

    // ── INTEL TAB (task list with fix buttons) ────────────
    function renderIntelTab() {
        var users = 0, totalBits = 0, bitCount = 0, health = 0, scopeCount = 0;
        galaxy.nodes.forEach(function (n) {
            if (n.kind === 'USER') { users++; return; }
            if (typeof n.bits === 'number') {
                totalBits += n.bits; bitCount++; scopeCount++;
                if (n.bits >= 35) health++;
            }
        });
        var avgBits = bitCount > 0 ? Math.round(totalBits / bitCount) : 0;
        var avgTier = tierFor(avgBits);
        var stats = galaxy.stats || {};
        var healthPct = scopeCount > 0 ? Math.round(100 * health / scopeCount) : 0;

        var tierClass = avgBits >= 255 ? ' unicorn-text' : '';
        var html = '<div style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)">';
        html += ringHTML(avgBits, 48);
        html += '<div style="flex:1;min-width:0">';
        html += '<div class="' + tierClass + '" style="font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:0.1em;' + (tierClass ? '' : 'color:' + avgTier.color) + '">' + avgTier.name + '</div>';
        html += '<div style="font-family:var(--mono);font-size:9px;color:var(--dim);opacity:0.5">' + galaxy.nodes.length + ' nodes \u00b7 ' + healthPct + '% fleet \u00b7 ' + users + ' people</div>';
        html += '</div></div>';

        // INTEL tasks
        var tasks = galaxy.nodes.filter(function (n) {
            return n.kind !== 'USER' && typeof n.bits === 'number' && n.bits < 255 && n.bits > 0 && n.next_tier;
        }).sort(function (a, b) { return (a.next_tier_gap || 999) - (b.next_tier_gap || 999); }).slice(0, 30);

        html += '<div style="font-family:var(--mono);font-size:9px;color:var(--dim);letter-spacing:0.12em;padding:8px 16px 4px">INTEL \u00b7 ' + tasks.length + ' tasks</div>';
        html += '<div class="intel-tasks">';
        if (tasks.length === 0) {
            html += '<div style="padding:12px 16px;text-align:center;color:#86868b;font-size:10px">All scopes at MAGIC 255</div>';
        } else {
            tasks.forEach(function (n) {
                var tier = tierFor(n.bits);
                var action = n.roadmap_now || (n.missing_dims && n.missing_dims.length > 0 ? 'Add ' + n.missing_dims.join(', ') : 'Increase compliance');
                var gapLabel = n.next_tier ? '+' + n.next_tier_gap + ' \u2192 ' + n.next_tier : '';
                html += '<div class="intel-task" data-node="' + n.id + '" onclick="event.stopPropagation(); GALAXY.fixFromIntel(\'' + n.id + '\')">';
                html += '<span class="intel-task-bits" style="color:' + tier.color + '">' + n.bits + '</span>';
                html += '<div class="intel-task-info"><div class="intel-task-name" style="color:' + (n.color || '#f5f5f7') + '">' + n.label + '</div>';
                html += '<div class="intel-task-action">' + action + '</div></div>';
                if (gapLabel) html += '<span class="intel-task-gap">' + gapLabel + '</span>';
                html += '<button type="button" class="intel-task-fix" onclick="event.stopPropagation(); GALAXY.fixScope(\'' + n.id + '\')" title="Fix"><i class="fas fa-wrench"></i></button>';
                html += '</div>';
            });
        }
        html += '</div>';
        return html;
    }

    // ── FIX FUNCTIONS (cross-panel coordination) ──────────
    function pulseNode(nodeId) {
        if (!nodeDS || !nodeDS.get(nodeId)) return;
        var orig = nodeDS.get(nodeId);
        var origSize = orig.icon ? orig.icon.size : 20;
        var bigger = {};
        for (var k in orig.icon) bigger[k] = orig.icon[k];
        bigger.size = origSize * 1.5;
        nodeDS.update({ id: nodeId, icon: bigger });
        setTimeout(function () {
            var restore = {};
            for (var k2 in orig.icon) restore[k2] = orig.icon[k2];
            restore.size = origSize;
            nodeDS.update({ id: nodeId, icon: restore });
        }, 600);
    }

    function highlightTask(nodeId) {
        var tasks = document.querySelectorAll('.intel-task');
        for (var i = 0; i < tasks.length; i++) {
            tasks[i].classList.remove('active');
        }
        var target = document.querySelector('.intel-task[data-node="' + nodeId + '"]');
        if (target) {
            target.classList.add('active');
            target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    function fixFromIntel(nodeId) {
        var node = nodeMap[nodeId];
        if (!node) return;
        _selectedNodeId = nodeId;
        renderControlPanel();
        highlightTask(nodeId);
        pulseNode(nodeId);
        if (nodeDS && nodeDS.get(nodeId)) {
            network.focus(nodeId, { scale: 1.5, animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        }
        openRightDrawer();
    }

    function fixScope(nodeId) {
        var node = nodeMap[nodeId];
        if (!node) return;
        pulseNode(nodeId);
        if (nodeDS && nodeDS.get(nodeId)) {
            network.focus(nodeId, { scale: 1.5, animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        }
        _selectedNodeId = nodeId;
        renderControlPanel();
        openRightDrawer();
        var url = launchUrl(node);
        if (url) window.open(url, '_blank');
    }

    function fixDim(nodeId, dimName) {
        var node = nodeMap[nodeId];
        if (!node) return;
        pulseNode(nodeId);
        var url = launchUrl(node);
        if (url) window.open(url, '_blank');
    }

    // ── SEARCH BAR ──
    function openSearch(prefill) {
        _searchOpen = true;
        var input = document.getElementById('searchInput');
        if (input) {
            input.value = prefill || '';
            input.focus();
            if (prefill) handleSearchInput(prefill);
        }
    }

    function closeSearch() {
        _searchOpen = false;
        var input = document.getElementById('searchInput');
        if (input) input.value = '';
        var results = document.getElementById('searchResults');
        if (results) results.classList.remove('open');
    }

    function handleSearchInput(query) {
        var results = document.getElementById('searchResultsInner');
        if (!results) return;
        var resultsWrap = document.getElementById('searchResults');
        if (resultsWrap) resultsWrap.classList.add('open');

        var q = query.toLowerCase().trim();
        if (!q) { results.innerHTML = renderLaunchpadGrid(); return; }

        var html = '';

        // Node matches (scopes, services, ORGs, federation)
        var allNodes = galaxy.nodes.slice();
        Object.keys(FEDERATION).forEach(function (key) {
            allNodes.push({ id: 'fed:' + key, label: FEDERATION[key].label, kind: 'ORG', color: FEDERATION[key].color, category: 'FEDERATION' });
        });

        var seenLabels = {};
        var nodeMatches = allNodes.filter(function (n) {
            if (n.label.toLowerCase().indexOf(q) < 0
                && (n.kind || '').toLowerCase().indexOf(q) < 0
                && (n.category || '').toLowerCase().indexOf(q) < 0) return false;
            var key = n.label;
            if (seenLabels[key]) return false;
            seenLabels[key] = true;
            return true;
        }).slice(0, 8);

        nodeMatches.forEach(function (n) {
            var tierInfo = tierFor(n.bits || 0);
            var coinStr = (n.wallet && n.wallet.balance > 0) ? formatCoin(n.wallet.balance) + ' COIN' : '';
            var lUrl = launchUrl(n);

            html += '<div class="lp-row" onclick="GALAXY.launchpadSelect(\'' + n.id + '\')">';
            html += '<span class="lp-row-icon" style="color:' + (n.color || '#64748b') + '">\u25C6</span>';
            html += '<span class="lp-row-label">' + n.label + '</span>';
            html += '<span class="lp-row-kind">' + n.kind + '</span>';
            html += '<span class="lp-row-bits" style="color:' + tierInfo.color + '">' + (n.bits || 0) + '</span>';
            if (coinStr) html += '<span class="lp-row-coin">' + coinStr + '</span>';
            if (lUrl) html += '<a class="lp-launch" href="' + lUrl + '" target="_blank" onclick="event.stopPropagation()">\ud83d\ude80</a>';
            html += '</div>';
        });

        // LEARNING pattern matches
        var learningMatches = [];
        galaxy.nodes.forEach(function (n) {
            if (!n.learning) return;
            n.learning.forEach(function (p) {
                if (p.pattern.toLowerCase().indexOf(q) >= 0 || p.signal.toLowerCase().indexOf(q) >= 0) {
                    learningMatches.push({ node: n, pattern: p });
                }
            });
        });
        learningMatches = learningMatches.slice(0, 5);

        if (learningMatches.length > 0) {
            html += '<div class="lp-section">LEARNING</div>';
            learningMatches.forEach(function (m) {
                html += '<div class="lp-row lp-learning" onclick="GALAXY.launchpadSelect(\'' + m.node.id + '\')">';
                html += '<span class="lp-row-icon" style="color:#00ff88">\uf19d</span>';
                html += '<span class="lp-pattern">' + m.pattern.pattern + '</span>';
                html += '<span class="lp-source">' + m.node.label + ' \u00b7 ' + m.pattern.date + '</span>';
                html += '</div>';
            });
        }

        results.innerHTML = html;
    }

    function renderLaunchpadGrid() {
        // 2-col icon grid of launchable services, grouped by category
        var flagships = galaxy.nodes.filter(function (n) {
            return n.talk && n.talk.sessions > 0 && launchUrl(n);
        }).sort(function (a, b) {
            return (b.talk.sessions || 0) - (a.talk.sessions || 0);
        });

        // Deduplicate by label (same service in multiple repos)
        var seen = {};
        flagships = flagships.filter(function (n) {
            if (seen[n.label]) return false;
            seen[n.label] = true;
            return true;
        });

        // Group by category
        var groups = {};
        flagships.forEach(function (n) {
            var cat = n.category || 'OTHER';
            if (!groups[cat]) groups[cat] = [];
            groups[cat].push(n);
        });

        var html = '';
        Object.keys(groups).forEach(function (cat) {
            html += '<div class="lp-section">' + cat + '</div>';
            html += '<div class="lp-grid">';
            groups[cat].forEach(function (n) {
                var lUrl = launchUrl(n);
                html += '<div class="lp-item" onclick="GALAXY.launchpadSelect(\'' + n.id + '\')">';
                html += '<div class="lp-icon" style="color:' + (n.color || '#64748b') + ';border-color:' + hexToRgba(n.color || '#64748b', 0.15) + '"><span style="font-family:\'Font Awesome 5 Free\';font-weight:900;font-size:13px">' + iconFor(n) + '</span></div>';
                html += '<div class="lp-info"><div class="lp-name">' + n.label + '</div>';
                html += '<div class="lp-meta">' + n.talk.sessions + ' sessions</div></div>';
                if (lUrl) html += '<a class="lp-launch" href="' + lUrl + '" target="_blank" onclick="event.stopPropagation()">\ud83d\ude80</a>';
                html += '</div>';
            });
            html += '</div>';
        });

        // Top scopes by score (non-TALK)
        var topScopes = galaxy.nodes.filter(function (n) {
            return n.kind !== 'USER' && typeof n.score === 'number' && n.score > 0 && (!n.talk || !n.talk.sessions);
        }).sort(function (a, b) {
            return (b.score || 0) - (a.score || 0);
        }).slice(0, 6);

        if (topScopes.length > 0) {
            html += '<div class="lp-section">TOP SCOPES</div>';
            html += '<div class="lp-grid">';
            topScopes.forEach(function (n) {
                var tierInfo = tierFor(n.bits || 0);
                html += '<div class="lp-item" onclick="GALAXY.launchpadSelect(\'' + n.id + '\')">';
                html += '<div class="lp-icon" style="color:' + (n.color || '#64748b') + ';border-color:' + hexToRgba(n.color || '#64748b', 0.15) + '"><span style="font-family:\'Font Awesome 5 Free\';font-weight:900;font-size:13px">' + iconFor(n) + '</span></div>';
                html += '<div class="lp-info"><div class="lp-name">' + n.label + '</div>';
                html += '<div class="lp-meta" style="color:' + tierInfo.color + '">' + (n.bits || 0) + '/255</div></div>';
                html += '</div>';
            });
            html += '</div>';
        }

        return html;
    }

    function launchpadSelect(id) {
        focusScope(id);
    }

    function focusScope(id) {
        var node = nodeMap[id];
        if (!node) return;
        _selectedNodeId = id;
        renderControlPanel();
        if (nodeDS && nodeDS.get(id)) {
            network.focus(id, { scale: 1.5, animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        }
        openRightDrawer();
    }

    // ── FINDER CRITICAL STYLES (injected from JS — no remote_theme dependency) ──
    (function injectFinderStyles() {
        if (document.getElementById('finder-styles')) return;
        var s = document.createElement('style');
        s.id = 'finder-styles';
        s.textContent = '.fc-hud-avatar{width:28px;height:28px;border-radius:50%;border:1px solid rgba(255,255,255,.12);object-fit:cover}' +
            '.fc-hud{background:rgba(255,255,255,.04);border-color:rgba(0,255,136,.15)}' +
            '.fb-identity{display:flex;align-items:center;gap:8px;flex-shrink:0;margin-right:8px;padding-right:10px;border-right:1px solid rgba(255,255,255,.08)}' +
            '.fb-avatar{width:22px;height:22px;border-radius:50%;border:1px solid rgba(255,255,255,.12)}' +
            '.fb-ring{flex-shrink:0}' +
            '.fb-coin{font-family:var(--mono);font-size:10px;font-weight:700;color:#ffd60a;text-decoration:none;white-space:nowrap;display:flex;align-items:center;gap:4px}' +
            '.fb-coin i{font-size:9px}' +
            '.finder-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;padding:16px 16px 80px 260px;min-height:100vh;align-content:start}' +
            '.fc-hud-crumb{font-family:var(--mono);font-size:9px;color:rgba(255,255,255,.4);margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
            '.fc-hud-crumb span:hover{color:#00ff88}' +
            '.fc-hud-toggle{display:flex;gap:4px;margin-top:6px}' +
            '.fc-toggle-btn{font-size:10px;padding:3px 6px;border-radius:4px;cursor:pointer;color:rgba(255,255,255,.3);transition:all .15s}' +
            '.fc-toggle-btn:hover{color:#f5f5f7;background:rgba(255,255,255,.04)}' +
            '.fc-toggle-btn.active{color:#00ff88}' +
            '.cp-view-toggle{display:flex;gap:4px}' +
            '.cp-breadcrumb{font-family:var(--mono);font-size:9px;color:rgba(255,255,255,.4);margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
            '.cp-crumb{cursor:pointer;transition:color .15s}.cp-crumb:hover{color:#00ff88}' +
            '.cp-crumb-current{color:#f5f5f7;cursor:default}' +
            '.fb-bar{display:flex;align-items:center;gap:8px;padding:8px 14px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.10);-webkit-backdrop-filter:blur(30px);backdrop-filter:blur(30px);box-shadow:0 4px 24px rgba(0,0,0,.5)}' +
            '.fb-segments{display:flex;align-items:center;gap:2px;flex:1;min-width:0;overflow:hidden}' +
            '.fb-segment{font-family:var(--mono);font-size:11px;color:rgba(255,255,255,.4);cursor:pointer;padding:2px 6px;border-radius:4px;transition:all .15s;white-space:nowrap}' +
            '.fb-segment:hover{background:rgba(255,255,255,.06);color:#f5f5f7}' +
            '.fb-current{color:#f5f5f7;font-weight:600;cursor:default}.fb-current:hover{background:transparent}' +
            '.fb-root{font-size:12px;color:#00ff88;opacity:.6}.fb-root:hover{opacity:1}' +
            '.fb-sep{font-family:var(--mono);font-size:10px;color:rgba(255,255,255,.4);opacity:.3;margin:0 1px}' +
            '.fb-toggle{display:flex;gap:2px;margin-left:auto;flex-shrink:0}' +
            '.fb-toggle-btn{font-family:var(--mono);font-size:10px;padding:4px 10px;border-radius:6px;border:1px solid transparent;background:transparent;color:rgba(255,255,255,.4);cursor:pointer;transition:all .2s;min-width:32px;display:flex;align-items:center;gap:5px}' +
            '.fb-toggle-btn:hover{background:rgba(255,255,255,.04);color:#f5f5f7}' +
            '.fb-toggle-btn.active{background:rgba(0,255,136,.08);color:#00ff88;border-color:rgba(0,255,136,.2)}' +
            '.fb-toggle-btn i{font-size:10px}' +
            '.finder-card{padding:14px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);-webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);cursor:pointer;transition:all .2s cubic-bezier(.4,0,.2,1)}' +
            '.finder-card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,.15);box-shadow:0 8px 24px rgba(0,0,0,.3)}' +
            '.fc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}' +
            '.fc-icon{font-size:18px;opacity:.8}' +
            '.fc-label{font-family:var(--mono);font-size:11px;font-weight:600;color:#f5f5f7;letter-spacing:.06em;margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
            '.fc-meta{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:9px}' +
            '.fc-bits{font-weight:700}.fc-children{color:rgba(255,255,255,.4);opacity:.5}.fc-coin{color:#ffd60a;font-weight:600}' +
            '.talk-mode-toggle.active{color:#00ff88;background:rgba(0,255,136,.1);border-radius:50%}' +
            '@media(max-width:768px){.finder-breadcrumb{left:8px;right:8px;top:auto;bottom:60px}.finder-grid{padding:64px 8px 120px;grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}.fb-segments .fb-segment:not(.fb-current):not(.fb-root){display:none}}';
        document.head.appendChild(s);
    })();

    // ── FINDER VIEW ──────────────────────────────────────
    function renderBreadcrumb() {
        // Breadcrumb bar is dead — HUD (control panel) handles everything
        var fb = document.getElementById('finderBreadcrumb');
        if (fb) fb.style.display = 'none';
    }

    function renderFinder() {
        var container = document.getElementById('galaxy');
        if (!container) return;
        var parentId = _finderPath.length > 0 ? _finderPath[_finderPath.length - 1] : null;
        var children = galaxy.nodes.filter(function (n) {
            return n.parent === parentId;
        }).sort(function (a, b) {
            // Folders first, then by bits descending
            var aFolder = (a.children || 0) > 0 ? 0 : 1;
            var bFolder = (b.children || 0) > 0 ? 0 : 1;
            if (aFolder !== bFolder) return aFolder - bFolder;
            return (b.bits || 0) - (a.bits || 0);
        });

        var html = '<div class="finder-grid">';

        children.forEach(function (n, i) {
            var isFolder = (n.children || 0) > 0;
            var label = n.kind === 'USER' ? titleCase(n.label.toLowerCase()) : n.label;
            var bits = (typeof n.bits === 'number') ? n.bits : 0;
            var tierInfo = tierFor(bits);
            var coinStr = (n.wallet && n.wallet.balance > 0) ? formatCoin(n.wallet.balance) : '';
            var onclick = isFolder
                ? 'GALAXY.navigateTo(\'' + n.id + '\')'
                : 'GALAXY.selectFinderNode(\'' + n.id + '\')';

            html += '<div class="finder-card sc-card" onclick="' + onclick + '" style="--i:' + i + '">';
            html += '<div class="fc-header">';
            html += '<span class="fc-icon" style="color:' + (n.color || '#64748b') + '"><i class="fas" style="font-family:\'Font Awesome 5 Free\';font-weight:900">' + iconFor(n) + '</i></span>';
            html += '<div class="fc-ring">' + ringHTML(bits, 28, true) + '</div>';
            html += '</div>';
            html += '<div class="fc-label">' + label + '</div>';
            html += '<div class="fc-meta">';
            html += '<span class="fc-bits" style="color:' + tierInfo.color + '">' + bits + '</span>';
            if (isFolder) html += '<span class="fc-children">' + n.children + ' <i class="fas fa-folder" style="font-size:8px"></i></span>';
            if (coinStr) html += '<span class="fc-coin">\u2229' + coinStr + '</span>';
            html += '</div>';
            html += '</div>';
        });
        if (children.length === 0) {
            html += '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#86868b;font-family:var(--mono);font-size:11px">No children at this scope</div>';
        }
        html += '</div>';
        container.innerHTML = html;
        renderBreadcrumb();

        // Update control panel to reflect current scope
        if (_finderPath.length > 0) {
            _selectedNodeId = _finderPath[_finderPath.length - 1];
        } else {
            _selectedNodeId = null;
        }
        renderControlPanel();
    }

    function navigateTo(nodeId) {
        _finderPath.push(nodeId);
        renderFinder();
        location.hash = _finderPath.map(function (id) { return id.split('/').pop(); }).join('/');
    }

    function navigateUp() {
        if (_finderPath.length > 0) {
            _finderPath.pop();
            renderFinder();
            location.hash = _finderPath.map(function (id) { return id.split('/').pop(); }).join('/');
        }
    }

    function navigateToBreadcrumb(index) {
        _finderPath = _finderPath.slice(0, index + 1);
        renderFinder();
        location.hash = _finderPath.map(function (id) { return id.split('/').pop(); }).join('/');
    }

    function navigateToRoot() {
        _finderPath = [];
        renderFinder();
        location.hash = '';
    }

    function selectFinderNode(nodeId) {
        _selectedNodeId = nodeId;
        renderControlPanel();
        openRightDrawer();
    }

    function setView(mode) {
        if (mode === _viewMode) return;
        _viewMode = mode;
        var container = document.getElementById('galaxy');
        if (!container) return;

        if (mode === 'finder') {
            if (network) { network.destroy(); network = null; _graphBuilt = false; }
            renderFinder();
        } else {
            _finderPath = [];
            renderBreadcrumb();
            container.innerHTML = '';
            if (!_graphBuilt) {
                buildGraph(container);
                _graphBuilt = true;
                renderControlPanel();
                renderCatLegend();
                if (network) {
                    network.once('stabilizationIterationsDone', function () {
                        var loader = document.getElementById('galaxyLoader');
                        if (loader) loader.classList.add('hidden');
                    });
                }
            }
        }
    }

    function toggleTalkMode() {
        _talkMode = !_talkMode;
        var input = document.getElementById('searchInput');
        var btn = document.getElementById('talkModeBtn');
        if (_talkMode) {
            var scopeLabel = _selectedNodeId && nodeMap[_selectedNodeId] ? nodeMap[_selectedNodeId].label : 'GALAXY';
            if (input) input.placeholder = 'Ask about ' + scopeLabel + '...';
            if (btn) btn.classList.add('active');
        } else {
            if (input) input.placeholder = 'Search galaxy...';
            if (btn) btn.classList.remove('active');
        }
    }

    // ── BUILD GRAPH ──────────────────────────────────────
    function buildGraph(container) {
        var FA = '"Font Awesome 5 Free"';
        // nodeMap already built in init() — no duplicate

        var inheritsTo = {};
        var clusterEdges = [];
        var domainEdges = [];
        (galaxy.edges || []).forEach(function (e) {
            if (e.kind === 'INHERITS') inheritsTo[e.from] = e.to;
            else if (e.kind === 'CLUSTER') clusterEdges.push(e);
            else if (e.kind === 'DOMAINS') domainEdges.push(e);
        });

        function govOrg(node) {
            var cur = node, seen = {};
            while (cur) {
                if (seen[cur.id]) return null;
                seen[cur.id] = true;
                if (cur.kind === 'ORG') return cur.id;
                var next = inheritsTo[cur.id] || cur.parent;
                if (!next) return null;
                cur = nodeMap[next];
            }
            return null;
        }

        var branches = [];
        var users = [];
        var leaves = [];
        galaxy.nodes.forEach(function (n) {
            if (n.kind === 'ORG' || (n.children && n.children > 0)) branches.push(n);
            else if (n.kind === 'USER') users.push(n);
            else leaves.push(n);
        });

        var branchSet = new Set(branches.map(function (b) { return b.id; }));

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

        function makeBranchNode(n) {
            if (n.privacy === 'PRIVATE' && !canSeeNode(n)) return null;
            var leafCount = hiddenLeaves[n.id] ? hiddenLeaves[n.id].length : 0;
            var label = n.label;
            if (leafCount > 0) label += '\n+' + leafCount;
            var isPrivateVisible = n.privacy === 'PRIVATE' && canSeeNode(n);
            if (isPrivateVisible) label = '\uf023 ' + label;
            var nodeBits = (typeof n.bits === 'number') ? n.bits : 0;

            if (n.kind === 'ORG') {
                return {
                    id: n.id, label: label, shape: 'icon',
                    icon: { face: FA, weight: '900', code: iconFor(n), size: 52, color: n.color },
                    font: { color: n.color, size: 14, vadjust: 8, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                    shadow: tierShadow(nodeBits), mass: 4
                };
            }

            if (n.principal) {
                return {
                    id: n.id, label: titleCase(label.toLowerCase()), shape: 'icon',
                    icon: { face: FA, weight: '900', code: '\uf505', size: 32, color: n.color || '#ec4899' },
                    font: { color: n.color || '#ec4899', size: 11, vadjust: 5, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                    shadow: tierShadow(nodeBits), mass: 1.5
                };
            }

            // Score-aware sizing: use score if available, fall back to bits
            var scoreVal = (typeof n.score === 'number') ? n.score : nodeBits;
            var size = 16 + (scoreVal / 255) * 28;
            var nodeColor = isPrivateVisible ? '#ffd60a' : (n.color || '#64748b');

            return {
                id: n.id, label: label, shape: 'icon',
                icon: { face: FA, weight: '900', code: iconFor(n), size: size, color: nodeColor },
                font: { color: isPrivateVisible ? '#ffd60a' : '#86868b', size: 9, vadjust: 4, multi: true, face: 'SF Mono, Menlo, monospace' },
                shadow: tierShadow(nodeBits),
                mass: 0.8 + (scoreVal / 255) * 1.5
            };
        }

        var nodes = branches.map(makeBranchNode).filter(function (n) { return n !== null; });

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
                width: n.parent === pid ? 1.5 : 1, smooth: { type: 'continuous' }
            });
        });

        users.forEach(function (n) {
            var key = userKey(n.id);
            if (USER_ORGS[key]) return;
            var orgId = govOrg(n);
            if (!orgId) return;
            edges.push({
                id: 'u' + (eid++), from: orgId, to: n.id,
                color: { color: 'rgba(255,255,255,0.06)', highlight: 'rgba(255,255,255,0.25)' },
                width: 0.5, smooth: { type: 'continuous' }
            });
        });

        Object.keys(FEDERATION).forEach(function (key) {
            var fed = FEDERATION[key];
            var fedId = 'fed:' + key;
            var fedNode = { id: fedId, kind: 'ORG', label: fed.label, color: fed.color, category: 'FEDERATION', children: 0 };
            nodeMap[fedId] = fedNode;
            nodes.push({
                id: fedId, label: fed.label, shape: 'icon',
                icon: { face: FA, weight: '900', code: fed.icon, size: 40, color: fed.color },
                font: { color: fed.color, size: 12, vadjust: 6, multi: true, face: '-apple-system,system-ui,sans-serif', bold: true },
                shadow: { enabled: true, color: fed.color, size: 20, x: 0, y: 0 }, mass: 2
            });
        });

        Object.keys(FEDERATION).forEach(function (key) {
            var fed = FEDERATION[key];
            var fedId = 'fed:' + key;
            edges.push({
                id: 'fbr:' + key, from: 'hadleylab-canonic/DEXTER', to: fedId,
                color: { color: hexToRgba(fed.color, 0.10), highlight: hexToRgba(fed.color, 0.4) },
                width: 1, dashes: [6, 10], smooth: { type: 'curvedCW', roundness: 0.2 }
            });
        });

        users.forEach(function (n) {
            var key = userKey(n.id);
            var fedKey = USER_ORGS[key];
            if (!fedKey) return;
            var fedId = 'fed:' + fedKey;
            var fedColor = FEDERATION[fedKey].color;
            edges.push({
                id: 'fed:' + (eid++), from: fedId, to: n.id,
                color: { color: hexToRgba(fedColor, 0.25), highlight: hexToRgba(fedColor, 0.6) },
                width: 1.5, smooth: { type: 'continuous' }
            });
        });

        var orgs = branches.filter(function (n) { return n.kind === 'ORG'; });
        for (var i = 0; i < orgs.length; i++) {
            for (var j = i + 1; j < orgs.length; j++) {
                edges.push({
                    id: 'bridge' + i + j, from: orgs[i].id, to: orgs[j].id,
                    label: 'DISTRIBUTED COMPUTE',
                    font: { color: 'rgba(255,255,255,0.12)', size: 8, face: 'SF Mono, Menlo, monospace', strokeWidth: 0 },
                    color: { color: 'rgba(255,255,255,0.05)', highlight: 'rgba(255,255,255,0.25)' },
                    width: 2, dashes: [8, 12], smooth: { type: 'curvedCW', roundness: 0.15 }
                });
            }
        }

        var nodeIdSet = new Set(nodes.map(function (n) { return n.id; }));
        clusterEdges.forEach(function (ce) {
            if (!nodeIdSet.has(ce.from) || !nodeIdSet.has(ce.to)) return;
            var w = ce.weight || 1;
            edges.push({
                id: 'cluster:' + ce.from + ':' + ce.to,
                from: ce.from, to: ce.to,
                color: { color: 'rgba(0,255,136,0.08)', highlight: 'rgba(0,255,136,0.35)' },
                width: Math.min(w * 1.5, 5), dashes: [4, 8],
                smooth: { type: 'curvedCW', roundness: 0.25 },
                title: 'CLUSTER: ' + (ce.domains || []).join(', ')
            });
        });

        domainEdges.forEach(function (de) {
            if (!nodeIdSet.has(de.from) || !nodeIdSet.has(de.to)) return;
            edges.push({
                id: 'domain:' + de.from + ':' + de.to,
                from: de.from, to: de.to,
                color: { color: 'rgba(191,90,242,0.10)', highlight: 'rgba(191,90,242,0.4)' },
                width: 1, dashes: [2, 6], smooth: { type: 'curvedCCW', roundness: 0.3 }
            });
        });

        nodeDS = new vis.DataSet(nodes);
        edgeDS = new vis.DataSet(edges);

        network = new vis.Network(container, { nodes: nodeDS, edges: edgeDS }, {
            physics: {
                barnesHut: {
                    gravitationalConstant: -8000, centralGravity: 0.2,
                    springLength: 180, springConstant: 0.04, damping: 0.9
                },
                stabilization: { iterations: 500 }
            },
            nodes: { shape: 'dot' },
            edges: { arrows: { to: { enabled: false } } },
            interaction: { hover: true, tooltipDelay: 200, zoomView: true, dragView: true }
        });

        // Expand / Collapse
        var expanded = {};

        function makeLeafVis(leaf) {
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
                    icon: { face: FA, weight: '900', code: iconFor(leaf), size: 20, color: leaf.color || '#64748b' },
                    font: { color: '#86868b', size: 8, vadjust: 3, face: 'SF Mono, Menlo, monospace' }, mass: 0.5
                };
            }
            return {
                id: leaf.id, label: leaf.label, shape: 'text',
                font: { color: hexToRgba(leaf.color || '#64748b', 0.5), size: 9, face: 'SF Mono, Menlo, monospace' }, mass: 0.3
            };
        }

        function expandBranch(branchId) {
            if (!hiddenLeaves[branchId] || expanded[branchId]) return;
            expanded[branchId] = true;
            var n = nodeMap[branchId];
            if (n) nodeDS.update({ id: branchId, label: n.label });
            hiddenLeaves[branchId].forEach(function (leaf) {
                nodeDS.add(makeLeafVis(leaf));
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

        network.on('click', function (params) {
            if (params.nodes.length === 1) {
                var nid = params.nodes[0];
                var node = nodeMap[nid];
                if (hiddenLeaves[nid]) {
                    if (expanded[nid]) collapseBranch(nid);
                    else {
                        expandBranch(nid);
                        network.focus(nid, { scale: 1.5, animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
                    }
                }
                if (node) {
                    _selectedNodeId = nid;
                    renderControlPanel();
                    openRightDrawer();
                }
            }
        });

        network.on('doubleClick', function (params) {
            if (params.nodes.length === 1) {
                network.focus(params.nodes[0], { scale: 2.5, animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
            }
        });
    }

    // (renderLeftDrawer removed — logic moved to renderIntelTab)

    // ── FILTER BAR (compact tier pills, replaces legend) ──
    var _activeFilter = null;
    function clearFilter() {
        _activeFilter = null;
        galaxy.nodes.forEach(function (n) {
            if (nodeDS.get(n.id)) nodeDS.update({ id: n.id, opacity: 1.0 });
        });
    }
    function filterCategory(cat) {
        if (!nodeDS) return;
        if (_activeFilter === cat) {
            clearFilter();
        } else {
            _activeFilter = cat;
            galaxy.nodes.forEach(function (n) {
                if (nodeDS.get(n.id)) {
                    nodeDS.update({ id: n.id, opacity: n.category === cat ? 1.0 : 0.15 });
                }
            });
        }
        renderControlPanel();
        renderCatLegend();
    }
    function filterTier(tierName) {
        if (!nodeDS) return;
        var key = 'tier:' + tierName;
        if (_activeFilter === key) {
            clearFilter();
        } else {
            _activeFilter = key;
            galaxy.nodes.forEach(function (n) {
                if (nodeDS.get(n.id)) {
                    var t = tierFor(n.bits || 0);
                    nodeDS.update({ id: n.id, opacity: t.name === tierName ? 1.0 : 0.15 });
                }
            });
        }
        renderControlPanel();
        renderCatLegend();
    }

    function filterKind(kindName) {
        if (!nodeDS) return;
        var key = 'kind:' + kindName;
        if (_activeFilter === key) {
            clearFilter();
        } else {
            _activeFilter = key;
            galaxy.nodes.forEach(function (n) {
                if (nodeDS.get(n.id)) {
                    nodeDS.update({ id: n.id, opacity: n.kind === kindName ? 1.0 : 0.15 });
                }
            });
        }
        renderControlPanel();
        renderCatLegend();
    }

    function filterHealthy(below) {
        if (!nodeDS) return;
        var key = below ? 'health:below' : 'health:ok';
        if (_activeFilter === key) {
            clearFilter();
        } else {
            _activeFilter = key;
            galaxy.nodes.forEach(function (n) {
                if (nodeDS.get(n.id)) {
                    var isHealthy = n.kind !== 'USER' && (n.bits || 0) >= 35;
                    var show = below ? (!isHealthy && n.kind !== 'USER') : isHealthy;
                    nodeDS.update({ id: n.id, opacity: show ? 1.0 : 0.15 });
                }
            });
        }
        renderControlPanel();
        renderCatLegend();
    }

    // ── TRANSFORM SCOPES → GALAXY ────────────────────────
    function transformScopes(scopes) {
        var childCount = {};
        scopes.forEach(function (s) {
            if (s.inherits) childCount[s.inherits] = (childCount[s.inherits] || 0) + 1;
        });
        var nodes = [];
        var edges = [];
        scopes.forEach(function (s) {
            var kind = 'SCOPE';
            if (s.category === 'ORG') kind = 'ORG';
            else if (s.category === 'SERVICES') kind = 'SERVICE';
            nodes.push({
                id: s.id, label: s.label, kind: kind, parent: s.inherits || null,
                children: childCount[s.id] || 0, color: s.color, category: s.category,
                bits: s.bits, source: s.source, repo: s.repo
            });
            if (s.inherits) edges.push({ from: s.id, to: s.inherits, kind: 'INHERITS' });
        });
        return { nodes: nodes, edges: edges };
    }

    // ── INIT ─────────────────────────────────────────────
    async function init(elOrOpts) {
        // Accept DOM element, options object { session }, or nothing
        var opts = (elOrOpts && !elOrOpts.nodeType) ? elOrOpts : {};
        var el = (elOrOpts && elOrOpts.nodeType) ? elOrOpts : null;

        // Store full session object for personal HUD
        if (opts.session) {
            _authUser = opts.session;
            if (!_authUser.login) _authUser.login = _authUser.user;
        }
        if (!_authUser) _authUser = await validateGalaxyAuth();

        var res = await fetch('../galaxy.json');
        var raw = await res.json();
        galaxy = Array.isArray(raw) ? transformScopes(raw) : raw;

        // Load HTTP.json for vanity domains
        try {
            var httpRes = await fetch('./HTTP.json');
            if (httpRes.ok) buildVanityMap(await httpRes.json());
        } catch (_) {}

        AUTH_API = galaxy.api_base || '';
        _compiledTiers = galaxy.tiers || [];

        // Build nodeMap and federation from compiled data (no hardcoding)
        galaxy.nodes.forEach(function (n) { nodeMap[n.id] = n; });
        buildFederationFromData();

        // Read default view from compiled view_config
        var vc = galaxy.view_config || {};
        _viewMode = vc.default_view || 'finder';

        var container = el || document.getElementById('galaxy');
        if (!container) return;

        if (_viewMode === 'finder') {
            renderFinder();
            // Hide loader immediately (no graph stabilization needed)
            var loader = document.getElementById('galaxyLoader');
            if (loader) loader.classList.add('hidden');
        } else {
            buildGraph(container);
            _graphBuilt = true;
            renderControlPanel();
            renderCatLegend();
            if (network) {
                network.once('stabilizationIterationsDone', function () {
                    var loader = document.getElementById('galaxyLoader');
                    if (loader) loader.classList.add('hidden');
                });
            }
        }

        // Search keybinding (Cmd+K / Ctrl+K)
        document.addEventListener('keydown', function (e) {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                if (GALAXY.showSearch) GALAXY.showSearch();
            }
            if (e.key === 'Escape') {
                if (_searchOpen) {
                    closeSearch();
                } else if (_leftOpen) {
                    closeLeftDrawer();
                } else if (_rightOpen) {
                    closeRightDrawer();
                } else {
                    if (_collapseAll) _collapseAll();
                    closeDetail();
                    if (network) network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
                }
            }
        });

        // Search input
        var searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function () { handleSearchInput(this.value); });
            searchInput.addEventListener('focus', function () {
                if (_leftOpen) closeLeftDrawer();
                if (_rightOpen) closeRightDrawer();
                showSearchBar();
            });
            searchInput.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') closeSearch();
            });
        }

        // Clear animation so CSS transitions can control transform
        var searchBar = document.getElementById('searchBar');
        if (searchBar) {
            searchBar.addEventListener('animationend', function () {
                searchBar.classList.add('animated');
            });
        }

        // Auto-hide search bar after idle
        var searchPeek = document.getElementById('searchPeek');
        // Search bar always visible (stable across views — no auto-hide)
        function showSearchBar() {
            if (searchBar) searchBar.classList.remove('collapsed');
            if (searchPeek) searchPeek.classList.remove('visible');
        }
        showSearchBar();
        // Expose for Cmd+K
        GALAXY.showSearch = function () {
            showSearchBar();
            if (searchInput) searchInput.focus();
        };
    }

    return {
        init: init,
        closeDetail: closeDetail,
        focusScope: focusScope,
        launchpadSelect: launchpadSelect,
        filterCategory: filterCategory,
        filterTier: filterTier,
        filterKind: filterKind,
        filterHealthy: filterHealthy,
        toggleLeft: toggleLeft,
        toggleRight: toggleRight,
        closeLeft: closeLeftDrawer,
        closeRight: closeRightDrawer,
        fixScope: fixScope,
        fixDim: fixDim,
        fixFromIntel: fixFromIntel,
        clearScope: clearScope,
        // Finder navigation
        navigateTo: navigateTo,
        navigateUp: navigateUp,
        navigateToBreadcrumb: navigateToBreadcrumb,
        navigateToRoot: navigateToRoot,
        selectFinderNode: selectFinderNode,
        setView: setView,
        toggleTalkMode: toggleTalkMode,
        auth: function () { return _authUser; }
    };
})();
