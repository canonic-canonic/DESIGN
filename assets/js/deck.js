/* ═══════════════════════════════════════════════════════════════
   deck.js — Standard Deck Viewer (see base/DECK.md)

   Converts {SCOPE}.json sections into a slide presentation.
   Runs AFTER DESIGN.js: DESIGN.init() → DECK.init() → TALK.init()

   Exposes window.DECK API per base/DECK.md governance standard.
   Decktape-compliant. Print-ready. TALK-wired.
   ═══════════════════════════════════════════════════════════════ */
var DECK = (function () {
    'use strict';

    var _slides, _current = 1, _total = 0;
    var _timerStart = null, _timerInterval = null;

    /* ── CSS injection ─────────────────────────────────────── */
    function injectCSS() {
        var s = document.createElement('style');
        s.textContent = [
            /* hide dashboard layout */
            '.deck-mode #nav,',
            '.deck-mode #hero,',
            '.deck-mode #stats,',
            '.deck-mode .container,',
            '.deck-mode #footer { display: none !important; }',

            'html.deck-mode, .deck-mode body {',
            '  height: 100vh; overflow: hidden;',
            '}',
            '.deck-mode body {',
            '  display: flex; flex-direction: column;',
            '}',

            /* header */
            '.deck-header {',
            '  background: rgba(0,0,0,0.95); backdrop-filter: blur(20px);',
            '  border-bottom: 1px solid rgba(255,255,255,0.12);',
            '  padding: 10px 24px; display: flex; justify-content: space-between;',
            '  align-items: center; flex-shrink: 0; z-index: 10;',
            '}',
            '.deck-header-left { display: flex; align-items: center; gap: 16px; }',
            '.deck-header-brand { font-size: 16px; font-weight: 700; letter-spacing: 0.15em; color: #c0c0c0; }',
            '.deck-header-brand strong { color: var(--accent, #f5a623); }',
            '.deck-header-label {',
            '  font-size: 13px; color: #999; padding-left: 16px;',
            '  border-left: 1px solid rgba(255,255,255,0.12);',
            '}',
            '.deck-header-right { display: flex; align-items: center; gap: 12px; }',

            /* timer */
            '.deck-timer {',
            '  font-family: monospace; font-size: 15px; color: var(--accent, #f5a623);',
            '  background: rgba(245,158,11,0.1); padding: 4px 12px; border-radius: 6px;',
            '  border: 1px solid rgba(245,158,11,0.2);',
            '}',

            /* slide counter */
            '.deck-counter { font-size: 13px; color: #999; }',
            '.deck-counter span { color: #fff; font-weight: 600; }',

            /* export dropdown */
            '.deck-dl-wrap { position: relative; }',
            '.deck-dl-btn {',
            '  background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);',
            '  color: #999; padding: 4px 10px; border-radius: 6px;',
            '  font-size: 11px; font-weight: 600; letter-spacing: 0.05em;',
            '  cursor: pointer; transition: all 0.2s; font-family: inherit;',
            '}',
            '.deck-dl-btn:hover { background: rgba(255,255,255,0.15); color: #fff; }',
            '.deck-dl-menu {',
            '  position: absolute; top: 100%; right: 0; margin-top: 6px;',
            '  background: #141414; border: 1px solid rgba(255,255,255,0.12); border-radius: 8px;',
            '  min-width: 120px; overflow: hidden; z-index: 50;',
            '  opacity: 0; pointer-events: none; transform: translateY(-4px);',
            '  transition: opacity 0.15s, transform 0.15s;',
            '  box-shadow: 0 8px 24px rgba(0,0,0,0.5);',
            '}',
            '.deck-dl-wrap.open .deck-dl-menu { opacity: 1; pointer-events: auto; transform: translateY(0); }',
            '.deck-dl-item {',
            '  display: block; width: 100%; padding: 8px 14px; background: none; border: none;',
            '  color: #c0c0c0; font-family: inherit; font-size: 12px; font-weight: 600;',
            '  letter-spacing: 0.06em; cursor: pointer; text-align: left; text-decoration: none;',
            '  transition: background 0.15s;',
            '}',
            '.deck-dl-item:hover { background: rgba(255,255,255,0.08); color: #fff; }',
            '.deck-dl-item + .deck-dl-item { border-top: 1px solid rgba(255,255,255,0.12); }',

            /* talk button */
            '.deck-talk-btn {',
            '  display: flex; align-items: center; gap: 6px;',
            '  background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.3);',
            '  color: #34d399; padding: 4px 12px; border-radius: 6px;',
            '  font-size: 11px; font-weight: 700; letter-spacing: 0.1em;',
            '  cursor: pointer; transition: all 0.2s; font-family: inherit;',
            '}',
            '.deck-talk-btn:hover { background: rgba(52,211,153,0.2); }',
            '.deck-talk-dot {',
            '  width: 6px; height: 6px; border-radius: 50%; background: #34d399;',
            '  animation: deckDotPulse 2s ease-in-out infinite;',
            '}',
            '@keyframes deckDotPulse {',
            '  0%,100% { opacity: 1; } 50% { opacity: 0.4; }',
            '}',

            /* slide area */
            '.deck-main { flex: 1; display: flex; overflow: hidden; flex-direction: column; }',
            '.deck-slide-area { flex: 1; position: relative; display: flex; flex-direction: column; }',
            '.deck-slide-container { flex: 1; position: relative; overflow: hidden; }',

            '.deck-slide {',
            '  display: none; position: absolute; inset: 0;',
            '  padding: 48px 64px; flex-direction: column; justify-content: flex-start;',
            '  overflow-y: auto;',
            '  animation: deckFadeIn 0.4s ease;',
            '}',
            '.deck-slide.active { display: flex; }',
            '@keyframes deckFadeIn {',
            '  from { opacity: 0; transform: translateY(8px); }',
            '  to { opacity: 1; transform: translateY(0); }',
            '}',

            /* title slide */
            '.deck-title-slide {',
            '  justify-content: center; align-items: center; text-align: center;',
            '}',
            '.deck-title-badge {',
            '  display: inline-block; padding: 4px 16px; border: 1px solid var(--accent, #f5a623);',
            '  border-radius: 20px; font-size: 12px; font-weight: 700;',
            '  letter-spacing: 0.15em; color: var(--accent, #f5a623); margin-bottom: 24px;',
            '}',
            '.deck-title-heading {',
            '  font-size: clamp(32px, 5vw, 56px); font-weight: 800;',
            '  letter-spacing: -0.02em; line-height: 1.1; margin-bottom: 16px;',
            '}',
            '.deck-title-desc {',
            '  font-size: clamp(14px, 1.5vw, 18px); color: #999; max-width: 640px; line-height: 1.6;',
            '}',

            /* section slide heading */
            '.deck-slide-eyebrow {',
            '  font-size: 12px; font-weight: 700; letter-spacing: 0.15em;',
            '  color: var(--accent, #f5a623); margin-bottom: 8px;',
            '}',
            '.deck-slide-title {',
            '  font-size: clamp(22px, 3vw, 36px); font-weight: 700; margin-bottom: 8px;',
            '}',
            '.deck-slide-desc {',
            '  font-size: 14px; color: #999; margin-bottom: 24px; max-width: 720px;',
            '}',
            '.deck-slide-content {',
            '  flex: 1; display: flex; flex-direction: column;',
            '}',

            /* slide nav */
            '.deck-slide-nav {',
            '  padding: 10px 24px; display: flex; justify-content: center;',
            '  align-items: center; gap: 16px; flex-shrink: 0;',
            '  border-top: 1px solid rgba(255,255,255,0.06);',
            '  background: rgba(0,0,0,0.5);',
            '}',
            '.deck-nav-btn {',
            '  width: 36px; height: 36px; border-radius: 50%;',
            '  background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);',
            '  color: #999; font-size: 14px; cursor: pointer; transition: all 0.2s;',
            '  display: flex; align-items: center; justify-content: center;',
            '  font-family: inherit;',
            '}',
            '.deck-nav-btn:hover { background: rgba(255,255,255,0.12); color: #fff; }',
            '.deck-nav-counter { font-size: 13px; color: #999; }',
            '.deck-nav-counter span { color: #fff; font-weight: 600; }',

            /* export mode (decktape) */
            '.export-mode .deck-header,',
            '.export-mode .deck-slide-nav { display: none !important; }',
            '.export-mode .deck-slide { animation: none !important; }',

            /* print */
            '@media print {',
            '  .deck-header, .deck-slide-nav, .talk-overlay { display: none !important; }',
            '  html.deck-mode, .deck-mode body {',
            '    height: auto; overflow: visible;',
            '  }',
            '  .deck-main, .deck-slide-area, .deck-slide-container {',
            '    display: block !important; height: auto !important;',
            '    overflow: visible !important; position: static !important;',
            '    background: #0a0a0a !important;',
            '    -webkit-print-color-adjust: exact; print-color-adjust: exact;',
            '  }',
            '  .deck-slide {',
            '    position: static !important; display: flex !important;',
            '    page-break-after: always; break-after: page;',
            '    min-height: 100vh; width: 100vw;',
            '    animation: none !important;',
            '  }',
            '}',

            /* responsive */
            '@media (max-width: 768px) {',
            '  .deck-header-label { display: none; }',
            '  .deck-slide { padding: 32px 24px; }',
            '}'
        ].join('\n');
        document.head.appendChild(s);
    }

    /* ── Build header ──────────────────────────────────────── */
    function buildHeader(content, canon) {
        var hero = content.hero || {};
        var brand = (canon && canon.brand && canon.brand.label) || 'HADLEYLAB';
        var label = hero.badge ? hero.badge + ' | ' + (hero.title || '') : (hero.title || '');

        var h = document.createElement('header');
        h.className = 'deck-header';
        h.innerHTML =
            '<div class="deck-header-left">' +
                '<div class="deck-header-brand"><strong>' + esc(brand) + '</strong> DECK</div>' +
                '<div class="deck-header-label">' + esc(label) + '</div>' +
            '</div>' +
            '<div class="deck-header-right">' +
                '<div class="deck-timer" id="deckTimer">0:00</div>' +
                '<div class="deck-counter"><span id="deckCurr">1</span> / <span id="deckTotal">0</span></div>' +
                '<div class="deck-dl-wrap" id="deckDlWrap">' +
                    '<button type="button" class="deck-dl-btn" onclick="document.getElementById(\'deckDlWrap\').classList.toggle(\'open\')">EXPORT &#9662;</button>' +
                    '<div class="deck-dl-menu">' +
                        '<button type="button" class="deck-dl-item" onclick="DECK.download();document.getElementById(\'deckDlWrap\').classList.remove(\'open\')">PDF</button>' +
                    '</div>' +
                '</div>' +
                '<button type="button" class="deck-talk-btn" onclick="TALK.open()"><span class="deck-talk-dot"></span>TALK</button>' +
            '</div>';
        return h;
    }

    /* ── Build title slide (slide 1) from hero ─────────────── */
    function buildTitleSlide(hero) {
        var slide = document.createElement('div');
        slide.className = 'deck-slide deck-title-slide active';
        slide.setAttribute('data-slide', '1');

        var html = '';
        if (hero.badge) html += '<div class="deck-title-badge">' + esc(hero.badge) + '</div>';
        if (hero.title) html += '<h1 class="deck-title-heading">' + esc(hero.title) + '</h1>';
        if (hero.description) html += '<p class="deck-title-desc">' + esc(hero.description) + '</p>';
        slide.innerHTML = html;
        return slide;
    }

    /* ── Convert rendered section to slide ──────────────────── */
    function buildSectionSlide(sectionEl, sectionData, slideNum) {
        var slide = document.createElement('div');
        slide.className = 'deck-slide';
        slide.setAttribute('data-slide', String(slideNum));

        // DESIGN.js already rendered the heading (eyebrow/title/desc)
        // into the section — just move all children directly
        while (sectionEl.firstChild) {
            slide.appendChild(sectionEl.firstChild);
        }

        return slide;
    }

    /* ── Build slide nav ───────────────────────────────────── */
    function buildSlideNav() {
        var nav = document.createElement('div');
        nav.className = 'deck-slide-nav';
        nav.innerHTML =
            '<button type="button" class="deck-nav-btn" onclick="DECK.prev()">&larr;</button>' +
            '<div class="deck-nav-counter"><span id="deckCurrNav">1</span> / <span id="deckTotalNav">0</span></div>' +
            '<button type="button" class="deck-nav-btn" onclick="DECK.next()">&rarr;</button>';
        return nav;
    }

    /* ── Show slide (Decktape-compliant) ───────────────────── */
    function showSlide(n) {
        if (n < 1 || n > _total || n === _current) return; // zero mutation at boundaries
        for (var i = 0; i < _slides.length; i++) _slides[i].classList.remove('active');
        _slides[n - 1].classList.add('active');
        _current = n;
        updateCounters();
        history.replaceState(null, '', '#' + n);
        if (n === 2 && !_timerStart) startTimer();
    }

    function updateCounters() {
        var els = ['deckCurr', 'deckCurrNav'];
        for (var i = 0; i < els.length; i++) {
            var el = document.getElementById(els[i]);
            if (el) el.textContent = _current;
        }
    }

    /* ── Timer ─────────────────────────────────────────────── */
    function startTimer() {
        if (navigator.webdriver) return;
        _timerStart = Date.now();
        _timerInterval = setInterval(function () {
            var elapsed = Math.floor((Date.now() - _timerStart) / 1000);
            var min = Math.floor(elapsed / 60);
            var sec = String(elapsed % 60);
            if (sec.length < 2) sec = '0' + sec;
            var el = document.getElementById('deckTimer');
            if (el) {
                el.textContent = min + ':' + sec;
                if (elapsed >= 270) el.style.color = '#ef4444';
                else if (elapsed >= 240) el.style.color = '#f97316';
            }
        }, 1000);
    }

    /* ── Keyboard navigation ───────────────────────────────── */
    function wireKeyboard() {
        document.addEventListener('keydown', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); showSlide(_current + 1); }
            if (e.key === 'ArrowLeft') { e.preventDefault(); showSlide(_current - 1); }
        });
    }

    /* ── Touch swipe ───────────────────────────────────────── */
    function wireTouch() {
        var startX = 0, startY = 0;
        document.addEventListener('touchstart', function (e) {
            startX = e.changedTouches[0].screenX;
            startY = e.changedTouches[0].screenY;
        }, { passive: true });
        document.addEventListener('touchend', function (e) {
            var dx = e.changedTouches[0].screenX - startX;
            var dy = e.changedTouches[0].screenY - startY;
            if (Math.abs(dx) < 50 || Math.abs(dy) > Math.abs(dx)) return;
            if (dx < 0) showSlide(_current + 1); else showSlide(_current - 1);
        }, { passive: true });
    }

    /* ── Hash navigation ───────────────────────────────────── */
    function wireHash() {
        if (window.location.hash) {
            var n = parseInt(window.location.hash.slice(1));
            if (n >= 1 && n <= _total) { _current = 0; showSlide(n); }
        }
    }

    /* ── Export dropdown close on outside click ─────────────── */
    function wireExportClose() {
        document.addEventListener('click', function (e) {
            var wrap = document.getElementById('deckDlWrap');
            if (wrap && !wrap.contains(e.target)) wrap.classList.remove('open');
        });
    }

    /* ── Escape helper ─────────────────────────────────────── */
    function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

    /* ── INIT ──────────────────────────────────────────────── */
    function init(config) {
        config = config || {};
        var content = DESIGN.content();
        var canon = DESIGN.canon();
        if (!content || !content.sections || !content.sections.length) return;

        // 1. Inject CSS
        injectCSS();

        // 2. Switch to deck mode
        document.documentElement.classList.add('deck-mode');
        if (navigator.webdriver) document.body.classList.add('export-mode');

        // 3. Build header
        var header = buildHeader(content, canon);
        document.body.insertBefore(header, document.body.firstChild);

        // 4. Build main structure
        var main = document.createElement('main');
        main.className = 'deck-main';
        var slideArea = document.createElement('div');
        slideArea.className = 'deck-slide-area';
        var slideContainer = document.createElement('div');
        slideContainer.className = 'deck-slide-container';

        // 5. Title slide from hero
        if (content.hero) {
            slideContainer.appendChild(buildTitleSlide(content.hero));
        }

        // 6. Section slides — move rendered DOM into slides
        var sections = content.sections;
        for (var i = 0; i < sections.length; i++) {
            var sec = sections[i];
            var el = document.getElementById(sec.id);
            if (!el) continue;
            var slideNum = content.hero ? i + 2 : i + 1;
            slideContainer.appendChild(buildSectionSlide(el, sec, slideNum));
        }

        // 7. Assemble
        slideArea.appendChild(slideContainer);
        slideArea.appendChild(buildSlideNav());
        main.appendChild(slideArea);
        document.body.insertBefore(main, document.querySelector('.talk-overlay') || null);

        // 8. Set slide references
        _slides = slideContainer.querySelectorAll('.deck-slide');
        _total = _slides.length;

        // Update total counters
        var totals = ['deckTotal', 'deckTotalNav'];
        for (var t = 0; t < totals.length; t++) {
            var tel = document.getElementById(totals[t]);
            if (tel) tel.textContent = _total;
        }
        updateCounters();

        // 9. Wire navigation
        wireKeyboard();
        wireTouch();
        wireHash();
        wireExportClose();
    }

    /* ── Public API (per base/DECK.md) ─────────────────────── */
    return {
        init:     init,
        current:  function () { return _current; },
        total:    function () { return _total; },
        next:     function () { showSlide(_current + 1); },
        prev:     function () { showSlide(_current - 1); },
        goto:     function (n) { showSlide(n); },
        isFirst:  function () { return _current === 1; },
        isLast:   function () { return _current === _total; },
        download: function () { window.print(); }
    };
})();
