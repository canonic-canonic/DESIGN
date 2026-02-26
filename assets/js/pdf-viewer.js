/* ═══════════════════════════════════════════════════════════════
   pdf-viewer.js — DESIGN.md 255 Map
   Paginated PDF viewer with deck.js-style navigation.
   PDF.js renders each page to canvas. Keyboard, touch, hash.
   ═══════════════════════════════════════════════════════════════ */
var PDFVIEWER = (function () {
    'use strict';

    var _pdf = null, _current = 1, _total = 0;
    var _canvas, _ctx, _rendering = false, _queued = null;
    var _scale = 0; /* 0 = auto-fit */

    /* ── Render page ───────────────────────────────────────────── */
    function renderPage(n) {
        if (!_pdf || n < 1 || n > _total) return;
        if (_rendering) { _queued = n; return; }
        _rendering = true;
        _pdf.getPage(n).then(function (page) {
            /* Auto-fit: scale to fill available viewport */
            var container = _canvas.parentElement;
            var maxW = container.clientWidth * 0.92;
            var maxH = container.clientHeight * 0.88;
            var unscaled = page.getViewport({ scale: 1 });
            var fitW = maxW / unscaled.width;
            var fitH = maxH / unscaled.height;
            var scale = Math.min(fitW, fitH);
            /* HiDPI: render at 2x, display at 1x */
            var dpr = window.devicePixelRatio || 1;
            var viewport = page.getViewport({ scale: scale * dpr });
            _canvas.width = viewport.width;
            _canvas.height = viewport.height;
            _canvas.style.width = (viewport.width / dpr) + 'px';
            _canvas.style.height = (viewport.height / dpr) + 'px';
            return page.render({ canvasContext: _ctx, viewport: viewport }).promise;
        }).then(function () {
            _current = n;
            updateUI();
            history.replaceState(null, '', '#' + n);
            _rendering = false;
            if (_queued !== null) {
                var q = _queued;
                _queued = null;
                renderPage(q);
            }
        }).catch(function (err) {
            console.error('PDFVIEWER render error:', err);
            _rendering = false;
        });
    }

    /* ── Update UI ─────────────────────────────────────────────── */
    function updateUI() {
        var curr = document.getElementById('pdfCurr');
        if (curr) curr.textContent = _current;
        var prev = document.getElementById('pdfPrev');
        var next = document.getElementById('pdfNext');
        if (prev) prev.disabled = _current === 1;
        if (next) next.disabled = _current === _total;
    }

    /* ── Keyboard ──────────────────────────────────────────────── */
    function wireKeyboard() {
        document.addEventListener('keydown', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'j') {
                e.preventDefault(); renderPage(_current + 1);
            }
            if (e.key === 'ArrowLeft' || e.key === 'k') {
                e.preventDefault(); renderPage(_current - 1);
            }
        });
    }

    /* ── Touch swipe ───────────────────────────────────────────── */
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
            if (dx < 0) renderPage(_current + 1); else renderPage(_current - 1);
        }, { passive: true });
    }

    /* ── Hash navigation ───────────────────────────────────────── */
    function wireHash() {
        window.addEventListener('hashchange', function () {
            var n = parseInt(window.location.hash.slice(1));
            if (n >= 1 && n <= _total && n !== _current) renderPage(n);
        });
    }

    /* ── Resize handler ────────────────────────────────────────── */
    function wireResize() {
        var timeout;
        window.addEventListener('resize', function () {
            clearTimeout(timeout);
            timeout = setTimeout(function () { renderPage(_current); }, 150);
        });
    }

    /* ── INIT ──────────────────────────────────────────────────── */
    function init(url) {
        _canvas = document.getElementById('pdfCanvas');
        if (!_canvas) return;
        _ctx = _canvas.getContext('2d');

        /* Load PDF */
        pdfjsLib.getDocument(url).promise.then(function (pdf) {
            _pdf = pdf;
            _total = pdf.numPages;
            var total = document.getElementById('pdfTotal');
            if (total) total.textContent = _total;

            /* Start from hash or page 1 */
            var hash = parseInt(window.location.hash.slice(1));
            var start = (hash >= 1 && hash <= _total) ? hash : 1;
            _current = 0; /* force first render */
            renderPage(start);
        }).catch(function (err) {
            console.error('PDFVIEWER load error:', err);
        });

        /* Wire button handlers */
        var prev = document.getElementById('pdfPrev');
        var next = document.getElementById('pdfNext');
        if (prev) prev.addEventListener('click', function () { renderPage(_current - 1); });
        if (next) next.addEventListener('click', function () { renderPage(_current + 1); });

        wireKeyboard();
        wireTouch();
        wireHash();
        wireResize();
    }

    /* ── Public API ────────────────────────────────────────────── */
    return {
        init:     init,
        go:       function (n) { renderPage(n); },
        current:  function () { return _current; },
        total:    function () { return _total; },
        next:     function () { renderPage(_current + 1); },
        prev:     function () { renderPage(_current - 1); },
        isFirst:  function () { return _current === 1; },
        isLast:   function () { return _current === _total; },
        download: function () { window.print(); }
    };
})();
