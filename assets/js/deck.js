/* ═══════════════════════════════════════════════════════════════
   deck.js — DESIGN.md 255 Map
   Navigation for Jekyll pre-rendered DECK.html slides.
   Keyboard, touch, hash, timer. Decktape-compliant.
   ═══════════════════════════════════════════════════════════════ */
var DECK = (function () {
    'use strict';

    var _slides, _dots, _current = 1, _total = 0;
    var _timerStart = null, _timerInterval = null;

    /* ── Show slide ──────────────────────────────────────────── */
    function showSlide(n) {
        if (n < 1 || n > _total || n === _current) return;
        for (var i = 0; i < _slides.length; i++) {
            _slides[i].classList.toggle('active', i === n - 1);
            if (_dots && _dots[i]) _dots[i].classList.toggle('active', i === n - 1);
        }
        _current = n;
        var curr = document.getElementById('deckCurr');
        if (curr) curr.textContent = _current;
        history.replaceState(null, '', '#' + n);
        if (n === 2 && !_timerStart) startTimer();
    }

    /* ── Timer ───────────────────────────────────────────────── */
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

    /* ── Keyboard ────────────────────────────────────────────── */
    function wireKeyboard() {
        document.addEventListener('keydown', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); showSlide(_current + 1); }
            if (e.key === 'ArrowLeft') { e.preventDefault(); showSlide(_current - 1); }
        });
    }

    /* ── Touch swipe ─────────────────────────────────────────── */
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

    /* ── Hash navigation ─────────────────────────────────────── */
    function wireHash() {
        if (window.location.hash) {
            var n = parseInt(window.location.hash.slice(1));
            if (n >= 1 && n <= _total) { _current = 0; showSlide(n); }
        }
    }

    /* ── INIT ────────────────────────────────────────────────── */
    function init() {
        _slides = document.querySelectorAll('.slide');
        _dots = document.querySelectorAll('.nav-dot');
        _total = _slides.length;
        if (!_total) return;

        if (navigator.webdriver) document.body.classList.add('export-mode');

        wireKeyboard();
        wireTouch();
        wireHash();
    }

    /* ── Public API ──────────────────────────────────────────── */
    return {
        init:     init,
        go:       function (n) { showSlide(n); },
        current:  function () { return _current; },
        total:    function () { return _total; },
        next:     function () { showSlide(_current + 1); },
        prev:     function () { showSlide(_current - 1); },
        isFirst:  function () { return _current === 1; },
        isLast:   function () { return _current === _total; },
        download: function () { window.print(); }
    };
})();
