/* ═══════════════════════════════════════════════════════════════
   pdf-viewer.js — DESIGN.md 255 Map
   Book-spread PDF viewer. PDF.js renders pages into facing
   spreads (desktop ≥768px) or vertical scroll (mobile).
   Apple-style page-turn effects. Token-only CSS.
   GOV: PAPERS.md → TEX View — PDF.js canvas (book-spread)
   ═══════════════════════════════════════════════════════════════ */
var PDFVIEWER = (function () {
    'use strict';

    var _pdf = null, _total = 0, _current = 1;
    var _container, _nav;
    var _pages = [];       // { canvas, wrapper, num, rendered }
    var _spreads = [];     // [ [pageNum, pageNum?], ... ]
    var _spreadIdx = 0;
    var _rendering = false;
    var _mode = 'spread';  // 'spread' or 'scroll'
    var _observer = null;
    var _url = '';
    var BREAKPOINT = 768;

    /* ── Mode detection ───────────────────────────────────────── */
    function detectMode() {
        return window.innerWidth >= BREAKPOINT ? 'spread' : 'scroll';
    }

    /* ── Build spread index ───────────────────────────────────── */
    function buildSpreads() {
        _spreads = [];
        if (_total < 1) return;
        // Page 1: solo recto (right side)
        _spreads.push([null, 1]);
        // Pairs: 2-3, 4-5, 6-7, ...
        for (var i = 2; i <= _total; i += 2) {
            if (i + 1 <= _total) {
                _spreads.push([i, i + 1]);
            } else {
                // Last odd page: solo verso (left side)
                _spreads.push([i, null]);
            }
        }
    }

    /* ── Find spread containing a page number ─────────────────── */
    function spreadForPage(n) {
        for (var i = 0; i < _spreads.length; i++) {
            var s = _spreads[i];
            if (s[0] === n || s[1] === n) return i;
        }
        return 0;
    }

    /* ── Render single page to canvas ─────────────────────────── */
    function renderPage(pageNum, canvas, maxW) {
        return _pdf.getPage(pageNum).then(function (page) {
            var dpr = window.devicePixelRatio || 1;
            var unscaled = page.getViewport({ scale: 1 });
            var scale = maxW / unscaled.width;
            var viewport = page.getViewport({ scale: scale * dpr });

            canvas.width = viewport.width;
            canvas.height = viewport.height;
            canvas.style.width = (viewport.width / dpr) + 'px';
            canvas.style.height = (viewport.height / dpr) + 'px';

            var ctx = canvas.getContext('2d');
            return page.render({ canvasContext: ctx, viewport: viewport }).promise;
        });
    }

    /* ── Compute page width for current mode ──────────────────── */
    function pageWidth() {
        if (!_container) return 300;
        var cw = _container.clientWidth;
        var ch = _container.clientHeight;
        if (_mode === 'spread') {
            // Two pages side by side — each page gets ~45% of container width
            // but also constrain by height
            var w = Math.min(cw * 0.45, ch * 0.6);
            return Math.max(w, 200);
        }
        // Scroll mode — single page, 94% of container width
        return cw * 0.94;
    }

    /* ═══ SPREAD MODE ═════════════════════════════════════════════ */

    function renderSpread(idx, direction) {
        if (idx < 0 || idx >= _spreads.length || _rendering) return;
        _rendering = true;
        var spread = _spreads[idx];
        var oldSpreadEl = _container.querySelector('.pdf-spread');

        // Create new spread element
        var spreadEl = document.createElement('div');
        spreadEl.className = 'pdf-spread';

        var pw = pageWidth();
        var promises = [];

        // Left page
        if (spread[0]) {
            var leftW = createPageSlot(spread[0], 'left');
            spreadEl.appendChild(leftW.wrapper);
            promises.push(renderPage(spread[0], leftW.canvas, pw));
        } else {
            var blank = document.createElement('div');
            blank.className = 'pdf-page-blank';
            blank.style.width = pw + 'px';
            spreadEl.appendChild(blank);
        }

        // Spine
        var spine = document.createElement('div');
        spine.className = 'pdf-spine';
        spreadEl.appendChild(spine);

        // Right page
        if (spread[1]) {
            var rightW = createPageSlot(spread[1], 'right');
            spreadEl.appendChild(rightW.wrapper);
            promises.push(renderPage(spread[1], rightW.canvas, pw));
        } else {
            var blank2 = document.createElement('div');
            blank2.className = 'pdf-page-blank';
            blank2.style.width = pw + 'px';
            spreadEl.appendChild(blank2);
        }

        // Insert new spread (hidden for animation)
        if (direction && oldSpreadEl) {
            spreadEl.classList.add('pdf-spread--entering');
            spreadEl.classList.add(direction === 'next' ? 'pdf-spread--from-right' : 'pdf-spread--from-left');
        }
        _container.insertBefore(spreadEl, _nav);

        Promise.all(promises).then(function () {
            if (direction && oldSpreadEl) {
                // Animate old spread out
                oldSpreadEl.classList.add('pdf-spread--leaving');
                oldSpreadEl.classList.add(direction === 'next' ? 'pdf-spread--to-left' : 'pdf-spread--to-right');

                // Trigger reflow then animate new spread in
                void spreadEl.offsetWidth;
                spreadEl.classList.remove('pdf-spread--from-right', 'pdf-spread--from-left');
                spreadEl.classList.add('pdf-spread--entered');

                setTimeout(function () {
                    if (oldSpreadEl.parentNode) oldSpreadEl.parentNode.removeChild(oldSpreadEl);
                    spreadEl.classList.remove('pdf-spread--entering', 'pdf-spread--entered');
                }, 400);
            } else if (oldSpreadEl) {
                oldSpreadEl.parentNode.removeChild(oldSpreadEl);
            }

            _spreadIdx = idx;
            _current = spread[1] || spread[0];
            _rendering = false;
            updateUI();

            // Pre-render adjacent spreads
            preRenderAdjacent(idx);
        }).catch(function (err) {
            console.error('PDFVIEWER spread render error:', err);
            _rendering = false;
        });
    }

    function createPageSlot(pageNum, side) {
        var wrapper = document.createElement('div');
        wrapper.className = 'pdf-page-wrapper pdf-page--' + side;
        wrapper.setAttribute('data-page', pageNum);
        var canvas = document.createElement('canvas');
        canvas.className = 'pdf-canvas';
        wrapper.appendChild(canvas);
        return { wrapper: wrapper, canvas: canvas };
    }

    /* Pre-render adjacent spread canvases in memory */
    var _preRendered = {};
    function preRenderAdjacent(idx) {
        [idx - 1, idx + 1].forEach(function (adjIdx) {
            if (adjIdx < 0 || adjIdx >= _spreads.length) return;
            var key = adjIdx;
            if (_preRendered[key]) return;
            _preRendered[key] = true;
            // Just warm the PDF.js page cache
            var spread = _spreads[adjIdx];
            if (spread[0]) _pdf.getPage(spread[0]);
            if (spread[1]) _pdf.getPage(spread[1]);
        });
    }

    /* ═══ SCROLL MODE ═════════════════════════════════════════════ */

    function renderScroll(scrollToPage) {
        if (!_pdf || _rendering) return;
        _rendering = true;

        // Clear all spread/page elements (keep nav)
        var children = Array.from(_container.children);
        children.forEach(function (c) {
            if (c !== _nav && !c.classList.contains('pdf-nav')) {
                _container.removeChild(c);
            }
        });
        _pages = [];

        var pw = pageWidth();
        var promises = [];

        for (var i = 1; i <= _total; i++) {
            (function (pageNum) {
                var wrapper = document.createElement('div');
                wrapper.className = 'pdf-page-wrapper pdf-page--scroll';
                wrapper.setAttribute('data-page', pageNum);
                var canvas = document.createElement('canvas');
                canvas.className = 'pdf-canvas';
                wrapper.appendChild(canvas);
                _container.insertBefore(wrapper, _nav);
                _pages.push({ canvas: canvas, wrapper: wrapper, num: pageNum });
                promises.push(renderPage(pageNum, canvas, pw));
            })(i);
        }

        Promise.all(promises).then(function () {
            _rendering = false;
            wireScrollSpy();

            // Restore scroll position from mode transition
            if (scrollToPage && scrollToPage > 1) {
                var item = _pages[scrollToPage - 1];
                if (item) {
                    item.wrapper.scrollIntoView({ behavior: 'instant' });
                    _current = scrollToPage;
                    updateUI();
                }
            } else {
                // Ensure counter reflects page 1 at top
                _current = 1;
                updateUI();
            }
        }).catch(function (err) {
            console.error('PDFVIEWER scroll render error:', err);
            _rendering = false;
        });
    }

    function wireScrollSpy() {
        if (_observer) _observer.disconnect();
        _observer = new IntersectionObserver(function (entries) {
            var best = null;
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    if (!best || entry.intersectionRatio > best.ratio) {
                        best = { page: parseInt(entry.target.getAttribute('data-page')), ratio: entry.intersectionRatio };
                    }
                }
            });
            if (best && best.page && best.page !== _current) {
                _current = best.page;
                updateUI();
            }
        }, { root: _container, threshold: [0.1, 0.3, 0.5, 0.7] });

        _pages.forEach(function (item) {
            _observer.observe(item.wrapper);
        });
    }

    /* ═══ NAVIGATION ══════════════════════════════════════════════ */

    function nextSpread() {
        if (_mode === 'spread') {
            if (_spreadIdx < _spreads.length - 1) renderSpread(_spreadIdx + 1, 'next');
        } else {
            var next = Math.min(_current + 1, _total);
            goPage(next);
        }
    }

    function prevSpread() {
        if (_mode === 'spread') {
            if (_spreadIdx > 0) renderSpread(_spreadIdx - 1, 'prev');
        } else {
            var prev = Math.max(_current - 1, 1);
            goPage(prev);
        }
    }

    function goPage(n) {
        if (n < 1 || n > _total) return;
        if (_mode === 'spread') {
            var idx = spreadForPage(n);
            var direction = idx > _spreadIdx ? 'next' : idx < _spreadIdx ? 'prev' : null;
            renderSpread(idx, direction);
        } else {
            var item = _pages[n - 1];
            if (item) item.wrapper.scrollIntoView({ behavior: 'smooth' });
            _current = n;
            updateUI();
        }
    }

    /* ── Touch swipe (horizontal, spread mode) ────────────────── */
    var _touchStartX = 0;
    function wireTouch() {
        _container.addEventListener('touchstart', function (e) {
            _touchStartX = e.changedTouches[0].clientX;
        }, { passive: true });

        _container.addEventListener('touchend', function (e) {
            if (_mode !== 'spread') return;
            var dx = e.changedTouches[0].clientX - _touchStartX;
            if (Math.abs(dx) > 50) {
                if (dx < 0) nextSpread();
                else prevSpread();
            }
        }, { passive: true });
    }

    /* ── Keyboard ─────────────────────────────────────────────── */
    function wireKeyboard() {
        document.addEventListener('keydown', function (e) {
            // Only when viewer is visible
            if (!_container || _container.style.display === 'none') return;
            switch (e.key) {
                case 'ArrowRight': case 'j': nextSpread(); e.preventDefault(); break;
                case 'ArrowLeft':  case 'k': prevSpread(); e.preventDefault(); break;
                case ' ':
                    if (_mode === 'spread') { nextSpread(); e.preventDefault(); }
                    break;
            }
        });
    }

    /* ── Click edges (spread mode) ────────────────────────────── */
    function wireClickEdges() {
        _container.addEventListener('click', function (e) {
            if (_mode !== 'spread') return;
            // Ignore clicks on nav
            if (e.target.closest('.pdf-nav')) return;
            var rect = _container.getBoundingClientRect();
            var x = e.clientX - rect.left;
            if (x < rect.width * 0.25) prevSpread();
            else if (x > rect.width * 0.75) nextSpread();
        });
    }

    /* ── Hash URL ─────────────────────────────────────────────── */
    function wireHash() {
        function checkHash() {
            var h = window.location.hash;
            if (h && /^#\d+$/.test(h)) {
                var n = parseInt(h.slice(1));
                if (n >= 1 && n <= _total) goPage(n);
            }
        }
        window.addEventListener('hashchange', checkHash);
        checkHash();
    }

    /* ═══ UI ══════════════════════════════════════════════════════ */

    function updateUI() {
        var curr = document.getElementById('pdfCurr');
        var total = document.getElementById('pdfTotal');
        if (total) total.textContent = _total;

        if (_mode === 'spread' && _spreads[_spreadIdx]) {
            var s = _spreads[_spreadIdx];
            var left = s[0], right = s[1];
            if (curr) {
                if (left && right) curr.textContent = left + '\u2013' + right;
                else curr.textContent = left || right;
            }
        } else {
            if (curr) curr.textContent = _current;
        }
    }

    /* ═══ RESIZE ══════════════════════════════════════════════════ */

    function wireResize() {
        var timeout;
        window.addEventListener('resize', function () {
            clearTimeout(timeout);
            timeout = setTimeout(function () {
                var newMode = detectMode();
                if (newMode !== _mode) {
                    _mode = newMode;
                    _preRendered = {};
                    rebuild();
                } else {
                    // Same mode — just re-render at new size
                    _preRendered = {};
                    rebuild();
                }
            }, 250);
        });
    }

    function rebuild() {
        // Preserve page context across mode transitions
        var savedPage = _current;

        // Clear everything except nav
        var children = Array.from(_container.children);
        children.forEach(function (c) {
            if (c !== _nav && !c.classList.contains('pdf-nav')) {
                _container.removeChild(c);
            }
        });
        _pages = [];
        if (_observer) { _observer.disconnect(); _observer = null; }

        _container.classList.toggle('pdf-viewer--spread', _mode === 'spread');
        _container.classList.toggle('pdf-viewer--scroll', _mode === 'scroll');

        if (_mode === 'spread') {
            _spreadIdx = spreadForPage(savedPage);
            renderSpread(_spreadIdx, null);
        } else {
            _current = savedPage;
            renderScroll(savedPage);
        }
    }

    /* ═══ INIT ════════════════════════════════════════════════════ */

    function init(url) {
        _container = document.getElementById('pdfViewer');
        if (!_container) return;
        _url = url;
        _nav = _container.querySelector('.pdf-nav');

        _mode = detectMode();
        _container.classList.add(_mode === 'spread' ? 'pdf-viewer--spread' : 'pdf-viewer--scroll');

        pdfjsLib.getDocument(url).promise.then(function (pdf) {
            _pdf = pdf;
            _total = pdf.numPages;
            buildSpreads();

            var totalEl = document.getElementById('pdfTotal');
            if (totalEl) totalEl.textContent = _total;

            // Check for hash
            var startPage = 1;
            var h = window.location.hash;
            if (h && /^#\d+$/.test(h)) {
                startPage = Math.max(1, Math.min(parseInt(h.slice(1)), _total));
            }

            if (_mode === 'spread') {
                _spreadIdx = spreadForPage(startPage);
                renderSpread(_spreadIdx, null);
            } else {
                renderScroll();
                if (startPage > 1) {
                    setTimeout(function () { goPage(startPage); }, 100);
                }
            }

            updateUI();
        }).catch(function (err) {
            console.error('PDFVIEWER load error:', err);
        });

        wireKeyboard();
        wireTouch();
        wireClickEdges();
        wireHash();
        wireResize();
    }

    /* ── Re-init when revealed from hidden ────────────────────── */
    function reveal() {
        if (!_pdf || !_container) return;
        _mode = detectMode();
        _preRendered = {};
        rebuild();
    }

    /* ═══ PUBLIC API ══════════════════════════════════════════════ */

    return {
        init:     init,
        reveal:   reveal,
        go:       function (n) { goPage(n); },
        current:  function () { return _current; },
        total:    function () { return _total; },
        next:     nextSpread,
        prev:     prevSpread,
        isFirst:  function () {
            return _mode === 'spread' ? _spreadIdx === 0 : _current === 1;
        },
        isLast:   function () {
            return _mode === 'spread' ? _spreadIdx === _spreads.length - 1 : _current === _total;
        },
        download: function () { window.open(_url, '_blank'); },
        mode:     function () { return _mode; }
    };
})();
