/* ═══════════════════════════════════════════════════════════════
   pdf-viewer.js — DESIGN.md 255 Map
   Scrollable PDF viewer. PDF.js renders all pages into a
   vertical scroll container — like a real PDF reader.
   ═══════════════════════════════════════════════════════════════ */
var PDFVIEWER = (function () {
    'use strict';

    var _pdf = null, _total = 0, _current = 1;
    var _container, _canvases = [], _rendering = false;
    var _observer = null;

    /* ── Render single page to canvas ─────────────────────────── */
    function renderPage(page, canvas) {
        var dpr = window.devicePixelRatio || 1;
        var containerW = _container.clientWidth * 0.94;
        var unscaled = page.getViewport({ scale: 1 });
        var scale = containerW / unscaled.width;
        var viewport = page.getViewport({ scale: scale * dpr });

        canvas.width = viewport.width;
        canvas.height = viewport.height;
        canvas.style.width = (viewport.width / dpr) + 'px';
        canvas.style.height = (viewport.height / dpr) + 'px';

        var ctx = canvas.getContext('2d');
        return page.render({ canvasContext: ctx, viewport: viewport }).promise;
    }

    /* ── Render all pages ─────────────────────────────────────── */
    function renderAll() {
        if (!_pdf || _rendering) return;
        _rendering = true;

        /* Clear container except nav */
        var nav = _container.querySelector('.pdf-nav');
        var children = Array.from(_container.children);
        children.forEach(function (c) {
            if (c !== nav && !c.classList.contains('pdf-nav')) {
                _container.removeChild(c);
            }
        });
        _canvases = [];

        var promises = [];
        for (var i = 1; i <= _total; i++) {
            (function (pageNum) {
                var wrapper = document.createElement('div');
                wrapper.className = 'pdf-page-wrapper';
                wrapper.setAttribute('data-page', pageNum);
                var canvas = document.createElement('canvas');
                canvas.className = 'pdf-canvas';
                wrapper.appendChild(canvas);
                _container.insertBefore(wrapper, nav);
                _canvases.push({ canvas: canvas, wrapper: wrapper, num: pageNum });

                promises.push(
                    _pdf.getPage(pageNum).then(function (page) {
                        return renderPage(page, canvas);
                    })
                );
            })(i);
        }

        Promise.all(promises).then(function () {
            _rendering = false;
            wireScrollSpy();
        }).catch(function (err) {
            console.error('PDFVIEWER render error:', err);
            _rendering = false;
        });
    }

    /* ── Scroll spy: track current page ───────────────────────── */
    function wireScrollSpy() {
        if (_observer) _observer.disconnect();

        _observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    var n = parseInt(entry.target.getAttribute('data-page'));
                    if (n && n !== _current) {
                        _current = n;
                        updateUI();
                    }
                }
            });
        }, {
            root: _container,
            threshold: 0.5
        });

        _canvases.forEach(function (item) {
            _observer.observe(item.wrapper);
        });
    }

    /* ── Update UI ────────────────────────────────────────────── */
    function updateUI() {
        var curr = document.getElementById('pdfCurr');
        if (curr) curr.textContent = _current;
    }

    /* ── Resize handler ───────────────────────────────────────── */
    function wireResize() {
        var timeout;
        window.addEventListener('resize', function () {
            clearTimeout(timeout);
            timeout = setTimeout(function () { renderAll(); }, 250);
        });
    }

    /* ── INIT ─────────────────────────────────────────────────── */
    function init(url) {
        _container = document.getElementById('pdfViewer');
        if (!_container) return;

        /* Make container scrollable */
        _container.style.overflowY = 'auto';
        _container.style.maxHeight = '85vh';

        /* Hide old single-page nav buttons */
        var prevBtn = document.getElementById('pdfPrev');
        var nextBtn = document.getElementById('pdfNext');
        if (prevBtn) prevBtn.style.display = 'none';
        if (nextBtn) nextBtn.style.display = 'none';

        /* Load PDF */
        pdfjsLib.getDocument(url).promise.then(function (pdf) {
            _pdf = pdf;
            _total = pdf.numPages;
            var total = document.getElementById('pdfTotal');
            if (total) total.textContent = _total;
            updateUI();
            renderAll();
        }).catch(function (err) {
            console.error('PDFVIEWER load error:', err);
        });

        wireResize();
    }

    /* ── Public API ───────────────────────────────────────────── */
    return {
        init:     init,
        go:       function (n) {
            var item = _canvases[n - 1];
            if (item) item.wrapper.scrollIntoView({ behavior: 'smooth' });
        },
        current:  function () { return _current; },
        total:    function () { return _total; },
        next:     function () { PDFVIEWER.go(_current + 1); },
        prev:     function () { PDFVIEWER.go(_current - 1); },
        isFirst:  function () { return _current === 1; },
        isLast:   function () { return _current === _total; },
        download: function () { window.print(); }
    };
})();
