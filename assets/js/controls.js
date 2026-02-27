// CONTROLS — Unified control bar controller
// GOV declares → Compiler emits → Theme renders → This toggles
var CONTROLS = (function() {
    'use strict';

    function talk(btn) {
        var overlay = document.getElementById('talkOverlay');
        if (!overlay) return;
        var pos = btn.dataset.position;
        var next = pos === 'side' ? 'top' : 'side';
        overlay.setAttribute('data-position', next);
        btn.dataset.position = next;
        btn.innerHTML = '<span class="controls-dot"></span> TALK ' + next.toUpperCase();
    }

    function view(btn) {
        var mode = btn.dataset.view;
        var next = mode === 'latex' ? 'html' : 'latex';
        var pdfViewer = document.getElementById('pdfViewer');
        var prose = document.querySelector('.post-body, .paper-body, .book-body');

        if (next === 'html') {
            if (pdfViewer) pdfViewer.style.display = 'none';
            if (prose) prose.style.display = '';
        } else {
            if (pdfViewer) pdfViewer.style.display = '';
            if (prose) prose.style.display = 'none';
        }

        btn.dataset.view = next;
        btn.textContent = next.toUpperCase();
    }

    return { talk: talk, view: view };
})();
