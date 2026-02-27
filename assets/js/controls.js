// CONTROLS — Inline nav-right controller
// Four dimensions: TALK (position), DOWNLOAD (assets), VIEW (latex|html), THEME (light|dark)
// GOV declares → Compiler emits → NAV renders inline → This toggles
var CONTROLS = (function() {
    'use strict';

    function talk(btn) {
        var overlay = document.getElementById('talkOverlay');
        if (!overlay) return;
        var pos = btn.dataset.position || overlay.getAttribute('data-position') || 'side';
        var next = pos === 'side' ? 'top' : 'side';
        overlay.setAttribute('data-position', next);
        // Sync all talk-position buttons (nav-right + any legacy controls-bar)
        document.querySelectorAll('[data-position]').forEach(function(b) {
            if (b.id === 'talkOverlay') return;
            b.dataset.position = next;
            if (b.classList.contains('controls-talk')) {
                b.innerHTML = '<span class="controls-dot"></span> TALK ' + next.toUpperCase();
            }
        });
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

        // Sync all view buttons (nav-right .nav-view + any legacy .controls-view)
        document.querySelectorAll('.nav-view, .controls-view').forEach(function(b) {
            b.dataset.view = next;
            b.textContent = next.toUpperCase();
        });
    }

    return { talk: talk, view: view };
})();
