// CONTROLS — Inline nav-right controller
// Four dimensions: TALK (position), DOWNLOAD (assets), VIEW (tex|md), THEME (light|dark)
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
        var next = mode === 'tex' ? 'md' : 'tex';
        var pdfViewer = document.getElementById('pdfViewer');
        var mdView = document.querySelector('.view-md');

        if (next === 'md') {
            if (pdfViewer) pdfViewer.style.display = 'none';
            if (mdView) mdView.style.display = '';
        } else {
            if (pdfViewer) pdfViewer.style.display = '';
            if (mdView) mdView.style.display = 'none';
        }

        document.querySelectorAll('.nav-view, .controls-view').forEach(function(b) {
            b.dataset.view = next;
            b.textContent = next.toUpperCase();
        });
    }

    return { talk: talk, view: view };
})();
