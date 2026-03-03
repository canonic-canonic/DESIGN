// CONTROLS — Inline nav-right controller
// Four dimensions: TALK (position), DOWNLOAD (assets), VIEW (md|html|tex), THEME (light|dark)
// GOV declares → Compiler emits → NAV renders inline → This toggles
var CONTROLS = (function() {
    'use strict';

    function talk(btn) {
        var overlay = document.getElementById('talkOverlay');
        if (!overlay) return;
        var pos = btn.dataset.position || overlay.getAttribute('data-position') || 'side';
        var next = pos === 'side' ? 'top' : 'side';
        overlay.setAttribute('data-position', next);
        document.querySelectorAll('[data-position]').forEach(function(b) {
            if (b.id === 'talkOverlay') return;
            b.dataset.position = next;
            if (b.classList.contains('controls-talk')) {
                b.innerHTML = '<span class="controls-dot"></span> TALK ' + next.toUpperCase();
            }
        });
    }

    // Dual-view toggle (paper/book: tex ↔ md)
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

    // Tri-view direct jump (service: md | html | tex)
    function viewTo(target) {
        var mdView = document.querySelector('.view-md');
        var htmlView = document.querySelector('.view-html');
        var pdfViewer = document.getElementById('pdfViewer');

        // Hide all views
        if (mdView) mdView.style.display = 'none';
        if (htmlView) htmlView.style.display = 'none';
        if (pdfViewer) pdfViewer.style.display = 'none';

        // Show target view
        if (target === 'md' && mdView) mdView.style.display = '';
        if (target === 'html' && htmlView) htmlView.style.display = '';
        if (target === 'tex' && pdfViewer) pdfViewer.style.display = '';

        // Update toggle bar active state
        document.querySelectorAll('.view-toggle-btn').forEach(function(b) {
            b.classList.toggle('active', b.dataset.target === target);
        });
    }

    return { talk: talk, view: view, viewTo: viewTo };
})();
