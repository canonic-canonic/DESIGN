// CONTROLS — Inline nav-right controller
// Four dimensions: TALK (position), DOWNLOAD (assets), VIEW (gov|web|tex), THEME (light|dark)
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

    // Universal view switch — GOV → WEB → TEX
    function viewTo(target) {
        var govView = document.querySelector('.view-gov');
        var webView = document.querySelector('.view-web');
        var pdfViewer = document.getElementById('pdfViewer');

        // Hide all views
        if (govView) govView.style.display = 'none';
        if (webView) webView.style.display = 'none';
        if (pdfViewer) pdfViewer.style.display = 'none';

        // Show target view
        if (target === 'gov' && govView) govView.style.display = '';
        if (target === 'web' && webView) webView.style.display = '';
        if (target === 'tex' && pdfViewer) {
            pdfViewer.style.display = '';
            // Re-render PDF when revealed from hidden (fixes 0×0 canvas)
            if (typeof PDFVIEWER !== 'undefined' && PDFVIEWER.reveal) PDFVIEWER.reveal();
        }

        // Update toggle bar active state
        document.querySelectorAll('.view-toggle-btn').forEach(function(b) {
            b.classList.toggle('active', b.dataset.target === target);
        });

        // Adapt body for contract view (deck overflow, chrome visibility)
        document.body.classList.toggle('contract-view', target === 'gov');

        // Hide deck-specific chrome when not in WEB view
        var deckCounter = document.querySelector('.nav-deck-counter');
        var deckTimer = document.querySelector('.nav-deck-timer');
        if (deckCounter) deckCounter.style.display = (target === 'web') ? '' : 'none';
        if (deckTimer) deckTimer.style.display = (target === 'web') ? '' : 'none';
    }

    // On load: detect default view and apply contract-view if GOV is active
    document.addEventListener('DOMContentLoaded', function() {
        var govView = document.querySelector('.view-gov');
        var webView = document.querySelector('.view-web');
        if (govView && webView && webView.style.display === 'none') {
            viewTo('gov');
        }
    });

    return { talk: talk, viewTo: viewTo };
})();
