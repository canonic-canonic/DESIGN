/**
 * NAV — Unified Navigation Controller
 * ONE bar. Fleet tabs (primary). Breadcrumbs from CANON.json.
 */
var NAV = (function() {

    function init() {
        loadBreadcrumbs();
    }

    function loadBreadcrumbs() {
        var el = document.getElementById('navBreadcrumbs');
        if (!el) return;
        fetch('./CANON.json')
            .then(function(r) { return r.ok ? r.json() : null; })
            .then(function(data) {
                if (!data || !data.breadcrumbs) return;
                var html = '';
                for (var i = 0; i < data.breadcrumbs.length; i++) {
                    var c = data.breadcrumbs[i];
                    if (i > 0) html += '<span class="nav-crumb-sep">\u203a</span>';
                    if (i === data.breadcrumbs.length - 1)
                        html += '<span class="nav-crumb nav-crumb--current">' + c.label + '</span>';
                    else
                        html += '<a href="' + c.href + '" class="nav-crumb">' + c.label + '</a>';
                }
                el.innerHTML = html;
            })
            .catch(function() { /* CANON.json missing — breadcrumbs silently omitted */ });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { init: init };
})();
