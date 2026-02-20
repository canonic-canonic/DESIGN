/**
 * NAV — Unified Navigation Controller
 * ONE bar. MIN/MAX toggle. Governed by scope.
 */
var NAV = (function() {
    var brand, dropdown, open = false;

    function init() {
        brand = document.getElementById('navBrand');
        dropdown = document.getElementById('navDropdown');
        if (!brand || !dropdown) return;

        brand.addEventListener('click', toggle);
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && open) close();
        });
        document.addEventListener('click', function(e) {
            if (open && !brand.contains(e.target) && !dropdown.contains(e.target)) close();
        });
    }

    function toggle() {
        open ? close() : openDropdown();
    }

    function openDropdown() {
        dropdown.classList.add('open');
        brand.classList.add('open');
        brand.setAttribute('aria-expanded', 'true');
        open = true;
    }

    function close() {
        dropdown.classList.remove('open');
        brand.classList.remove('open');
        brand.setAttribute('aria-expanded', 'false');
        open = false;
    }

    // Auto-init on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { toggle: toggle, close: close };
})();
