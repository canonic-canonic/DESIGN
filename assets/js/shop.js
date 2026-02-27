/**
 * SHOP — Composable commerce singleton.
 * Same pattern as TALK: one include, one script, frontmatter-controlled.
 *
 * SHOP.json is the data source (compiled from GOV SHOP.md Card tables).
 * WALLET.load() is the wallet projection (never reimplemented).
 *
 * Usage:
 *   page frontmatter: shop: true|inline
 *   {% include SHOP.html %}
 *   <script src="/assets/js/shop.js"></script>
 *   <script>SHOP.init();</script>
 *
 * SHOP | CANONIC | 2026
 */
const SHOP = {
    products: [],
    bag: [],
    wallet: null,
    activeFilters: { domain: '', audience: '', type: '' },
    API: (window.CANONIC_SHOP_API || 'https://api.canonic.org').replace(/\/+$/, ''),
    TOKEN_KEY: 'canonic_auth_token',

    // ── Initialize ────────────────────────────────────────────
    async init() {
        this.loadBag();
        this.renderBagCount();

        // Load products from SHOP.json (static, compiled from GOV)
        await this.loadProducts();
        this.renderFilterBar();
        this.renderProducts();

        // Wallet projection — delegate to shared WALLET module
        if (typeof WALLET !== 'undefined') {
            this.wallet = await WALLET.load(['/wallet.json', '/SHOP/wallet.json']);
            this.renderWallet();
        }

        // Handle checkout returns
        this.handleReturn();

        // ESC to close bag
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') SHOP.closeBag();
        });
    },

    // ── Products ──────────────────────────────────────────────
    async loadProducts() {
        var paths = ['./SHOP.json', '/SERVICES/SHOP/SHOP.json', '/SHOP/SHOP.json'];
        for (var i = 0; i < paths.length; i++) {
            try {
                var res = await fetch(paths[i]);
                if (!res.ok) continue;
                var data = await res.json();
                this.products = data.products || data.shop || [];
                if (this.products.length) return;
            } catch (e) { /* next */ }
        }
    },

    // ── Filter bar ────────────────────────────────────────────
    renderFilterBar() {
        var bar = document.getElementById('shopFilterBar');
        if (!bar) return;

        var mode = document.getElementById('shopRoot');
        if (mode && mode.getAttribute('data-mode') === 'inline') {
            bar.style.display = 'none';
            return;
        }

        // Collect unique values
        var domains = {}, audiences = {}, types = {};
        for (var i = 0; i < this.products.length; i++) {
            var p = this.products[i];
            if (p.domain) domains[p.domain] = true;
            if (p.audience) audiences[p.audience] = true;
            if (p.type) types[p.type.toUpperCase()] = true;
        }

        var html = '';
        var self = this;

        function renderGroup(label, values, filterKey) {
            if (!Object.keys(values).length) return '';
            var h = '<span class="shop-filter-label">' + label + '</span>';
            h += '<button class="shop-filter-btn' + (self.activeFilters[filterKey] === '' ? ' active' : '') + '" data-filter="' + filterKey + '" data-value="">All</button>';
            var keys = Object.keys(values).sort();
            for (var j = 0; j < keys.length; j++) {
                h += '<button class="shop-filter-btn' + (self.activeFilters[filterKey] === keys[j] ? ' active' : '') + '" data-filter="' + filterKey + '" data-value="' + keys[j] + '">' + keys[j].charAt(0).toUpperCase() + keys[j].slice(1) + '</button>';
            }
            return h;
        }

        html += renderGroup('Type', types, 'type');
        html += renderGroup('Domain', domains, 'domain');
        html += renderGroup('Audience', audiences, 'audience');

        bar.innerHTML = html;

        // Bind click handlers
        var btns = bar.querySelectorAll('.shop-filter-btn');
        for (var k = 0; k < btns.length; k++) {
            btns[k].addEventListener('click', function () {
                var key = this.getAttribute('data-filter');
                var val = this.getAttribute('data-value');
                SHOP.activeFilters[key] = val;
                SHOP.renderFilterBar();
                SHOP.renderProducts();
            });
        }
    },

    renderProducts() {
        var container = document.getElementById('shopProducts');
        if (!container) return;
        container.innerHTML = '';

        var mode = document.getElementById('shopRoot');
        var dataMode = mode ? mode.getAttribute('data-mode') : 'catalog';

        var items = this.products;
        if (dataMode === 'inline') {
            // Inline mode: filter by page context (e.g. BOOKS page shows only BOOKs)
            var scope = document.querySelector('[data-scope]');
            var s = scope ? scope.getAttribute('data-scope') : '';
            if (s && s !== 'shop') {
                items = items.filter(function (p) {
                    return (p.type || '').toUpperCase() === s.toUpperCase() ||
                           (p.shop_lane || '').toUpperCase() === s.toUpperCase();
                });
            }
        } else {
            // Catalog mode: apply active filters
            var af = this.activeFilters;
            items = items.filter(function (p) {
                if (af.domain && (p.domain || '') !== af.domain) return false;
                if (af.audience && (p.audience || '') !== af.audience) return false;
                if (af.type && (p.type || '').toUpperCase() !== af.type) return false;
                return true;
            });
        }

        if (!items.length) {
            container.innerHTML = '<p class="shop-empty">No products match the current filters.</p>';
            return;
        }

        for (var i = 0; i < items.length; i++) {
            container.appendChild(this.renderCard(items[i]));
        }
    },

    renderCard(product) {
        var card = document.createElement('div');
        card.className = 'shop-card';

        var price = parseInt(product.price) || 0;
        var priceText = price > 0 ? price + ' COIN' : 'Free';
        var ctaText = price > 0 ? 'Add to Bag' : 'Get';
        var status = product.status || '';

        // Build tags HTML
        var tagsHtml = '';
        var tags = product.tags || [];
        if (typeof tags === 'string') tags = tags.split(',').map(function (t) { return t.trim(); });
        if (tags.length) {
            tagsHtml = '<div class="shop-card-tags">';
            for (var t = 0; t < tags.length; t++) {
                tagsHtml += '<span class="shop-tag">' + tags[t] + '</span>';
            }
            tagsHtml += '</div>';
        }

        // Build badges HTML
        var badgesHtml = '';
        if (product.audience || product.domain) {
            badgesHtml = '<div class="shop-card-badges">';
            if (product.audience) badgesHtml += '<span class="shop-badge shop-badge-audience">' + product.audience + '</span>';
            if (product.domain) badgesHtml += '<span class="shop-badge shop-badge-domain">' + product.domain + '</span>';
            badgesHtml += '</div>';
        }

        card.innerHTML =
            (product.cover
                ? '<div class="shop-card-cover" style="background-image:url(' + product.cover + ')"></div>'
                : '<div class="shop-card-cover shop-card-gradient"></div>') +
            '<div class="shop-card-body">' +
                '<div class="shop-card-eyebrow">' + (product.type || '') + '</div>' +
                '<div class="shop-card-title">' + (product.title || '') + '</div>' +
                (product.synopsis ? '<div class="shop-card-synopsis">' + product.synopsis + '</div>' : '') +
                badgesHtml +
                tagsHtml +
                (status ? '<div class="shop-card-status">' + status + '</div>' : '') +
                '<div class="shop-card-price">' + priceText + '</div>' +
            '</div>';

        var btn = document.createElement('button');
        btn.className = 'shop-card-cta' + (price > 0 ? '' : ' shop-card-cta-free');
        btn.textContent = ctaText;

        var self = this;
        if (price > 0) {
            btn.onclick = function () { self.addToBag(product); };
        } else {
            btn.onclick = function () {
                if (product.route) window.location.href = product.route;
            };
        }

        card.appendChild(btn);
        return card;
    },

    // ── Bag ───────────────────────────────────────────────────
    loadBag() {
        try {
            this.bag = JSON.parse(localStorage.getItem('canonic-bag') || '[]');
        } catch (e) { this.bag = []; }
    },

    saveBag() {
        localStorage.setItem('canonic-bag', JSON.stringify(this.bag));
    },

    addToBag(product) {
        this.bag.push({
            title: product.title,
            price: parseInt(product.price) || 0,
            type: product.type || '',
            seller: product.seller || '',
            route: product.route || ''
        });
        this.saveBag();
        this.renderBagCount();
        this.showMessage('Added to bag');
        this.openBag();
    },

    removeFromBag(index) {
        this.bag.splice(index, 1);
        this.saveBag();
        this.renderBagCount();
        this.renderBagItems();
    },

    renderBagCount() {
        var el = document.getElementById('shopBagCount');
        if (el) {
            var n = this.bag.length;
            el.textContent = n > 0 ? n : '';
            el.style.display = n > 0 ? '' : 'none';
        }
    },

    renderBagItems() {
        var items = document.getElementById('shopBagItems');
        var empty = document.getElementById('shopBagEmpty');
        var footer = document.getElementById('shopBagFooter');
        if (!items) return;

        items.innerHTML = '';

        if (!this.bag.length) {
            if (empty) empty.style.display = 'block';
            if (footer) footer.style.display = 'none';
            return;
        }

        if (empty) empty.style.display = 'none';
        if (footer) footer.style.display = '';

        var total = 0;
        for (var i = 0; i < this.bag.length; i++) {
            var item = this.bag[i];
            total += item.price;

            var row = document.createElement('div');
            row.className = 'shop-bag-item';
            row.innerHTML =
                '<div class="shop-bag-item-info">' +
                    '<div class="shop-bag-item-title">' + item.title + '</div>' +
                    '<div class="shop-bag-item-price">' + item.price + ' COIN</div>' +
                '</div>';

            var rm = document.createElement('button');
            rm.className = 'shop-bag-item-remove';
            rm.textContent = 'Remove';
            rm.setAttribute('data-index', i);
            rm.onclick = function () { SHOP.removeFromBag(parseInt(this.getAttribute('data-index'))); };
            row.appendChild(rm);
            items.appendChild(row);
        }

        var totalEl = document.getElementById('shopBagTotal');
        if (totalEl) totalEl.textContent = total + ' COIN';

        // Show COIN button only if authenticated
        var coinBtn = document.querySelector('.shop-checkout-btn:not(.shop-checkout-card)');
        if (coinBtn) {
            coinBtn.style.display = localStorage.getItem(this.TOKEN_KEY) ? '' : 'none';
        }
    },

    openBag() {
        var overlay = document.getElementById('shopBag');
        if (overlay) {
            overlay.classList.add('open');
            this.renderBagItems();
        }
    },

    closeBag() {
        var overlay = document.getElementById('shopBag');
        if (overlay) overlay.classList.remove('open');
    },

    // ── Checkout ──────────────────────────────────────────────
    async checkout(method) {
        if (!this.bag.length) return;

        var total = 0;
        var products = [];
        for (var i = 0; i < this.bag.length; i++) {
            total += this.bag[i].price;
            products.push(this.bag[i].title);
        }

        var productLabel = products.join(', ');

        if (method === 'coin') {
            var token = localStorage.getItem(this.TOKEN_KEY);
            if (!token) {
                this.showAuth();
                return;
            }

            try {
                var res = await fetch(this.API + '/api/v1/spend', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({
                        seller: this.bag[0].seller || '',
                        amount: total,
                        product: productLabel
                    })
                });
                var data = await res.json();
                if (data.error) {
                    this.showMessage('Error: ' + data.error, 'error');
                } else {
                    this.bag = [];
                    this.saveBag();
                    this.renderBagCount();
                    this.closeBag();
                    this.showMessage('Purchased for ' + total + ' COIN', 'success');
                    if (typeof WALLET !== 'undefined') {
                        this.wallet = await WALLET.load(['/wallet.json']);
                        this.renderWallet();
                    }
                }
            } catch (e) {
                this.showMessage('Network error', 'error');
            }
        } else {
            // Card — delegate to WALLET.checkout (Stripe)
            try {
                if (typeof WALLET !== 'undefined') {
                    await WALLET.checkout('SALE', productLabel, total, {
                        service: 'SHOP',
                        channel: 'SHOP'
                    });
                }
            } catch (e) {
                this.showMessage('Checkout unavailable: ' + e.message, 'error');
            }
        }
    },

    // ── Wallet ────────────────────────────────────────────────
    renderWallet() {
        var el = document.getElementById('shopBalance');
        if (!el || !this.wallet) return;
        var balance = this.wallet.balance || 0;
        el.textContent = (typeof WALLET !== 'undefined' ? WALLET.fmt(balance) : balance) + ' COIN';
        el.style.display = balance > 0 ? '' : 'none';
    },

    // ── Auth ──────────────────────────────────────────────────
    showAuth() {
        var returnTo = encodeURIComponent(window.location.href);
        window.location.href = this.API + '/api/v1/auth/github?return_to=' + returnTo;
    },

    // ── Checkout Return ───────────────────────────────────────
    handleReturn() {
        try {
            var p = new URLSearchParams(window.location.search);
            if (p.get('checkout') === 'success') {
                this.bag = [];
                this.saveBag();
                this.renderBagCount();
                this.showMessage('Checkout complete', 'success');
                window.history.replaceState({}, '', window.location.pathname);
            } else if (p.get('checkout') === 'cancel') {
                this.showMessage('Checkout canceled', 'info');
                window.history.replaceState({}, '', window.location.pathname);
            }
            // Handle auth token in URL (GitHub OAuth callback)
            var token = p.get('token');
            if (token) {
                localStorage.setItem(this.TOKEN_KEY, token);
                var user = p.get('user');
                if (user) localStorage.setItem('canonic_user', user);
                window.history.replaceState({}, '', window.location.pathname);
            }
        } catch (e) { /* no params */ }
    },

    // ── Message ───────────────────────────────────────────────
    showMessage(msg, type) {
        var el = document.getElementById('shopMessage');
        if (!el) return;
        el.textContent = msg;
        el.className = 'shop-message shop-message-' + (type || 'success');
        el.style.display = 'block';
        setTimeout(function () { el.style.display = 'none'; }, 3000);
    }
};
