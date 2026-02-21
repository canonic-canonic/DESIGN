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
    API: (window.CANONIC_SHOP_API || 'https://api.canonic.org').replace(/\/+$/, ''),
    TOKEN_KEY: 'canonic_auth_token',

    // ── Initialize ────────────────────────────────────────────
    async init() {
        this.loadBag();
        this.renderBagCount();

        // Load products from SHOP.json (static, compiled from GOV)
        await this.loadProducts();
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

    renderProducts() {
        var container = document.getElementById('shopProducts');
        if (!container) return;
        container.innerHTML = '';

        var mode = document.getElementById('shopRoot');
        var filter = mode ? mode.getAttribute('data-mode') : 'catalog';

        var items = this.products;
        if (filter === 'inline') {
            // Inline mode: filter by page context (e.g. BOOKS page shows only BOOKs)
            var scope = document.querySelector('[data-scope]');
            var s = scope ? scope.getAttribute('data-scope') : '';
            if (s && s !== 'shop') {
                items = items.filter(function (p) {
                    return (p.type || '').toUpperCase() === s.toUpperCase() ||
                           (p.shop_lane || '').toUpperCase() === s.toUpperCase();
                });
            }
        }

        if (!items.length) {
            container.innerHTML = '<p class="shop-empty">No products yet.</p>';
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

        card.innerHTML =
            (product.cover
                ? '<div class="shop-card-cover" style="background-image:url(' + product.cover + ')"></div>'
                : '<div class="shop-card-cover shop-card-gradient"></div>') +
            '<div class="shop-card-body">' +
                '<div class="shop-card-eyebrow">' + (product.type || '') + '</div>' +
                '<div class="shop-card-title">' + (product.title || '') + '</div>' +
                (product.synopsis ? '<div class="shop-card-synopsis">' + product.synopsis + '</div>' : '') +
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
