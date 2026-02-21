/**
 * WALLET — Composable COIN wallet display + Stripe checkout.
 * Same pattern as TALK/SHOP/AUTH: one script, frontmatter-controlled.
 *
 * Static wallet.json first (vault-backed), API fallback (Stripe-sourced).
 *
 * Usage:
 *   page frontmatter: wallet: true  (or loaded as SHOP dependency)
 *   <script src="/assets/js/wallet.js"></script>
 *
 * WALLET | CANONIC | 2026
 */
var WALLET = (function () {
  'use strict';
  var API = (window.CANONIC_SHOP_API || 'https://api.canonic.org').replace(/\/+$/, '');

  function fmt(n) { return (Number(n || 0)).toLocaleString(); }

  /* Load wallet: static paths first (vault truth), then API fallback */
  async function load(paths) {
    var sources = (paths || []).concat([API + '/shop/wallet?top=12']);
    for (var i = 0; i < sources.length; i++) {
      try {
        var res = await fetch(sources[i], { cache: 'no-store' });
        if (!res.ok) continue;
        var data = await res.json();
        var w = data.wallet || data;
        if (w && w.totals) return w;
      } catch (e) { /* next source */ }
    }
    return null;
  }

  /* Render wallet into DOM elements by ID prefix convention */
  function render(w, prefix) {
    if (!w) return;
    prefix = prefix || 'w-';
    var map = {
      'balance': w.balance,
      'sale': (w.totals && w.totals.SALE) || 0,
      'donation': (w.totals && w.totals.DONATION) || 0,
      'invest': (w.totals && w.totals.INVEST) || 0,
      'events': w.events || 0
    };
    for (var key in map) {
      var el = document.getElementById(prefix + key);
      if (el) el.textContent = fmt(map[key]);
    }
  }

  /* Render transaction list into a container element */
  function renderTimeline(events, containerId) {
    var container = document.getElementById(containerId);
    if (!container || !events || !events.length) return;
    container.innerHTML = '';
    events.forEach(function (ev) {
      var row = document.createElement('div');
      row.className = 'tx-row';
      var isCredit = (ev.delta || ev.amount || 0) >= 0;
      row.innerHTML =
        '<div class="tx-date">' + fmtDate(ev.ts) + '</div>' +
        '<div class="tx-badge tx-' + (ev.type || ev.event || 'UNKNOWN').toLowerCase().replace(':', '-') + '">' + (ev.type || ev.event || '') + '</div>' +
        '<div class="tx-desc">' + (ev.product || ev.detail || '') + (ev.service ? ' / ' + ev.service : '') + '</div>' +
        '<div class="tx-amount ' + (isCredit ? 'tx-credit' : 'tx-debit') + '">' + (isCredit ? '+' : '') + fmt(ev.delta || ev.amount || 0) + '</div>';
      container.appendChild(row);
    });
  }

  function fmtDate(ts) {
    if (!ts) return '';
    try {
      var d = new Date(ts);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch (e) { return String(ts).slice(0, 10); }
  }

  /* Load timeline.json for a user */
  async function loadTimeline(paths) {
    for (var i = 0; i < (paths || []).length; i++) {
      try {
        var res = await fetch(paths[i], { cache: 'no-store' });
        if (!res.ok) continue;
        var data = await res.json();
        return data.events || data.recent || data;
      } catch (e) { /* next */ }
    }
    return [];
  }

  /* Start Stripe checkout */
  async function checkout(eventType, product, amount, opts) {
    opts = opts || {};
    var payload = {
      event: eventType,
      service: opts.service || 'SHOP',
      product: product,
      channel: opts.channel || 'SHOP',
      amount_coin: Number(amount || 0)
    };
    if (opts.name) payload.name = opts.name;
    if (opts.email) payload.email = opts.email;
    if (opts.note) payload.note = opts.note;

    var res = await fetch(API + '/shop/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok || !data || !data.url) {
      throw new Error(data && data.error ? data.error : ('HTTP ' + res.status));
    }
    window.location.href = data.url;
  }

  return {
    load: load,
    render: render,
    renderTimeline: renderTimeline,
    loadTimeline: loadTimeline,
    checkout: checkout,
    fmt: fmt,
    API: API
  };
})();
