// mcode.js — mCODE structured health profile extraction
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: extract structured oncology data from conversation, render sidebar
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('mcode.js') !== -1)
        return ss[i].src.replace(/[^/]+$/, '');
    }
    return '';
  })();

  function _boot() {
    if (_cfg) return Promise.resolve(_cfg);
    if (!window._canonicCatalog) {
      window._canonicCatalog = fetch(_catBase + 'catalog.json')
        .then(function (r) { return r.json(); })
        .catch(function () { return { plugins: [] }; });
    }
    return window._canonicCatalog.then(function (cat) {
      for (var i = 0; i < (cat.plugins || []).length; i++) {
        if (cat.plugins[i].plugin === 'mcode') { _cfg = cat.plugins[i]; return _cfg; }
      }
      return null;
    });
  }

  var STORE_KEY = 'mcode-profile';
  var profile = { phase: 'SCREENING', fields: {}, updated: null };

  // ── mCODE field patterns (client-side extraction) ──
  var PATTERNS = {
    'Cancer Type':     /\b(breast|prostate|lung|colorectal|pancreatic|ovarian|melanoma)\s*(cancer|carcinoma|adenocarcinoma)\b/i,
    'Stage':           /\b(stage|staging)\s*(0|I{1,3}V?|[1-4][A-C]?)\b/i,
    'BI-RADS':         /\bBI-?RADS\s*([0-6])\b/i,
    'Grade':           /\bgrade\s*([1-3]|I{1,3})\b/i,
    'ER Status':       /\b(ER|estrogen\s*receptor)\s*[:\-]?\s*(positive|negative|\+|\-)\b/i,
    'PR Status':       /\b(PR|progesterone\s*receptor)\s*[:\-]?\s*(positive|negative|\+|\-)\b/i,
    'HER2':            /\bHER2\s*[:\-]?\s*(positive|negative|\+|\-|equivocal)\b/i,
    'Ki-67':           /\bKi-?67\s*[:\-]?\s*(\d+)\s*%?\b/i,
    'Tumor Size':      /\btumor\s*(?:size)?\s*[:\-]?\s*(\d+\.?\d*)\s*(cm|mm)\b/i,
    'Lymph Nodes':     /\b(\d+)\s*(?:of\s*\d+\s*)?(?:lymph\s*)?nodes?\s*(positive|negative|involved)\b/i,
    'Treatment':       /\b(chemotherapy|radiation|surgery|lumpectomy|mastectomy|immunotherapy|tamoxifen|letrozole|herceptin|trastuzumab|pertuzumab|doxorubicin|cyclophosphamide)\b/i,
    'Genetic':         /\b(BRCA[12]|TP53|PIK3CA|ATM|CHEK2|PALB2)\s*(mutation|variant|positive|negative)?\b/i,
  };

  function load() {
    try {
      var saved = localStorage.getItem(STORE_KEY);
      if (saved) profile = JSON.parse(saved);
    } catch (e) { /* ignore */ }
  }

  function save() {
    profile.updated = new Date().toISOString();
    try { localStorage.setItem(STORE_KEY, JSON.stringify(profile)); } catch (e) { /* ignore */ }
    try { window.dispatchEvent(new CustomEvent('mcode-update', { detail: profile })); } catch (e) { /* ignore */ }
  }

  function extract(text) {
    if (!text) return;
    var found = false;
    for (var field in PATTERNS) {
      var m = text.match(PATTERNS[field]);
      if (m) {
        var val = m[0].trim();
        if (profile.fields[field] !== val) {
          profile.fields[field] = val;
          found = true;
        }
      }
    }
    if (found) { save(); render(); updateStatus(); }
  }

  function render() {
    var el = document.getElementById('mcode-content');
    if (!el) return;

    var keys = Object.keys(profile.fields);
    if (keys.length === 0) {
      el.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">Health Profile</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">Start chatting — your health profile builds as you share details.</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">Health Profile</div><div class="mcode-grid">';
    for (var i = 0; i < keys.length; i++) {
      html += '<div class="mcode-item"><div class="mcode-item-label">' + keys[i] + '</div>' +
        '<div class="mcode-item-value">' + escapeHtml(profile.fields[keys[i]]) + '</div></div>';
    }
    html += '</div></div>';

    if (profile.phase) {
      html += '<div class="mcode-section"><div class="mcode-section-title">Phase</div>' +
        '<div class="mcode-grid"><div class="mcode-item full"><div class="mcode-item-value">' +
        escapeHtml(profile.phase) + '</div></div></div></div>';
    }

    el.innerHTML = html;
  }

  function updateStatus() {
    var el = document.getElementById('mcode-status');
    if (!el) return;
    var count = Object.keys(profile.fields).length;
    el.textContent = count > 0 ? count + ' fields' : 'Listening...';
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ── Public API ──

  window.MCODE = {
    init: function () {
      _boot();
      load();
      render();
      updateStatus();
      var observer = new MutationObserver(function (mutations) {
        mutations.forEach(function (m) {
          m.addedNodes.forEach(function (node) {
            if (node.nodeType === 1) extract(node.textContent);
          });
        });
      });
      var msgs = document.getElementById('talkMessages');
      if (msgs) observer.observe(msgs, { childList: true, subtree: true });
    },

    toggleSidebar: function () {
      var el = document.getElementById('mcode-sidebar');
      if (el) el.classList.toggle('collapsed');
    },

    export: function () {
      var data = JSON.stringify(profile, null, 2);
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'mcode-profile-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },

    setPhase: function (value) {
      profile.phase = value;
      save();
      render();
    },

    extract: extract,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', window.MCODE.init);
  } else {
    window.MCODE.init();
  }
})();
