// clinvar.js — Variant classification (ACMG/AMP) via NCBI ClinVar
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: search ClinVar for gene variants, render clinical significance
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('clinvar.js') !== -1)
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
        if (cat.plugins[i].plugin === 'clinvar') { _cfg = cat.plugins[i]; return _cfg; }
      }
      return null;
    });
  }

  var EUTILS = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/';
  var cache = {};

  function _getGene() {
    try {
      var p = JSON.parse(localStorage.getItem('mcode-profile') || '{}');
      var g = (p.fields || {})['Genetic'] || '';
      var m = g.match(/^(\w+)/);
      return m ? m[1] : '';
    } catch (e) { return ''; }
  }

  function search(gene) {
    if (!gene) { render([]); return; }
    if (cache[gene]) { render(cache[gene]); return; }

    _boot().then(function (cfg) {
      if (!cfg) return;

      var searchUrl = EUTILS + 'esearch.fcgi?db=clinvar&term=' +
        encodeURIComponent(gene + '[gene]') + '&retmode=json&retmax=8';

      fetch(searchUrl)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var ids = (data.esearchresult || {}).idlist || [];
          if (ids.length === 0) { cache[gene] = []; render([]); return; }
          return fetch(EUTILS + 'esummary.fcgi?db=clinvar&id=' + ids.join(',') + '&retmode=json')
            .then(function (r) { return r.json(); });
        })
        .then(function (sum) {
          if (!sum) return;
          var uids = (sum.result || {}).uids || [];
          var variants = uids.map(function (uid) {
            var rec = sum.result[uid] || {};
            return {
              id: uid,
              title: rec.title || 'Unknown variant',
              significance: (rec.clinical_significance || {}).description || 'Not provided',
              type: rec.obj_type || '',
            };
          });
          cache[gene] = variants;
          try { localStorage.setItem('clinvar-data', JSON.stringify(variants)); } catch (e) { /* ignore */ }
          render(variants);
        })
        .catch(function () { render([]); });
    });
  }

  function render(variants) {
    var container = document.getElementById('clinvar-section');
    if (!container) return;

    var baseUrl = _cfg ? 'https://' + _cfg.api : 'https://ncbi.nlm.nih.gov/clinvar';

    if (!variants || variants.length === 0) {
      var gene = _getGene();
      container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">ClinVar Variants</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">' +
        (gene ? 'No variants found for ' + escapeHtml(gene) + '.' : 'Waiting for genetic data...') + '</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">ClinVar (' + variants.length + ')</div>';
    for (var i = 0; i < variants.length; i++) {
      var v = variants[i];
      var sigStyle = v.significance.toLowerCase().indexOf('pathogenic') !== -1 ? 'color:#ef4444' :
        v.significance.toLowerCase().indexOf('benign') !== -1 ? 'color:#22c55e' : 'color:var(--dim)';
      html += '<div class="mcode-item full">' +
        '<div class="mcode-item-label"><a href="' + baseUrl + '/variation/' + escapeHtml(v.id) +
        '" target="_blank" rel="noopener" style="color:var(--accent)">' +
        escapeHtml(v.title.length > 50 ? v.title.substring(0, 50) + '...' : v.title) + '</a></div>' +
        '<div class="mcode-item-value" style="font-size:var(--font-xs);' + sigStyle + '">' +
        escapeHtml(v.significance) + '</div></div>';
    }
    html += '</div>';
    container.innerHTML = html;
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // ── Public API ──

  window.CLINVAR = {
    init: function () {
      var gene = _getGene();
      if (gene) search(gene);
      else render([]);
    },

    search: search,
    render: render,

    export: function () {
      var data = localStorage.getItem('clinvar-data') || '[]';
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'clinvar-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { window.CLINVAR.init(); });
  } else {
    window.CLINVAR.init();
  }

  window.addEventListener('mcode-update', function (e) {
    var g = (e.detail.fields || {})['Genetic'] || '';
    var m = g.match(/^(\w+)/);
    if (m) search(m[1]);
  });
})();
