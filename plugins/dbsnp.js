// dbsnp.js — Variant annotation (rs IDs) via NCBI dbSNP
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: search dbSNP for gene variants, render rs IDs with annotations
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('dbsnp.js') !== -1)
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
        if (cat.plugins[i].plugin === 'dbsnp') { _cfg = cat.plugins[i]; return _cfg; }
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

      var searchUrl = EUTILS + 'esearch.fcgi?db=snp&term=' +
        encodeURIComponent(gene + '[Gene Name] AND clinical[Filter]') + '&retmode=json&retmax=8';

      fetch(searchUrl)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var ids = (data.esearchresult || {}).idlist || [];
          if (ids.length === 0) { cache[gene] = []; render([]); return; }
          return fetch(EUTILS + 'esummary.fcgi?db=snp&id=' + ids.join(',') + '&retmode=json')
            .then(function (r) { return r.json(); });
        })
        .then(function (sum) {
          if (!sum) return;
          var uids = (sum.result || {}).uids || [];
          var snps = uids.map(function (uid) {
            var rec = sum.result[uid] || {};
            return {
              id: uid,
              rsid: 'rs' + uid,
              gene: rec.genes ? rec.genes.map(function (g) { return g.name; }).join(', ') : gene,
              fxn: rec.fxn_class || rec.docsum || '',
              clinical: rec.clinical_significance || '',
            };
          });
          cache[gene] = snps;
          try { localStorage.setItem('dbsnp-data', JSON.stringify(snps)); } catch (e) { /* ignore */ }
          render(snps);
        })
        .catch(function () { render([]); });
    });
  }

  function render(snps) {
    var container = document.getElementById('dbsnp-section');
    if (!container) return;

    var baseUrl = _cfg ? 'https://' + _cfg.api : 'https://ncbi.nlm.nih.gov/snp';

    if (!snps || snps.length === 0) {
      var gene = _getGene();
      container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">dbSNP Variants</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">' +
        (gene ? 'No clinically relevant SNPs for ' + escapeHtml(gene) + '.' : 'Waiting for genetic data...') + '</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">dbSNP (' + snps.length + ')</div>';
    for (var i = 0; i < snps.length; i++) {
      var s = snps[i];
      html += '<div class="mcode-item full">' +
        '<div class="mcode-item-label"><a href="' + baseUrl + '/' + escapeHtml(s.rsid) +
        '" target="_blank" rel="noopener" style="color:var(--accent)">' + escapeHtml(s.rsid) + '</a>' +
        ' <span style="color:var(--dim);font-size:var(--font-xs)">' + escapeHtml(s.gene) + '</span></div>' +
        '<div class="mcode-item-value" style="font-size:var(--font-xs)">' +
        escapeHtml(s.fxn || s.clinical || 'Annotation pending') + '</div></div>';
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

  window.DBSNP = {
    init: function () {
      var gene = _getGene();
      if (gene) search(gene);
      else render([]);
    },

    search: search,
    render: render,

    export: function () {
      var data = localStorage.getItem('dbsnp-data') || '[]';
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'dbsnp-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { window.DBSNP.init(); });
  } else {
    window.DBSNP.init();
  }

  window.addEventListener('mcode-update', function (e) {
    var g = (e.detail.fields || {})['Genetic'] || '';
    var m = g.match(/^(\w+)/);
    if (m) search(m[1]);
  });
})();
