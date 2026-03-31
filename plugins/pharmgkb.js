// pharmgkb.js — Drug-gene interactions via PharmGKB
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: search PharmGKB for drug-gene annotations, render evidence levels
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('pharmgkb.js') !== -1)
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
        if (cat.plugins[i].plugin === 'pharmgkb') { _cfg = cat.plugins[i]; return _cfg; }
      }
      return null;
    });
  }

  var cache = {};

  function _getContext() {
    try {
      var p = JSON.parse(localStorage.getItem('mcode-profile') || '{}');
      var gene = ((p.fields || {})['Genetic'] || '').match(/^(\w+)/);
      var drug = (p.fields || {})['Treatment'] || '';
      return { gene: gene ? gene[1] : '', drug: drug };
    } catch (e) { return { gene: '', drug: '' }; }
  }

  function search(gene) {
    if (!gene) { render([]); return; }
    if (cache[gene]) { render(cache[gene]); return; }

    _boot().then(function (cfg) {
      if (!cfg) return;

      var apiBase = 'https://' + cfg.api;
      var url = apiBase + '/v1/data/clinicalAnnotation?view=min&location.genes.symbol=' +
        encodeURIComponent(gene);

      fetch(url)
        .then(function (r) {
          if (!r.ok) throw new Error('API error');
          return r.json();
        })
        .then(function (data) {
          var items = (data.data || []).slice(0, 8).map(function (a) {
            var genes = a.location && a.location.genes ? a.location.genes.map(function (g) { return g.symbol; }) : [];
            var drugs = a.relatedChemicals ? a.relatedChemicals.map(function (c) { return c.name; }) : [];
            var phenos = a.phenotypes ? a.phenotypes.map(function (p) { return p.name; }) : [];
            return {
              id: a.id || '',
              gene: genes.join(', ') || gene,
              drug: drugs.join(', ') || '',
              level: a.evidenceLevel || '',
              phenotype: phenos.join(', ') || '',
            };
          });
          cache[gene] = items;
          try { localStorage.setItem('pharmgkb-data', JSON.stringify(items)); } catch (e) { /* ignore */ }
          render(items);
        })
        .catch(function () {
          // API unavailable (CORS or network) — render search links
          renderFallback(gene);
        });
    });
  }

  function render(annotations) {
    var container = document.getElementById('pharmgkb-section');
    if (!container) return;

    if (!annotations || annotations.length === 0) {
      var ctx = _getContext();
      container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">PharmGKB</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">' +
        (ctx.gene ? 'No drug-gene data for ' + escapeHtml(ctx.gene) + '.' : 'Waiting for genetic data...') + '</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">PharmGKB (' + annotations.length + ')</div>';
    for (var i = 0; i < annotations.length; i++) {
      var a = annotations[i];
      var levelStyle = a.level === '1A' || a.level === '1B' ? 'color:#22c55e' :
        a.level === '2A' || a.level === '2B' ? 'color:#eab308' : 'color:var(--dim)';
      html += '<div class="mcode-item full">' +
        '<div class="mcode-item-label">' +
        (a.id ? '<a href="https://www.pharmgkb.org/clinicalAnnotation/' + escapeHtml(a.id) +
        '" target="_blank" rel="noopener" style="color:var(--accent)">' : '') +
        escapeHtml(a.drug || 'Unknown drug') +
        (a.id ? '</a>' : '') +
        ' <span style="font-size:var(--font-xs);' + levelStyle + '">' + escapeHtml(a.level) + '</span></div>' +
        '<div class="mcode-item-value" style="font-size:var(--font-xs)">' +
        escapeHtml(a.phenotype || a.gene) + '</div></div>';
    }
    html += '</div>';
    container.innerHTML = html;
  }

  function renderFallback(gene) {
    var container = document.getElementById('pharmgkb-section');
    if (!container) return;

    var searchUrl = 'https://www.pharmgkb.org/gene/' + encodeURIComponent(gene);
    container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">PharmGKB</div>' +
      '<div class="mcode-item full"><div class="mcode-item-value" style="font-size:var(--font-xs)">' +
      '<a href="' + escapeHtml(searchUrl) + '" target="_blank" rel="noopener" style="color:var(--accent)">' +
      'View ' + escapeHtml(gene) + ' on PharmGKB &rarr;</a></div></div></div>';
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // ── Public API ──

  window.PHARMGKB = {
    init: function () {
      var ctx = _getContext();
      if (ctx.gene) search(ctx.gene);
      else render([]);
    },

    search: search,
    render: render,

    export: function () {
      var data = localStorage.getItem('pharmgkb-data') || '[]';
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'pharmgkb-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { window.PHARMGKB.init(); });
  } else {
    window.PHARMGKB.init();
  }

  window.addEventListener('mcode-update', function (e) {
    var g = (e.detail.fields || {})['Genetic'] || '';
    var m = g.match(/^(\w+)/);
    if (m) search(m[1]);
  });
})();
