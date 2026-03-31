// geo.js — Expression data via NCBI GEO DataSets
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: search GEO for gene expression datasets, render series info
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('geo.js') !== -1)
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
        if (cat.plugins[i].plugin === 'geo') { _cfg = cat.plugins[i]; return _cfg; }
      }
      return null;
    });
  }

  var EUTILS = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/';
  var cache = {};

  function _getQuery() {
    try {
      var p = JSON.parse(localStorage.getItem('mcode-profile') || '{}');
      var gene = ((p.fields || {})['Genetic'] || '').match(/^(\w+)/);
      var cancer = (p.fields || {})['Cancer Type'] || '';
      gene = gene ? gene[1] : '';
      return { gene: gene, cancer: cancer, term: [gene, cancer].filter(Boolean).join(' ') };
    } catch (e) { return { gene: '', cancer: '', term: '' }; }
  }

  function search(term) {
    if (!term) { render([]); return; }
    if (cache[term]) { render(cache[term]); return; }

    _boot().then(function (cfg) {
      if (!cfg) return;

      var searchUrl = EUTILS + 'esearch.fcgi?db=gds&term=' +
        encodeURIComponent(term + ' AND Homo sapiens[Organism]') + '&retmode=json&retmax=6';

      fetch(searchUrl)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var ids = (data.esearchresult || {}).idlist || [];
          if (ids.length === 0) { cache[term] = []; render([]); return; }
          return fetch(EUTILS + 'esummary.fcgi?db=gds&id=' + ids.join(',') + '&retmode=json')
            .then(function (r) { return r.json(); });
        })
        .then(function (sum) {
          if (!sum) return;
          var uids = (sum.result || {}).uids || [];
          var datasets = uids.map(function (uid) {
            var rec = sum.result[uid] || {};
            return {
              id: uid,
              accession: rec.accession || '',
              title: rec.title || 'Untitled dataset',
              taxon: rec.taxon || '',
              samples: rec.n_samples || rec.samplecount || '?',
              type: rec.gdstype || rec.entrytype || '',
            };
          });
          cache[term] = datasets;
          try { localStorage.setItem('geo-data', JSON.stringify(datasets)); } catch (e) { /* ignore */ }
          render(datasets);
        })
        .catch(function () { render([]); });
    });
  }

  function render(datasets) {
    var container = document.getElementById('geo-section');
    if (!container) return;

    var baseUrl = _cfg ? 'https://' + _cfg.api : 'https://ncbi.nlm.nih.gov/geo';

    if (!datasets || datasets.length === 0) {
      var q = _getQuery();
      container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">GEO Expression</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">' +
        (q.term ? 'No datasets found for ' + escapeHtml(q.term) + '.' : 'Waiting for profile data...') + '</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">GEO (' + datasets.length + ')</div>';
    for (var i = 0; i < datasets.length; i++) {
      var ds = datasets[i];
      var acc = ds.accession || ('GDS' + ds.id);
      html += '<div class="mcode-item full">' +
        '<div class="mcode-item-label"><a href="' + baseUrl + '/query/acc.cgi?acc=' + escapeHtml(acc) +
        '" target="_blank" rel="noopener" style="color:var(--accent)">' + escapeHtml(acc) + '</a>' +
        ' <span style="color:var(--dim);font-size:var(--font-xs)">' + escapeHtml(ds.samples) + ' samples</span></div>' +
        '<div class="mcode-item-value" style="font-size:var(--font-xs)">' +
        escapeHtml(ds.title.length > 60 ? ds.title.substring(0, 60) + '...' : ds.title) + '</div></div>';
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

  window.GEO = {
    init: function () {
      var q = _getQuery();
      if (q.term) search(q.term);
      else render([]);
    },

    search: search,
    render: render,

    export: function () {
      var data = localStorage.getItem('geo-data') || '[]';
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'geo-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { window.GEO.init(); });
  } else {
    window.GEO.init();
  }

  window.addEventListener('mcode-update', function (e) {
    var gene = ((e.detail.fields || {})['Genetic'] || '').match(/^(\w+)/);
    var cancer = (e.detail.fields || {})['Cancer Type'] || '';
    gene = gene ? gene[1] : '';
    var term = [gene, cancer].filter(Boolean).join(' ');
    if (term) search(term);
  });
})();
