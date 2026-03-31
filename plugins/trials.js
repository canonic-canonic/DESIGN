// trials.js — ClinicalTrials.gov live trial matching
// PLUGINS | SERVICES | hadleylab-canonic
// One concern: search ClinicalTrials.gov, render matches with NCT citations
(function () {
  'use strict';

  // ── Governed config — derived from plugins/catalog.json ──
  var _cfg = null;
  var _catBase = (function () {
    var ss = document.getElementsByTagName('script');
    for (var i = ss.length - 1; i >= 0; i--) {
      if (ss[i].src && ss[i].src.indexOf('trials.js') !== -1)
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
        if (cat.plugins[i].plugin === 'trials') { _cfg = cat.plugins[i]; return _cfg; }
      }
      return null;
    });
  }

  var cache = {};
  var lastQuery = '';

  function search(condition, location) {
    var key = condition + '|' + (location || '');
    if (cache[key]) { render(cache[key]); return; }

    _boot().then(function (cfg) {
      if (!cfg) return;
      var apiBase = 'https://' + cfg.api + '/studies';
      var params = [
        'query.cond=' + encodeURIComponent(condition),
        'filter.overallStatus=RECRUITING',
        'pageSize=5',
        'fields=protocolSection.identificationModule,protocolSection.statusModule',
      ];
      if (location) params.push('query.locn=' + encodeURIComponent(location));

      lastQuery = key;

      fetch(apiBase + '?' + params.join('&'))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var trials = (data.studies || []).map(function (s) {
            var id = s.protocolSection && s.protocolSection.identificationModule;
            var status = s.protocolSection && s.protocolSection.statusModule;
            return {
              nct: id ? id.nctId : 'Unknown',
              title: id ? id.briefTitle : 'Untitled',
              status: status ? status.overallStatus : 'Unknown',
            };
          });
          cache[key] = trials;
          try { localStorage.setItem('trials-data', JSON.stringify(trials)); } catch (e) { /* ignore */ }
          if (lastQuery === key) render(trials);
        })
        .catch(function () { render([]); });
    });
  }

  function render(trials) {
    var container = document.getElementById('trials-section');
    if (!container) {
      var parent = document.getElementById('mcode-content');
      if (!parent) return;
      container = document.createElement('div');
      container.id = 'trials-section';
      parent.parentNode.insertBefore(container, parent.nextSibling);
    }

    if (!trials || trials.length === 0) {
      container.innerHTML = '<div class="mcode-section"><div class="mcode-section-title">Clinical Trials</div>' +
        '<p style="font-size:var(--font-xs);color:var(--dim)">No recruiting trials found for current criteria.</p></div>';
      return;
    }

    var html = '<div class="mcode-section"><div class="mcode-section-title">Clinical Trials (' + trials.length + ')</div>';
    for (var i = 0; i < trials.length; i++) {
      var t = trials[i];
      html += '<div class="mcode-item full">' +
        '<div class="mcode-item-label"><a href="https://clinicaltrials.gov/study/' + escapeHtml(t.nct) +
        '" target="_blank" rel="noopener" style="color:var(--accent)">' + escapeHtml(t.nct) + '</a></div>' +
        '<div class="mcode-item-value" style="font-size:var(--font-xs)">' + escapeHtml(t.title) + '</div></div>';
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

  window.TRIALS = {
    init: function (condition, location) {
      if (!condition) {
        try {
          var p = JSON.parse(localStorage.getItem('mcode-profile') || '{}');
          condition = (p.fields || {})['Cancer Type'] || 'breast cancer';
        } catch (e) { condition = 'breast cancer'; }
      }
      search(condition, location);
    },

    search: search,
    render: render,

    export: function () {
      var data = JSON.stringify(cache, null, 2);
      var blob = new Blob([data], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'trials-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(url);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { window.TRIALS.init(); });
  } else {
    window.TRIALS.init();
  }

  window.addEventListener('mcode-update', function (e) {
    var ct = (e.detail.fields || {})['Cancer Type'];
    if (ct) window.TRIALS.init(ct);
  });
})();
