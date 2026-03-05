/**
 * STAR — Personal portal in the GALAXY.
 * INTEL + CHAT + COIN composed into a unified personal surface.
 * The TIMELINE is the joint lane for all cross-axiomatic intel.
 *
 * Governed by: canonic-canonic/MAGIC/SERVICES/STAR/STAR.md
 */
var STAR = (function () {
  'use strict';

  var API = 'https://api.canonic.org';
  var LANES = ['TIMELINE', 'SERVICES', 'INTEL', 'ECON', 'VAULT', 'IDENTITY', 'MEDIA', 'GOV'];
  var LANE_ROUTES = {
    TIMELINE: '/star/timeline',
    SERVICES: '/star/services',
    INTEL: '/star/intel',
    ECON: '/star/econ',
    VAULT: '/star/econ',
    IDENTITY: '/star/identity',
    MEDIA: '/star/media',
    GOV: '/star/gov',
  };
  var PRIMITIVE_COLORS = {
    INTEL: '#bf5af2',
    CHAT: '#ec4899',
    COIN: '#ff9f0a',
  };
  var STREAM_ICONS = {
    VAULT: '\u26c1',     // coin
    LEDGER: '\u2693',    // anchor
    CALENDAR: '\u25f7',  // clock
    NOTIFIER: '\u2709',  // envelope
    LEARNING: '\u2605',  // star
    CAMPAIGN: '\u2691',  // flag
    TALK: '\u2767',      // chat
  };

  var activeLane = 'TIMELINE';
  var principal = null;
  var cache = {};

  // ── Auth ──────────────────────────────────────────────

  function token() {
    if (typeof AUTH !== 'undefined' && AUTH.sessionToken) return AUTH.sessionToken();
    return localStorage.getItem('canonic_session_token');
  }

  function headers() {
    var h = { 'Content-Type': 'application/json' };
    var t = token();
    if (t) h['Authorization'] = 'Bearer ' + t;
    return h;
  }

  // ── API ───────────────────────────────────────────────

  function fetchLane(lane, params) {
    var route = LANE_ROUTES[lane] || '/star/status';
    var qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return fetch(API + route + qs, { headers: headers() })
      .then(function (r) { return r.json(); })
      .catch(function (e) { console.error('[STAR]', lane, e); return null; });
  }

  // ── DOM helpers ───────────────────────────────────────

  function el(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  // ── Rendering ─────────────────────────────────────────

  function renderLaneTabs() {
    var tabs = el('starLaneTabs');
    if (!tabs) return;
    tabs.innerHTML = '';
    LANES.forEach(function (lane) {
      var btn = document.createElement('button');
      btn.className = 'star-lane-btn' + (lane === activeLane ? ' active' : '');
      btn.textContent = lane;
      btn.onclick = function () { switchLane(lane); };
      tabs.appendChild(btn);
    });
  }

  function switchLane(lane) {
    activeLane = lane;
    renderLaneTabs();
    loadLane(lane);
  }

  function loadLane(lane) {
    var content = el('starContent');
    if (!content) return;
    content.innerHTML = '<div class="star-loading">Loading ' + lane + '...</div>';

    if (lane === 'TIMELINE') return loadTimeline();
    if (lane === 'GOV') return loadGov();

    // Auth-gated lanes
    if (!token()) {
      content.innerHTML = '<div class="star-auth-gate">Sign in to view ' + lane + '</div>';
      return;
    }

    fetchLane(lane).then(function (data) {
      if (!data) { content.innerHTML = '<div class="star-empty">No data</div>'; return; }
      cache[lane] = data;

      if (lane === 'SERVICES') return renderServices(data);
      if (lane === 'INTEL') return renderIntel(data);
      if (lane === 'ECON') return renderEcon(data);
      if (lane === 'IDENTITY') return renderIdentity(data);
      if (lane === 'MEDIA') return renderMedia(data);
      if (lane === 'VAULT') return renderEcon(data);

      content.innerHTML = '<pre class="star-raw">' + esc(JSON.stringify(data, null, 2)) + '</pre>';
    });
  }

  // ── TIMELINE ──────────────────────────────────────────

  function loadTimeline(filter) {
    var content = el('starContent');
    if (!token()) {
      content.innerHTML = '<div class="star-auth-gate">Sign in to view your TIMELINE</div>';
      return;
    }
    var params = { limit: 100 };
    if (filter && filter.stream) params.stream = filter.stream;
    if (filter && filter.primitive) params.primitive = filter.primitive;

    fetchLane('TIMELINE', params).then(function (data) {
      if (!data || !data.entries) {
        content.innerHTML = '<div class="star-empty">No timeline events</div>';
        return;
      }
      principal = data.principal;
      renderPrincipal();

      var html = '<div class="star-timeline">';
      // Primitive filters
      html += '<div class="star-filters">';
      html += '<button class="star-filter-btn' + (!filter ? ' active' : '') + '" onclick="STAR.filterTimeline()">ALL</button>';
      ['INTEL', 'CHAT', 'COIN'].forEach(function (p) {
        var isActive = filter && filter.primitive === p;
        html += '<button class="star-filter-btn' + (isActive ? ' active' : '') + '" ';
        html += 'style="--filter-color:' + PRIMITIVE_COLORS[p] + '" ';
        html += 'onclick="STAR.filterTimeline(\'' + p + '\')">' + p + '</button>';
      });
      html += '</div>';

      html += '<div class="star-timeline-entries">';
      data.entries.forEach(function (ev) {
        var icon = STREAM_ICONS[ev.stream] || '\u2022';
        var primColor = PRIMITIVE_COLORS[ev.primitive] || 'var(--dim)';
        var ts = ev.ts ? new Date(ev.ts).toLocaleString() : '';
        var shortTs = ev.ts ? new Date(ev.ts).toLocaleDateString() : '';
        html += '<div class="star-event">';
        html += '<div class="star-event-left">';
        html += '<span class="star-event-icon">' + icon + '</span>';
        html += '<span class="star-event-stream" style="color:' + primColor + '">' + esc(ev.stream) + '</span>';
        html += '</div>';
        html += '<div class="star-event-body">';
        html += '<div class="star-event-type">' + esc(ev.type || '') + '</div>';
        html += '<div class="star-event-summary">' + esc(ev.summary || '') + '</div>';
        html += '<div class="star-event-meta">';
        html += '<span class="star-event-scope">' + esc(ev.scope || '') + '</span>';
        html += '<span class="star-event-ts" title="' + esc(ts) + '">' + esc(shortTs) + '</span>';
        html += '</div>';
        html += '</div>';
        html += '</div>';
      });
      html += '</div>';
      html += '<div class="star-timeline-total">' + data.total + ' events</div>';
      html += '</div>';
      content.innerHTML = html;
    });
  }

  // ── SERVICES ──────────────────────────────────────────

  function renderServices(data) {
    var content = el('starContent');
    var services = data.services || [];
    if (!services.length) {
      content.innerHTML = '<div class="star-empty">No services discovered</div>';
      return;
    }
    var html = '<div class="star-services-grid">';
    services.forEach(function (svc) {
      html += '<a class="star-service-card" href="' + esc(svc.url || '#') + '">';
      html += '<div class="star-service-name">' + esc(svc.label || svc.id || '') + '</div>';
      html += '<div class="star-service-bits">' + (svc.bits || 0) + '/255</div>';
      html += '</a>';
    });
    html += '</div>';
    content.innerHTML = html;
  }

  // ── INTEL ─────────────────────────────────────────────

  function renderIntel(data) {
    var content = el('starContent');
    var patterns = data.patterns || [];
    if (!patterns.length) {
      content.innerHTML = '<div class="star-empty">No INTEL patterns</div>';
      return;
    }
    var html = '<div class="star-intel-list">';
    patterns.forEach(function (p) {
      html += '<div class="star-intel-row">';
      html += '<span class="star-intel-signal">' + esc(p.signal || p.type || '') + '</span>';
      html += '<span class="star-intel-pattern">' + esc(p.pattern || p.summary || '') + '</span>';
      html += '</div>';
    });
    html += '</div>';
    content.innerHTML = html;
  }

  // ── ECON ──────────────────────────────────────────────

  function renderEcon(data) {
    var content = el('starContent');
    var html = '<div class="star-econ">';
    html += '<div class="star-econ-balance">';
    html += '<div class="star-econ-label">BALANCE</div>';
    html += '<div class="star-econ-value">' + (data.balance || 0) + ' <span class="star-econ-unit">COIN</span></div>';
    html += '</div>';
    if (data.wallet) {
      html += '<div class="star-econ-row"><span>Total minted</span><span>' + (data.wallet.total_minted || 0) + '</span></div>';
      html += '<div class="star-econ-row"><span>Total spent</span><span>' + (data.wallet.total_spent || 0) + '</span></div>';
    }
    html += '</div>';
    content.innerHTML = html;
  }

  // ── IDENTITY ──────────────────────────────────────────

  function renderIdentity(data) {
    var content = el('starContent');
    var html = '<div class="star-identity">';
    html += '<div class="star-identity-name">' + esc(data.name || data.principal || '') + '</div>';
    if (data.title) html += '<div class="star-identity-title">' + esc(data.title) + '</div>';
    if (data.kyc) {
      html += '<div class="star-identity-kyc">';
      Object.keys(data.kyc).forEach(function (k) {
        html += '<div class="star-identity-row"><span>' + esc(k) + '</span><span>' + esc(data.kyc[k]) + '</span></div>';
      });
      html += '</div>';
    }
    html += '</div>';
    content.innerHTML = html;
  }

  // ── MEDIA ─────────────────────────────────────────────

  function renderMedia(data) {
    var content = el('starContent');
    var media = data.media || [];
    if (!media.length) {
      content.innerHTML = '<div class="star-empty">No published media</div>';
      return;
    }
    var html = '<div class="star-media-grid">';
    media.forEach(function (m) {
      html += '<a class="star-media-card" href="' + esc(m.url || '#') + '">';
      html += '<div class="star-media-type">' + esc(m.type || 'CONTENT') + '</div>';
      html += '<div class="star-media-title">' + esc(m.title || '') + '</div>';
      html += '</a>';
    });
    html += '</div>';
    content.innerHTML = html;
  }

  // ── GOV ───────────────────────────────────────────────

  function loadGov() {
    var content = el('starContent');
    fetchLane('GOV').then(function (data) {
      if (!data || !data.scopes || !data.scopes.length) {
        content.innerHTML = '<div class="star-empty">No governance scopes</div>';
        return;
      }
      var html = '<div class="star-gov-tree">';
      data.scopes.forEach(function (s) {
        var tierColor = s.bits >= 255 ? '#00ff88' : s.bits >= 127 ? '#2997ff' : s.bits >= 63 ? '#bf5af2' : '#ff9f0a';
        html += '<div class="star-gov-scope">';
        html += '<span class="star-gov-dot" style="background:' + tierColor + '"></span>';
        html += '<span class="star-gov-label">' + esc(s.label || s.id) + '</span>';
        html += '<span class="star-gov-bits">' + s.bits + '</span>';
        html += '</div>';
      });
      html += '</div>';
      content.innerHTML = html;
    });
  }

  // ── Principal badge ───────────────────────────────────

  function renderPrincipal() {
    var badge = el('starPrincipal');
    if (badge && principal) {
      badge.textContent = principal;
      badge.style.display = '';
    }
  }

  // ── Open / Close ──────────────────────────────────────

  function open() {
    var overlay = el('starOverlay');
    if (overlay) {
      overlay.classList.add('open');
      document.body.classList.add('star-open');
    }
    if (!cache.TIMELINE) loadLane(activeLane);
  }

  function close() {
    var overlay = el('starOverlay');
    if (overlay) {
      overlay.classList.remove('open');
      document.body.classList.remove('star-open');
    }
  }

  // ── Init ──────────────────────────────────────────────

  function init(opts) {
    opts = opts || {};
    if (opts.api) API = opts.api;
    renderLaneTabs();
    // If inline (not overlay), load immediately
    if (el('starContent') && !el('starOverlay')) {
      loadLane(activeLane);
    }
  }

  // ── Public API ────────────────────────────────────────

  return {
    init: init,
    open: open,
    close: close,
    switchLane: switchLane,
    filterTimeline: function (primitive) {
      loadTimeline(primitive ? { primitive: primitive } : null);
    },
  };
})();
