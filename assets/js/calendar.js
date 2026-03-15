/**
 * CALENDAR APP — The time axis of the galaxy.
 * Month/week/day views rendering from compiled TIMELINE INDEX.
 *
 * Data: /SERVICES/TIMELINE/TIMELINE-INDEX.json (summary)
 *       /SERVICES/TIMELINE/lanes/{LANE}.jsonl  (detail, loaded on demand)
 *
 * Governed by: hadleylab-canonic/SERVICES/CALENDAR/CANON.md
 * TIMELINE | CALENDAR | CANONIC
 */
var CAL = (function () {
  'use strict';

  // ── Lane config ─────────────────────────────────────────
  var LANE_CONFIG = {
    CALENDAR:  { color: '#2997ff',  icon: '\u25f7', label: 'Calendar' },
    COIN:      { color: '#ff9f0a',  icon: '\u26c1', label: 'Coin' },
    LEDGER:    { color: '#00ff88',  icon: '\u2693', label: 'Ledger' },
    LEARNING:  { color: '#bf5af2',  icon: '\u2605', label: 'Learning' },
    TRANSCRIPT:{ color: '#ec4899',  icon: '\u2709', label: 'Transcript' },
    CONTACTS:  { color: '#ffd60a',  icon: '\u2302', label: 'Contacts' },
  };

  var WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var MONTHS = ['January','February','March','April','May','June',
                'July','August','September','October','November','December'];

  // ── State ───────────────────────────────────────────────
  var view = 'month';          // month | week | day
  var cursor = new Date();     // current navigation position
  var events = [];             // all loaded events [{ts, lane, event, summary, meta, ...}]
  var activeLanes = {};        // lane -> boolean (toggle state)
  var eventsByDate = {};       // 'YYYY-MM-DD' -> [events]
  var dataPath = '';           // base path for data files

  // ── Init ────────────────────────────────────────────────

  function init(opts) {
    opts = opts || {};
    dataPath = opts.dataPath || '/SERVICES/TIMELINE';
    cursor = new Date();

    // Initialize all lanes as active
    Object.keys(LANE_CONFIG).forEach(function (k) { activeLanes[k] = true; });

    renderLaneToggles();
    loadEvents();
  }

  // ── Data loading ────────────────────────────────────────

  function loadEvents() {
    // Load all lane JSONL files in parallel
    var lanes = Object.keys(LANE_CONFIG);
    var loaded = 0;
    events = [];

    lanes.forEach(function (lane) {
      var url = dataPath + '/lanes/' + lane + '.jsonl';
      fetch(url).then(function (r) {
        if (!r.ok) { loaded++; checkReady(loaded, lanes.length); return; }
        return r.text();
      }).then(function (text) {
        if (!text) { loaded++; checkReady(loaded, lanes.length); return; }
        text.trim().split('\n').forEach(function (line) {
          if (!line) return;
          try {
            var ev = JSON.parse(line);
            ev._lane = ev.lane || lane;
            events.push(ev);
          } catch (e) { /* skip malformed */ }
        });
        loaded++;
        checkReady(loaded, lanes.length);
      }).catch(function () {
        loaded++;
        checkReady(loaded, lanes.length);
      });
    });
  }

  function checkReady(loaded, total) {
    if (loaded < total) return;
    indexByDate();
    render();
  }

  function indexByDate() {
    eventsByDate = {};
    events.forEach(function (ev) {
      var d = (ev.ts || '').substring(0, 10); // YYYY-MM-DD
      if (!d || d.length !== 10) return;
      if (!eventsByDate[d]) eventsByDate[d] = [];
      eventsByDate[d].push(ev);
    });
  }

  // ── Lane toggles ────────────────────────────────────────

  function renderLaneToggles() {
    var el = document.getElementById('calLanes');
    if (!el) return;
    var html = '';
    Object.keys(LANE_CONFIG).forEach(function (lane) {
      var cfg = LANE_CONFIG[lane];
      var active = activeLanes[lane] ? ' cal-lane--active' : '';
      html += '<button class="cal-lane-btn' + active + '" data-lane="' + lane + '" '
           + 'style="--lane-color:' + cfg.color + '" '
           + 'onclick="CAL.toggleLane(\'' + lane + '\')">'
           + '<span class="cal-lane-icon">' + cfg.icon + '</span>'
           + '<span class="cal-lane-label">' + cfg.label + '</span>'
           + '</button>';
    });
    el.innerHTML = html;
  }

  function toggleLane(lane) {
    activeLanes[lane] = !activeLanes[lane];
    renderLaneToggles();
    render();
  }

  // ── Navigation ──────────────────────────────────────────

  function today() { cursor = new Date(); render(); }

  function prev() {
    if (view === 'month') cursor.setMonth(cursor.getMonth() - 1);
    else if (view === 'week') cursor.setDate(cursor.getDate() - 7);
    else cursor.setDate(cursor.getDate() - 1);
    render();
  }

  function next() {
    if (view === 'month') cursor.setMonth(cursor.getMonth() + 1);
    else if (view === 'week') cursor.setDate(cursor.getDate() + 7);
    else cursor.setDate(cursor.getDate() + 1);
    render();
  }

  function setView(v) {
    view = v;
    render();
  }

  // ── Render dispatch ─────────────────────────────────────

  function render() {
    updateTitle();
    updateViewToggle();
    if (view === 'month') renderMonth();
    else if (view === 'week') renderWeek();
    else renderDay();
  }

  function updateTitle() {
    var el = document.getElementById('calTitle');
    if (!el) return;
    if (view === 'month') {
      el.textContent = MONTHS[cursor.getMonth()] + ' ' + cursor.getFullYear();
    } else if (view === 'week') {
      var start = weekStart(cursor);
      var end = new Date(start);
      end.setDate(end.getDate() + 6);
      el.textContent = fmtShort(start) + ' \u2013 ' + fmtShort(end);
    } else {
      el.textContent = fmtLong(cursor);
    }
  }

  function updateViewToggle() {
    var btns = document.querySelectorAll('.cal-view-btn');
    btns.forEach(function (b) {
      b.classList.toggle('cal-view-btn--active', b.getAttribute('data-view') === view);
    });
  }

  // ── Month view ──────────────────────────────────────────

  function renderMonth() {
    var header = document.getElementById('calWeekdayHeader');
    var grid = document.getElementById('calGrid');
    if (!header || !grid) return;

    // Weekday headers
    header.innerHTML = WEEKDAYS.map(function (d) {
      return '<div class="cal-weekday">' + d + '</div>';
    }).join('');
    header.style.display = '';

    var year = cursor.getFullYear();
    var month = cursor.getMonth();
    var firstDay = new Date(year, month, 1).getDay();
    var daysInMonth = new Date(year, month + 1, 0).getDate();
    var todayStr = fmtDate(new Date());

    var cells = '';

    // Leading blanks
    for (var i = 0; i < firstDay; i++) {
      cells += '<div class="cal-cell cal-cell--empty"></div>';
    }

    for (var d = 1; d <= daysInMonth; d++) {
      var dateStr = fmtDate(new Date(year, month, d));
      var dayEvents = getFilteredEvents(dateStr);
      var isToday = dateStr === todayStr ? ' cal-cell--today' : '';
      var hasEvents = dayEvents.length > 0 ? ' cal-cell--has-events' : '';

      cells += '<div class="cal-cell' + isToday + hasEvents + '" onclick="CAL.showDetail(\'' + dateStr + '\')">';
      cells += '<div class="cal-day-num">' + d + '</div>';

      if (dayEvents.length > 0) {
        cells += '<div class="cal-day-events">';
        var shown = Math.min(dayEvents.length, 3);
        for (var j = 0; j < shown; j++) {
          var ev = dayEvents[j];
          var cfg = LANE_CONFIG[ev._lane] || { color: '#666', icon: '' };
          cells += '<div class="cal-event-dot" style="--dot-color:' + cfg.color + '">'
                + truncate(ev.summary || ev.event, 20) + '</div>';
        }
        if (dayEvents.length > 3) {
          cells += '<div class="cal-event-more">+' + (dayEvents.length - 3) + ' more</div>';
        }
        cells += '</div>';
      }
      cells += '</div>';
    }

    // Trailing blanks to fill last row
    var totalCells = firstDay + daysInMonth;
    var remainder = totalCells % 7;
    if (remainder > 0) {
      for (var t = 0; t < 7 - remainder; t++) {
        cells += '<div class="cal-cell cal-cell--empty"></div>';
      }
    }

    grid.className = 'cal-grid cal-grid--month';
    grid.innerHTML = cells;
  }

  // ── Week view ───────────────────────────────────────────

  function renderWeek() {
    var header = document.getElementById('calWeekdayHeader');
    var grid = document.getElementById('calGrid');
    if (!header || !grid) return;

    var start = weekStart(cursor);
    var todayStr = fmtDate(new Date());

    // Header with dates
    var headerHtml = '';
    for (var i = 0; i < 7; i++) {
      var day = new Date(start);
      day.setDate(day.getDate() + i);
      var dateStr = fmtDate(day);
      var isToday = dateStr === todayStr ? ' cal-weekday--today' : '';
      headerHtml += '<div class="cal-weekday' + isToday + '">'
                  + WEEKDAYS[day.getDay()] + ' ' + day.getDate()
                  + '</div>';
    }
    header.innerHTML = headerHtml;
    header.style.display = '';

    // Day columns
    var cells = '';
    for (var d = 0; d < 7; d++) {
      var day = new Date(start);
      day.setDate(day.getDate() + d);
      var dateStr = fmtDate(day);
      var dayEvents = getFilteredEvents(dateStr);
      var isToday = dateStr === todayStr ? ' cal-cell--today' : '';

      cells += '<div class="cal-cell cal-cell--week' + isToday + '" onclick="CAL.showDetail(\'' + dateStr + '\')">';
      dayEvents.forEach(function (ev) {
        var cfg = LANE_CONFIG[ev._lane] || { color: '#666', icon: '' };
        var time = (ev.ts || '').substring(11, 16) || '';
        cells += '<div class="cal-week-event" style="--dot-color:' + cfg.color + '">'
              + (time && time !== '00:00' ? '<span class="cal-event-time">' + time + '</span>' : '')
              + '<span class="cal-event-text">' + truncate(ev.summary || ev.event, 30) + '</span>'
              + '</div>';
      });
      cells += '</div>';
    }

    grid.className = 'cal-grid cal-grid--week';
    grid.innerHTML = cells;
  }

  // ── Day view ────────────────────────────────────────────

  function renderDay() {
    var header = document.getElementById('calWeekdayHeader');
    var grid = document.getElementById('calGrid');
    if (!header || !grid) return;
    header.style.display = 'none';

    var dateStr = fmtDate(cursor);
    var dayEvents = getFilteredEvents(dateStr);

    // Sort by time
    dayEvents.sort(function (a, b) { return (a.ts || '').localeCompare(b.ts || ''); });

    var html = '<div class="cal-day-view">';
    if (dayEvents.length === 0) {
      html += '<div class="cal-day-empty">No events</div>';
    } else {
      dayEvents.forEach(function (ev) {
        var cfg = LANE_CONFIG[ev._lane] || { color: '#666', icon: '' };
        var time = (ev.ts || '').substring(11, 16) || '';
        var meta = ev.meta || {};

        html += '<div class="cal-day-event" style="--dot-color:' + cfg.color + '">';
        html += '<div class="cal-day-event-lane">'
             + '<span class="cal-lane-dot" style="background:' + cfg.color + '"></span>'
             + cfg.icon + ' ' + (ev._lane || '') + '</div>';
        if (time && time !== '00:00') {
          html += '<div class="cal-day-event-time">' + time + '</div>';
        }
        html += '<div class="cal-day-event-summary">' + escHtml(ev.summary || ev.event || '') + '</div>';

        // Meta details
        if (meta.location) {
          html += '<div class="cal-day-event-meta">\u{1F4CD} ' + escHtml(meta.location) + '</div>';
        }
        if (meta.participants && meta.participants.length > 0) {
          html += '<div class="cal-day-event-meta cal-participants">';
          meta.participants.forEach(function (p) {
            if (p.self) return;
            var label = p.name || p.email || '';
            if (!label) return;
            if (p.galaxy_node) {
              html += '<span class="cal-resolved-contact" title="' + escHtml(p.galaxy_node) + '">'
                   + '\u2302 ' + escHtml(label)
                   + '<span class="cal-node-badge">' + escHtml(p.galaxy_node.split('/').pop()) + '</span>'
                   + '</span>';
            } else {
              html += '<span class="cal-unresolved-contact">' + escHtml(label) + '</span>';
            }
          });
          html += '</div>';
        }
        if (meta.resolved_nodes && meta.resolved_nodes.length > 0) {
          html += '<div class="cal-day-event-meta cal-resolved-summary">'
               + '\u{1F310} ' + meta.resolved_nodes.length + ' resolved to galaxy</div>';
        }
        if (meta.delta !== undefined) {
          var sign = meta.delta >= 0 ? '+' : '';
          html += '<div class="cal-day-event-meta">' + sign + meta.delta + ' COIN</div>';
        }
        if (meta.gradient !== undefined) {
          html += '<div class="cal-day-event-meta">Governance: ' + meta.from_bits + '\u2192' + meta.to_bits + '</div>';
        }

        html += '</div>';
      });
    }
    html += '</div>';

    grid.className = 'cal-grid cal-grid--day';
    grid.innerHTML = html;
  }

  // ── Detail panel (click on day) ─────────────────────────

  function showDetail(dateStr) {
    var panel = document.getElementById('calDetail');
    var dateEl = document.getElementById('calDetailDate');
    var eventsEl = document.getElementById('calDetailEvents');
    if (!panel || !dateEl || !eventsEl) return;

    var dayEvents = getFilteredEvents(dateStr);
    dayEvents.sort(function (a, b) { return (a.ts || '').localeCompare(b.ts || ''); });

    dateEl.textContent = fmtLong(new Date(dateStr + 'T12:00:00'));

    var html = '';
    if (dayEvents.length === 0) {
      html = '<div class="cal-day-empty">No events for this day.</div>';
    } else {
      dayEvents.forEach(function (ev) {
        var cfg = LANE_CONFIG[ev._lane] || { color: '#666', icon: '' };
        var time = (ev.ts || '').substring(11, 16) || '';
        var meta = ev.meta || {};

        html += '<div class="cal-detail-event" style="border-left-color:' + cfg.color + '">';
        html += '<div class="cal-detail-event-head">'
             + '<span class="cal-detail-lane" style="color:' + cfg.color + '">'
             + cfg.icon + ' ' + (ev._lane || '') + '</span>';
        if (time && time !== '00:00') {
          html += '<span class="cal-detail-time">' + time + '</span>';
        }
        html += '</div>';
        html += '<div class="cal-detail-summary">' + escHtml(ev.summary || ev.event || '') + '</div>';

        if (meta.location) {
          html += '<div class="cal-detail-meta">\u{1F4CD} ' + escHtml(meta.location) + '</div>';
        }
        if (meta.participants && meta.participants.length > 0) {
          html += '<div class="cal-detail-participants">';
          meta.participants.forEach(function (p) {
            if (p.self) return;
            var label = p.name || p.email || '';
            if (!label) return;
            if (p.galaxy_node) {
              html += '<div class="cal-detail-person cal-detail-person--resolved">'
                   + '<span class="cal-person-name">' + escHtml(label) + '</span>'
                   + '<span class="cal-person-node">' + escHtml(p.galaxy_node) + '</span>'
                   + '</div>';
            } else {
              html += '<div class="cal-detail-person">'
                   + '<span class="cal-person-name">' + escHtml(label) + '</span>'
                   + '</div>';
            }
          });
          html += '</div>';
        }
        if (meta.delta !== undefined) {
          var sign = meta.delta >= 0 ? '+' : '';
          html += '<div class="cal-detail-meta">' + sign + meta.delta + ' COIN</div>';
        }
        html += '</div>';
      });
    }

    eventsEl.innerHTML = html;
    panel.style.display = '';
  }

  function closeDetail() {
    var panel = document.getElementById('calDetail');
    if (panel) panel.style.display = 'none';
  }

  // ── Helpers ─────────────────────────────────────────────

  function getFilteredEvents(dateStr) {
    var all = eventsByDate[dateStr] || [];
    return all.filter(function (ev) { return activeLanes[ev._lane]; });
  }

  function weekStart(d) {
    var s = new Date(d);
    s.setDate(s.getDate() - s.getDay());
    return s;
  }

  function fmtDate(d) {
    var y = d.getFullYear();
    var m = String(d.getMonth() + 1).padStart(2, '0');
    var dd = String(d.getDate()).padStart(2, '0');
    return y + '-' + m + '-' + dd;
  }

  function fmtShort(d) {
    return MONTHS[d.getMonth()].substring(0, 3) + ' ' + d.getDate();
  }

  function fmtLong(d) {
    return WEEKDAYS[d.getDay()] + ', ' + MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
  }

  function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.substring(0, n) + '\u2026' : s;
  }

  function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Public API ──────────────────────────────────────────

  return {
    init: init,
    today: today,
    prev: prev,
    next: next,
    setView: setView,
    toggleLane: toggleLane,
    showDetail: showDetail,
    closeDetail: closeDetail,
  };
})();
