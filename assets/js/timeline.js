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

  // ── Lane config (discovered from compiled TIMELINE-INDEX.json) ──
  var LANE_CONFIG = {};

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

    // Discover lanes from compiled TIMELINE-INDEX.json
    fetch(dataPath + '/TIMELINE-INDEX.json')
      .then(function (r) { return r.json(); })
      .then(function (index) {
        var lanes = index.lanes || {};
        Object.keys(lanes).forEach(function (lane) {
          LANE_CONFIG[lane] = {
            color: lanes[lane].color || '#666666',
            icon: lanes[lane].icon || '',
            label: lanes[lane].label || lane
          };
          activeLanes[lane] = true;
        });
        renderLaneToggles();
        loadEvents();
      })
      .catch(function () {
        console.warn('TIMELINE-INDEX.json not found, loading without lane config');
        loadEvents();
      });
  }

  // ── Data loading ────────────────────────────────────────

  function loadEvents() {
    // Load all lane JSONL files in parallel
    var lanes = Object.keys(LANE_CONFIG);
    var loaded = 0;
    events = [];

    lanes.forEach(function (lane) {
      var url = dataPath + '/TIMELINE-' + lane + '.json';
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
        // Campaign-specific metadata
        if (meta.completion_pct !== undefined) {
          html += '<div class="cal-day-event-meta">\u25b6 Cascade: '
               + meta.posted + '/' + meta.total + ' posted (' + meta.completion_pct + '%)'
               + (meta.passed > 0 ? ', ' + meta.passed + ' PASSED' : '')
               + '</div>';
        }
        if (meta.platform) {
          var statusClass = meta.status === 'POSTED' ? 'cal-status-posted'
                          : meta.status === 'PASSED' ? 'cal-status-passed'
                          : meta.status === 'SCHEDULED' ? 'cal-status-scheduled'
                          : 'cal-status-draft';
          html += '<div class="cal-day-event-meta ' + statusClass + '">'
               + escHtml(meta.platform) + ' \u2014 ' + escHtml(meta.status || 'DRAFT');
          if (meta.url) html += ' <a href="' + escHtml(meta.url) + '" target="_blank">\u{1F517}</a>';
          html += '</div>';
        }
        // Grant deadline
        if (meta.grant && ev.event === 'DEADLINE') {
          html += '<div class="cal-day-event-meta cal-deadline">\u{1F6A8} DEADLINE: ' + escHtml(meta.call || '') + '</div>';
        }

        // Action button
        html += renderAction(ev);

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
        // Campaign cascade
        if (meta.completion_pct !== undefined) {
          html += '<div class="cal-detail-meta">\u25b6 Cascade: '
               + meta.posted + '/' + meta.total + ' posted (' + meta.completion_pct + '%)'
               + (meta.passed > 0 ? ', ' + meta.passed + ' PASSED' : '')
               + '</div>';
        }
        // Campaign emission
        if (meta.platform) {
          html += '<div class="cal-detail-meta">'
               + escHtml(meta.platform) + ' (' + escHtml(meta.role || '') + ') \u2014 ' + escHtml(meta.status || 'DRAFT');
          if (meta.url) html += ' <a href="' + escHtml(meta.url) + '" target="_blank">\u{1F517}</a>';
          html += '</div>';
        }
        // Grant deadline
        if (meta.grant && ev.event === 'DEADLINE') {
          html += '<div class="cal-detail-meta cal-deadline">\u{1F6A8} DEADLINE: ' + escHtml(meta.call || '') + '</div>';
        }
        // Action button
        html += renderAction(ev);
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

  // ── Action resolution ───────────────────────────────────

  var GOV_BASE = 'https://github.com/hadleylab-canonic/hadleylab-canonic/edit/main/';
  var PLATFORM_URLS = {
    'LinkedIn':  'https://www.linkedin.com/feed/',
    'Twitter/X': 'https://x.com/compose/post',
    'Reddit':    'https://www.reddit.com/submit',
    'HackerNews':'https://news.ycombinator.com/submit',
    'Substack':  'https://idrdex.substack.com/publish',
  };

  function platformShareUrl(plat, meta) {
    var blogUrl = meta.blog_url || '';
    var postText = meta.post_text || '';
    if (plat.indexOf('LinkedIn') === 0 && blogUrl) {
      return 'https://www.linkedin.com/sharing/share-offsite/?url=' + encodeURIComponent(blogUrl);
    }
    if (plat.indexOf('Twitter') === 0 && postText) {
      var tweet = postText.length > 250 ? postText.substring(0, 247) + '...' : postText;
      if (blogUrl) tweet += '\n' + blogUrl;
      return 'https://x.com/intent/tweet?text=' + encodeURIComponent(tweet);
    }
    if (plat.indexOf('HackerNews') === 0 && blogUrl) {
      return 'https://news.ycombinator.com/submitlink?u=' + encodeURIComponent(blogUrl)
           + '&t=' + encodeURIComponent(meta.campaign || '');
    }
    return null;
  }

  function actionFor(ev) {
    var meta = ev.meta || {};
    var lane = ev._lane;
    var event = ev.event;

    // CAMPAIGN emissions — resolve by posting
    if (lane === 'CAMPAIGN' && event === 'EMIT') {
      if (meta.status === 'POSTED' || meta.status === 'REPOSTED') {
        return meta.url ? { label: 'View', url: meta.url, cls: 'cal-action--done' } : null;
      }
      if (meta.status === 'PASSED') {
        var src = meta.source || ('SERVICES/CAMPAIGN/EVENTS/' + (meta.campaign || '') + '.md');
        return { label: 'Acknowledge', url: GOV_BASE + src, cls: 'cal-action--warn' };
      }
      // DRAFT or SCHEDULED — edit draft + post to platform
      var plat = meta.platform || '';
      var draftSrc = meta.source || '';
      if (plat.indexOf('Reddit') === 0) {
        // Reddit: governed submission via API
        return { label: 'Post Now', cls: 'cal-action--go', api: true, meta: meta };
      }
      var shareUrl = platformShareUrl(plat, meta);
      var platKey = Object.keys(PLATFORM_URLS).find(function (k) { return plat.indexOf(k) === 0; });
      var postUrl = shareUrl || (platKey ? PLATFORM_URLS[platKey] : '#');
      return {
        label: 'Post Now', url: postUrl, cls: 'cal-action--go',
        draft: draftSrc ? (GOV_BASE.replace('/edit/', '/blob/') + draftSrc) : null
      };
    }

    // CAMPAIGN cascade — review the event file
    if (lane === 'CAMPAIGN' && event === 'CASCADE') {
      var src2 = meta.source || ('SERVICES/CAMPAIGN/EVENTS/' + (meta.campaign || '') + '.md');
      var pct = meta.completion_pct || 0;
      if (pct >= 100) return { label: 'Complete', url: GOV_BASE + src2, cls: 'cal-action--done' };
      return { label: 'Review Cascade', url: GOV_BASE + src2, cls: 'cal-action--go' };
    }

    // CAMPAIGN event — open the event governance file
    if (lane === 'CAMPAIGN' && event === 'EVENT') {
      var src3 = meta.source || ('SERVICES/CAMPAIGN/EVENTS/' + (meta.campaign || '') + '.md');
      return { label: 'Open Event', url: GOV_BASE + src3, cls: 'cal-action--go' };
    }

    // GRANT deadline — work on it
    if (lane === 'GRANT' && event === 'DEADLINE') {
      var src4 = meta.source || 'GRANTS/ROADMAP.md';
      return { label: 'Work', url: GOV_BASE + src4, cls: 'cal-action--urgent' };
    }
    if (lane === 'GRANT' && event === 'MILESTONE') {
      if (meta.status === 'DONE') return { label: 'Done', url: '#', cls: 'cal-action--done' };
      var src5 = meta.source || 'GRANTS/ROADMAP.md';
      return { label: 'Resolve', url: GOV_BASE + src5, cls: 'cal-action--go' };
    }

    // DEAL milestone — follow up
    if (lane === 'DEAL') {
      var src6 = meta.source || 'SERVICES/DEAL/INTEL.md';
      return { label: 'Follow Up', url: GOV_BASE + src6, cls: 'cal-action--go' };
    }

    return null;
  }

  var ACTION_STYLES = {
    'cal-action--go':     'background:#30d158;color:#000;',
    'cal-action--done':   'background:rgba(255,255,255,0.1);color:#86868b;',
    'cal-action--warn':   'background:#ff9f0a;color:#000;',
    'cal-action--urgent': 'background:#ff453a;color:#fff;',
  };

  var API_BASE = 'https://api.canonic.org';

  function renderAction(ev) {
    var action = actionFor(ev);
    if (!action) return '';
    var style = ACTION_STYLES[action.cls] || '';
    var btnStyle = 'display:inline-block;padding:4px 12px;border-radius:6px;'
         + 'font-size:11px;font-weight:600;font-family:var(--mono);text-decoration:none;'
         + 'margin-top:6px;letter-spacing:0.03em;cursor:pointer;border:none;' + style;

    if (action.api) {
      // Governed API action (e.g., Reddit submit)
      var meta = action.meta || {};
      var payload = JSON.stringify({
        campaign: meta.campaign || '',
        subreddit: (meta.platform || '').replace(/^Reddit\s*\(/, '').replace(/\)$/, '').replace(/^r\//, ''),
        kind: 'self',
        title: '', // Will be filled from campaign event data
      });
      return '<button class="cal-action ' + action.cls + '" style="' + btnStyle + '" '
           + 'onclick="CAL.govPost(\'' + escHtml(meta.campaign || '') + '\',\'' + escHtml(meta.platform || '') + '\')">'
           + escHtml(action.label) + '</button>';
    }

    var html = '<a class="cal-action ' + action.cls + '" href="' + escHtml(action.url || '#')
         + '" target="_blank" style="' + btnStyle + '">'
         + escHtml(action.label) + '</a>';
    if (action.draft) {
      var draftStyle = 'display:inline-block;padding:4px 12px;border-radius:6px;'
           + 'font-size:11px;font-weight:600;font-family:var(--mono);text-decoration:none;'
           + 'margin-top:6px;margin-left:6px;letter-spacing:0.03em;cursor:pointer;border:none;'
           + 'background:rgba(255,255,255,0.1);color:#60a5fa;';
      html += '<a class="cal-action" href="' + escHtml(action.draft)
           + '" target="_blank" style="' + draftStyle + '">View Draft</a>';
    }
    return html;
  }

  // ── Governed post submission ─────────────────────────────

  async function govPost(campaign, platform) {
    var token = null;
    try { token = localStorage.getItem('canonic_session_token'); } catch (_) {}
    if (!token) {
      alert('Not authenticated. Sign in with GitHub first.');
      return;
    }

    // Extract subreddit from platform string like "Reddit (r/MachineLearning)"
    var srMatch = platform.match(/r\/(\w+)/);
    var subreddit = srMatch ? srMatch[1] : '';
    if (!subreddit) {
      alert('Could not determine subreddit from: ' + platform);
      return;
    }

    if (!confirm('Post to r/' + subreddit + ' for campaign ' + campaign + '?')) return;

    try {
      var res = await fetch(API_BASE + '/reddit/submit', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          campaign: campaign,
          subreddit: subreddit,
          kind: 'self',
          title: '[D] ' + campaign.replace(/-/g, ' '),
          text: 'Governed submission via CANONIC TIMELINE. Content pending.',
        }),
      });
      var data = await res.json();
      if (data.success) {
        alert('Posted to r/' + subreddit + '!\n\n' + data.url);
        loadEvents(); // Reload to reflect status change
      } else {
        alert('Reddit post failed: ' + (data.error || JSON.stringify(data.reddit_errors || '')));
      }
    } catch (e) {
      alert('Network error: ' + e.message);
    }
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
    govPost: govPost,
  };
})();
