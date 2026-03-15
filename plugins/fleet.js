/**
 * FLEET — TALK Plugin for cross-fleet intelligence.
 * Loads sibling LEARNING.json + CANON.json summaries and injects relevant
 * cross-axiomatic INTEL into conversation context at query time.
 * GOV: SERVICES/TALK/CANON.md — zero hardcoding. Fleet array from CANON.json.
 *
 * Loaded by TALK.initPlugins() when CANON.json declares "fleet": true.
 *
 * FLEET | CANONIC | 2026-03
 */
window.FLEET = {
  talk: null,
  services: {},     // { scope: { name, logo, href, accent, intel, learning, summary } }
  currentScope: null,
  loaded: false,

  // ── Evidence route registry — maps citation keywords to authoritative URLs ──
  EVIDENCE_ROUTES: {
    'NCCN':     { url: 'https://www.nccn.org/guidelines',              tier: 'silver', scope: 'MAMMOCHAT' },
    'BI-RADS':  { url: 'https://www.acr.org/Clinical-Resources/Reporting-and-Data-Systems/Bi-Rads', tier: 'silver', scope: 'MAMMOCHAT' },
    'mCODE':    { url: 'https://hl7.org/fhir/us/mcode/',              tier: 'silver', scope: 'MAMMOCHAT' },
    'ClinVar':  { url: 'https://www.ncbi.nlm.nih.gov/clinvar/',       tier: 'bronze', scope: 'OMICSCHAT' },
    'PharmGKB': { url: 'https://www.pharmgkb.org/',                    tier: 'bronze', scope: 'OMICSCHAT' },
    'GEO':      { url: 'https://www.ncbi.nlm.nih.gov/geo/',           tier: 'bronze', scope: 'OMICSCHAT' },
    'COSMIC':   { url: 'https://cancer.sanger.ac.uk/cosmic',          tier: 'bronze', scope: 'OMICSCHAT' },
    'AJCC':     { url: 'https://www.facs.org/quality-programs/cancer-programs/american-joint-committee-on-cancer/', tier: 'silver', scope: 'ONCOCHAT' },
    'USC':      { url: 'https://uscode.house.gov/',                    tier: 'gold',   scope: 'LAWCHAT' },
    'CFR':      { url: 'https://www.ecfr.gov/',                        tier: 'gold',   scope: 'LAWCHAT' },
    'FDA':      { url: 'https://www.fda.gov/',                         tier: 'gold',   scope: 'LAWCHAT' },
    'HIPAA':    { url: 'https://www.hhs.gov/hipaa/',                   tier: 'gold',   scope: 'LAWCHAT' },
    'USC35':    { url: 'https://uscode.house.gov/view.xhtml?path=/prelim@title35', tier: 'gold', scope: 'LAWCHAT' },
    'FRED':     { url: 'https://fred.stlouisfed.org/',                 tier: 'bronze', scope: 'FINCHAT' },
    'SEC':      { url: 'https://www.sec.gov/cgi-bin/browse-edgar',     tier: 'bronze', scope: 'FINCHAT' },
    'CMS':      { url: 'https://www.cms.gov/',                         tier: 'silver', scope: 'FINCHAT' },
    'CPT':      { url: 'https://www.ama-assn.org/practice-management/cpt', tier: 'silver', scope: 'FINCHAT' },
    'IRS':      { url: 'https://www.irs.gov/',                         tier: 'gold',   scope: 'FINCHAT' },
    'USPSTF':   { url: 'https://www.uspreventiveservicestaskforce.org/', tier: 'silver', scope: 'MEDCHAT' },
    'CDC':      { url: 'https://www.cdc.gov/',                         tier: 'silver', scope: 'MEDCHAT' },
    'AHA':      { url: 'https://www.heart.org/',                       tier: 'silver', scope: 'MEDCHAT' },
    'ADA':      { url: 'https://diabetes.org/',                        tier: 'silver', scope: 'MEDCHAT' },
    'CARPHA':   { url: 'https://carpha.org/',                          tier: 'silver', scope: 'CARIBCHAT' },
    'CAOH':     { url: 'https://thecaribbeancancergroup.com/',         tier: 'silver', scope: 'CARIBCHAT' }
  },

  // ── Init (called by TALK.initPlugins) ──────────────────────────────
  async init(talk) {
    this.talk = talk;
    this.currentScope = (talk.scope || '').toUpperCase();

    var fleet = talk.canon.fleet || [];
    if (!fleet.length) return;

    // Load sibling LEARNING.json + CANON.json summaries in parallel
    var promises = [];
    for (var i = 0; i < fleet.length; i++) {
      var svc = fleet[i];
      // Skip self — don't inject own INTEL as cross-fleet
      if (svc.scope === this.currentScope) continue;
      promises.push(this._loadService(svc));
    }
    await Promise.allSettled(promises);
    this.loaded = true;

    // Render fleet nav if container exists
    this.renderFleetNav(fleet);
    // Render community learning dashboard
    this.renderCommunity();
  },

  async _loadService(svc) {
    var result = { scope: svc.scope, name: svc.name, logo: svc.logo, href: svc.href, accent: svc.accent, intel: svc.intel || [] };
    try {
      var [learningRes, canonRes] = await Promise.allSettled([
        fetch(svc.href + 'LEARNING.json'),
        fetch(svc.href + 'CANON.json')
      ]);

      if (learningRes.status === 'fulfilled' && learningRes.value.ok) {
        result.learning = await learningRes.value.json();
      }
      if (canonRes.status === 'fulfilled' && canonRes.value.ok) {
        var canon = await canonRes.value.json();
        // Extract compact summary (axiom + capabilities + INTEL domains), not the full systemPrompt
        result.summary = {
          scope: canon.scope || canon.name,
          axiom: canon.axiom || null,
          capabilities: canon.capabilities || [],
          intel_domains: svc.intel || [],
          welcome: canon.welcome || null
        };
      }
    } catch (e) {
      // Fail-closed per service: missing sibling must not break TALK
    }
    this.services[svc.scope] = result;
  },

  // ── TALK Plugin Hooks ──────────────────────────────────────────────
  hooks: {
    beforeSend(ctx) {
      var self = window.FLEET;
      if (!self.loaded) return ctx;

      // Find relevant cross-fleet INTEL based on user message
      var relevant = self.findRelevant(ctx.text);
      if (relevant.length) {
        ctx.config = ctx.config || {};
        ctx.config.fleet_intel = relevant;
      }
      return ctx;
    },

    afterReceive(ctx) {
      // No post-processing needed — evidence badges rendered by talk.js md()
      return ctx;
    }
  },

  // ── Cross-fleet relevance matching ─────────────────────────────────
  findRelevant(text) {
    if (!text) return [];
    var lower = text.toLowerCase();
    var results = [];

    var scopes = Object.keys(this.services);
    for (var i = 0; i < scopes.length; i++) {
      var svc = this.services[scopes[i]];
      var matched = [];

      // Match against INTEL domain keywords
      var intel = svc.intel || [];
      for (var j = 0; j < intel.length; j++) {
        if (lower.indexOf(intel[j].toLowerCase()) !== -1) {
          matched.push({ type: 'domain', keyword: intel[j] });
        }
      }

      // Match against LEARNING patterns
      var patterns = (svc.learning && svc.learning.patterns) || [];
      for (var k = 0; k < patterns.length; k++) {
        var pat = patterns[k];
        var patText = (pat.text || pat.signal || '').toLowerCase();
        // Simple word overlap: check if any significant word from user query appears in pattern
        var words = lower.split(/\s+/).filter(function(w) { return w.length > 3; });
        for (var w = 0; w < words.length; w++) {
          if (patText.indexOf(words[w]) !== -1) {
            matched.push({ type: 'pattern', date: pat.date, signal: pat.signal, text: pat.text, source: pat.source });
            break;
          }
        }
      }

      // Match against CANON.json summary capabilities
      if (svc.summary) {
        var caps = svc.summary.capabilities || [];
        for (var c = 0; c < caps.length; c++) {
          if (lower.indexOf(caps[c].toLowerCase()) !== -1) {
            matched.push({ type: 'capability', capability: caps[c] });
          }
        }
      }

      if (matched.length > 0) {
        results.push({
          scope: svc.scope,
          name: svc.name,
          href: svc.href,
          summary: svc.summary || null,
          matches: matched.slice(0, 5) // Cap at 5 matches per service to control token budget
        });
      }
    }

    return results;
  },

  // ── Fleet Navigation Bar ───────────────────────────────────────────
  renderFleetNav(fleet) {
    var container = document.getElementById('fleetNav');
    if (!container || !fleet || !fleet.length) return;

    var html = '';
    for (var i = 0; i < fleet.length; i++) {
      var svc = fleet[i];
      var isActive = svc.scope === this.currentScope;
      html += '<a href="' + this._esc(svc.href) + '" class="fleet-pill' + (isActive ? ' active' : '') + '"' +
        ' style="--pill-accent:' + this._esc(svc.accent || '#6b7280') + '"' +
        ' title="' + this._esc(svc.name) + '">' +
        '<span class="fleet-pill-logo">' + svc.logo + '</span>' +
        '<span class="fleet-pill-name">' + this._esc(svc.name) + '</span>' +
      '</a>';
    }
    container.innerHTML = html;
    container.style.display = 'flex';
  },

  // ── Community Learning Dashboard ───────────────────────────────────
  renderCommunity() {
    var container = document.getElementById('communitySection');
    if (!container) return;

    // Aggregate local + cross-fleet patterns
    var allPatterns = [];

    // Local patterns from TALK's own LEARNING.json
    if (this.talk && this.talk.intelLedger && this.talk.intelLedger.length) {
      for (var i = 0; i < this.talk.intelLedger.length; i++) {
        allPatterns.push({ scope: this.currentScope, accent: null, entry: this.talk.intelLedger[i] });
      }
    }

    // Cross-fleet patterns
    var scopes = Object.keys(this.services);
    for (var s = 0; s < scopes.length; s++) {
      var svc = this.services[scopes[s]];
      var patterns = (svc.learning && svc.learning.patterns) || [];
      for (var p = 0; p < Math.min(patterns.length, 3); p++) { // Cap at 3 per sibling
        allPatterns.push({ scope: svc.scope, accent: svc.accent, entry: patterns[p] });
      }
    }

    if (!allPatterns.length) { container.style.display = 'none'; return; }

    // Stats row
    var totalPatterns = allPatterns.length;
    var totalSources = Object.keys(this.services).length + 1; // +1 for self
    var html = '<div class="community-header" onclick="FLEET.toggleCommunity()">' +
      '<span class="community-title">Community Learning</span>' +
      '<span class="community-stats">' +
        '<span class="community-stat">' + totalPatterns + ' patterns</span>' +
        '<span class="community-stat">' + totalSources + ' sources</span>' +
      '</span>' +
      '<span class="community-toggle" id="communityToggle">&#9660;</span>' +
    '</div>';

    // Cards (collapsible)
    html += '<div class="community-cards" id="communityCards">';
    // Sort by date descending
    allPatterns.sort(function(a, b) {
      return (b.entry.date || '').localeCompare(a.entry.date || '');
    });
    for (var c = 0; c < Math.min(allPatterns.length, 12); c++) { // Show up to 12
      var item = allPatterns[c];
      var entry = item.entry;
      var borderColor = item.accent || 'var(--accent, #f97316)';
      html += '<div class="community-card" style="border-left-color:' + borderColor + '"' +
        ' onclick="FLEET.seedChat(\'' + this._esc(entry.text || entry.signal || '') + '\')">' +
        '<div class="community-card-meta">' +
          '<span class="community-card-date">' + this._esc(entry.date || '') + '</span>' +
          '<span class="community-card-scope" style="color:' + borderColor + '">' + this._esc(item.scope) + '</span>' +
        '</div>' +
        '<div class="community-card-text">' + this._esc(entry.text || entry.signal || '') + '</div>' +
        (entry.source ? '<div class="community-card-source">' + this._esc(entry.source) + '</div>' : '') +
      '</div>';
    }
    html += '</div>';

    container.innerHTML = html;
    container.style.display = 'block';
  },

  toggleCommunity() {
    var cards = document.getElementById('communityCards');
    var toggle = document.getElementById('communityToggle');
    if (!cards) return;
    var isOpen = cards.style.display !== 'none';
    cards.style.display = isOpen ? 'none' : 'grid';
    if (toggle) toggle.innerHTML = isOpen ? '&#9654;' : '&#9660;';
  },

  seedChat(text) {
    var input = document.getElementById('talkChatInput');
    if (!input || !text) return;
    input.value = text;
    input.focus();
  },

  // ── Utility ────────────────────────────────────────────────────────
  _esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
};

// Auto-register with TALK if loaded via <script> tag (frontmatter plugins array).
// TALK.initPlugins() discovers window.FLEET and calls init() + registers hooks.
// If CANON.json doesn't have a fleet flag, self-init after TALK loads.
(function() {
  var _autoInit = setInterval(function() {
    if (typeof TALK !== 'undefined' && TALK.governed && TALK.canon) {
      clearInterval(_autoInit);
      // If TALK didn't auto-discover us (no fleet flag in CANON.json), self-init
      if (TALK.plugins.indexOf(window.FLEET) === -1) {
        window.FLEET.init(TALK);
        TALK.plugins.push(window.FLEET);
      }
    }
  }, 200);
  // Safety: stop checking after 10s
  setTimeout(function() { clearInterval(_autoInit); }, 10000);
})();
