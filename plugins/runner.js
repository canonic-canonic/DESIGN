/**
 * RUNNER — TALK Plugin for task marketplace.
 * Renders rich task cards, onboarding flow, lifecycle tracking, and ops widgets inline in chat.
 * GOV: SERVICES/TALK/RUNNER/CANON.json — zero hardcoding.
 *
 * Loaded by TALK.initPlugins() when CANON.json declares "runner": true.
 *
 * RUNNER | CANONIC | 2026-03
 */
window.RUNNER_PLUGIN = {
  talk: null,
  canon: null,
  taskTypes: {},
  taskInstructions: {},
  userId: null,
  role: null,
  principal: null,
  API: 'https://api.canonic.org',
  _locationWatcher: null,
  _pollTimers: {},
  onboardState: null,

  // ── Icon map — category-driven, from CANON.json ────────────────────
  ICONS: {
    lockbox_install: '\uD83D\uDD10', lockbox_remove: '\uD83D\uDD10',
    yard_sign_install: '\uD83E\uDEA7', yard_sign_remove: '\uD83E\uDEA7',
    photo_shoot: '\uD83D\uDCF8', staging: '\uD83D\uDECB\uFE0F',
    inspection: '\uD83D\uDD0D', appraisal: '\uD83D\uDCCA',
    title: '\uD83D\uDCDC', open_house: '\uD83C\uDFE0',
    showing: '\uD83D\uDC41\uFE0F', cma: '\uD83D\uDCC8',
    contract: '\uD83D\uDCDD', closing: '\uD83C\uDFAF',
    flyer_delivery: '\uD83D\uDCC4', vendor_meetup: '\uD83E\uDD1D',
    key_run: '\uD83D\uDD11'
  },

  STATUS_COLORS: {
    posted: '#3b82f6', assigned: '#8b5cf6', accepted: '#6366f1',
    in_progress: '#f59e0b', completed: '#22c55e', rated: '#10b981',
    cancelled: '#ef4444'
  },

  // ── Init (called by TALK.initPlugins) ──────────────────────────────
  init(talk) {
    this.talk = talk;
    this.canon = talk.canon || {};
    this.API = (window.CANONIC_API || 'https://api.canonic.org').replace(/\/+$/, '');

    // Index task types from CANON.json
    var types = this.canon.task_types || [];
    for (var i = 0; i < types.length; i++) {
      this.taskTypes[types[i].key] = types[i];
    }
    this.taskInstructions = this.canon.task_instructions || {};

    // Resolve user identity
    this.userId = localStorage.getItem('runner_user_id');
    this.principal = localStorage.getItem('runner_principal');
    this._resolveRole();

    this.injectStyles();
  },

  // ── Role resolution from AUTH ──────────────────────────────────────
  async _resolveRole() {
    if (typeof AUTH !== 'undefined' && AUTH.ready) await AUTH.ready();
    var authUser = (typeof AUTH !== 'undefined' && AUTH.user) ? AUTH.user() : null;
    if (authUser && authUser.user) {
      try {
        var res = await fetch(this.API + '/runner/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: authUser.name || authUser.user, github: authUser.user, role: 'Requester' })
        });
        if (res.ok) {
          var data = await res.json();
          if (data.user) {
            this.userId = data.user.id;
            this.role = data.user.role;
            this.principal = data.principal || null;
            localStorage.setItem('runner_user_id', data.user.id);
            if (data.principal) localStorage.setItem('runner_principal', data.principal);
          }
        }
      } catch (e) { /* silent */ }
    }
  },

  // ── TALK Plugin Hooks ──────────────────────────────────────────────
  hooks: {
    beforeSend(ctx) {
      var text = ctx.text || '';
      var self = window.RUNNER_PLUGIN;

      // Inject user context into LLM message for role-aware responses
      if (self.userId && self.role) {
        ctx.config = ctx.config || {};
        ctx.config.runner_user = { id: self.userId, role: self.role, principal: self.principal };
      }

      // Detect direct commands and handle client-side
      var lower = text.toLowerCase().trim();

      if (lower === 'show my tasks' || lower === 'my tasks') {
        self._showMyTasks();
        return { text: text };
      }
      if (lower === 'show stats' || lower === 'stats') {
        self._showStats();
        return { text: text };
      }
      if (lower === 'show runners' || lower === 'runners') {
        self._showRunners();
        return { text: text };
      }

      // Assign command: "assign TXXXX to Runner Name"
      var assignMatch = lower.match(/^assign\s+(t[a-f0-9]+)\s+to\s+(.+)$/i);
      if (assignMatch) {
        self._assignTask(assignMatch[1].toUpperCase(), assignMatch[2].trim());
        return { text: text };
      }

      // Cancel command: "cancel TXXXX"
      var cancelMatch = lower.match(/^cancel\s+(t[a-f0-9]+)$/i);
      if (cancelMatch) {
        self._cancelTask(cancelMatch[1].toUpperCase());
        return { text: text };
      }

      return { text: text };
    },

    afterReceive(ctx) {
      var self = window.RUNNER_PLUGIN;
      var reply = ctx.reply || '';

      // Scan for task IDs and inject rich cards
      var taskIds = [];
      var idPattern = /\b(T[A-F0-9]{12,})\b/g;
      var match;
      while ((match = idPattern.exec(reply)) !== null) {
        if (taskIds.indexOf(match[1]) === -1) taskIds.push(match[1]);
      }

      if (taskIds.length > 0) {
        self._fetchAndInjectCards(taskIds);
      }

      return { reply: reply };
    }
  },

  // ── API Helper ─────────────────────────────────────────────────────
  async api(path, opts) {
    opts = opts || {};
    var url = this.API + '/runner' + path;
    var headers = {};
    if (opts.body) headers['Content-Type'] = 'application/json';
    try {
      var token = (typeof AUTH !== 'undefined' && AUTH.sessionToken) ? AUTH.sessionToken() : null;
      if (token) headers['Authorization'] = 'Bearer ' + token;
    } catch (_) {}
    var res = await fetch(url, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
    return res.json();
  },

  // ── Chat message helper ────────────────────────────────────────────
  _chatMsg(html, role) {
    role = role || 'assistant';
    var el = document.getElementById('talkMessages');
    if (!el) return;
    var div = document.createElement('div');
    div.className = 'message ' + role;
    var inner = document.createElement('div');
    inner.innerHTML = html;
    div.appendChild(inner);
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
  },

  // ══════════════════════════════════════════════════════════════════
  // PHASE 7: Rich Task Cards
  // ══════════════════════════════════════════════════════════════════

  renderTaskCard(task) {
    var type = this.taskTypes[task.type] || { label: task.type, coin: 0, category: 'physical' };
    var icon = this.ICONS[task.type] || '\uD83D\uDCE6';
    var color = this.STATUS_COLORS[task.status] || '#6b7280';
    var role = this.role || '';

    var html = '<div class="rp-card">' +
      '<div class="rp-card-top">' +
        '<span class="rp-card-type">' + icon + ' ' + this._esc(type.label) + '</span>' +
        '<span class="rp-badge" style="background:' + color + '20;color:' + color + '">' + this._esc(task.status) + '</span>' +
      '</div>';

    if (task.title) html += '<div class="rp-card-title">' + this._esc(task.title) + '</div>';
    if (task.location && task.location.address) html += '<div class="rp-card-addr">' + this._esc(task.location.address) + '</div>';

    html += '<div class="rp-card-meta">' +
      '<span class="rp-coin">' + (task.fee_coin || type.coin || 0) + ' Credits</span>' +
      (task.scheduled_time ? '<span class="rp-time">' + this._esc(task.scheduled_time) + '</span>' : '') +
      '<span class="rp-id">' + this._esc(task.id) + '</span>' +
    '</div>';

    // Action buttons based on role + status
    html += '<div class="rp-card-actions">';
    if (role === 'Runner' && task.status === 'posted') {
      html += '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN.claimTask(\'' + task.id + '\')">Claim</button>';
    }
    if (role === 'Runner' && (task.status === 'accepted' || task.status === 'in_progress') && task.runner_id === this.userId) {
      html += '<button class="rp-btn rp-btn-proof" onclick="RUNNER_PLUGIN.showProofFlow(\'' + task.id + '\',\'' + task.type + '\')">Upload Proof</button>';
      html += '<button class="rp-btn rp-btn-complete" onclick="RUNNER_PLUGIN.completeTask(\'' + task.id + '\')">Complete</button>';
    }
    if (role === 'Requester' && task.status === 'completed') {
      html += '<button class="rp-btn rp-btn-rate" onclick="RUNNER_PLUGIN.showRatingWidget(\'' + task.id + '\')">Rate</button>';
    }
    if (task.status !== 'completed' && task.status !== 'rated' && task.status !== 'cancelled') {
      html += '<button class="rp-btn rp-btn-ghost" onclick="RUNNER_PLUGIN.cancelTaskConfirm(\'' + task.id + '\')">Cancel</button>';
    }
    html += '</div></div>';
    return html;
  },

  renderTaskList(tasks, title) {
    title = title || 'Tasks';
    if (!tasks || !tasks.length) return '<div class="rp-empty">' + this._esc(title) + ' &mdash; none yet.</div>';
    var html = '<div class="rp-task-list"><div class="rp-list-title">' + this._esc(title) + ' (' + tasks.length + ')</div>';
    for (var i = 0; i < tasks.length; i++) {
      html += this.renderTaskCard(tasks[i]);
    }
    html += '</div>';
    return html;
  },

  async _showMyTasks() {
    if (!this.userId) { this._chatMsg('Sign in to see your tasks.'); return; }
    var data = await this.api('/tasks?role=' + (this.role || 'Requester') + '&user_id=' + this.userId);
    var tasks = data.tasks || [];
    var active = tasks.filter(function(t) { return t.status !== 'completed' && t.status !== 'rated' && t.status !== 'cancelled'; });
    this._chatMsg(this.renderTaskList(active, 'Your Active Tasks'));
  },

  async _fetchAndInjectCards(taskIds) {
    var data = await this.api('/tasks?role=' + (this.role || 'Requester') + '&user_id=' + (this.userId || ''));
    var tasks = data.tasks || [];
    var matched = tasks.filter(function(t) { return taskIds.indexOf(t.id) !== -1; });
    if (matched.length) {
      var html = '';
      for (var i = 0; i < matched.length; i++) html += this.renderTaskCard(matched[i]);
      this._chatMsg(html);
    }
  },

  // ── Task Actions ───────────────────────────────────────────────────
  async claimTask(taskId) {
    if (!this.userId) { this._chatMsg('Sign in first.'); return; }
    var data = await this.api('/tasks/' + taskId + '/accept', { method: 'POST', body: { runner_id: this.userId } });
    if (data.success) {
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Task ' + taskId + ' claimed! You\'re assigned.</div>');
      this.startLocationUpdates();
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Could not claim task') + '</div>');
    }
  },

  async completeTask(taskId) {
    var data = await this.api('/tasks/' + taskId + '/complete', { method: 'POST' });
    if (data.success) {
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Task ' + taskId + ' completed! Credits earned.</div>');
      this.stopLocationUpdates();
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Could not complete task') + '</div>');
    }
  },

  cancelTaskConfirm(taskId) {
    this._chatMsg(
      '<div class="rp-confirm">Cancel task ' + this._esc(taskId) + '?' +
      '<button class="rp-btn rp-btn-ghost" onclick="RUNNER_PLUGIN._cancelTask(\'' + taskId + '\')">Yes, Cancel</button></div>'
    );
  },

  async _cancelTask(taskId) {
    var data = await this.api('/tasks/' + taskId + '/cancel', { method: 'POST' });
    if (data.success) {
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Task ' + taskId + ' cancelled. Credits refunded.</div>');
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Could not cancel task') + '</div>');
    }
  },

  // ══════════════════════════════════════════════════════════════════
  // PHASE 8: Runner Onboarding in Chat
  // ══════════════════════════════════════════════════════════════════

  renderOnboardProgress(step, total) {
    total = total || 5;
    var pct = Math.round((step / total) * 100);
    return '<div class="rp-onboard-progress">' +
      '<div class="rp-progress-label">Onboarding &mdash; Step ' + step + ' of ' + total + '</div>' +
      '<div class="rp-progress-bar"><div class="rp-progress-fill" style="width:' + pct + '%"></div></div>' +
    '</div>';
  },

  async startOnboarding() {
    this.onboardState = { step: 1, data: {} };
    this._chatMsg(
      this.renderOnboardProgress(1, 5) +
      '<div class="rp-onboard-form">' +
        '<div class="rp-form-title">Tell us about yourself</div>' +
        '<input type="text" id="rpOnboardName" class="rp-input" placeholder="Full name" />' +
        '<input type="tel" id="rpOnboardPhone" class="rp-input" placeholder="Phone number" />' +
        '<select id="rpOnboardVehicle" class="rp-input">' +
          '<option value="">Vehicle type...</option>' +
          '<option value="car">Car</option><option value="suv">SUV</option>' +
          '<option value="truck">Truck</option><option value="van">Van</option>' +
        '</select>' +
        '<input type="text" id="rpOnboardArea" class="rp-input" placeholder="Service area (e.g. Lake Nona)" />' +
        '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._submitOnboardProfile()">Continue</button>' +
      '</div>'
    );
  },

  async _submitOnboardProfile() {
    var name = (document.getElementById('rpOnboardName') || {}).value || '';
    var phone = (document.getElementById('rpOnboardPhone') || {}).value || '';
    var vehicle = (document.getElementById('rpOnboardVehicle') || {}).value || '';
    var area = (document.getElementById('rpOnboardArea') || {}).value || '';
    if (!name.trim()) { this._chatMsg('Name is required.'); return; }

    var data = await this.api('/onboard/profile', {
      method: 'POST',
      body: { name: name.trim(), phone: phone.trim(), vehicle: vehicle, service_area: area.trim() }
    });

    if (data.success) {
      this.onboardState = { step: 2, data: { user_id: data.user_id, name: name.trim() } };
      this._chatMsg(
        this.renderOnboardProgress(2, 5) +
        '<div class="rp-onboard-form">' +
          '<div class="rp-form-title">Identity Verification</div>' +
          '<p class="rp-form-desc">Upload a government-issued ID for KYC verification (FL DBPR).</p>' +
          '<input type="file" id="rpOnboardDoc" class="rp-input" accept="image/*,.pdf" />' +
          '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._submitOnboardVerify()">Submit for Verification</button>' +
          '<button class="rp-btn rp-btn-ghost" onclick="RUNNER_PLUGIN._skipOnboardVerify()">Skip for now</button>' +
        '</div>'
      );
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Profile submission failed') + '</div>');
    }
  },

  async _submitOnboardVerify() {
    // For now, log the verification as pending (real KYC integration is Phase 13)
    var userId = this.onboardState && this.onboardState.data && this.onboardState.data.user_id;
    var data = await this.api('/onboard/verify', {
      method: 'POST',
      body: { user_id: userId, verification_type: 'id_document', status: 'pending' }
    });
    this._advanceOnboardToStep3(data);
  },

  _skipOnboardVerify() {
    this._advanceOnboardToStep3({ success: true, skipped: true });
  },

  _advanceOnboardToStep3(data) {
    this.onboardState.step = 3;
    this._chatMsg(
      this.renderOnboardProgress(3, 5) +
      '<div class="rp-onboard-form">' +
        '<div class="rp-form-title">Background Check</div>' +
        '<p class="rp-form-desc">Background check integration coming soon. For now, you\'re pre-approved for MVP tasks.</p>' +
        '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._advanceOnboardToStep4()">Continue</button>' +
      '</div>'
    );
  },

  _advanceOnboardToStep4() {
    this.onboardState.step = 4;
    this._chatMsg(
      this.renderOnboardProgress(4, 5) +
      '<div class="rp-onboard-form">' +
        '<div class="rp-form-title">Payout Setup</div>' +
        '<p class="rp-form-desc">Your VAULT wallet will be created automatically. Credits earned from tasks will accumulate here.</p>' +
        '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._advanceOnboardToStep5()">Set Up Wallet</button>' +
      '</div>'
    );
  },

  _advanceOnboardToStep5() {
    this.onboardState.step = 5;
    this._chatMsg(
      this.renderOnboardProgress(5, 5) +
      '<div class="rp-onboard-form">' +
        '<div class="rp-form-title">Agreements</div>' +
        '<div class="rp-agreement">' +
          '<label><input type="checkbox" id="rpAgreeTerms" /> I agree to the Runner Terms of Service</label>' +
          '<label><input type="checkbox" id="rpAgreeIC" /> I agree to the Independent Contractor Agreement</label>' +
        '</div>' +
        '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._completeOnboarding()">Complete Onboarding</button>' +
      '</div>'
    );
  },

  async _completeOnboarding() {
    var terms = document.getElementById('rpAgreeTerms');
    var ic = document.getElementById('rpAgreeIC');
    if ((!terms || !terms.checked) || (!ic || !ic.checked)) {
      this._chatMsg('Please agree to both terms to continue.');
      return;
    }

    var userId = this.onboardState && this.onboardState.data && this.onboardState.data.user_id;
    var data = await this.api('/onboard/complete', {
      method: 'POST',
      body: { user_id: userId, agreements: { terms: true, independent_contractor: true } }
    });

    if (data.success) {
      this.userId = data.user_id || userId;
      this.role = 'Runner';
      if (data.user_id) localStorage.setItem('runner_user_id', data.user_id);
      this.onboardState = null;
      this._chatMsg(
        '<div class="rp-status-msg rp-status-ok">' +
          'Welcome to Runner! Your wallet is set up and you\'re ready to earn Credits.' +
        '</div>'
      );
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Onboarding failed') + '</div>');
    }
  },

  // ══════════════════════════════════════════════════════════════════
  // PHASE 9: Task Lifecycle + Tracking
  // ══════════════════════════════════════════════════════════════════

  renderETAWidget(task, location) {
    if (!location || !task.location || !task.location.address) return '';
    var dist = location.distance_mi || '?';
    var eta = location.eta_min || '?';
    var pct = Math.min(100, Math.max(5, 100 - (parseFloat(dist) || 0) * 10));
    return '<div class="rp-eta">' +
      '<div class="rp-eta-row"><span class="rp-eta-label">Distance</span><span class="rp-eta-value">' + dist + ' mi</span></div>' +
      '<div class="rp-eta-row"><span class="rp-eta-label">ETA</span><span class="rp-eta-value">' + eta + ' min</span></div>' +
      '<div class="rp-progress-bar"><div class="rp-progress-fill rp-progress-eta" style="width:' + pct + '%"></div></div>' +
    '</div>';
  },

  showProofFlow(taskId, taskType) {
    var instructions = this.taskInstructions[taskType] || {};
    var steps = instructions.steps || [];
    var reqs = instructions.requirements || [];

    var html = '<div class="rp-proof-flow">';
    html += '<div class="rp-form-title">' + this._esc(instructions.title || 'Complete Task') + '</div>';

    if (instructions.overview) {
      html += '<p class="rp-form-desc">' + this._esc(instructions.overview) + '</p>';
    }

    if (reqs.length) {
      html += '<div class="rp-checklist"><div class="rp-checklist-title">Requirements</div>';
      for (var i = 0; i < reqs.length; i++) {
        html += '<label class="rp-check"><input type="checkbox" /> ' + this._esc(reqs[i]) + '</label>';
      }
      html += '</div>';
    }

    if (steps.length) {
      html += '<div class="rp-steps"><div class="rp-checklist-title">Steps</div>';
      for (var j = 0; j < steps.length; j++) {
        html += '<div class="rp-step"><span class="rp-step-num">' + steps[j].step + '</span>' +
          '<div><strong>' + this._esc(steps[j].title) + '</strong><br>' + this._esc(steps[j].description) + '</div></div>';
      }
      html += '</div>';
    }

    html += '<div class="rp-proof-upload">' +
      '<label class="rp-btn rp-btn-proof">Upload Photo Evidence' +
        '<input type="file" id="rpProofFile" accept="image/*" capture="environment" style="display:none" onchange="RUNNER_PLUGIN._handleProofUpload(\'' + taskId + '\')" />' +
      '</label>' +
      '<textarea id="rpProofNote" class="rp-input" placeholder="Notes about completion..." rows="2"></textarea>' +
      '<button class="rp-btn rp-btn-complete" onclick="RUNNER_PLUGIN._submitProof(\'' + taskId + '\')">Submit Proof & Complete</button>' +
    '</div>';

    if (instructions.tips && instructions.tips.length) {
      html += '<div class="rp-tips"><div class="rp-checklist-title">Tips</div>';
      for (var k = 0; k < instructions.tips.length; k++) {
        html += '<p class="rp-tip">' + this._esc(instructions.tips[k]) + '</p>';
      }
      html += '</div>';
    }

    html += '</div>';
    this._chatMsg(html);
  },

  _proofFileData: null,

  _handleProofUpload(taskId) {
    var input = document.getElementById('rpProofFile');
    if (input && input.files && input.files[0]) {
      this._proofFileData = { taskId: taskId, file: input.files[0] };
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Photo attached: ' + this._esc(input.files[0].name) + '</div>');
    }
  },

  async _submitProof(taskId) {
    var note = (document.getElementById('rpProofNote') || {}).value || 'Task completed as requested';

    // Upload proof (multipart if file attached, JSON otherwise)
    if (this._proofFileData && this._proofFileData.taskId === taskId && this._proofFileData.file) {
      var formData = new FormData();
      formData.append('file', this._proofFileData.file);
      formData.append('note', note);
      try {
        await fetch(this.API + '/runner/tasks/' + taskId + '/proof', { method: 'POST', body: formData });
      } catch (e) { /* proof upload best-effort */ }
      this._proofFileData = null;
    } else {
      await this.api('/tasks/' + taskId + '/proof', { method: 'POST', body: { note: note } });
    }

    // Complete the task
    await this.completeTask(taskId);
  },

  showRatingWidget(taskId) {
    var html = '<div class="rp-rating">' +
      '<div class="rp-form-title">Rate this task</div>' +
      '<div class="rp-stars" id="rpStars">';
    for (var i = 1; i <= 5; i++) {
      html += '<button class="rp-star" data-rating="' + i + '" onclick="RUNNER_PLUGIN._selectRating(' + i + ')">' +
        '\u2605</button>';
    }
    html += '</div>' +
      '<input type="number" id="rpTip" class="rp-input" placeholder="Tip (Credits, optional)" min="0" value="0" />' +
      '<button class="rp-btn rp-btn-primary" onclick="RUNNER_PLUGIN._submitRating(\'' + taskId + '\')">Submit Rating</button>' +
    '</div>';
    this._chatMsg(html);
  },

  _selectedRating: 5,

  _selectRating(n) {
    this._selectedRating = n;
    var stars = document.querySelectorAll('.rp-star');
    for (var i = 0; i < stars.length; i++) {
      stars[i].classList.toggle('rp-star-active', parseInt(stars[i].getAttribute('data-rating')) <= n);
    }
  },

  async _submitRating(taskId) {
    var tip = parseInt((document.getElementById('rpTip') || {}).value) || 0;
    var data = await this.api('/tasks/' + taskId + '/rate', {
      method: 'POST',
      body: { rating: this._selectedRating, tip_coin: tip }
    });
    if (data.success) {
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Rated ' + this._selectedRating + ' stars' + (tip > 0 ? ' + ' + tip + ' Credits tip' : '') + '. Thank you!</div>');
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (data.error || 'Rating failed') + '</div>');
    }
  },

  // ── Location tracking ──────────────────────────────────────────────
  startLocationUpdates() {
    if (this._locationWatcher) return;
    if (!navigator.geolocation) return;
    var self = this;
    this._locationWatcher = navigator.geolocation.watchPosition(
      function(pos) {
        self.api('/location', {
          method: 'POST',
          body: { user_id: self.userId, lat: pos.coords.latitude, lng: pos.coords.longitude }
        }).catch(function() {});
      },
      function() { /* location error — silent */ },
      { enableHighAccuracy: true, maximumAge: 10000 }
    );
  },

  stopLocationUpdates() {
    if (this._locationWatcher) {
      navigator.geolocation.clearWatch(this._locationWatcher);
      this._locationWatcher = null;
    }
  },

  async pollTaskStatus(taskId) {
    if (this._pollTimers[taskId]) return;
    var self = this;
    var lastStatus = null;
    this._pollTimers[taskId] = setInterval(async function() {
      try {
        var data = await self.api('/tasks?role=' + (self.role || 'Requester') + '&user_id=' + (self.userId || ''));
        var task = (data.tasks || []).find(function(t) { return t.id === taskId; });
        if (!task) { clearInterval(self._pollTimers[taskId]); delete self._pollTimers[taskId]; return; }
        if (lastStatus && task.status !== lastStatus) {
          self._chatMsg('<div class="rp-status-msg rp-status-ok">Task ' + taskId + ' is now <strong>' + self._esc(task.status) + '</strong></div>');
          if (task.status === 'completed' || task.status === 'rated' || task.status === 'cancelled') {
            clearInterval(self._pollTimers[taskId]);
            delete self._pollTimers[taskId];
          }
        }
        lastStatus = task.status;

        // ETA for requester watching runner
        if (self.role === 'Requester' && (task.status === 'accepted' || task.status === 'in_progress') && task.runner_id) {
          try {
            var loc = await self.api('/location?task_id=' + taskId);
            if (loc && loc.lat) {
              // We'd render ETA inline, but for polling we just note it's updating
            }
          } catch (_) {}
        }
      } catch (_) {}
    }, 10000);
  },

  // ══════════════════════════════════════════════════════════════════
  // PHASE 10: Ops Dashboard in Chat
  // ══════════════════════════════════════════════════════════════════

  renderStatsWidget(stats) {
    var s = stats || {};
    return '<div class="rp-stats">' +
      '<div class="rp-stat"><span class="rp-stat-value">' + (s.total_tasks || 0) + '</span><span class="rp-stat-label">Total Tasks</span></div>' +
      '<div class="rp-stat"><span class="rp-stat-value">' + (s.active_tasks || 0) + '</span><span class="rp-stat-label">Active</span></div>' +
      '<div class="rp-stat"><span class="rp-stat-value">' + (s.completed_tasks || 0) + '</span><span class="rp-stat-label">Completed</span></div>' +
      '<div class="rp-stat"><span class="rp-stat-value">' + (s.total_coin || 0) + '</span><span class="rp-stat-label">Credits</span></div>' +
      '<div class="rp-stat"><span class="rp-stat-value">' + (s.total_runners || 0) + '</span><span class="rp-stat-label">Runners</span></div>' +
    '</div>';
  },

  renderRunnerList(runners) {
    if (!runners || !runners.length) return '<div class="rp-empty">No runners registered yet.</div>';
    var html = '<div class="rp-runner-list">';
    for (var i = 0; i < runners.length; i++) {
      var r = runners[i];
      html += '<div class="rp-runner-card">' +
        '<strong>' + this._esc(r.name) + '</strong>' +
        '<span class="rp-badge" style="background:#22c55e20;color:#22c55e">' + this._esc(r.status || 'active') + '</span>' +
        (r.email ? '<span class="rp-runner-email">' + this._esc(r.email) + '</span>' : '') +
      '</div>';
    }
    html += '</div>';
    return html;
  },

  async _showStats() {
    var data = await this.api('/stats');
    this._chatMsg(this.renderStatsWidget(data));
  },

  async _showRunners() {
    var data = await this.api('/list');
    this._chatMsg(this.renderRunnerList(data.runners || []));
  },

  async _assignTask(taskId, runnerName) {
    // Look up runner by name
    var data = await this.api('/list');
    var runners = data.runners || [];
    var runner = runners.find(function(r) { return r.name.toLowerCase().indexOf(runnerName.toLowerCase()) !== -1; });
    if (!runner) {
      this._chatMsg('<div class="rp-status-msg rp-status-err">Runner "' + this._esc(runnerName) + '" not found.</div>');
      return;
    }
    var result = await this.api('/tasks/' + taskId + '/assign', { method: 'PATCH', body: { runner_id: runner.id } });
    if (result.success) {
      this._chatMsg('<div class="rp-status-msg rp-status-ok">Assigned ' + taskId + ' to ' + this._esc(runner.name) + '.</div>');
    } else {
      this._chatMsg('<div class="rp-status-msg rp-status-err">' + (result.error || 'Assignment failed') + '</div>');
    }
  },

  // ── Utility ────────────────────────────────────────────────────────
  _esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; },

  // ── Styles ─────────────────────────────────────────────────────────
  injectStyles() {
    if (document.getElementById('rpStyles')) return;
    var s = document.createElement('style');
    s.id = 'rpStyles';
    s.textContent =
      /* Card */
      '.rp-card{background:var(--card,#fff);border:1px solid var(--border,#e5e7eb);border-radius:.75rem;padding:1rem;margin:.5rem 0;max-width:24rem;}' +
      '.rp-card-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;}' +
      '.rp-card-type{font-weight:600;font-size:.875rem;}' +
      '.rp-badge{font-size:.7rem;font-weight:700;padding:.125rem .5rem;border-radius:999px;text-transform:uppercase;letter-spacing:.03em;}' +
      '.rp-card-title{font-weight:600;margin-bottom:.25rem;}' +
      '.rp-card-addr{font-size:.8rem;color:var(--fg-secondary,#6b7280);margin-bottom:.5rem;}' +
      '.rp-card-meta{display:flex;gap:.75rem;font-size:.75rem;color:var(--fg-secondary,#6b7280);margin-bottom:.5rem;}' +
      '.rp-coin{font-weight:700;color:#f97316;}' +
      '.rp-id{font-family:monospace;font-size:.7rem;}' +
      '.rp-card-actions{display:flex;gap:.375rem;flex-wrap:wrap;}' +
      /* Buttons */
      '.rp-btn{font-size:.75rem;font-weight:600;padding:.375rem .75rem;border-radius:.375rem;border:1px solid transparent;cursor:pointer;transition:all .15s;}' +
      '.rp-btn-primary{background:#f97316;color:#fff;border-color:#f97316;}.rp-btn-primary:hover{background:#ea580c;}' +
      '.rp-btn-complete{background:#22c55e;color:#fff;border-color:#22c55e;}.rp-btn-complete:hover{background:#16a34a;}' +
      '.rp-btn-proof{background:#3b82f6;color:#fff;border-color:#3b82f6;}.rp-btn-proof:hover{background:#2563eb;}' +
      '.rp-btn-rate{background:#8b5cf6;color:#fff;border-color:#8b5cf6;}.rp-btn-rate:hover{background:#7c3aed;}' +
      '.rp-btn-ghost{background:transparent;color:var(--fg-secondary,#6b7280);border-color:var(--border,#e5e7eb);}.rp-btn-ghost:hover{border-color:#f97316;color:#f97316;}' +
      /* List */
      '.rp-task-list{display:flex;flex-direction:column;gap:.25rem;}' +
      '.rp-list-title{font-weight:700;font-size:.875rem;margin-bottom:.25rem;}' +
      '.rp-empty{font-size:.85rem;color:var(--fg-secondary,#6b7280);padding:.5rem 0;}' +
      /* Status messages */
      '.rp-status-msg{font-size:.85rem;padding:.5rem .75rem;border-radius:.5rem;margin:.25rem 0;}' +
      '.rp-status-ok{background:#22c55e15;color:#16a34a;border:1px solid #22c55e30;}' +
      '.rp-status-err{background:#ef444415;color:#dc2626;border:1px solid #ef444430;}' +
      '.rp-confirm{font-size:.85rem;display:flex;align-items:center;gap:.5rem;}' +
      /* Stats */
      '.rp-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(5.5rem,1fr));gap:.5rem;margin:.5rem 0;}' +
      '.rp-stat{display:flex;flex-direction:column;align-items:center;padding:.75rem;background:var(--card,#fff);border:1px solid var(--border,#e5e7eb);border-radius:.5rem;}' +
      '.rp-stat-value{font-size:1.5rem;font-weight:800;line-height:1;}' +
      '.rp-stat-label{font-size:.65rem;color:var(--fg-secondary,#6b7280);text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem;}' +
      /* Runners list */
      '.rp-runner-list{display:flex;flex-direction:column;gap:.375rem;}' +
      '.rp-runner-card{display:flex;align-items:center;gap:.5rem;padding:.5rem .75rem;background:var(--card,#fff);border:1px solid var(--border,#e5e7eb);border-radius:.5rem;font-size:.85rem;}' +
      '.rp-runner-email{font-size:.75rem;color:var(--fg-secondary,#6b7280);}' +
      /* Onboarding */
      '.rp-onboard-progress{margin:.5rem 0;}' +
      '.rp-progress-label{font-size:.75rem;font-weight:600;margin-bottom:.25rem;}' +
      '.rp-progress-bar{height:.375rem;background:var(--border,#e5e7eb);border-radius:999px;overflow:hidden;}' +
      '.rp-progress-fill{height:100%;background:#f97316;border-radius:999px;transition:width .3s;}' +
      '.rp-progress-eta{background:#3b82f6;}' +
      '.rp-onboard-form{display:flex;flex-direction:column;gap:.5rem;margin:.5rem 0;max-width:20rem;}' +
      '.rp-form-title{font-weight:700;font-size:.9rem;}' +
      '.rp-form-desc{font-size:.8rem;color:var(--fg-secondary,#6b7280);margin:0;}' +
      '.rp-input{padding:.5rem .75rem;border:1px solid var(--border,#e5e7eb);border-radius:.375rem;font-size:.85rem;background:var(--bg,#f9fafb);}' +
      '.rp-agreement{display:flex;flex-direction:column;gap:.375rem;font-size:.8rem;}' +
      '.rp-agreement label{display:flex;align-items:center;gap:.375rem;}' +
      /* Proof flow */
      '.rp-proof-flow{margin:.5rem 0;max-width:24rem;}' +
      '.rp-checklist{margin:.5rem 0;}.rp-checklist-title{font-weight:600;font-size:.8rem;margin-bottom:.25rem;}' +
      '.rp-check{display:flex;align-items:center;gap:.375rem;font-size:.8rem;padding:.125rem 0;}' +
      '.rp-steps{margin:.5rem 0;}' +
      '.rp-step{display:flex;gap:.5rem;padding:.25rem 0;font-size:.8rem;}' +
      '.rp-step-num{flex-shrink:0;width:1.5rem;height:1.5rem;background:#f97316;color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;}' +
      '.rp-proof-upload{display:flex;flex-direction:column;gap:.5rem;margin:.75rem 0;}' +
      '.rp-tips{margin:.5rem 0;}.rp-tip{font-size:.8rem;color:var(--fg-secondary,#6b7280);margin:.125rem 0;}' +
      /* Rating */
      '.rp-rating{margin:.5rem 0;max-width:16rem;}' +
      '.rp-stars{display:flex;gap:.25rem;margin:.5rem 0;}' +
      '.rp-star{font-size:1.5rem;background:none;border:none;cursor:pointer;color:var(--border,#e5e7eb);transition:color .15s;}' +
      '.rp-star-active,.rp-star:hover{color:#f59e0b;}' +
      /* ETA */
      '.rp-eta{margin:.5rem 0;padding:.75rem;background:var(--card,#fff);border:1px solid var(--border,#e5e7eb);border-radius:.5rem;max-width:16rem;}' +
      '.rp-eta-row{display:flex;justify-content:space-between;font-size:.8rem;margin-bottom:.25rem;}' +
      '.rp-eta-label{color:var(--fg-secondary,#6b7280);}.rp-eta-value{font-weight:700;}';
    document.head.appendChild(s);
  }
};
