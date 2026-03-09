/**
 * RUNNER — Task marketplace singleton.
 * CANONIC native. Same pattern as SHOP + TALK.
 *
 * Three roles: Requester (post tasks), Runner (complete tasks), Ops (manage).
 * Backend: api.canonic.org/api/v1/runner/*
 *
 * Usage:
 *   {% include RUNNER.html %}
 *   <script src="/assets/js/runner.js"></script>
 *   <script>RUNNER.init();</script>
 *
 * RUNNER | CANONIC | 2026
 */
window.RUNNER = {
  user: null,
  balance: 0,
  tasks: [],
  runners: [],
  stats: null,
  view: 'login',
  API: (window.CANONIC_API || 'https://api.canonic.org').replace(/\/+$/, ''),
  USER_KEY: 'runner_user',

  TASK_TYPES: [
    { value: 'lockbox_install', label: 'Lockbox Install', icon: '\uD83D\uDD10' },
    { value: 'yard_sign_install', label: 'Yard Sign Install', icon: '\uD83E\uDEA7' },
    { value: 'yard_sign_removal', label: 'Yard Sign Removal', icon: '\uD83E\uDEA7' },
    { value: 'showings', label: 'Showings', icon: '\uD83D\uDC41' },
    { value: 'open_house', label: 'Open House', icon: '\uD83C\uDFE0' },
    { value: 'photos', label: 'Photo Run', icon: '\uD83D\uDCF8' },
    { value: 'inspection', label: 'Inspection', icon: '\uD83D\uDD0D' },
    { value: 'cma', label: 'CMA Report', icon: '\uD83D\uDCC8' },
    { value: 'contracts', label: 'Contracts', icon: '\uD83D\uDCDD' },
    { value: 'staging', label: 'Staging', icon: '\uD83D\uDECB' },
    { value: 'appraisal', label: 'Appraisal', icon: '\uD83D\uDCCA' },
    { value: 'title', label: 'Title Search', icon: '\uD83D\uDCDC' },
    { value: 'closing', label: 'Closing', icon: '\uD83C\uDFAF' },
    { value: 'document_drop', label: 'Document Drop', icon: '\uD83D\uDCC4' },
    { value: 'vendor_meetup', label: 'Vendor Meetup', icon: '\uD83E\uDD1D' },
    { value: 'key_run', label: 'Key Run', icon: '\uD83D\uDD11' },
  ],

  // ── Init ──────────────────────────────────────────────────
  init() {
    var saved = localStorage.getItem(this.USER_KEY);
    if (saved) {
      try {
        this.user = JSON.parse(saved);
        this.view = 'home';
      } catch (e) { localStorage.removeItem(this.USER_KEY); }
    }
    this.render();
    if (this.user) {
      this.loadBalance();
      this.loadData();
    }
    // Handle Stripe checkout return
    if (window.location.search.indexOf('checkout=success') !== -1) {
      this.toast('COIN Purchased!', 'Your balance has been updated.');
      this.loadBalance();
      window.history.replaceState({}, '', window.location.pathname);
    }
  },

  // ── API ───────────────────────────────────────────────────
  async api(path, opts) {
    opts = opts || {};
    var url = this.API + '/runner' + path;
    var res = await fetch(url, {
      method: opts.method || 'GET',
      headers: opts.body ? { 'Content-Type': 'application/json' } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    return res.json();
  },

  // ── Auth ──────────────────────────────────────────────────
  async login(name, email, role) {
    var data = await this.api('/auth', {
      method: 'POST',
      body: { name: name, email: email, role: role },
    });
    if (data.success) {
      this.user = data.user;
      this.balance = data.balance || 0;
      localStorage.setItem(this.USER_KEY, JSON.stringify(data.user));
      this.view = 'home';
      this.render();
      this.loadData();
    }
    return data;
  },

  logout() {
    this.user = null;
    this.tasks = [];
    this.runners = [];
    localStorage.removeItem(this.USER_KEY);
    this.view = 'login';
    this.render();
  },

  // ── Data Loading ──────────────────────────────────────────
  async loadData() {
    if (!this.user) return;
    await this.loadTasks();
    if (this.user.role === 'Ops') {
      await Promise.all([this.loadRunners(), this.loadStats()]);
    }
    if (this.user.role === 'Runner') {
      await this.loadRunnerProfile();
    }
    this.render();
  },

  async loadTasks() {
    var data = await this.api('/tasks?role=' + this.user.role + '&user_id=' + this.user.id);
    this.tasks = data.tasks || [];
  },

  async loadRunners() {
    var data = await this.api('/list');
    this.runners = data.runners || [];
  },

  async loadStats() {
    var data = await this.api('/stats');
    this.stats = data;
  },

  async loadRunnerProfile() {
    var data = await this.api('/profile?user_id=' + this.user.id);
    this.runnerProfile = data.runner || null;
  },

  async loadBalance() {
    if (!this.user) return;
    var data = await this.api('/balance?user_id=' + this.user.id);
    this.balance = data.balance || 0;
    var el = document.getElementById('runnerBalance');
    if (el) el.textContent = this.balance + ' COIN';
  },

  async buyCoin(amount) {
    amount = amount || 50;
    var data = await this.api('/checkout', {
      method: 'POST',
      body: { user_id: this.user.id, amount_coin: amount },
    });
    if (data.url) {
      window.location.href = data.url;
    } else {
      this.toast('Error', data.error || 'Could not start checkout');
    }
  },

  COIN_PACKS: [
    { coin: 25, price: 25, label: '25 COIN', badge: 'Starter' },
    { coin: 50, price: 50, label: '50 COIN', badge: 'Popular' },
    { coin: 100, price: 95, label: '100 COIN', badge: 'Save 5%' },
    { coin: 250, price: 225, label: '250 COIN', badge: 'Save 10%' },
    { coin: 500, price: 425, label: '500 COIN', badge: 'Best Value' },
  ],

  showBuyModal() {
    var self = this;
    var overlay = document.createElement('div');
    overlay.className = 'runner-modal-overlay';
    overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
    var html = '<div class="runner-modal">' +
      '<div class="runner-modal-header"><h3>Buy COIN</h3><button class="runner-btn runner-btn-ghost runner-btn-sm" onclick="this.closest(\'.runner-modal-overlay\').remove()">Close</button></div>' +
      '<p class="runner-muted" style="margin:0 0 1rem;font-size:0.85rem">COIN powers every task on RUNNER. Pick a pack:</p>' +
      '<div class="runner-pack-grid">';
    for (var i = 0; i < this.COIN_PACKS.length; i++) {
      var p = this.COIN_PACKS[i];
      html += '<button class="runner-pack" data-coin="' + p.coin + '">' +
        '<span class="runner-pack-badge">' + this.esc(p.badge) + '</span>' +
        '<span class="runner-pack-amount">' + p.coin + '</span>' +
        '<span class="runner-pack-label">COIN</span>' +
        '<span class="runner-pack-price">$' + p.price + '</span>' +
      '</button>';
    }
    html += '</div></div>';
    overlay.innerHTML = html;
    document.body.appendChild(overlay);
    var packs = overlay.querySelectorAll('.runner-pack');
    for (var j = 0; j < packs.length; j++) {
      packs[j].addEventListener('click', function() {
        var coin = parseInt(this.getAttribute('data-coin'));
        overlay.remove();
        self.buyCoin(coin);
      });
    }
  },

  // ── Actions ───────────────────────────────────────────────
  async createTask(form) {
    var data = await this.api('/tasks', {
      method: 'POST',
      body: {
        requester_id: this.user.id,
        type: form.type,
        title: form.title,
        location: { address: form.address },
        scheduled_time: form.scheduled_time,
        offered_fee_usd: parseInt(form.offered_fee_usd) || 50,
        notes: form.notes,
      },
    });
    if (data.success) {
      this.balance = data.balance != null ? data.balance : this.balance;
      this.view = 'home';
      await this.loadTasks();
      this.render();
      this.toast('Task Posted!', 'Your task is now live for runners.');
    } else if (data.error === 'Insufficient COIN') {
      this.toast('Not Enough COIN', 'You need ' + data.required + ' COIN. Balance: ' + data.balance);
    }
    return data;
  },

  async acceptTask(taskId) {
    var data = await this.api('/tasks/' + taskId + '/accept', {
      method: 'POST',
      body: { runner_id: this.user.id },
    });
    if (data.success) {
      await this.loadTasks();
      this.render();
      this.toast('Task Accepted!', 'You are now assigned to this task.');
    }
  },

  async assignTask(taskId, runnerId) {
    var data = await this.api('/tasks/' + taskId + '/assign', {
      method: 'PATCH',
      body: { runner_id: runnerId },
    });
    if (data.success) {
      await this.loadTasks();
      this.render();
      this.toast('Runner Assigned!');
    }
  },

  async completeTask(taskId) {
    // Upload proof first, then complete
    await this.api('/tasks/' + taskId + '/proof', {
      method: 'POST',
      body: { note: 'Task completed as requested' },
    });
    var data = await this.api('/tasks/' + taskId + '/complete', { method: 'POST' });
    if (data.success) {
      await this.loadTasks();
      this.render();
      this.toast('Task Completed!', 'COIN earned.');
    }
  },

  async rateTask(taskId, rating, tip) {
    var data = await this.api('/tasks/' + taskId + '/rate', {
      method: 'POST',
      body: { rating: rating, tip_usd: tip || 0 },
    });
    if (data.success) {
      await this.loadTasks();
      this.render();
      this.toast('Rated!', 'Thank you for your feedback.');
    }
  },

  async cancelTask(taskId) {
    var data = await this.api('/tasks/' + taskId + '/cancel', { method: 'POST' });
    if (data.success) {
      await this.loadTasks();
      this.render();
      this.toast('Task Cancelled');
    }
  },

  // ── Toast ─────────────────────────────────────────────────
  toast(title, desc) {
    var el = document.getElementById('runnerToast');
    if (!el) return;
    el.innerHTML = '<strong>' + this.esc(title) + '</strong>' + (desc ? '<br>' + this.esc(desc) : '');
    el.classList.add('show');
    setTimeout(function () { el.classList.remove('show'); }, 3000);
  },

  // ── Render ────────────────────────────────────────────────
  render() {
    var root = document.getElementById('runnerRoot');
    if (!root) return;

    if (this.view === 'login') {
      root.innerHTML = this.renderLogin();
      this.bindLogin();
      return;
    }

    var role = this.user ? this.user.role : '';
    if (role === 'Requester') root.innerHTML = this.renderRequester();
    else if (role === 'Runner') root.innerHTML = this.renderRunnerDash();
    else if (role === 'Ops') root.innerHTML = this.renderOps();
    else root.innerHTML = this.renderLogin();

    this.bindEvents();
  },

  esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; },

  // ── Login ─────────────────────────────────────────────────
  renderLogin() {
    return '<div class="runner-login">' +
      '<div class="runner-logo">' +
        '<div class="runner-logo-icon"><svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"/><path d="M12 22V12"/><polyline points="3.29 7 12 12 20.71 7"/><path d="m7.5 4.27 9 5.15"/></svg></div>' +
        '<h1 class="runner-title">Runner</h1>' +
        '<p class="runner-subtitle">Real Estate Tasks Made Easy</p>' +
      '</div>' +
      '<form class="runner-form" id="runnerLoginForm">' +
        '<div class="runner-field">' +
          '<label>I am a...</label>' +
          '<select id="runnerRole" class="runner-select">' +
            '<option value="Requester">Requester \u2014 Post Tasks</option>' +
            '<option value="Runner">Runner \u2014 Complete Tasks</option>' +
            '<option value="Ops">Ops \u2014 Manage Platform</option>' +
          '</select>' +
        '</div>' +
        '<div class="runner-field">' +
          '<label>Name</label>' +
          '<input type="text" id="runnerName" placeholder="Enter your name" required class="runner-input" />' +
        '</div>' +
        '<div class="runner-field">' +
          '<label>Email (optional)</label>' +
          '<input type="email" id="runnerEmail" placeholder="your@email.com" class="runner-input" />' +
        '</div>' +
        '<button type="submit" class="runner-btn runner-btn-primary" id="runnerLoginBtn">Get Started</button>' +
      '</form>' +
    '</div>';
  },

  bindLogin() {
    var self = this;
    var form = document.getElementById('runnerLoginForm');
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var name = document.getElementById('runnerName').value.trim();
      var email = document.getElementById('runnerEmail').value.trim();
      var role = document.getElementById('runnerRole').value;
      if (!name) return;
      var btn = document.getElementById('runnerLoginBtn');
      btn.disabled = true;
      btn.textContent = 'Getting Started...';
      self.login(name, email, role).finally(function () {
        btn.disabled = false;
        btn.textContent = 'Get Started';
      });
    });
  },

  // ── Header ────────────────────────────────────────────────
  renderHeader(title) {
    return '<div class="runner-header">' +
      '<div class="runner-header-left">' +
        '<span class="runner-header-icon">\uD83D\uDCE6</span>' +
        '<div><h2>' + this.esc(title) + '</h2><p class="runner-header-name">' + this.esc(this.user.name) + '</p></div>' +
      '</div>' +
      '<div class="runner-header-right">' +
        '<span class="runner-coin-badge" id="runnerBalance">' + this.balance + ' COIN</span>' +
        '<button class="runner-btn runner-btn-accent runner-btn-sm" onclick="RUNNER.showBuyModal()">Buy COIN</button>' +
        '<button class="runner-btn runner-btn-ghost" onclick="RUNNER.logout()">Sign Out</button>' +
      '</div>' +
    '</div>';
  },

  // ── Nav ───────────────────────────────────────────────────
  renderNav(items) {
    var html = '<div class="runner-nav">';
    for (var i = 0; i < items.length; i++) {
      var active = this.view === items[i].view ? ' active' : '';
      html += '<button class="runner-nav-item' + active + '" data-view="' + items[i].view + '">' + items[i].label + '</button>';
    }
    html += '</div>';
    return html;
  },

  // ── Requester Dashboard ───────────────────────────────────
  renderRequester() {
    var nav = [
      { view: 'home', label: 'My Tasks' },
      { view: 'create', label: '+ New Task' },
      { view: 'history', label: 'History' },
    ];
    var html = this.renderHeader('Dashboard');
    html += this.renderNav(nav);
    html += '<div class="runner-content">';

    if (this.view === 'create') {
      html += this.renderCreateTask();
    } else if (this.view === 'history') {
      var done = this.tasks.filter(function (t) { return t.status === 'completed' || t.status === 'rated' || t.status === 'cancelled'; });
      html += this.renderTaskList(done, 'History');
    } else {
      var active = this.tasks.filter(function (t) { return t.status !== 'completed' && t.status !== 'rated' && t.status !== 'cancelled'; });
      html += this.renderTaskList(active, 'Active Tasks');
    }

    html += '</div>';
    return html;
  },

  renderCreateTask() {
    var html = '<div class="runner-card">' +
      '<h3>Post a New Task</h3>' +
      '<form id="runnerCreateForm" class="runner-form">';

    html += '<div class="runner-field"><label>Task Type</label><select id="taskType" class="runner-select">';
    for (var i = 0; i < this.TASK_TYPES.length; i++) {
      var t = this.TASK_TYPES[i];
      html += '<option value="' + t.value + '">' + t.icon + ' ' + t.label + '</option>';
    }
    html += '</select></div>';

    html += '<div class="runner-field"><label>Title (optional)</label><input type="text" id="taskTitle" class="runner-input" placeholder="Brief description" /></div>';
    html += '<div class="runner-field"><label>Address</label><input type="text" id="taskAddress" class="runner-input" placeholder="Property address" required /></div>';
    html += '<div class="runner-field"><label>Scheduled Time</label><input type="datetime-local" id="taskTime" class="runner-input" /></div>';
    html += '<div class="runner-field"><label>Offered Fee (USD)</label><input type="number" id="taskFee" class="runner-input" value="50" min="1" /></div>';
    html += '<div class="runner-field"><label>Notes</label><textarea id="taskNotes" class="runner-input runner-textarea" placeholder="Any special instructions..."></textarea></div>';

    html += '<button type="submit" class="runner-btn runner-btn-primary">Post Task</button>';
    html += '</form></div>';
    return html;
  },

  // ── Runner Dashboard ──────────────────────────────────────
  renderRunnerDash() {
    var nav = [
      { view: 'home', label: 'Available' },
      { view: 'active', label: 'My Tasks' },
      { view: 'earnings', label: 'Earnings' },
      { view: 'profile', label: 'Profile' },
    ];
    var html = this.renderHeader('Runner');
    html += this.renderNav(nav);
    html += '<div class="runner-content">';

    if (this.view === 'active') {
      var mine = this.tasks.filter(function (t) { return t.runner_id === RUNNER.user.id && t.status !== 'posted'; });
      html += this.renderTaskList(mine, 'My Tasks');
    } else if (this.view === 'earnings') {
      html += this.renderEarnings();
    } else if (this.view === 'profile') {
      html += this.renderProfile();
    } else {
      var available = this.tasks.filter(function (t) { return t.status === 'posted'; });
      html += this.renderTaskList(available, 'Available Tasks');
    }

    html += '</div>';
    return html;
  },

  renderEarnings() {
    var completed = this.tasks.filter(function (t) {
      return t.runner_id === RUNNER.user.id && (t.status === 'completed' || t.status === 'rated');
    });
    var total = completed.reduce(function (s, t) { return s + (t.fee_coin || 0); }, 0);
    return '<div class="runner-card">' +
      '<div class="runner-stat-row">' +
        '<div class="runner-stat"><span class="runner-stat-value">' + completed.length + '</span><span class="runner-stat-label">Completed</span></div>' +
        '<div class="runner-stat"><span class="runner-stat-value">' + total + '</span><span class="runner-stat-label">COIN Earned</span></div>' +
      '</div>' +
      this.renderTaskList(completed, 'Completed Tasks') +
    '</div>';
  },

  renderProfile() {
    var p = this.runnerProfile || {};
    return '<div class="runner-card">' +
      '<h3>' + this.esc(this.user.name) + '</h3>' +
      '<p class="runner-muted">' + this.esc(this.user.email || 'No email') + '</p>' +
      '<div class="runner-stat-row" style="margin-top:1rem">' +
        '<div class="runner-stat"><span class="runner-stat-value">' + (p.completed_tasks || 0) + '</span><span class="runner-stat-label">Tasks</span></div>' +
        '<div class="runner-stat"><span class="runner-stat-value">' + (p.total_earned_coin || 0) + '</span><span class="runner-stat-label">COIN</span></div>' +
        '<div class="runner-stat"><span class="runner-stat-value">' + (p.avg_rating || '-') + '</span><span class="runner-stat-label">Rating</span></div>' +
      '</div>' +
    '</div>';
  },

  // ── Ops Dashboard ─────────────────────────────────────────
  renderOps() {
    var nav = [
      { view: 'home', label: 'Dashboard' },
      { view: 'tasks_all', label: 'All Tasks' },
      { view: 'runners_all', label: 'Runners' },
    ];
    var html = this.renderHeader('Ops Dashboard');
    html += this.renderNav(nav);
    html += '<div class="runner-content">';

    if (this.view === 'tasks_all') {
      html += this.renderTaskList(this.tasks, 'All Tasks');
    } else if (this.view === 'runners_all') {
      html += this.renderRunnersList();
    } else {
      html += this.renderOpsStats();
      var active = this.tasks.filter(function (t) { return t.status !== 'completed' && t.status !== 'rated' && t.status !== 'cancelled'; });
      html += this.renderTaskList(active, 'Active Tasks');
    }

    html += '</div>';
    return html;
  },

  renderOpsStats() {
    var s = this.stats || {};
    return '<div class="runner-stat-row" style="margin-bottom:1.5rem">' +
      '<div class="runner-stat"><span class="runner-stat-value">' + (s.total_tasks || 0) + '</span><span class="runner-stat-label">Total Tasks</span></div>' +
      '<div class="runner-stat"><span class="runner-stat-value">' + (s.active_tasks || 0) + '</span><span class="runner-stat-label">Active</span></div>' +
      '<div class="runner-stat"><span class="runner-stat-value">' + (s.completed_tasks || 0) + '</span><span class="runner-stat-label">Completed</span></div>' +
      '<div class="runner-stat"><span class="runner-stat-value">' + (s.total_coin || 0) + '</span><span class="runner-stat-label">COIN</span></div>' +
      '<div class="runner-stat"><span class="runner-stat-value">' + (s.total_runners || 0) + '</span><span class="runner-stat-label">Runners</span></div>' +
    '</div>';
  },

  renderRunnersList() {
    if (!this.runners.length) return '<div class="runner-empty">No runners registered yet.</div>';
    var html = '<div class="runner-list">';
    for (var i = 0; i < this.runners.length; i++) {
      var r = this.runners[i];
      html += '<div class="runner-card runner-card-compact">' +
        '<strong>' + this.esc(r.name) + '</strong>' +
        '<span class="runner-muted">' + this.esc(r.email || '') + '</span>' +
        '<span class="runner-badge runner-badge-green">' + this.esc(r.status || 'active') + '</span>' +
      '</div>';
    }
    html += '</div>';
    return html;
  },

  // ── Task List ─────────────────────────────────────────────
  renderTaskList(tasks, title) {
    var html = '<h3 class="runner-section-title">' + this.esc(title) + ' (' + tasks.length + ')</h3>';
    if (!tasks.length) return html + '<div class="runner-empty">No tasks here yet.</div>';

    html += '<div class="runner-list">';
    for (var i = 0; i < tasks.length; i++) {
      html += this.renderTaskCard(tasks[i]);
    }
    html += '</div>';
    return html;
  },

  renderTaskCard(task) {
    var typeInfo = this.TASK_TYPES.find(function (t) { return t.value === task.type; }) || { icon: '\uD83D\uDCE6', label: task.type };
    var statusClass = 'runner-badge-' + task.status;

    var html = '<div class="runner-card">' +
      '<div class="runner-card-top">' +
        '<div class="runner-card-type">' + typeInfo.icon + ' ' + this.esc(typeInfo.label) + '</div>' +
        '<span class="runner-badge ' + statusClass + '">' + this.esc(task.status) + '</span>' +
      '</div>' +
      '<div class="runner-card-body">' +
        (task.title ? '<p class="runner-card-title">' + this.esc(task.title) + '</p>' : '') +
        '<p class="runner-muted">' + this.esc((task.location || {}).address || '') + '</p>' +
        '<div class="runner-card-meta">' +
          '<span class="runner-coin">' + (task.fee_coin || 0) + ' COIN</span>' +
          (task.scheduled_time ? '<span class="runner-muted">' + this.esc(task.scheduled_time) + '</span>' : '') +
        '</div>' +
      '</div>';

    // Actions based on role + status
    html += '<div class="runner-card-actions">';
    var role = this.user ? this.user.role : '';

    if (role === 'Runner' && task.status === 'posted') {
      html += '<button class="runner-btn runner-btn-primary runner-btn-sm" onclick="RUNNER.acceptTask(\'' + task.id + '\')">Accept</button>';
    }
    if (role === 'Runner' && (task.status === 'accepted' || task.status === 'in_progress') && task.runner_id === this.user.id) {
      html += '<button class="runner-btn runner-btn-primary runner-btn-sm" onclick="RUNNER.completeTask(\'' + task.id + '\')">Complete</button>';
    }
    if (role === 'Requester' && task.status === 'completed') {
      html += '<button class="runner-btn runner-btn-primary runner-btn-sm" onclick="RUNNER.promptRate(\'' + task.id + '\')">Rate</button>';
    }
    if (role === 'Ops' && task.status === 'posted' && this.runners.length) {
      html += '<select class="runner-select runner-select-sm" onchange="RUNNER.assignTask(\'' + task.id + '\', this.value)">' +
        '<option value="">Assign runner...</option>';
      for (var j = 0; j < this.runners.length; j++) {
        html += '<option value="' + this.runners[j].id + '">' + this.esc(this.runners[j].name) + '</option>';
      }
      html += '</select>';
    }
    if (task.status !== 'completed' && task.status !== 'rated' && task.status !== 'cancelled') {
      html += '<button class="runner-btn runner-btn-ghost runner-btn-sm" onclick="RUNNER.cancelTask(\'' + task.id + '\')">Cancel</button>';
    }

    html += '</div></div>';
    return html;
  },

  promptRate(taskId) {
    var rating = prompt('Rate this task (1-5):', '5');
    if (rating === null) return;
    var tip = prompt('Tip (COIN, 0 for none):', '0');
    this.rateTask(taskId, parseInt(rating) || 5, parseInt(tip) || 0);
  },

  // ── Event Binding ─────────────────────────────────────────
  bindEvents() {
    var self = this;

    // Nav clicks
    var navItems = document.querySelectorAll('.runner-nav-item');
    for (var i = 0; i < navItems.length; i++) {
      navItems[i].addEventListener('click', function () {
        self.view = this.getAttribute('data-view');
        self.render();
      });
    }

    // Create task form
    var createForm = document.getElementById('runnerCreateForm');
    if (createForm) {
      createForm.addEventListener('submit', function (e) {
        e.preventDefault();
        self.createTask({
          type: document.getElementById('taskType').value,
          title: document.getElementById('taskTitle').value,
          address: document.getElementById('taskAddress').value,
          scheduled_time: document.getElementById('taskTime').value,
          offered_fee_usd: document.getElementById('taskFee').value,
          notes: document.getElementById('taskNotes').value,
        });
      });
    }
  },
};
