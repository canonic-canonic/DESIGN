/**
 * RUNNER — Task marketplace engine (edge-native, KV-backed).
 * Three roles: Requester, Runner, Ops.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../kernel/http.js';
import { intEnv } from '../kernel/env.js';
import { appendToLedger } from '../kernel/ledger.js';
import { stripeApiRequest } from './shop.js';

const TASK_PRICES = {
  yard_sign_install: 3, yard_sign_removal: 3, lockbox_install: 3, lockbox_removal: 3,
  showings: 5, open_house: 8, cma: 5, contracts: 15,
  photos: 10, staging: 8, inspection: 10, appraisal: 10,
  title: 10, closing: 25, document_drop: 3, vendor_meetup: 5, key_run: 3,
};

const KYC_REQUIRED = {
  photos: 'business_license', staging: 'business_license',
  inspection: 'FL_468', appraisal: 'FL_FREAB_USPAP',
  title: 'FL_626', closing: 'FL_626_NMLS',
};

function uid() {
  return Array.from(crypto.getRandomValues(new Uint8Array(6)))
    .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function notifyVendors(env, kv, task) {
  const runnerIds = JSON.parse(await kv.get('runner:role:runner') || '[]');
  const kycReq = KYC_REQUIRED[task.type];
  for (const id of runnerIds) {
    const raw = await kv.get(`runner:user:${id}`);
    if (!raw) continue;
    const vendor = JSON.parse(raw);
    if (!vendor.email) continue;
    if (kycReq) {
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== 'verified') continue;
    }
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'founder@canonic.org', to: [vendor.email],
        bcc: [env.EMAIL_FROM || 'founder@canonic.org'],
        subject: `RUNNER: New ${task.title} task — ${task.fee_coin} COIN`,
        html: `<p>A new task has been posted on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || 'TBD'}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">ID</td><td style="padding:4px 12px;font-family:monospace;">${task.id}</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Claim on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC · Every task ledgered.</p>`,
      }),
    });
  }
}

async function notifyAgent(env, kv, task) {
  if (!task.requester_id) return;
  const raw = await kv.get(`runner:user:${task.requester_id}`);
  if (!raw) return;
  const agent = JSON.parse(raw);
  if (!agent.email) return;
  let vendorName = 'A vendor';
  if (task.runner_id) {
    const vRaw = await kv.get(`runner:user:${task.runner_id}`);
    if (vRaw) vendorName = JSON.parse(vRaw).name || vendorName;
  }
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.RESEND_API_KEY}` },
    body: JSON.stringify({
      from: env.EMAIL_FROM || 'founder@canonic.org', to: [agent.email],
      bcc: [env.EMAIL_FROM || 'founder@canonic.org'],
      subject: `RUNNER: ${vendorName} claimed your ${task.title} task`,
      html: `<p><strong>${vendorName}</strong> has claimed your task on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || 'TBD'}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Vendor</td><td style="padding:4px 12px;">${vendorName}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">View on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC · Every task ledgered.</p>`,
    }),
  });
}

export async function handle(subpath, request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: 'KV not configured' }, 500);
  const method = request.method;
  const url = new URL(request.url);

  // POST /runner/auth
  if (subpath === 'auth' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const name = (body.name || '').trim();
    const email = (body.email || '').trim();
    const role = body.role || 'Requester';
    if (!name) return json({ error: 'name is required' }, 400);
    if (!['Requester', 'Runner', 'Ops'].includes(role)) return json({ error: 'invalid role' }, 400);

    if (email) {
      const existing = await kv.get(`runner:email:${email.toLowerCase()}`);
      if (existing) {
        const user = JSON.parse(existing);
        const bal = parseInt(await kv.get(`runner:balance:${user.id}`) || '0', 10);
        return json({ success: true, user, balance: bal });
      }
    }

    const id = 'U' + uid();
    const startupCoin = intEnv(env, 'RUNNER_STARTUP_COIN', 50);
    const user = { id, name, email, role, created_at: new Date().toISOString(), status: 'active' };
    await kv.put(`runner:user:${id}`, JSON.stringify(user));
    if (email) await kv.put(`runner:email:${email.toLowerCase()}`, JSON.stringify(user));
    await kv.put(`runner:balance:${id}`, String(startupCoin));
    const roleKey = `runner:role:${role.toLowerCase()}`;
    const roleList = JSON.parse(await kv.get(roleKey) || '[]');
    roleList.push(id);
    await kv.put(roleKey, JSON.stringify(roleList));
    return json({ success: true, user, balance: startupCoin });
  }

  // GET /runner/tasks
  if (subpath === 'tasks' && method === 'GET') {
    const role = url.searchParams.get('role') || '';
    const userId = url.searchParams.get('user_id') || '';
    let tasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    if (role === 'Requester' && userId) tasks = tasks.filter(t => t.requester_id === userId);
    else if (role === 'Runner' && userId) tasks = tasks.filter(t => t.status === 'posted' || t.runner_id === userId);
    tasks.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    return json({ tasks });
  }

  // POST /runner/tasks — create
  if (subpath === 'tasks' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!body.requester_id) return json({ error: 'requester_id is required' }, 400);
    const taskType = body.type || 'lockbox_install';
    const feeCoin = TASK_PRICES[taskType] || Math.max(1, parseInt(body.offered_fee_usd) || 50);
    const bal = parseInt(await kv.get(`runner:balance:${body.requester_id}`) || '0', 10);
    if (bal < feeCoin) return json({ error: 'Insufficient COIN', balance: bal, required: feeCoin }, 402);

    const tid = 'T' + uid();
    const task = {
      id: tid, requester_id: body.requester_id, runner_id: null, type: taskType,
      title: body.title || taskType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      status: 'posted', location: { address: (body.location || {}).address || body.address || '' },
      scheduled_time: body.scheduled_time || '', fee_coin: feeCoin,
      offered_fee_usd: parseInt(body.offered_fee_usd) || 50, notes: body.notes || '',
      proof_url: null, proof_note: null, rating: null, tip_coin: 0,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    };
    await kv.put(`runner:balance:${body.requester_id}`, String(bal - feeCoin));
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    allTasks.push(task);
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_POSTED', task_id: tid, task_type: taskType, requester_id: body.requester_id, fee_coin: feeCoin, address: task.location.address });
    if (env.RESEND_API_KEY) notifyVendors(env, kv, task).catch(e => console.error('[RUNNER:NOTIFY]', e.message || e));
    return json({ success: true, task, balance: bal - feeCoin });
  }

  // Task actions: /runner/tasks/{id}/{action}
  const taskMatch = subpath.match(/^tasks\/([A-Z0-9]+)\/(\w+)$/);
  if (taskMatch) return handleTaskAction(taskMatch[1], taskMatch[2], request, env, kv);

  // GET /runner/list
  if (subpath === 'list' && method === 'GET') {
    const ids = JSON.parse(await kv.get('runner:role:runner') || '[]');
    const runners = [];
    for (const id of ids) { const raw = await kv.get(`runner:user:${id}`); if (raw) runners.push(JSON.parse(raw)); }
    return json({ runners });
  }

  // GET /runner/profile
  if (subpath === 'profile' && method === 'GET') {
    const userId = url.searchParams.get('user_id') || '';
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: 'user not found' }, 404);
    const user = JSON.parse(raw);
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const completed = allTasks.filter(t => t.runner_id === userId && ['completed', 'rated'].includes(t.status));
    const totalEarned = completed.reduce((s, t) => s + (t.fee_coin || 0), 0);
    const ratings = completed.filter(t => t.rating).map(t => t.rating);
    const avgRating = ratings.length ? Math.round(ratings.reduce((a, b) => a + b, 0) / ratings.length * 10) / 10 : 0;
    return json({ runner: { ...user, completed_tasks: completed.length, total_earned_coin: totalEarned, avg_rating: avgRating } });
  }

  // GET /runner/stats
  if (subpath === 'stats' && method === 'GET') {
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const reqIds = JSON.parse(await kv.get('runner:role:requester') || '[]');
    const runIds = JSON.parse(await kv.get('runner:role:runner') || '[]');
    const active = allTasks.filter(t => ['posted', 'assigned', 'accepted', 'in_progress'].includes(t.status));
    const done = allTasks.filter(t => ['completed', 'rated'].includes(t.status));
    return json({
      total_tasks: allTasks.length, active_tasks: active.length, completed_tasks: done.length,
      total_coin: done.reduce((s, t) => s + (t.fee_coin || 0), 0),
      total_users: reqIds.length + runIds.length, total_runners: runIds.length, total_requesters: reqIds.length,
    });
  }

  // GET /runner/balance
  if (subpath === 'balance' && method === 'GET') {
    const userId = url.searchParams.get('user_id') || '';
    if (!userId) return json({ error: 'user_id required' }, 400);
    return json({ balance: parseInt(await kv.get(`runner:balance:${userId}`) || '0', 10), user_id: userId });
  }

  // POST /runner/checkout
  if (subpath === 'checkout' && method === 'POST') {
    if (!env.STRIPE_SECRET_KEY) return json({ error: 'Stripe not configured' }, 500);
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const amountCoin = parseInt(body.amount_coin, 10);
    if (!Number.isFinite(amountCoin) || amountCoin < 10 || amountCoin > 10000) return json({ error: 'amount_coin must be 10–10000' }, 400);
    const coinToCents = Math.max(1, intEnv(env, 'RUNNER_COIN_USD_CENTS', 100));
    const fields = {
      mode: 'payment', success_url: (body.success_url || 'https://gorunner.pro/?checkout=success').trim(),
      cancel_url: (body.cancel_url || 'https://gorunner.pro/?checkout=cancel').trim(),
      'line_items[0][quantity]': '1', 'line_items[0][price_data][currency]': 'usd',
      'line_items[0][price_data][unit_amount]': String(amountCoin * coinToCents),
      'line_items[0][price_data][product_data][name]': `RUNNER — ${amountCoin} COIN`,
      'metadata[service]': 'RUNNER', 'metadata[user_id]': userId, 'metadata[amount_coin]': String(amountCoin),
      'payment_intent_data[metadata][service]': 'RUNNER', 'payment_intent_data[metadata][user_id]': userId,
      'payment_intent_data[metadata][amount_coin]': String(amountCoin),
    };
    const created = await stripeApiRequest(env, 'POST', '/v1/checkout/sessions', fields);
    if (!created.ok) return json({ error: created.error || 'Stripe checkout failed' }, created.status || 502);
    return json({ ok: true, session_id: (created.data || {}).id, url: (created.data || {}).url, amount_coin: amountCoin });
  }

  // POST /runner/credit
  if (subpath === 'credit' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    const amount = parseInt(body.amount_coin, 10);
    if (!userId || !Number.isFinite(amount) || amount < 1) return json({ error: 'user_id and amount_coin required' }, 400);
    const bal = parseInt(await kv.get(`runner:balance:${userId}`) || '0', 10);
    const newBal = bal + amount;
    await kv.put(`runner:balance:${userId}`, String(newBal));
    return json({ ok: true, balance: newBal, credited: amount });
  }

  // GET /runner/evidence/{task_id}
  const evidenceMatch = subpath.match(/^evidence\/([A-Z0-9]+)$/);
  if (evidenceMatch && method === 'GET') {
    const eid = evidenceMatch[1];
    const keys = await kv.list({ prefix: `runner:evidence:${eid}:` });
    if (!keys.keys.length) return json({ error: 'no evidence found' }, 404);
    const key = keys.keys[0];
    const { value, metadata } = await kv.getWithMetadata(key.name, { type: 'arrayBuffer' });
    if (!value) return json({ error: 'evidence data missing' }, 404);
    return new Response(value, {
      headers: {
        'Content-Type': (metadata && metadata.content_type) || 'application/octet-stream',
        'X-Evidence-Hash': (metadata && metadata.hash) || '', 'X-Task-Id': eid,
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  }

  // GET /runner/ledger
  if (subpath === 'ledger' && method === 'GET') {
    const raw = await kv.get('ledger:RUNNER:RUNNER');
    const ledger = raw ? JSON.parse(raw) : [];
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
    const since = url.searchParams.get('since') || '';
    let entries = since ? ledger.filter(e => e.ts > since) : ledger;
    return json({ entries: entries.slice(-limit), total: ledger.length });
  }

  // POST /runner/referral
  if (subpath === 'referral' && method === 'POST') return handleReferral(request, env, kv);

  // Credentials CRUD
  if (subpath === 'credentials' && method === 'POST') return handleCredentialSubmit(request, kv, env);
  if (subpath === 'credentials/verify' && method === 'POST') return handleCredentialVerify(request, kv, env);
  if (subpath === 'credentials' && method === 'GET') {
    const userId = url.searchParams.get('user_id') || '';
    if (!userId) return json({ error: 'user_id required' }, 400);
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: 'user not found' }, 404);
    return json({ user_id: userId, credentials: JSON.parse(raw).credentials || {} });
  }

  // Availability
  if (subpath === 'availability' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    if (!Array.isArray(body.slots)) return json({ error: 'slots array required' }, 400);
    await kv.put(`runner:availability:${userId}`, JSON.stringify({ user_id: userId, slots: body.slots, updated_at: new Date().toISOString(), timezone: body.timezone || 'America/New_York' }));
    return json({ success: true, user_id: userId, slots: body.slots });
  }
  if (subpath === 'availability' && method === 'GET') {
    const userId = url.searchParams.get('user_id') || '';
    if (!userId) return json({ error: 'user_id required' }, 400);
    const raw = await kv.get(`runner:availability:${userId}`);
    return json(raw ? JSON.parse(raw) : { user_id: userId, slots: [] });
  }

  // Calendar
  if (subpath === 'calendar' && method === 'GET') return handleCalendar(url, kv);

  // Board
  if (subpath === 'board' && method === 'GET') {
    const address = (url.searchParams.get('address') || '').trim().toLowerCase();
    if (!address) return json({ error: 'address required' }, 400);
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const matched = allTasks.filter(t => t.location && t.location.address && t.location.address.toLowerCase().includes(address));
    const board = { posted: [], accepted: [], in_progress: [], completed: [], rated: [], cancelled: [] };
    for (const t of matched) { if (board[t.status]) board[t.status].push(t); }
    const totalCoin = matched.reduce((s, t) => s + (t.fee_coin || 0), 0);
    const completedCoin = matched.filter(t => ['completed', 'rated'].includes(t.status)).reduce((s, t) => s + (t.fee_coin || 0), 0);
    return json({ address: url.searchParams.get('address'), total_tasks: matched.length, total_coin: totalCoin, completed_coin: completedCoin, board });
  }

  // Listings
  if (subpath === 'listings' && method === 'GET') {
    const userId = url.searchParams.get('user_id') || '';
    if (!userId) return json({ error: 'user_id required' }, 400);
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const userTasks = allTasks.filter(t => t.requester_id === userId);
    const addrMap = {};
    for (const t of userTasks) {
      const addr = (t.location && t.location.address) || 'Unknown';
      if (!addrMap[addr]) addrMap[addr] = { address: addr, tasks: 0, coin: 0, active: 0, completed: 0 };
      addrMap[addr].tasks++; addrMap[addr].coin += t.fee_coin || 0;
      if (['completed', 'rated'].includes(t.status)) addrMap[addr].completed++;
      else if (!['cancelled'].includes(t.status)) addrMap[addr].active++;
    }
    return json({ listings: Object.values(addrMap) });
  }

  return json({ error: 'unknown runner route' }, 404);
}

// ── Task actions ──

async function handleTaskAction(taskId, action, request, env, kv) {
  const method = request.method;
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const task = allTasks.find(t => t.id === taskId);
  if (!task) return json({ error: 'task not found' }, 404);

  if (action === 'accept' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: 'runner_id required' }, 400);
    if (!['posted', 'assigned'].includes(task.status)) return json({ error: `cannot accept in status: ${task.status}` }, 400);
    const kycReq = KYC_REQUIRED[task.type];
    if (kycReq) {
      const vendorRaw = await kv.get(`runner:user:${body.runner_id}`);
      const vendor = vendorRaw ? JSON.parse(vendorRaw) : {};
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== 'verified') return json({ error: 'Credential verification required', task_type: task.type, required_credential: kycReq, vendor_id: body.runner_id }, 403);
    }
    task.runner_id = body.runner_id; task.status = 'accepted'; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'VENDOR_CLAIMED', task_id: taskId, task_type: task.type, runner_id: body.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin });
    if (env.RESEND_API_KEY) notifyAgent(env, kv, task).catch(e => console.error('[RUNNER:NOTIFY]', e.message || e));
    return json({ success: true, task });
  }

  if (action === 'assign' && method === 'PATCH') {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: 'runner_id required' }, 400);
    if (task.status !== 'posted') return json({ error: `cannot assign in status: ${task.status}` }, 400);
    task.runner_id = body.runner_id; task.status = 'assigned'; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    return json({ success: true, task });
  }

  if (action === 'proof' && method === 'POST') {
    if (!['accepted', 'in_progress'].includes(task.status)) return json({ error: `cannot upload proof in status: ${task.status}` }, 400);
    let body, fileHash = null, fileKey = null;
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('multipart/form-data')) {
      const formData = await request.formData();
      const file = formData.get('file');
      const note = formData.get('note') || 'Task completed as requested';
      if (file && file.size > 0) {
        const buf = await file.arrayBuffer();
        const hashBuf = await crypto.subtle.digest('SHA-256', buf);
        fileHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        fileKey = `runner:evidence:${taskId}:${fileHash.slice(0, 12)}`;
        await kv.put(fileKey, buf, { metadata: { task_id: taskId, filename: file.name || 'evidence', content_type: file.type || 'application/octet-stream', hash: fileHash, uploaded_at: new Date().toISOString() }});
      }
      body = { note };
    } else {
      body = await request.json().catch(() => ({}));
      fileHash = body.proof_hash || null;
    }
    task.status = 'in_progress'; task.proof_note = body.note || 'Task completed as requested';
    task.proof_hash = fileHash; task.proof_key = fileKey; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'EVIDENCE_UPLOADED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, proof_hash: fileHash, proof_note: task.proof_note });
    return json({ success: true, task, proof_hash: fileHash });
  }

  if (action === 'complete' && method === 'POST') {
    if (!['in_progress', 'accepted'].includes(task.status)) return json({ error: `cannot complete in status: ${task.status}` }, 400);
    task.status = 'completed'; task.completed_at = new Date().toISOString(); task.updated_at = new Date().toISOString();
    if (task.runner_id && task.fee_coin) {
      const vendorBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(vendorBal + task.fee_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_COMPLETED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin, coin_credited_to: task.runner_id });
    return json({ success: true, task });
  }

  if (action === 'rate' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (task.status !== 'completed') return json({ error: `cannot rate in status: ${task.status}` }, 400);
    task.rating = Math.max(1, Math.min(5, parseInt(body.rating) || 5));
    task.tip_coin = Math.max(0, parseInt(body.tip_usd || body.tip_coin) || 0);
    task.status = 'rated'; task.updated_at = new Date().toISOString();
    if (task.tip_coin > 0 && task.runner_id) {
      const tipBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(tipBal + task.tip_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'DEAL_CLOSED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, rating: task.rating, tip_coin: task.tip_coin, fee_coin: task.fee_coin });
    return json({ success: true, task });
  }

  if (action === 'cancel' && method === 'POST') {
    if (['completed', 'rated'].includes(task.status)) return json({ error: `cannot cancel in status: ${task.status}` }, 400);
    const prevStatus = task.status;
    task.status = 'cancelled'; task.updated_at = new Date().toISOString();
    if (task.fee_coin && task.requester_id) {
      const refBal = parseInt(await kv.get(`runner:balance:${task.requester_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.requester_id}`, String(refBal + task.fee_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_CANCELLED', task_id: taskId, task_type: task.type, requester_id: task.requester_id, fee_coin: task.fee_coin, prev_status: prevStatus });
    return json({ success: true, task });
  }

  return json({ error: 'unknown action' }, 404);
}

// ── Referral ──

async function handleReferral(request, env, kv) {
  const body = await request.json().catch(() => ({}));
  const { requester_id, address, stage, deal_id, source } = body;
  if (!requester_id || !address) return json({ error: 'requester_id and address required' }, 400);

  const STAGE_TASKS = {
    inquiry: ['cma'], match: ['yard_sign_install', 'lockbox_install'],
    show: ['showings', 'photos'], offer: ['contracts', 'inspection', 'appraisal'],
    negotiate: ['title'], close: ['closing'],
  };
  const dealStage = (stage || 'inquiry').toLowerCase();
  const taskTypes = STAGE_TASKS[dealStage] || STAGE_TASKS.inquiry;
  const totalCoin = taskTypes.reduce((s, t) => s + (TASK_PRICES[t] || 5), 0);
  let bal = parseInt(await kv.get(`runner:balance:${requester_id}`) || '0', 10);
  if (bal < totalCoin) return json({ error: 'Insufficient COIN for referral batch', balance: bal, required: totalCoin }, 402);

  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const created = [];
  for (const taskType of taskTypes) {
    const feeCoin = TASK_PRICES[taskType] || 5;
    const tid = 'T' + uid();
    const task = {
      id: tid, requester_id, runner_id: null, type: taskType,
      title: taskType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      status: 'posted', location: { address }, scheduled_time: '', fee_coin: feeCoin, offered_fee_usd: 50,
      notes: `Auto-staged from ${source || 'NONA'} ${dealStage} (deal: ${deal_id || 'n/a'})`,
      proof_url: null, proof_note: null, rating: null, tip_coin: 0,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    };
    bal -= feeCoin; allTasks.push(task); created.push(task);
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_POSTED', task_id: tid, task_type: taskType, requester_id, fee_coin: feeCoin, address, referral_source: source || 'NONA', referral_stage: dealStage, deal_id: deal_id || null });
  }
  await kv.put(`runner:balance:${requester_id}`, String(bal));
  await kv.put('runner:tasks:all', JSON.stringify(allTasks));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'REFERRAL_STAGED', source: source || 'NONA', stage: dealStage, deal_id: deal_id || null, requester_id, address, tasks_created: created.length, total_coin: totalCoin });
  return json({ success: true, stage: dealStage, tasks: created, balance: bal, deal_id });
}

// ── Credentials ──

async function handleCredentialSubmit(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || '').trim();
  const credType = (body.type || '').trim();
  const licenseNumber = (body.license_number || '').trim();
  if (!userId || !credType || !licenseNumber) return json({ error: 'user_id, type, and license_number required' }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: 'user not found' }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  creds[credType] = { license_number: licenseNumber, issuing_authority: body.issuing_authority || '', expiry: body.expiry || '', status: 'pending', submitted_at: new Date().toISOString() };
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'CREDENTIAL_SUBMITTED', user_id: userId, credential_type: credType, license_number: licenseNumber });
  return json({ success: true, user_id: userId, credential: creds[credType] });
}

async function handleCredentialVerify(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || '').trim();
  const credType = (body.type || '').trim();
  const verdict = body.verified === true ? 'verified' : 'rejected';
  if (!userId || !credType) return json({ error: 'user_id and type required' }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: 'user not found' }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  if (!creds[credType]) return json({ error: 'credential not found' }, 404);
  creds[credType].status = verdict; creds[credType].verified_at = new Date().toISOString(); creds[credType].verified_by = body.verified_by || 'ops';
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'CREDENTIAL_VERIFIED', user_id: userId, credential_type: credType, verdict, verified_by: body.verified_by || 'ops' });
  if (user.email && env.RESEND_API_KEY) {
    const statusText = verdict === 'verified' ? 'approved' : 'rejected';
    fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'founder@canonic.org', to: [user.email],
        subject: `RUNNER: Your ${credType} credential has been ${statusText}`,
        html: `<p>Your <strong>${credType}</strong> credential (${creds[credType].license_number}) has been <strong>${statusText}</strong> on RUNNER.</p>
${verdict === 'verified' ? '<p>You can now claim tasks that require this credential.</p>' : '<p>Please resubmit with a valid license number.</p>'}
<p><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Go to RUNNER</a></p>`,
      }),
    }).catch(() => {});
  }
  return json({ success: true, user_id: userId, credential: creds[credType] });
}

// ── Calendar ──

async function handleCalendar(url, kv) {
  const userId = url.searchParams.get('user_id') || '';
  const dateStr = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const range = url.searchParams.get('range') || 'week';
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const base = new Date(dateStr + 'T00:00:00Z');
  let rangeStart, rangeEnd;
  if (range === 'day') { rangeStart = rangeEnd = dateStr; }
  else if (range === 'month') {
    rangeStart = dateStr.slice(0, 8) + '01';
    rangeEnd = dateStr.slice(0, 8) + String(new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() + 1, 0)).getUTCDate()).padStart(2, '0');
  } else {
    const dow = base.getUTCDay() || 7;
    const mon = new Date(base.getTime() - (dow - 1) * 86400000);
    rangeStart = mon.toISOString().slice(0, 10);
    rangeEnd = new Date(mon.getTime() + 6 * 86400000).toISOString().slice(0, 10);
  }
  const events = allTasks.filter(t => {
    if (userId && t.requester_id !== userId && t.runner_id !== userId) return false;
    const d = (t.scheduled_time || t.created_at || '').slice(0, 10);
    return d >= rangeStart && d <= rangeEnd;
  }).map(t => ({
    id: t.id, type: t.type, title: t.title, status: t.status,
    date: (t.scheduled_time || t.created_at || '').slice(0, 10),
    time: (t.scheduled_time || '').slice(11, 16) || null,
    address: (t.location && t.location.address) || '', fee_coin: t.fee_coin,
  })).sort((a, b) => (a.date + (a.time || '')).localeCompare(b.date + (b.time || '')));
  let availability = null;
  if (userId) { const avRaw = await kv.get(`runner:availability:${userId}`); if (avRaw) availability = JSON.parse(avRaw); }
  return json({ range: { start: rangeStart, end: rangeEnd, type: range }, events, availability });
}
