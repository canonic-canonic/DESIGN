/**
 * RUNNER — Task marketplace engine (edge-native, KV-backed).
 * Three roles: Requester, Runner, Ops.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';
import { intEnv } from '../../kernel/env.js';
import { appendToLedger } from '../../kernel/ledger.js';
import { stripeApiRequest } from '../shop.js';
import { createTask, listTasks, handleTaskAction } from './tasks.js';
import { handleReferral } from './referral.js';
import { handleCredentialSubmit, handleCredentialVerify } from './credentials.js';
import { handleCalendar } from './calendar.js';
import { listRunners, profile, stats, balance, evidence, ledger, board, listings } from './queries.js';
import { TASK_PRICES, KYC_REQUIRED, ROLES } from './constants.generated.js';

export { TASK_PRICES, KYC_REQUIRED };

export function uid() {
  return Array.from(crypto.getRandomValues(new Uint8Array(6)))
    .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Haversine distance in miles
export function haversine(lat1, lng1, lat2, lng2) {
  const R = 3959; // Earth radius in miles
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// Interpolate position between origin and destination
export function interpolate(origin, destination, progress) {
  const t = Math.max(0, Math.min(1, progress));
  const curve = Math.sin(t * Math.PI) * 0.003; // slight curve for realism
  return {
    lat: origin.lat + (destination.lat - origin.lat) * t + curve,
    lng: origin.lng + (destination.lng - origin.lng) * t - curve,
  };
}

export async function handle(subpath, request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: 'KV not configured' }, 500);
  const method = request.method;
  const url = new URL(request.url);

  // POST /runner/auth
  // GOV: COIN/CANON.md — balance reads from VAULT, not KV counter.
  // Build step 09-econ publishes vault:email:{email} → principal and vault:wallet:{principal} → wallet.json to KV.
  if (subpath === 'auth' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const name = (body.name || '').trim();
    const email = (body.email || '').trim();
    const role = body.role || 'Requester';
    if (!name) return json({ error: 'name is required' }, 400);
    if (!ROLES.includes(role)) return json({ error: 'invalid role' }, 400);

    // Try VAULT principal resolution: email → principal, or github → principal
    const github = (body.github || '').trim().toLowerCase();
    const principalLookup = email
      ? await kv.get(`vault:email:${email.toLowerCase()}`)
      : (github ? await kv.get(`vault:github:${github}`) : null);

    if (principalLookup) {
      const principal = principalLookup;
      const lookupKey = email ? email.toLowerCase() : github;
      // Known VAULT principal — read governed balance
      const existing = email ? await kv.get(`runner:email:${lookupKey}`) : await kv.get(`runner:github:${lookupKey}`);
      let user;
      if (existing) {
        user = JSON.parse(existing);
      } else {
        const id = 'U' + uid();
        user = { id, name, email, github, role, principal, created_at: new Date().toISOString(), status: 'active' };
        await kv.put(`runner:user:${id}`, JSON.stringify(user));
        if (email) await kv.put(`runner:email:${email.toLowerCase()}`, JSON.stringify(user));
        if (github) await kv.put(`runner:github:${github}`, JSON.stringify(user));
        await kv.put(`runner:principal:${id}`, principal);
        const roleKey = `runner:role:${role.toLowerCase()}`;
        const roleList = JSON.parse(await kv.get(roleKey) || '[]');
        roleList.push(id);
        await kv.put(roleKey, JSON.stringify(roleList));
      }
      if (user.id && !user.principal) {
        user.principal = principal;
        await kv.put(`runner:user:${user.id}`, JSON.stringify(user));
        await kv.put(`runner:principal:${user.id}`, principal);
      }
      const walletRaw = await kv.get(`vault:wallet:${principal}`);
      let bal = 0;
      if (walletRaw) {
        try { bal = JSON.parse(walletRaw).balance || 0; } catch {}
      }
      return json({ success: true, user, balance: bal, principal, source: 'vault' });
    }

    if (email) {
      // Existing KV user (no VAULT principal yet)
      const existing = await kv.get(`runner:email:${email.toLowerCase()}`);
      if (existing) {
        const user = JSON.parse(existing);
        const bal = parseInt(await kv.get(`runner:balance:${user.id}`) || '0', 10);
        return json({ success: true, user, balance: bal, source: 'kv' });
      }
    }

    // Existing KV user by github (no VAULT principal yet)
    if (github) {
      const existing = await kv.get(`runner:github:${github}`);
      if (existing) {
        const user = JSON.parse(existing);
        const bal = parseInt(await kv.get(`runner:balance:${user.id}`) || '0', 10);
        return json({ success: true, user, balance: bal, source: 'kv' });
      }
    }

    // New anonymous user — KV-only until VAULT principal is bound
    const id = 'U' + uid();
    const startupCoin = intEnv(env, 'RUNNER_STARTUP_COIN', 50);
    const user = { id, name, email, role, created_at: new Date().toISOString(), status: 'active' };
    await kv.put(`runner:user:${id}`, JSON.stringify(user));
    if (email) await kv.put(`runner:email:${email.toLowerCase()}`, JSON.stringify(user));
    if (github) await kv.put(`runner:github:${github}`, JSON.stringify(user));
    await kv.put(`runner:balance:${id}`, String(startupCoin));
    const roleKey = `runner:role:${role.toLowerCase()}`;
    const roleList = JSON.parse(await kv.get(roleKey) || '[]');
    roleList.push(id);
    await kv.put(roleKey, JSON.stringify(roleList));
    return json({ success: true, user, balance: startupCoin, source: 'kv' });
  }

  // GET /runner/tasks
  if (subpath === 'tasks' && method === 'GET') return listTasks(url, kv);
  // POST /runner/tasks
  if (subpath === 'tasks' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    return createTask(body, env, kv);
  }

  // GET /runner/tasks/{id} — single task lookup
  const singleTaskMatch = subpath.match(/^tasks\/([A-Z0-9]+)$/);
  if (singleTaskMatch && method === 'GET') {
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const task = allTasks.find(t => t.id === singleTaskMatch[1]);
    if (!task) return json({ error: 'task not found' }, 404);
    return json({ task });
  }

  // Task actions: /runner/tasks/{id}/{action}
  const taskMatch = subpath.match(/^tasks\/([A-Z0-9]+)\/(\w+)$/);
  if (taskMatch) return handleTaskAction(taskMatch[1], taskMatch[2], request, env, kv);

  // GET /runner/list
  if (subpath === 'list' && method === 'GET') return listRunners(kv);
  // GET /runner/profile
  if (subpath === 'profile' && method === 'GET') return profile(url, kv);
  // GET /runner/stats
  if (subpath === 'stats' && method === 'GET') return stats(kv);
  // GET /runner/balance
  if (subpath === 'balance' && method === 'GET') return balance(url, kv);

  // POST /runner/checkout
  if (subpath === 'checkout' && method === 'POST') {
    if (!env.STRIPE_SECRET_KEY) return json({ error: 'Stripe not configured' }, 500);
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const amountCoin = parseInt(body.amount_coin, 10);
    if (!Number.isFinite(amountCoin) || amountCoin < 10 || amountCoin > 10000) return json({ error: 'amount_coin must be 10–10000' }, 400);
    const coinToCents = Math.max(1, intEnv(env, 'RUNNER_COIN_USD_CENTS', 100));
    const creditsCents = amountCoin * coinToCents;
    // Service fee covers Stripe processing (2.9% + $0.30) so net = credits value
    const serviceFeeCents = Math.ceil((creditsCents + 30) / (1 - 0.029)) - creditsCents;
    const fields = {
      mode: 'payment', success_url: (body.success_url || 'https://gorunner.pro/?checkout=success').trim(),
      cancel_url: (body.cancel_url || 'https://gorunner.pro/?checkout=cancel').trim(),
      'line_items[0][quantity]': '1', 'line_items[0][price_data][currency]': 'usd',
      'line_items[0][price_data][unit_amount]': String(creditsCents),
      'line_items[0][price_data][product_data][name]': `GoRunner — ∩${amountCoin} Credits`,
      'line_items[1][quantity]': '1', 'line_items[1][price_data][currency]': 'usd',
      'line_items[1][price_data][unit_amount]': String(serviceFeeCents),
      'line_items[1][price_data][product_data][name]': 'Service Fee',
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
  if (evidenceMatch && method === 'GET') return evidence(evidenceMatch[1], kv);

  // GET /runner/ledger
  if (subpath === 'ledger' && method === 'GET') return ledger(url, kv);

  // POST /runner/referral
  if (subpath === 'referral' && method === 'POST') return handleReferral(request, env, kv);

  // Credentials
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
  if (subpath === 'board' && method === 'GET') return board(url, kv);
  // Listings
  if (subpath === 'listings' && method === 'GET') return listings(url, kv);

  // ── Phase 8: Onboarding ─────────────────────────────────────────
  if (subpath === 'onboard/profile' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const name = (body.name || '').trim();
    if (!name) return json({ error: 'name is required' }, 400);
    const id = 'U' + uid();
    const user = {
      id, name, phone: (body.phone || '').trim(), vehicle: body.vehicle || '',
      service_area: (body.service_area || '').trim(), role: 'Runner',
      status: 'onboarding', created_at: new Date().toISOString()
    };
    await kv.put(`runner:user:${id}`, JSON.stringify(user));
    const roleList = JSON.parse(await kv.get('runner:role:runner') || '[]');
    roleList.push(id);
    await kv.put('runner:role:runner', JSON.stringify(roleList));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'ONBOARD_PROFILE', user_id: id, name });
    return json({ success: true, user_id: id });
  }

  if (subpath === 'onboard/verify' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: 'user not found' }, 404);
    const user = JSON.parse(raw);
    user.kyc_status = body.status || 'pending';
    user.kyc_type = body.verification_type || 'id_document';
    user.updated_at = new Date().toISOString();
    await kv.put(`runner:user:${userId}`, JSON.stringify(user));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'ONBOARD_VERIFY', user_id: userId, kyc_status: user.kyc_status });
    return json({ success: true, user_id: userId, kyc_status: user.kyc_status });
  }

  if (subpath === 'onboard/complete' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: 'user not found' }, 404);
    const user = JSON.parse(raw);
    user.status = 'active';
    user.agreements = body.agreements || {};
    user.onboarded_at = new Date().toISOString();
    user.updated_at = new Date().toISOString();
    await kv.put(`runner:user:${userId}`, JSON.stringify(user));
    // Bootstrap wallet with signup bonus
    const startupCoin = intEnv(env, 'RUNNER_STARTUP_COIN', 50);
    await kv.put(`runner:balance:${userId}`, String(startupCoin));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'ONBOARD_COMPLETE', user_id: userId, startup_coin: startupCoin });
    return json({ success: true, user_id: userId, balance: startupCoin });
  }

  // ── Runner Availability Toggle ─────────────────────────────────
  if (subpath === 'available' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const available = body.available !== false;
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: 'user not found' }, 404);
    const user = JSON.parse(raw);
    user.available = available;
    user.updated_at = new Date().toISOString();
    await kv.put(`runner:user:${userId}`, JSON.stringify(user));
    return json({ success: true, user_id: userId, available });
  }

  // ── Phase 9: Location Tracking ──────────────────────────────────
  if (subpath === 'location' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || '').trim();
    if (!userId) return json({ error: 'user_id required' }, 400);
    const lat = parseFloat(body.lat);
    const lng = parseFloat(body.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json({ error: 'valid lat/lng required' }, 400);
    await kv.put(`runner:location:${userId}`, JSON.stringify({ lat, lng, ts: new Date().toISOString() }), { expirationTtl: 300 });
    return json({ success: true });
  }

  if (subpath === 'location' && method === 'GET') {
    const taskId = url.searchParams.get('task_id') || '';
    if (!taskId) return json({ error: 'task_id required' }, 400);
    const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
    const task = allTasks.find(t => t.id === taskId);
    if (!task || !task.runner_id) return json({ error: 'task or runner not found' }, 404);
    const locRaw = await kv.get(`runner:location:${task.runner_id}`);
    if (!locRaw) return json({ lat: null, lng: null, message: 'No recent location' });
    const loc = JSON.parse(locRaw);
    // Haversine distance + ETA (avg 25mph city driving)
    let distance_mi = null, eta_min = null;
    if (loc.lat != null && task.location?.lat != null) {
      distance_mi = Math.round(haversine(loc.lat, loc.lng, task.location.lat, task.location.lng) * 10) / 10;
      eta_min = Math.max(1, Math.round((distance_mi / 25) * 60));
    } else if (loc.lat != null && task.location?.address) {
      // Fallback: no geocoded task location, report raw runner position
      distance_mi = null;
      eta_min = null;
    }
    return json({ ...loc, distance_mi, eta_min, task_id: taskId, runner_id: task.runner_id });
  }

  return json({ error: 'unknown runner route' }, 404);
}
