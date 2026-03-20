/**
 * RUNNER/QUERIES — Read-only queries (profile, stats, balance, board, listings, evidence, ledger).
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';

export async function listRunners(kv) {
  const ids = JSON.parse(await kv.get('runner:role:runner') || '[]');
  const runners = [];
  for (const id of ids) {
    const raw = await kv.get(`runner:user:${id}`);
    if (raw) {
      const user = JSON.parse(raw);
      const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
      const completed = allTasks.filter(t => t.runner_id === id && ['completed', 'rated'].includes(t.status));
      const ratings = completed.filter(t => t.rating).map(t => t.rating);
      const avgRating = ratings.length ? Math.round(ratings.reduce((a, b) => a + b, 0) / ratings.length * 10) / 10 : 0;
      runners.push({
        id: user.id,
        user_id: user.id,
        name: user.name || user.github || `Runner ${id.slice(0,8)}`,
        profile: { first_name: user.name || user.github || 'Runner', last_name: '' },
        completed_tasks: completed.length,
        rating_avg: avgRating,
        total_ratings: ratings.length,
        available: !allTasks.some(t => t.runner_id === id && ['assigned', 'accepted', 'in_progress'].includes(t.status)),
        onboarding_completed: true,
        onboarding_step: 5,
      });
    }
  }
  return json({ runners });
}

export async function profile(url, kv) {
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

export async function stats(kv) {
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const reqIds = JSON.parse(await kv.get('runner:role:requester') || '[]');
  const runIds = JSON.parse(await kv.get('runner:role:runner') || '[]');
  const active = allTasks.filter(t => ['posted', 'assigned', 'accepted', 'in_progress'].includes(t.status));
  const done = allTasks.filter(t => ['completed', 'rated'].includes(t.status));
  return json({
    total_tasks: allTasks.length, active_tasks: active.length, completed_tasks: done.length,
    total_coin: done.reduce((s, t) => s + (t.fee_coin || 0), 0),
    coin_minted: done.reduce((s, t) => s + (t.fee_coin || 0), 0),
    total_users: reqIds.length + runIds.length, total_runners: runIds.length, total_requesters: reqIds.length,
  });
}

export async function balance(url, kv) {
  const userId = url.searchParams.get('user_id') || '';
  if (!userId) return json({ error: 'user_id required' }, 400);

  // GOV: COIN/CANON.md — balance reads from VAULT wallet, not KV counter.
  // Resolve user → principal → wallet. Fall back to KV if no binding yet.
  const principal = await kv.get(`runner:principal:${userId}`);
  if (principal) {
    const walletRaw = await kv.get(`vault:wallet:${principal}`);
    if (walletRaw) {
      try {
        const wallet = JSON.parse(walletRaw);
        return json({ balance: wallet.balance || 0, user_id: userId, principal, source: 'vault' });
      } catch {}
    }
  }

  // Fallback: KV counter (ungoverned — will be removed when all users have VAULT bindings)
  return json({ balance: parseInt(await kv.get(`runner:balance:${userId}`) || '0', 10), user_id: userId, source: 'kv' });
}

export async function evidence(taskId, kv) {
  const keys = await kv.list({ prefix: `runner:evidence:${taskId}:` });
  if (!keys.keys.length) return json({ error: 'no evidence found' }, 404);
  const key = keys.keys[0];
  const { value, metadata } = await kv.getWithMetadata(key.name, { type: 'arrayBuffer' });
  if (!value) return json({ error: 'evidence data missing' }, 404);
  return new Response(value, {
    headers: {
      'Content-Type': (metadata && metadata.content_type) || 'application/octet-stream',
      'X-Evidence-Hash': (metadata && metadata.hash) || '', 'X-Task-Id': taskId,
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  });
}

export async function ledger(url, kv) {
  const raw = await kv.get('ledger:RUNNER:RUNNER');
  const entries = raw ? JSON.parse(raw) : [];
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const since = url.searchParams.get('since') || '';
  const filtered = since ? entries.filter(e => e.ts > since) : entries;
  return json({ entries: filtered.slice(-limit), total: entries.length });
}

export async function board(url, kv) {
  const address = (url.searchParams.get('address') || '').trim().toLowerCase();
  if (!address) return json({ error: 'address required' }, 400);
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const matched = allTasks.filter(t => t.location && t.location.address && t.location.address.toLowerCase().includes(address));
  const b = { posted: [], accepted: [], in_progress: [], completed: [], rated: [], cancelled: [] };
  for (const t of matched) { if (b[t.status]) b[t.status].push(t); }
  const totalCoin = matched.reduce((s, t) => s + (t.fee_coin || 0), 0);
  const completedCoin = matched.filter(t => ['completed', 'rated'].includes(t.status)).reduce((s, t) => s + (t.fee_coin || 0), 0);
  return json({ address: url.searchParams.get('address'), total_tasks: matched.length, total_coin: totalCoin, completed_coin: completedCoin, board: b });
}

export async function listings(url, kv) {
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
