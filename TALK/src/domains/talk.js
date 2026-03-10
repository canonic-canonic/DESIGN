/**
 * TALK — Ledger + cross-user messaging.
 * GOV: TALK/CANON.md, LEDGER/CANON.md
 */

import { json } from '../kernel/http.js';
import { sha256, sanitize } from '../kernel/crypto.js';
import { checkRate } from '../kernel/rate.js';
import { appendToLedger } from '../kernel/ledger.js';

export async function ledgerWrite(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { scope, trace_id, provider_used, elapsed_ms } = body;
  const user_message = sanitize(body.user_message);
  const assistant_message = sanitize(body.assistant_message);
  if (!scope || !user_message) return json({ error: 'Missing scope or user_message' }, 400);

  if (await checkRate(env, 'ledger', scope, 100)) return json({ error: 'Rate limited', scope }, 429);

  const ts = new Date().toISOString();
  const key = `ledger:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${scope}:${user_message}:${prev}`);

  const entry = {
    id, prev, ts, type: 'TALK', scope, trace_id: trace_id || null,
    user: user_message, assistant: assistant_message || null,
    provider: provider_used || null, elapsed_ms: elapsed_ms || null,
  };

  ledger.push(entry);
  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(ledger.slice(0, ledger.length - 1000)));
    ledger = ledger.slice(-1000);
  }
  await env.TALK_KV.put(key, JSON.stringify(ledger));

  // Notify targets inline at write time (GOV: CANON.json via talk.js)
  const notify = Array.isArray(body.notify) ? body.notify : [];
  for (const target of notify) {
    if (!target || typeof target !== 'string') continue;
    const inboxKey = `inbox:${target}`;
    let inbox = [];
    try {
      const raw = await env.TALK_KV.get(inboxKey);
      if (raw) inbox = JSON.parse(raw);
    } catch (e) { console.error('[TALK_KV]', e.message || e); }
    inbox.push({ id, ts, from: scope, to: target, message: user_message, context: assistant_message || null, read: false });
    if (inbox.length > 500) inbox = inbox.slice(-500);
    await env.TALK_KV.put(inboxKey, JSON.stringify(inbox));
  }

  return json({ ok: true, id, scope, entries: ledger.length, ts, notified: notify });
}

export async function ledgerRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const key = `ledger:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const slice = ledger.slice(-(offset + limit), offset ? -offset : undefined);
  return json({ scope, total: ledger.length, entries: slice });
}

export async function send(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { from, to, message, context } = body;
  if (!from || !to || !message) return json({ error: 'Missing from, to, or message' }, 400);

  const ts = new Date().toISOString();
  const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const entry = { id, ts, from, to, message, context: context || null, read: false };

  // Recipient inbox
  const key = `inbox:${to}`;
  let inbox = [];
  try { const raw = await env.TALK_KV.get(key); if (raw) inbox = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }
  inbox.push(entry);
  if (inbox.length > 500) inbox = inbox.slice(-500);
  await env.TALK_KV.put(key, JSON.stringify(inbox));

  // Sender outbox
  const outKey = `outbox:${from}`;
  let outbox = [];
  try { const raw = await env.TALK_KV.get(outKey); if (raw) outbox = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }
  outbox.push(entry);
  if (outbox.length > 500) outbox = outbox.slice(-500);
  await env.TALK_KV.put(outKey, JSON.stringify(outbox));

  await appendToLedger(env, 'TALK', `MSG:${from}:${to}`, { from, to, message_id: id, work_ref: id });
  return json({ ok: true, id, from, to, ts });
}

export async function inbox(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  let inboxData = [];
  try { const raw = await env.TALK_KV.get(`inbox:${scope}`); if (raw) inboxData = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const unreadOnly = url.searchParams.get('unread') === 'true';
  const messages = unreadOnly ? inboxData.filter(m => !m.read) : inboxData;
  return json({ scope, total: inboxData.length, unread: inboxData.filter(m => !m.read).length, messages });
}

export async function ack(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { scope, message_ids } = body;
  if (!scope || !Array.isArray(message_ids)) return json({ error: 'Missing scope or message_ids' }, 400);

  let inboxData = [];
  try { const raw = await env.TALK_KV.get(`inbox:${scope}`); if (raw) inboxData = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const idSet = new Set(message_ids);
  let acked = 0;
  for (const msg of inboxData) {
    if (idSet.has(msg.id) && !msg.read) { msg.read = true; acked++; }
  }

  await env.TALK_KV.put(`inbox:${scope}`, JSON.stringify(inboxData));
  return json({ ok: true, scope, acked });
}
