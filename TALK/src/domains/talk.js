/**
 * TALK — Ledger + cross-user messaging.
 * GOV: TALK/CANON.md, LEDGER/CANON.md, NOTIFIER/CANON.md
 */

import { json } from '../kernel/http.js';
import { sha256, sanitize } from '../kernel/crypto.js';
import { checkRate } from '../kernel/rate.js';
import { appendToLedger } from '../kernel/ledger.js';
import { kvGet, kvPut } from '../kernel/kv.js';

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

  const result = await appendToLedger(env, 'TALK', scope, {
    trace_id: trace_id || null,
    user: user_message, assistant: assistant_message || null,
    provider: provider_used || null, elapsed_ms: elapsed_ms || null,
    model: body.model || null,
    input_tokens: body.input_tokens || null,
    output_tokens: body.output_tokens || null,
    cache_read_input_tokens: body.cache_read_input_tokens || null,
  }, { key: `ledger:${scope}` });

  // Notify targets inline at write time (GOV: NOTIFIER/CANON.md)
  const notify = Array.isArray(body.notify) ? body.notify : [];
  for (const target of notify) {
    if (!target || typeof target !== 'string') continue;
    const inboxKey = `inbox:${target}`;
    let inbox = await kvGet(env.TALK_KV, inboxKey, []);
    inbox.push({ id: result.id, ts: result.ts, from: scope, to: target, message: user_message, context: assistant_message || null, read: false });
    if (inbox.length > 500) inbox = inbox.slice(-500);
    await kvPut(env.TALK_KV, inboxKey, inbox);
  }

  return json({ ok: true, id: result.id, scope, entries: result.entries, ts: result.ts, notified: notify });
}

export async function ledgerRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const ledger = await kvGet(env.TALK_KV, `ledger:${scope}`, []);
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
  let inbox = await kvGet(env.TALK_KV, `inbox:${to}`, []);
  inbox.push(entry);
  if (inbox.length > 500) inbox = inbox.slice(-500);
  await kvPut(env.TALK_KV, `inbox:${to}`, inbox);

  // Sender outbox
  let outbox = await kvGet(env.TALK_KV, `outbox:${from}`, []);
  outbox.push(entry);
  if (outbox.length > 500) outbox = outbox.slice(-500);
  await kvPut(env.TALK_KV, `outbox:${from}`, outbox);

  await appendToLedger(env, 'TALK', `MSG:${from}:${to}`, { from, to, message_id: id, work_ref: id });
  return json({ ok: true, id, from, to, ts });
}

export async function inbox(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const inboxData = await kvGet(env.TALK_KV, `inbox:${scope}`, []);
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

  const inboxData = await kvGet(env.TALK_KV, `inbox:${scope}`, []);
  const idSet = new Set(message_ids);
  let acked = 0;
  for (const msg of inboxData) {
    if (idSet.has(msg.id) && !msg.read) { msg.read = true; acked++; }
  }

  await kvPut(env.TALK_KV, `inbox:${scope}`, inboxData);
  return json({ ok: true, scope, acked });
}
