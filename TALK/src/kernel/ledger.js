/**
 * LEDGER — Unified hash-chained append for all stream types.
 * GOV: LEDGER/CANON.md — every record gets id + prev + type + scope.
 * Types: GRADIENT | TALK | CONTRIBUTE | EMAIL | PROVISION | AUTH | SHOP
 */

import { sha256 } from './crypto.js';

export async function appendToLedger(env, type, scope, fields, { key: overrideKey } = {}) {
  if (!env.TALK_KV) return null;
  const key = overrideKey || `ledger:${type}:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const ts = new Date().toISOString();
  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${type}:${scope}:${prev}:${JSON.stringify(fields)}`);

  const entry = { id, prev, ts, type, scope, ...fields };
  ledger.push(entry);

  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    const overflow = ledger.slice(0, ledger.length - 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(overflow));
    ledger = ledger.slice(-1000);
  }

  await env.TALK_KV.put(key, JSON.stringify(ledger));
  return { id, ts, entries: ledger.length };
}
