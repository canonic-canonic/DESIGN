/**
 * MINT:READ — Attention economy pipeline (pageview → COIN for author).
 * GOV: COIN/CANON.md, MINT/CANON.md
 *
 * Flow: browser beacon → POST /mint/read → KV dedup (24h) → ledger append
 * Session hash = SHA-256(session_id + page_path) — deduplicates per reader per page per day.
 */

import { json } from '../kernel/http.js';
import { sha256 } from '../kernel/crypto.js';
import { appendToLedger } from '../kernel/ledger.js';

const DEDUP_TTL = 86400; // 24 hours in seconds

export async function mintRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, page, session_id } = body;
  if (!scope || !page) return json({ error: 'Missing scope or page' }, 400);

  // Resolve author from scope metadata (stored in KV by build pipeline)
  const author = body.author || await resolveAuthor(env, scope);
  if (!author) return json({ error: 'Cannot resolve author for scope' }, 400);

  // Session dedup: SHA-256(session_id + page) with 24h TTL in KV
  const sessionKey = session_id || request.headers.get('CF-Connecting-IP') || 'anon';
  const sessionHash = await sha256(sessionKey + ':' + page);
  const dedupKey = `mint:read:${sessionHash}`;

  const existing = await env.TALK_KV.get(dedupKey);
  if (existing) {
    return json({ status: 'dedup', detail: 'Already minted in this window' });
  }

  // Mark as minted (24h TTL)
  await env.TALK_KV.put(dedupKey, new Date().toISOString(), { expirationTtl: DEDUP_TTL });

  // Append to ledger
  const result = await appendToLedger(env, 'MINT:READ', scope, {
    author: author.toUpperCase(),
    page,
    amount: 1,
    session_hash: sessionHash,
    work_ref: `read:${scope}:${sessionHash}`
  }, { key: `ledger:mint-read:${scope}` });

  return json({
    status: 'minted',
    author: author.toUpperCase(),
    page,
    amount: 1,
    id: result ? result.id : null
  });
}

/**
 * Resolve author for a scope from KV-cached CANON.json metadata.
 * Falls back to scope name as author if no metadata found.
 */
async function resolveAuthor(env, scope) {
  try {
    const meta = await env.TALK_KV.get(`canon:${scope}`);
    if (meta) {
      const parsed = JSON.parse(meta);
      if (parsed.author) return parsed.author;
    }
  } catch {}
  return null;
}
