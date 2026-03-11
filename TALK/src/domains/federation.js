/**
 * FEDERATION — Cross-ORG witness protocol.
 * GOV: LEDGER/WITNESS.md, LEDGER/FEDERATION.md
 * KV keys: digest:{org}, witness:{org}:{witness_org}
 */

import { json } from '../kernel/http.js';
import { kvGet, kvPut } from '../kernel/kv.js';
import { requireSession } from './auth.js';

export async function digestWrite(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;

  const body = await request.json();
  if (!body.org || !body.head || !body.signer || !body.signature) return json({ error: 'Missing required fields: org, head, signer, signature' }, 400);
  if (typeof body.event_count !== 'number' || typeof body.coin_total !== 'number') return json({ error: 'event_count and coin_total must be numbers' }, 400);

  const digest = {
    type: 'DIGEST', org: body.org, head: body.head, event_count: body.event_count,
    coin_total: body.coin_total, balances: body.balances || {},
    ts: body.ts || new Date().toISOString(), signer: body.signer, signature: body.signature,
  };
  await kvPut(env.TALK_KV, `digest:${body.org}`, digest);
  return json({ ok: true, org: body.org, type: 'DIGEST' });
}

export async function digestRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get('org');
  if (!org) return json({ error: 'Missing org param' }, 400);
  const digest = await kvGet(env.TALK_KV, `digest:${org}`);
  if (!digest) return json({ error: 'No digest found', org }, 404);
  return json(digest);
}

export async function witnessWrite(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;

  const body = await request.json();
  if (!body.org || !body.witness_org || !body.witness_user || !body.digest_hash || !body.signature)
    return json({ error: 'Missing required fields: org, witness_org, witness_user, digest_hash, signature' }, 400);

  const digest = await kvGet(env.TALK_KV, `digest:${body.org}`);
  if (!digest) return json({ error: 'No digest found for org — publish digest first' }, 404);

  const witness = {
    type: 'WITNESS', digest_hash: body.digest_hash, org: body.org,
    witness_org: body.witness_org, witness_user: body.witness_user,
    ts: body.ts || new Date().toISOString(), signature: body.signature,
  };
  await kvPut(env.TALK_KV, `witness:${body.org}:${body.witness_org}`, witness);
  return json({ ok: true, org: body.org, witness_org: body.witness_org, type: 'WITNESS' });
}

export async function witnessRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get('org');
  if (!org) return json({ error: 'Missing org param' }, 400);

  const list = await env.TALK_KV.list({ prefix: `witness:${org}:` });
  const witnesses = [];
  for (const key of list.keys) {
    const w = await kvGet(env.TALK_KV, key.name);
    if (w) witnesses.push(w);
  }
  return json({ org, witnesses, count: witnesses.length });
}

export async function verify(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get('org');
  if (!org) return json({ error: 'Missing org param' }, 400);

  const digest = await kvGet(env.TALK_KV, `digest:${org}`);
  if (!digest) return json({ error: 'No digest found', org }, 404);

  const list = await env.TALK_KV.list({ prefix: `witness:${org}:` });
  const witnesses = [];
  for (const key of list.keys) {
    const w = await kvGet(env.TALK_KV, key.name);
    if (w) witnesses.push(w);
  }

  const matching = witnesses.filter(w => w.digest_hash && w.org === org);
  return json({
    org,
    digest: {
      head: digest.head, event_count: digest.event_count, coin_total: digest.coin_total,
      signer: digest.signer, ts: digest.ts, signed: !!digest.signature,
    },
    witnesses: matching.map(w => ({ witness_org: w.witness_org, witness_user: w.witness_user, ts: w.ts, signed: !!w.signature })),
    witness_count: matching.length,
  });
}
