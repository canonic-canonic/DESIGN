/**
 * STAR — Personal Portal Handlers.
 * GOV: STAR/CANON.md
 */

import { json } from '../kernel/http.js';

export async function status(request, env) {
  return json({ status: 'ok', service: 'STAR', star_kv: !!env.STAR_KV, talk_kv: !!env.TALK_KV, ts: new Date().toISOString() });
}

export async function gov(request, env) {
  let scopes = [];
  try {
    const raw = await (env.STAR_KV || env.TALK_KV).get('star:gov');
    if (raw) scopes = JSON.parse(raw);
  } catch (e) { console.error('[STAR] gov read:', e.message || e); }
  return json({ total: scopes.length, scopes });
}

export async function timeline(request, env, session) {
  const url = new URL(request.url);
  const principal = session.user?.toUpperCase() || '';
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), parseInt(env.STAR_TIMELINE_LIMIT, 10));
  const streamFilter = url.searchParams.get('stream')?.toUpperCase() || null;
  const primitiveFilter = url.searchParams.get('primitive')?.toUpperCase() || null;
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);

  let tl = [];
  try {
    const cached = await (env.STAR_KV || env.TALK_KV).get(`star:timeline:${principal}`);
    if (cached) { const data = JSON.parse(cached); tl = data.entries || data || []; }
  } catch (e) { console.error('[STAR] timeline read:', e.message || e); }

  if (streamFilter) tl = tl.filter(e => e.stream === streamFilter);
  if (primitiveFilter) tl = tl.filter(e => e.primitive === primitiveFilter);
  return json({ principal, total: tl.length, offset, limit, entries: tl.slice(offset, offset + limit) });
}

async function readStarKV(env, key) {
  try {
    const raw = await (env.STAR_KV || env.TALK_KV).get(key);
    if (raw) return JSON.parse(raw);
  } catch (e) { console.error('[STAR] read:', e.message || e); }
  return null;
}

export async function services(request, env, session) {
  const principal = session.user?.toUpperCase() || '';
  const data = await readStarKV(env, 'star:services:' + principal) || [];
  return json({ principal, total: data.length, services: data });
}

export async function intel(request, env, session) {
  const principal = session.user?.toUpperCase() || '';
  const data = await readStarKV(env, 'star:intel:' + principal) || [];
  return json({ principal, total: data.length, patterns: data });
}

export async function econ(request, env, session) {
  const principal = session.user?.toUpperCase() || '';
  const data = await readStarKV(env, 'star:econ:' + principal) || {};
  return json({ principal, ...data });
}

export async function identity(request, env, session) {
  const principal = session.user?.toUpperCase() || '';
  const data = await readStarKV(env, 'star:identity:' + principal) || {};
  return json({ principal, ...data });
}

export async function media(request, env, session) {
  const principal = session.user?.toUpperCase() || '';
  const data = await readStarKV(env, 'star:media:' + principal) || [];
  return json({ principal, total: data.length, media: data });
}
