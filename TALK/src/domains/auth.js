/**
 * AUTH — GitHub OAuth KYC + session management.
 * GOV: AUTH/CANON.md, LEDGER/CANON.md
 */

import { json } from '../kernel/http.js';
import { fetchWithRetry } from '../kernel/http.js';
import { appendToLedger } from '../kernel/ledger.js';
import { extractSessionToken } from '../kernel/util.js';
import { kvGet } from '../kernel/kv.js';

export function authConfig(env) {
  if (!env.GITHUB_CLIENT_ID) return json({ error: 'GITHUB_CLIENT_ID not configured' }, 500);
  return json({ github_client_id: env.GITHUB_CLIENT_ID, scopes: 'read:user' });
}

export async function authGitHub(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { code, redirect_uri } = body;
  if (!code) return json({ error: 'Missing code' }, 400);
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return json({ error: 'GitHub OAuth not configured' }, 500);

  const tokenRes = await fetchWithRetry('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri }),
  }, { maxRetries: 2, timeoutMs: 10000 });

  const tokenData = await tokenRes.json();
  if (tokenData.error) return json({ error: tokenData.error_description || tokenData.error }, 401);

  const userRes = await fetchWithRetry('https://api.github.com/user', {
    headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'User-Agent': 'CANONIC-KYC', 'Accept': 'application/json' },
  }, { maxRetries: 2, timeoutMs: 10000 });

  if (!userRes.ok) return json({ error: 'Failed to fetch GitHub user' }, 502);
  const user = await userRes.json();

  const sessionToken = crypto.randomUUID();
  const session = {
    user: user.login, github_uid: user.id, name: user.name, avatar_url: user.avatar_url,
    org: 'hadleylab', ts: new Date().toISOString(),
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  };

  if (env.TALK_KV) {
    await env.TALK_KV.put(`session:${sessionToken}`, JSON.stringify(session), { expirationTtl: 7 * 24 * 60 * 60 });
    await appendToLedger(env, 'AUTH', 'AUTH', { event: 'login', user: user.login, github_uid: user.id, provider: 'github', work_ref: `login:${user.login}` });
  }

  return json({
    session_token: sessionToken, user: user.login, name: user.name, avatar_url: user.avatar_url,
    provenance: { provider: 'github', uid: user.id, verified_at: session.ts, gate: 'MAGIC-KYC' },
  });
}

export async function authSession(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: 'Missing session token' }, 401);
  if (!env.TALK_KV) return json({ error: 'KV not configured' }, 500);

  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ error: 'Invalid or expired session' }, 401);

  const session = JSON.parse(raw);
  if (new Date(session.expires) < new Date()) {
    await env.TALK_KV.delete(`session:${token}`);
    return json({ error: 'Session expired' }, 401);
  }

  return json({
    user: session.user, github_uid: session.github_uid, name: session.name,
    avatar_url: session.avatar_url, org: session.org, ts: session.ts, expires: session.expires,
  });
}

export async function authLogout(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: 'Missing session token' }, 401);

  if (env.TALK_KV) {
    const raw = await env.TALK_KV.get(`session:${token}`);
    if (raw) {
      const session = JSON.parse(raw);
      await env.TALK_KV.delete(`session:${token}`);
      await appendToLedger(env, 'AUTH', 'AUTH', { event: 'logout', user: session.user, work_ref: `logout:${session.user}` });
    }
  }
  return json({ ok: true });
}

export async function authGrants(request, env) {
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope parameter' }, 400);

  const token = extractSessionToken(request);
  if (!token) return json({ granted: false, reason: 'no_session' });
  if (!env.TALK_KV) return json({ error: 'KV not configured' }, 500);

  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ granted: false, reason: 'invalid_session' });

  const session = JSON.parse(raw);
  if (new Date(session.expires) < new Date()) return json({ granted: false, reason: 'expired_session' });

  const canonRaw = await env.TALK_KV.get(`canon:${scope}`);
  if (!canonRaw) return json({ granted: true, user: session.user, reason: 'org_member_default' });

  const canon = JSON.parse(canonRaw);
  if (!canon.privacy || canon.privacy === 'PUBLIC') return json({ granted: true, user: session.user, reason: 'public_scope' });

  const readers = canon.readers || [];
  if (readers.length === 0) return json({ granted: true, user: session.user, reason: 'org_member' });
  if (readers.includes('*') || readers.includes(session.user)) return json({ granted: true, user: session.user, reason: 'reader' });

  if (env.TALK_KV) {
    await env.TALK_KV.put(
      `auth:deny:${session.user}:${scope}:${Date.now()}`,
      JSON.stringify({ user: session.user, scope, ts: new Date().toISOString() }),
      { expirationTtl: 30 * 24 * 60 * 60 },
    );
  }
  return json({ granted: false, user: session.user, reason: 'not_reader' });
}

export async function galaxyAuth(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: 'unauthorized' }, 401);
  const sessRaw = await env.TALK_KV.get(`session:${token}`);
  if (!sessRaw) return json({ error: 'unauthorized' }, 401);
  const sess = JSON.parse(sessRaw);
  if (new Date(sess.expires) < new Date()) return json({ error: 'session expired' }, 401);

  const raw = await env.TALK_KV.get('galaxy:auth');
  if (!raw) return json({ nodes: [], edges: [] });
  const data = JSON.parse(raw);

  const user = sess.user;
  const visible = data.nodes.filter(n => {
    const readers = n.readers || [];
    return readers.length === 0 || readers.includes('*') || readers.includes(user);
  });
  const visIds = new Set(visible.map(n => n.id));
  const visEdges = data.edges.filter(e => visIds.has(e.from) || visIds.has(e.to));

  return json({ nodes: visible, edges: visEdges });
}

// ── Scoped galaxy endpoint ──────────────────────────────
// Returns a principal-scoped galaxy from KV.
// Resolution order:
//   1. Explicit ?scope= parameter (direct KV lookup)
//   2. Principal's org from grants (org principal sees their federated org)
//   3. User-scoped galaxy (individual user sees their subtree)
//   4. Fallback to public galaxy.json
//
// Each org is a federated user of the canonic platform.
// Principals manage their org galaxy; users see their subtree within it.
export async function galaxyScope(request, env) {
  const { session, error } = await requireSession(request, env);
  if (error) return error;

  const url = new URL(request.url);
  const scopeParam = url.searchParams.get('scope');
  const user = session.user;

  // Load grants to determine org membership
  const grants = await kvGet(env.TALK_KV, `grants:${user}`, {});

  // 1. Explicit scope requested
  if (scopeParam) {
    const kvKey = scopeParam.includes('-canonic')
      ? `galaxy:scope:${scopeParam}`
      : `galaxy:user:${scopeParam.toUpperCase()}`;
    const raw = await env.TALK_KV.get(kvKey);
    if (!raw) return json({ error: 'scope not found', scope: scopeParam }, 404);
    const data = JSON.parse(raw);
    return json({ ...data, user, tier: 'explicit' });
  }

  // 2. Principal's org galaxy (org principal sees their federated org with all users)
  if (grants.org) {
    const orgKey = `galaxy:scope:${grants.org}`;
    const raw = await env.TALK_KV.get(orgKey);
    if (raw) {
      const data = JSON.parse(raw);
      return json({ ...data, user, tier: 'principal', org: grants.org });
    }
  }

  // 3. User-scoped galaxy (individual user subtree)
  const userKey = `galaxy:user:${user.toUpperCase()}`;
  const userRaw = await env.TALK_KV.get(userKey);
  if (userRaw) {
    const data = JSON.parse(userRaw);
    return json({ ...data, user, tier: 'user' });
  }

  // 4. Fallback: redirect to public static galaxy
  return json({ fallback: true, redirect: '/MAGIC/galaxy.json', user, tier: 'public' });
}

// Helper: validate session and return parsed session or error response
export async function requireSession(request, env) {
  const token = extractSessionToken(request);
  if (!token) return { error: json({ error: 'Missing session token' }, 401) };
  const sessRaw = await env.TALK_KV.get(`session:${token}`);
  if (!sessRaw) return { error: json({ error: 'Invalid or expired session' }, 401) };
  const sess = JSON.parse(sessRaw);
  if (new Date(sess.expires) < new Date()) return { error: json({ error: 'Session expired' }, 401) };
  return { session: sess };
}
