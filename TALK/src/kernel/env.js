/**
 * ENV — strict environment variable readers.
 * GOV: TALK/CANON.md — all config from wrangler.toml [vars].
 */

export function requireEnv(env, key, context) {
  const v = env[key];
  if (v === undefined || v === null || v === '')
    throw new Error(key + ' not set in wrangler.toml [vars] (' + context + ')');
  return String(v).trim();
}

export function requireIntEnv(env, key, context) {
  const v = requireEnv(env, key, context);
  const n = parseInt(v, 10);
  if (isNaN(n)) throw new Error(key + ' is not a valid integer (' + context + ')');
  return n;
}

export function parseIntEnv(env, key) {
  const v = env[key];
  if (v === undefined || v === null || v === '') return null;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}

export function boolEnv(env, key, fallback = false) {
  const raw = String(env && env[key] !== undefined ? env[key] : '').trim().toLowerCase();
  if (!raw) return !!fallback;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

export function intEnv(env, key, fallback) {
  const n = parseIntEnv(env, key);
  return Number.isFinite(n) ? n : fallback;
}
