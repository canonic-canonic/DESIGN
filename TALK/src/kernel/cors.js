/**
 * CORS — origin validation + header injection.
 * GOV: TALK/CANON.md
 */

export const CORS_DEFAULTS = {
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Per-request origin — set at top of fetch handler, read by json() and addCors()
export let _reqOrigin = '*';
export function setReqOrigin(v) { _reqOrigin = v; }

export function corsOrigin(request, env) {
  const raw = env && env.CORS_ALLOWED_ORIGINS ? String(env.CORS_ALLOWED_ORIGINS) : '*';
  const allowed = raw.split(',').map(s => s.trim());
  if (allowed.includes('*')) return '*';
  const origin = request.headers.get('Origin') || '';
  for (const a of allowed) {
    if (a === origin) return origin;
    if (a.startsWith('https://*.') && origin.startsWith('https://') && origin.endsWith(a.slice(9))) return origin;
  }
  return null;
}

// Security headers — HARDENING 6a (NETWORK_HEADERS)
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export function addCors(headers, origin) {
  const h = new Headers(headers || {});
  const o = origin !== undefined ? origin : _reqOrigin;
  if (o) h.set('Access-Control-Allow-Origin', o);
  for (const [k, v] of Object.entries(CORS_DEFAULTS)) h.set(k, v);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) h.set(k, v);
  return h;
}
