/**
 * HTTP — JSON response helpers + fetch utilities.
 * GOV: TALK/CANON.md
 */

import { CORS_DEFAULTS, _reqOrigin, addCors } from './cors.js';

export function json(data, status = 200) {
  const headers = { 'Content-Type': 'application/json', ...CORS_DEFAULTS };
  if (_reqOrigin) headers['Access-Control-Allow-Origin'] = _reqOrigin;
  return new Response(JSON.stringify(data), { status, headers });
}

export function oaiError(status, message, type = 'invalid_request_error', code = null) {
  return json({ error: { message, type, param: null, code } }, status);
}

export async function fetchWithTimeout(url, init, ms) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
  }
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function fetchWithRetry(url, opts = {}, { maxRetries = 3, baseMs = 500, timeoutMs = 10000 } = {}) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...opts, signal: controller.signal });
      clearTimeout(timer);
      if (res.ok || res.status < 500 || attempt === maxRetries) return res;
    } catch (e) {
      clearTimeout(timer);
      if (attempt === maxRetries) throw e;
    }
    const delay = baseMs * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5);
    await new Promise(r => setTimeout(r, delay));
  }
}

export { addCors };
