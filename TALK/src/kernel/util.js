/**
 * UTIL — Shared utility functions.
 */

export function clampInt(n, lo, hi) {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}

export function clampString(s, maxLen) {
  if (typeof s !== 'string') return '';
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + '…';
}

export function redactSecrets(s) {
  if (typeof s !== 'string' || !s) return '';
  return s
    .replace(/Bearer\\s+[A-Za-z0-9._\\-]+/g, 'Bearer [REDACTED]')
    .replace(/sk-[A-Za-z0-9_\\-]+/g, 'sk-[REDACTED]')
    .replace(/re_[A-Za-z0-9_\\-]+/g, 're_[REDACTED]');
}

export function coerceContentToText(content) {
  if (typeof content === 'string') return content;
  if (content && typeof content === 'object' && typeof content.text === 'string') return content.text;
  if (Array.isArray(content)) {
    const text = content
      .map(p => {
        if (!p) return '';
        if (typeof p === 'string') return p;
        if (typeof p.text === 'string') return p.text;
        if (p.type === 'text' && typeof p.text === 'string') return p.text;
        if (p.type === 'input_text' && typeof p.text === 'string') return p.text;
        return '';
      })
      .filter(Boolean)
      .join('');
    return text || '';
  }
  return '';
}

export function extractSessionToken(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const url = new URL(request.url);
  return url.searchParams.get('token') || null;
}
