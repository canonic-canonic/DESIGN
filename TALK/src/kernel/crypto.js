/**
 * CRYPTO — Content addressing + sanitization.
 * GOV: LEDGER/CANON.md — hash chain integrity.
 */

export async function sha256(message) {
  const data = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Sanitize input by removing all HTML tags and dangerous content.
 * Allowlist approach: strip everything that isn't plain text.
 * Handles malformed HTML, unclosed tags, and event handler injection.
 */
export function sanitize(str) {
  if (!str || typeof str !== 'string') return str;
  // Phase 1: decode HTML entities that could hide tags
  let s = str.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  s = s.replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
  // Phase 2: remove all tags including malformed/unclosed (greedy match to next > or end)
  s = s.replace(/<[^>]*>?/g, '');
  // Phase 3: remove event handlers that survived (on* attributes outside tags)
  s = s.replace(/\bon\w+\s*=/gi, '');
  // Phase 4: remove javascript: protocol URIs
  s = s.replace(/javascript\s*:/gi, '');
  return s.trim();
}
