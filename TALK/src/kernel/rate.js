/**
 * RATE — KV-backed per-key rate limiting.
 * GOV: TALK/CANON.md
 */

export async function checkRate(env, prefix, key, maxPerHour) {
  if (!env.TALK_KV) return false;
  const rateKey = `rate:${prefix}:${key}`;
  const count = parseInt(await env.TALK_KV.get(rateKey) || '0', 10);
  if (count >= maxPerHour) return true;
  await env.TALK_KV.put(rateKey, String(count + 1), { expirationTtl: 3600 });
  return false;
}
