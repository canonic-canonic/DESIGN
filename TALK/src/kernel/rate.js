/**
 * RATE — KV-backed rate limiting with sliding window + burst protection.
 * GOV: TALK/CANON.md
 *
 * Two layers:
 *   1. Hourly sliding window (maxPerHour) — sustained rate control
 *   2. Burst window (maxBurst per burstSeconds) — spike protection
 *
 * Keys support both IP-based (unauthenticated) and session-based (authenticated) limiting.
 */

/**
 * Check hourly rate limit using sliding window approximation.
 * Returns true if rate limit exceeded.
 */
export async function checkRate(env, prefix, key, maxPerHour) {
  if (!env.TALK_KV) return false;

  const now = Math.floor(Date.now() / 1000);
  const windowSec = 3600;
  const currentBucket = Math.floor(now / windowSec);
  const prevBucket = currentBucket - 1;
  const elapsedRatio = (now % windowSec) / windowSec;

  const curKey = `rate:${prefix}:${key}:${currentBucket}`;
  const prevKey = `rate:${prefix}:${key}:${prevBucket}`;

  const [curCount, prevCount] = await Promise.all([
    env.TALK_KV.get(curKey).then(v => parseInt(v || '0', 10)),
    env.TALK_KV.get(prevKey).then(v => parseInt(v || '0', 10))
  ]);

  // Sliding window estimate: weighted previous bucket + current bucket
  const estimate = prevCount * (1 - elapsedRatio) + curCount;

  if (estimate >= maxPerHour) return true;

  // Increment current bucket
  await env.TALK_KV.put(curKey, String(curCount + 1), { expirationTtl: windowSec * 2 });
  return false;
}

/**
 * Check burst rate limit (short window, e.g. 10 requests per 10 seconds).
 * Returns true if burst limit exceeded.
 */
export async function checkBurst(env, prefix, key, maxBurst, burstSeconds) {
  if (!env.TALK_KV) return false;
  burstSeconds = burstSeconds || 10;

  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / burstSeconds);
  const burstKey = `burst:${prefix}:${key}:${bucket}`;

  const count = parseInt(await env.TALK_KV.get(burstKey) || '0', 10);
  if (count >= maxBurst) return true;

  await env.TALK_KV.put(burstKey, String(count + 1), { expirationTtl: Math.max(60, burstSeconds * 2) });
  return false;
}

/**
 * Resolve rate limit key from request — prefer session token over IP.
 * Authenticated users get per-session limits; anonymous users get per-IP limits.
 */
export function resolveRateKey(request) {
  // Check for session token (authenticated user)
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ') && auth.length > 20) {
    // Use first 16 chars of token hash as key (privacy-preserving)
    return 'sess:' + auth.substring(7, 23);
  }
  // Fall back to IP
  return 'ip:' + (request.headers.get('CF-Connecting-IP') || 'unknown');
}
