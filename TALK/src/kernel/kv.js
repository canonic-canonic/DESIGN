/**
 * KV — Typed get/put helpers with error handling.
 * GOV: TALK/CANON.md — all KV access through governed helpers.
 */

export async function kvGet(kv, key, fallback = null) {
  if (!kv) return fallback;
  try {
    const raw = await kv.get(key);
    if (raw) return JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }
  return fallback;
}

export async function kvPut(kv, key, value, opts) {
  if (!kv) return;
  await kv.put(key, JSON.stringify(value), opts);
}
