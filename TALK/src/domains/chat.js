/**
 * CHAT — Governed conversation endpoint with provider fallback chain.
 * GOV: TALK/CANON.md
 */

import { json, fetchWithTimeout } from '../kernel/http.js';
import { requireEnv, requireIntEnv, parseIntEnv } from '../kernel/env.js';
import { clampString, redactSecrets } from '../kernel/util.js';
import { PROVIDERS, timeoutMsFor } from './providers.js';

export async function chat(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { message, history = [], system, scope } = body;
  if (!message) return json({ error: 'Missing message' }, 400);

  const messages = [];
  for (const msg of history.slice(-10)) {
    if (msg.role && msg.content) messages.push({ role: msg.role, content: msg.content });
  }
  if (!messages.length || messages[messages.length - 1].content !== message) {
    messages.push({ role: 'user', content: message });
  }

  const systemPrompt = system || `TALK. Scope: ${scope || 'UNGOVERNED'}.`;
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());

  const primary = env.PROVIDER;
  const fallback = requireEnv(env, 'FALLBACK_PROVIDER', 'chat');
  const chain = env.PROVIDER_CHAIN
    ? String(env.PROVIDER_CHAIN).split(',').map(s => s.trim()).filter(Boolean)
    : (primary === 'runpod' ? [primary, fallback] : [primary]);

  const attempts = [];
  const startedAt = Date.now();

  for (let i = 0; i < chain.length; i++) {
    const name = chain[i];
    const provider = PROVIDERS[name];
    if (!provider) { attempts.push({ provider: name, ok: false, error: `Unknown provider: ${name}` }); continue; }
    const providerError = provider.validate?.(env);
    if (providerError) { attempts.push({ provider: name, ok: false, error: providerError }); continue; }

    const { headers, body: reqBody } = provider.build(env, systemPrompt, messages);
    const providerUrl = typeof provider.url === 'function' ? provider.url(env) : provider.url;
    const ms = timeoutMsFor(name, env);

    const attemptStart = Date.now();
    const gov_pre = {
      provider: name, url: providerUrl, timeout_ms: ms,
      model: reqBody?.model || null, max_tokens: reqBody?.max_tokens || null,
      messages: Array.isArray(reqBody?.messages) ? reqBody.messages.length : null,
      tokens_min: requireIntEnv(env, 'TOKENS_MIN', 'tokens'),
      tokens_max: requireIntEnv(env, 'TOKENS_MAX', 'tokens'),
      provider_tokens_max: parseIntEnv(env, `${String(name || '').toUpperCase()}_TOKENS_MAX`),
    };

    let res;
    try {
      const maxTries = (name === 'runpod') ? (parseIntEnv(env, 'RUNPOD_TRIES') ?? 2) : (name === 'vastai') ? (parseIntEnv(env, 'VASTAI_TRIES') ?? 1) : 1;
      const retryDelayMs = (name === 'runpod') ? (parseIntEnv(env, 'RUNPOD_RETRY_DELAY_MS') ?? 750) : (name === 'vastai') ? (parseIntEnv(env, 'VASTAI_RETRY_DELAY_MS') ?? 0) : 0;
      let lastErr = null;
      for (let t = 0; t < maxTries; t++) {
        try {
          res = await fetchWithTimeout(providerUrl, { method: 'POST', headers, body: JSON.stringify(reqBody) }, ms);
          lastErr = null; break;
        } catch (e) { lastErr = e; if (t + 1 < maxTries && retryDelayMs > 0) await new Promise(r => setTimeout(r, retryDelayMs)); }
      }
      if (lastErr) throw lastErr;
    } catch (e) {
      attempts.push({ provider: name, ok: false, elapsed_ms: Date.now() - attemptStart, error: clampString(redactSecrets(String(e?.message || e)), 220), gov_pre });
      continue;
    }

    if (!res || !res.ok) {
      const status = res ? res.status : 0;
      const errBody = res ? await res.text() : '';
      const safeErr = redactSecrets(errBody);
      attempts.push({ provider: name, ok: false, elapsed_ms: Date.now() - attemptStart, status, detail: clampString(safeErr, 600), gov_pre, gov_post: { ok: false, status, elapsed_ms: Date.now() - attemptStart } });
      if (status >= 500 || status === 429 || status === 0) continue;
      return json({ error: `${name} ${status}`, detail: clampString(safeErr, 600), scope, trace_id }, 502);
    }

    const data = await res.json();
    const parsed = provider.parse(data) || '';
    attempts.push({
      provider: name, ok: true, elapsed_ms: Date.now() - attemptStart, gov_pre,
      gov_post: { ok: true, status: res.status, elapsed_ms: Date.now() - attemptStart, usage: data?.usage || null, parsed_chars: typeof parsed === 'string' ? parsed.length : 0, schema_ok: typeof parsed === 'string' && parsed.length > 0 },
    });
    console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: name, status: 200, latency_ms: Date.now() - startedAt, scope, trace_id }));
    return json({
      message: parsed || 'No response.', scope, provider_requested: primary, provider_used: name,
      provider_chain: chain, attempts, usage: data?.usage || null, elapsed_ms: Date.now() - startedAt, trace_id,
    });
  }

  console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: 'NONE', status: 502, latency_ms: Date.now() - startedAt, scope, trace_id, chain }));
  return json({ error: 'All providers failed', scope, provider_chain: chain, attempts, elapsed_ms: Date.now() - startedAt, trace_id }, 502);
}
