/**
 * PROVIDERS — LLM provider configs, preflight, health checks.
 * GOV: TALK/CANON.md § Preflight
 */

import { fetchWithTimeout } from '../kernel/http.js';
import { requireEnv, requireIntEnv, parseIntEnv, intEnv, boolEnv } from '../kernel/env.js';
import { clampString, clampInt, redactSecrets } from '../kernel/util.js';

function maxTokens(env) {
  const lo = requireIntEnv(env, 'TOKENS_MIN', 'tokens');
  const hi = requireIntEnv(env, 'TOKENS_MAX', 'tokens');
  const req = parseIntEnv(env, 'MAX_TOKENS') ?? hi;
  return clampInt(req, lo, hi);
}

export function maxTokensFor(providerName, env) {
  const prefix = String(providerName || '').toUpperCase();
  const lo = parseIntEnv(env, `${prefix}_TOKENS_MIN`) ?? requireIntEnv(env, 'TOKENS_MIN', 'tokens');
  const hi = parseIntEnv(env, `${prefix}_TOKENS_MAX`) ?? requireIntEnv(env, 'TOKENS_MAX', 'tokens');
  const req = parseIntEnv(env, 'MAX_TOKENS') ?? hi;
  return clampInt(req, lo, hi);
}

export function timeoutMsFor(providerName, env) {
  return requireIntEnv(env, 'PROVIDER_TIMEOUT_MS', 'timeout');
}

// ── Rate limit parsers ──

function parseAnthropicRateLimits(headers) {
  const rl = {};
  const rr = headers.get('anthropic-ratelimit-requests-remaining');
  const rlim = headers.get('anthropic-ratelimit-requests-limit');
  const tr = headers.get('anthropic-ratelimit-tokens-remaining');
  const tlim = headers.get('anthropic-ratelimit-tokens-limit');
  if (rr !== null) rl.requests_remaining = parseInt(rr, 10);
  if (rlim !== null) rl.requests_limit = parseInt(rlim, 10);
  if (tr !== null) rl.tokens_remaining = parseInt(tr, 10);
  if (tlim !== null) rl.tokens_limit = parseInt(tlim, 10);
  const rReset = headers.get('anthropic-ratelimit-requests-reset');
  const tReset = headers.get('anthropic-ratelimit-tokens-reset');
  if (rReset) rl.requests_reset = rReset;
  if (tReset) rl.tokens_reset = tReset;
  return rl;
}

function preflightDegraded(rl) {
  if (rl.requests_remaining !== undefined && rl.requests_limit > 0) {
    if (rl.requests_remaining / rl.requests_limit < 0.05) return 'requests_low';
  }
  if (rl.tokens_remaining !== undefined && rl.tokens_limit > 0) {
    if (rl.tokens_remaining / rl.tokens_limit < 0.05) return 'tokens_low';
  }
  return null;
}

// ── Provider definitions ──

export const PROVIDERS = {
  anthropic: {
    url: 'https://api.anthropic.com/v1/messages',
    validate(env) { return env.ANTHROPIC_API_KEY ? null : 'ANTHROPIC_API_KEY not configured'; },
    build(env, system, messages) {
      return {
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION },
        body: { model: env.MODEL, max_tokens: maxTokens(env), system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }], messages },
      };
    },
    parse(data) { return data.content?.[0]?.text; },
    async preflight(env) {
      const started = Date.now();
      const model = requireEnv(env, 'MODEL', 'chat');
      if (!env.ANTHROPIC_API_KEY) return { status: 'error', key_valid: false, model, error: 'ANTHROPIC_API_KEY not configured', elapsed_ms: 0 };
      const timeout = intEnv(env, 'PREFLIGHT_TIMEOUT_MS', 5000);
      try {
        const res = await fetchWithTimeout('https://api.anthropic.com/v1/messages', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION || '2023-06-01' },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] }),
        }, timeout);
        const rl = parseAnthropicRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text();
          const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try { const j = JSON.parse(text); if (j.error && j.error.message) detail = j.error.message; } catch (e) { console.error('[TALK]', e.message || e); }
          const isCredit = res.status === 400 && detail.toLowerCase().includes('credit');
          return { status: (isAuth || isCredit) ? 'error' : 'degraded', key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? 'degraded' : 'ok', key_valid: true, model, ...rl, error: deg || undefined, elapsed_ms: Date.now() - started };
      } catch (e) { return { status: 'error', key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started }; }
    },
  },
};

// ── Preflight orchestrator ──

export async function preflightAllProviders(env) {
  const chain = env.PROVIDER_CHAIN ? String(env.PROVIDER_CHAIN).split(',').map(s => s.trim()).filter(Boolean) : [env.PROVIDER];
  const seen = new Set();
  const toCheck = [];
  const primaryName = env.PROVIDER;
  if (primaryName && PROVIDERS[primaryName] && PROVIDERS[primaryName].preflight) { seen.add(primaryName); toCheck.push({ name: primaryName, provider: PROVIDERS[primaryName] }); }
  for (const name of chain) {
    if (seen.has(name)) continue; seen.add(name);
    const p = PROVIDERS[name]; if (!p || !p.preflight) continue;
    if (!boolEnv(env, `${name.toUpperCase()}_PREFLIGHT_HEALTH`, false)) continue;
    toCheck.push({ name, provider: p });
  }
  const results = {};
  const settled = await Promise.allSettled(toCheck.map(async ({ name, provider }) => ({ name, result: await provider.preflight(env) })));
  for (const s of settled) {
    if (s.status === 'fulfilled') results[s.value.name] = s.value.result;
    else results['unknown'] = { status: 'error', key_valid: false, model: null, error: String(s.reason), elapsed_ms: 0 };
  }
  const statuses = Object.values(results).map(r => r.status);
  const overall = statuses.every(s => s === 'ok') ? 'ok' : statuses.some(s => s === 'ok') ? 'degraded' : 'error';
  return { service: 'TALK_PREFLIGHT', status: overall, providers: results };
}
