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
  if (providerName === 'runpod') return requireIntEnv(env, 'RUNPOD_TIMEOUT_MS', 'runpod');
  if (providerName === 'vastai') return parseIntEnv(env, 'VASTAI_TIMEOUT_MS') ?? requireIntEnv(env, 'PROVIDER_TIMEOUT_MS', 'timeout');
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

function parseOpenAIRateLimits(headers) {
  const rl = {};
  const rr = headers.get('x-ratelimit-remaining-requests');
  const rlim = headers.get('x-ratelimit-limit-requests');
  const tr = headers.get('x-ratelimit-remaining-tokens');
  const tlim = headers.get('x-ratelimit-limit-tokens');
  if (rr !== null) rl.requests_remaining = parseInt(rr, 10);
  if (rlim !== null) rl.requests_limit = parseInt(rlim, 10);
  if (tr !== null) rl.tokens_remaining = parseInt(tr, 10);
  if (tlim !== null) rl.tokens_limit = parseInt(tlim, 10);
  const rReset = headers.get('x-ratelimit-reset-requests');
  const tReset = headers.get('x-ratelimit-reset-tokens');
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

// ── RunPod helpers ──

export function runpodEndpointIdFromBaseUrl(baseUrl) {
  if (!baseUrl) return null;
  const m = String(baseUrl).match(/\/v2\/([^/]+)\/openai\/v1\/?$/);
  return m ? m[1] : null;
}

export function isRunpodProxyBaseUrl(baseUrl) {
  if (!baseUrl) return false;
  return /\.proxy\.runpod\.net\/v1$/.test(String(baseUrl).replace(/\/+$/, ''));
}

export async function runpodProxyReady(baseUrl, env) {
  const b = String(baseUrl || '').replace(/\/+$/, '');
  if (!b) return null;
  try {
    const r = await fetchWithTimeout(b + '/models', { headers: { 'Accept': 'application/json' } }, requireIntEnv(env, 'RUNPOD_HEALTH_TIMEOUT_MS', 'health'));
    return { ok: r.ok, status: r.status };
  } catch (e) { console.error('[TALK]', e.message || e); return null; }
}

export async function runpodHealth(endpointId, env) {
  const id = String(endpointId || '').trim();
  if (!id) return null;
  try {
    const r = await fetchWithTimeout(`https://api.runpod.ai/v2/${id}/health`, {
      headers: { 'Accept': 'application/json', 'Authorization': String(env.RUNPOD_API_KEY || '') },
    }, requireIntEnv(env, 'RUNPOD_HEALTH_TIMEOUT_MS', 'health'));
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { console.error('[TALK]', e.message || e); return null; }
}

// ── Provider definitions ──

export const PROVIDERS = {
  anthropic: {
    url: 'https://api.anthropic.com/v1/messages',
    validate(env) { return env.ANTHROPIC_API_KEY ? null : 'ANTHROPIC_API_KEY not configured'; },
    build(env, system, messages) {
      return {
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION },
        body: { model: env.MODEL, max_tokens: maxTokens(env), system, messages },
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
  openai: {
    url(env) {
      const raw = (env.OPENAI_BASE_URL || 'https://api.openai.com/v1').trim();
      if (!raw) return '';
      const base = raw.replace(/\/+$/, '');
      if (base.endsWith('/chat/completions')) return base;
      if (base.endsWith('/v1')) return base + '/chat/completions';
      return base + '/v1/chat/completions';
    },
    validate(env) {
      if (!env.OPENAI_API_KEY) return 'OPENAI_API_KEY not configured';
      if ((env.LANE_PROVIDER || '') === 'openai' && !(env.OPENAI_MODEL || '').trim()) return 'OPENAI_MODEL not configured';
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.OPENAI_API_KEY}` },
        body: { model: env.OPENAI_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: 'system', content: system }, ...messages] },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
    async preflight(env) {
      const started = Date.now();
      const model = env.OPENAI_MODEL || requireEnv(env, 'MODEL', 'openai');
      if (!env.OPENAI_API_KEY) return { status: 'error', key_valid: false, model, error: 'OPENAI_API_KEY not configured', elapsed_ms: 0 };
      const timeout = intEnv(env, 'PREFLIGHT_TIMEOUT_MS', 5000);
      try {
        const url = typeof PROVIDERS.openai.url === 'function' ? PROVIDERS.openai.url(env) : PROVIDERS.openai.url;
        const res = await fetchWithTimeout(url, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.OPENAI_API_KEY}` },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] }),
        }, timeout);
        const rl = parseOpenAIRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text(); const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try { const j = JSON.parse(text); if (j.error && j.error.message) detail = j.error.message; } catch (e) { console.error('[TALK]', e.message || e); }
          return { status: isAuth ? 'error' : 'degraded', key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? 'degraded' : 'ok', key_valid: true, model, ...rl, error: deg || undefined, elapsed_ms: Date.now() - started };
      } catch (e) { return { status: 'error', key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started }; }
    },
  },
  deepseek: {
    url(env) {
      const raw = (env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com/v1').trim();
      if (!raw) return '';
      const base = raw.replace(/\/+$/, '');
      if (base.endsWith('/chat/completions')) return base;
      if (base.endsWith('/v1')) return base + '/chat/completions';
      return base + '/v1/chat/completions';
    },
    validate(env) {
      if (!env.DEEPSEEK_API_KEY) return 'DEEPSEEK_API_KEY not configured';
      if ((env.LANE_PROVIDER || '') === 'deepseek' && !(env.DEEPSEEK_MODEL || '').trim()) return 'DEEPSEEK_MODEL not configured';
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}` },
        body: { model: env.DEEPSEEK_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: 'system', content: system }, ...messages] },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
    async preflight(env) {
      const started = Date.now();
      const model = env.DEEPSEEK_MODEL || requireEnv(env, 'MODEL', 'deepseek');
      if (!env.DEEPSEEK_API_KEY) return { status: 'error', key_valid: false, model, error: 'DEEPSEEK_API_KEY not configured', elapsed_ms: 0 };
      const timeout = intEnv(env, 'PREFLIGHT_TIMEOUT_MS', 5000);
      try {
        const url = typeof PROVIDERS.deepseek.url === 'function' ? PROVIDERS.deepseek.url(env) : PROVIDERS.deepseek.url;
        const res = await fetchWithTimeout(url, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}` },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] }),
        }, timeout);
        const rl = parseOpenAIRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text(); const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try { const j = JSON.parse(text); if (j.error && j.error.message) detail = j.error.message; } catch (e) { console.error('[TALK]', e.message || e); }
          return { status: isAuth ? 'error' : 'degraded', key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? 'degraded' : 'ok', key_valid: true, model, ...rl, error: deg || undefined, elapsed_ms: Date.now() - started };
      } catch (e) { return { status: 'error', key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started }; }
    },
  },
  runpod: {
    url(env) {
      const raw = (env.RUNPOD_BASE_URL || '').trim();
      if (!raw) return '';
      const base = raw.replace(/\/+$/, '');
      if (base.endsWith('/chat/completions')) return base;
      return base + '/chat/completions';
    },
    validate(env) {
      if (!env.RUNPOD_API_KEY) return 'RUNPOD_API_KEY not configured';
      if (!env.RUNPOD_BASE_URL) return 'RUNPOD_BASE_URL not configured';
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.RUNPOD_API_KEY },
        body: { model: env.RUNPOD_MODEL || env.MODEL, max_tokens: maxTokensFor('RUNPOD', env), messages: [{ role: 'system', content: system }, ...messages] },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
    async preflight(env) {
      const started = Date.now();
      const model = env.RUNPOD_MODEL || env.MODEL;
      if (!env.RUNPOD_API_KEY) return { status: 'error', key_valid: false, model, error: 'RUNPOD_API_KEY not configured', elapsed_ms: 0 };
      const baseUrl = (env.RUNPOD_BASE_URL || '').trim();
      if (!baseUrl) return { status: 'error', key_valid: true, model, error: 'RUNPOD_BASE_URL not configured', elapsed_ms: 0 };
      const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
      if (endpointId) {
        const h = await runpodHealth(endpointId, env);
        const w = h && h.workers ? h.workers : null;
        if (!w) return { status: 'error', key_valid: true, model, error: 'health endpoint unreachable', elapsed_ms: Date.now() - started };
        return { status: (w.ready || 0) >= 1 && (w.throttled || 0) === 0 ? 'ok' : 'degraded', key_valid: true, model, workers_ready: w.ready || 0, workers_throttled: w.throttled || 0, elapsed_ms: Date.now() - started };
      }
      if (isRunpodProxyBaseUrl(baseUrl)) {
        const pr = await runpodProxyReady(baseUrl, env);
        return { status: pr && pr.ok ? 'ok' : 'degraded', key_valid: true, model, proxy_ready: pr ? pr.ok : false, elapsed_ms: Date.now() - started };
      }
      return { status: 'degraded', key_valid: true, model, error: 'unknown endpoint format', elapsed_ms: Date.now() - started };
    },
  },
  vastai: {
    url(env) {
      const raw = (env.VASTAI_BASE_URL || '').trim();
      if (!raw) return '';
      const base = raw.replace(/\/+$/, '');
      if (base.endsWith('/chat/completions')) return base;
      return base + '/chat/completions';
    },
    validate(env) { return env.VASTAI_BASE_URL ? null : 'VASTAI_BASE_URL not configured'; },
    build(env, system, messages) {
      const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim();
      const headers = { 'Content-Type': 'application/json' };
      if (key) headers.Authorization = 'Bearer ' + key;
      return { headers, body: { model: env.VASTAI_MODEL || env.MODEL, max_tokens: maxTokensFor('VASTAI', env), messages: [{ role: 'system', content: system }, ...messages] } };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
    async preflight(env) {
      const started = Date.now();
      const model = env.VASTAI_MODEL || env.MODEL;
      const baseUrl = (env.VASTAI_BASE_URL || '').trim();
      if (!baseUrl) return { status: 'error', key_valid: false, model, error: 'VASTAI_BASE_URL not configured', elapsed_ms: 0 };
      const timeout = intEnv(env, 'PREFLIGHT_TIMEOUT_MS', 5000);
      const b = baseUrl.replace(/\/+$/, '');
      try {
        const headers = { 'Accept': 'application/json' };
        const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim();
        if (key) headers.Authorization = 'Bearer ' + key;
        const r = await fetchWithTimeout(b + '/models', { headers }, timeout);
        return { status: r.ok ? 'ok' : 'degraded', key_valid: true, model, proxy_ready: r.ok, elapsed_ms: Date.now() - started };
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
