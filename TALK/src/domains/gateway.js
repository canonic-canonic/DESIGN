/**
 * GATEWAY — OpenAI-compatible model routing, bakeoff, responses shim.
 * GOV: TALK/CANON.md
 */

import { json, oaiError, fetchWithTimeout, addCors } from '../kernel/http.js';
import { requireIntEnv, parseIntEnv } from '../kernel/env.js';
import { clampInt, clampString, redactSecrets, coerceContentToText } from '../kernel/util.js';
import { PROVIDERS, runpodEndpointIdFromBaseUrl, isRunpodProxyBaseUrl, runpodProxyReady, runpodHealth } from './providers.js';

// ── Gateway key enforcement ──

function requireGatewayKey(env) { return !!(env && env.CANONIC_API_KEY); }

function checkGatewayKey(request, env) {
  if (!requireGatewayKey(env)) return null;
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const tok = m ? m[1].trim() : '';
  if (!tok || tok !== String(env.CANONIC_API_KEY)) return 'Unauthorized';
  return null;
}

// ── Lane routing ──

function laneProviderFromHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === 'anthropic.canonic.org') return 'anthropic';
  if (h === 'runpod.canonic.org') return 'runpod';
  if (h === 'vast.canonic.org') return 'vastai';
  if (h === 'openai.canonic.org') return 'openai';
  if (h === 'deepseek.canonic.org') return 'deepseek';
  return null;
}

export function envForLane(hostname, env) {
  const lane = laneProviderFromHostname(hostname);
  if (!lane) return env;
  const out = { ...env, LANE_PROVIDER: lane };
  out.PROVIDER = lane; out.FALLBACK_PROVIDER = lane; out.PROVIDER_CHAIN = lane;
  if (lane === 'runpod') out.MODEL = (env.RUNPOD_MODEL || env.MODEL);
  if (lane === 'vastai') out.MODEL = (env.VASTAI_MODEL || env.MODEL);
  if (lane === 'openai') out.MODEL = (env.OPENAI_MODEL || env.MODEL);
  if (lane === 'deepseek') out.MODEL = (env.DEEPSEEK_MODEL || env.MODEL);
  return out;
}

// ── Model registry ──

function completionsUrlFromBase(rawBase) {
  const raw = String(rawBase || '').trim(); if (!raw) return '';
  const base = raw.replace(/\/+$/, '');
  if (base.endsWith('/chat/completions')) return base;
  if (base.endsWith('/v1')) return base + '/chat/completions';
  return base + '/v1/chat/completions';
}

function tokenBoundsForEntry(entry, env) {
  const provider = String((entry && entry.provider) || '').toUpperCase();
  const profile = String((entry && entry.profile) || 'talk').toLowerCase();
  const lo = parseIntEnv(env, `${provider}_TOKENS_MIN`) ?? requireIntEnv(env, 'TOKENS_MIN', 'tokens');
  const hi = parseIntEnv(env, `${provider}_${profile === 'kilocode' ? 'KILOCODE_TOKENS_MAX' : 'TOKENS_MAX'}`) ?? parseIntEnv(env, `${provider}_TOKENS_MAX`) ?? (provider === 'RUNPOD' ? 512 : requireIntEnv(env, 'TOKENS_MAX', 'tokens'));
  return { lo, hi };
}

function providerHasGatewayConfig(provider, env) {
  const p = String(provider || '').toLowerCase();
  if (p === 'anthropic') return !!(env.ANTHROPIC_API_KEY && (env.MODEL || '').trim());
  if (p === 'openai') return !!(env.OPENAI_API_KEY && ((env.OPENAI_MODEL || env.OPENAI_KILOCODE_MODEL || '').trim()));
  if (p === 'deepseek') return !!(env.DEEPSEEK_API_KEY && ((env.DEEPSEEK_MODEL || env.DEEPSEEK_KILOCODE_MODEL || '').trim()));
  if (p === 'runpod') return !!(env.RUNPOD_API_KEY && ((env.RUNPOD_BASE_URL || env.RUNPOD_KILOCODE_BASE_URL || '').trim()) && ((env.RUNPOD_MODEL || env.RUNPOD_KILOCODE_MODEL || '').trim()));
  if (p === 'vastai') return !!((env.VASTAI_BASE_URL || env.VASTAI_KILOCODE_BASE_URL || '').trim()) && !!((env.VASTAI_MODEL || env.VASTAI_KILOCODE_MODEL || '').trim());
  return false;
}

function hasAliasConfig(env, prefix) {
  for (const k of ['MODEL_ID', 'PROVIDER', 'UPSTREAM_MODEL', 'BASE_URL']) {
    if (String(env[`${prefix}_${k}`] || '').trim()) return true;
  }
  return false;
}

function resolveGatewayAliasEntry(env, spec) {
  const prefix = String(spec?.prefix || '').toUpperCase();
  const profile = spec?.profile === 'kilocode' ? 'kilocode' : 'chat';
  const required = !!spec?.required;
  const defaultId = String(spec?.defaultId || `canonic-${profile}`).trim();
  const defaultProviderOrder = Array.isArray(spec?.defaultProviderOrder)
    ? spec.defaultProviderOrder
    : (profile === 'kilocode' ? ['runpod', 'deepseek', 'openai', 'anthropic', 'vastai'] : ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai']);
  if (!prefix) return null;
  if (!required && !hasAliasConfig(env, prefix)) return null;

  const requestedProvider = String(env[`${prefix}_PROVIDER`] || defaultProviderOrder[0]).toLowerCase().trim();
  const provider = providerHasGatewayConfig(requestedProvider, env)
    ? requestedProvider
    : (defaultProviderOrder.find(p => providerHasGatewayConfig(p, env)) || requestedProvider);

  const id = String(env[`${prefix}_MODEL_ID`] || defaultId).trim();
  let upstreamModel = String(env[`${prefix}_UPSTREAM_MODEL`] || '').trim();
  let baseUrl = String(env[`${prefix}_BASE_URL`] || '').trim();

  const providerKeys = {
    anthropic: { model: profile === 'kilocode' ? 'ANTHROPIC_KILOCODE_MODEL' : 'MODEL', fallback: 'MODEL', baseUrl: '' },
    openai: { model: profile === 'kilocode' ? 'OPENAI_KILOCODE_MODEL' : 'OPENAI_MODEL', fallback: 'OPENAI_MODEL', base: profile === 'kilocode' ? 'OPENAI_KILOCODE_BASE_URL' : 'OPENAI_BASE_URL', baseFallback: 'OPENAI_BASE_URL' },
    deepseek: { model: profile === 'kilocode' ? 'DEEPSEEK_KILOCODE_MODEL' : 'DEEPSEEK_MODEL', fallback: 'DEEPSEEK_MODEL', base: profile === 'kilocode' ? 'DEEPSEEK_KILOCODE_BASE_URL' : 'DEEPSEEK_BASE_URL', baseFallback: 'DEEPSEEK_BASE_URL' },
    runpod: { model: profile === 'kilocode' ? 'RUNPOD_KILOCODE_MODEL' : 'RUNPOD_MODEL', fallback: 'RUNPOD_MODEL', base: profile === 'kilocode' ? 'RUNPOD_KILOCODE_BASE_URL' : 'RUNPOD_BASE_URL', baseFallback: 'RUNPOD_BASE_URL' },
    vastai: { model: profile === 'kilocode' ? 'VASTAI_KILOCODE_MODEL' : 'VASTAI_MODEL', fallback: 'VASTAI_MODEL', base: profile === 'kilocode' ? 'VASTAI_KILOCODE_BASE_URL' : 'VASTAI_BASE_URL', baseFallback: 'VASTAI_BASE_URL' },
  };

  const pk = providerKeys[provider];
  if (pk) {
    if (!upstreamModel) upstreamModel = String(env[pk.model] || env[pk.fallback] || '').trim();
    if (provider === 'anthropic') { baseUrl = ''; }
    else if (!baseUrl && pk.base) { baseUrl = String(env[pk.base] || env[pk.baseFallback] || '').trim(); }
  }

  if (!id || !upstreamModel) return null;
  const entry = { id, provider, profile, upstream_model: upstreamModel };
  if (baseUrl) entry.base_url = baseUrl;
  return entry;
}

function pushGatewayModel(out, seen, entry) {
  if (!entry || typeof entry !== 'object') return;
  const id = String(entry.id || '').trim();
  const provider = String(entry.provider || '').trim();
  if (!id || !provider || seen.has(id)) return;
  seen.add(id); out.push({ ...entry, id, provider });
}

function listGatewayModels(env) {
  const out = []; const seen = new Set();
  const specs = [
    { prefix: 'CHAT', profile: 'chat', defaultId: 'canonic-chat', required: true, defaultProviderOrder: ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai'] },
    { prefix: 'KILOCODE', profile: 'kilocode', defaultId: 'canonic-kilocode', required: true, defaultProviderOrder: ['runpod', 'deepseek', 'openai', 'anthropic', 'vastai'] },
    { prefix: 'CHAT_COMMERCIAL', profile: 'chat', defaultId: 'canonic-chat-commercial', defaultProviderOrder: ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai'] },
    { prefix: 'CHAT_COMMERCIAL_OPENAI', profile: 'chat', defaultId: 'canonic-chat-commercial-openai', defaultProviderOrder: ['openai', 'deepseek', 'anthropic', 'runpod', 'vastai'] },
    { prefix: 'CHAT_COMMERCIAL_ANTHROPIC', profile: 'chat', defaultId: 'canonic-chat-commercial-anthropic', defaultProviderOrder: ['anthropic', 'deepseek', 'openai', 'runpod', 'vastai'] },
    { prefix: 'CHAT_OPENSOURCE_RUNPOD', profile: 'chat', defaultId: 'canonic-chat-opensource-runpod', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_OPENSOURCE_VAST', profile: 'chat', defaultId: 'canonic-chat-opensource-vast', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_RUNPOD_DEEPSEEK', profile: 'chat', defaultId: 'canonic-chat-runpod-deepseek', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_RUNPOD_QWEN', profile: 'chat', defaultId: 'canonic-chat-runpod-qwen', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_RUNPOD_MISTRAL', profile: 'chat', defaultId: 'canonic-chat-runpod-mistral', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_RUNPOD_LLAMA', profile: 'chat', defaultId: 'canonic-chat-runpod-llama', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_RUNPOD_GLM', profile: 'chat', defaultId: 'canonic-chat-runpod-glm', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_VAST_DEEPSEEK', profile: 'chat', defaultId: 'canonic-chat-vast-deepseek', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_VAST_QWEN', profile: 'chat', defaultId: 'canonic-chat-vast-qwen', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_VAST_MISTRAL', profile: 'chat', defaultId: 'canonic-chat-vast-mistral', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_VAST_LLAMA', profile: 'chat', defaultId: 'canonic-chat-vast-llama', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'CHAT_VAST_GLM', profile: 'chat', defaultId: 'canonic-chat-vast-glm', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_COMMERCIAL', profile: 'kilocode', defaultId: 'canonic-kilocode-commercial', defaultProviderOrder: ['openai', 'deepseek', 'anthropic', 'runpod', 'vastai'] },
    { prefix: 'KILOCODE_OPENSOURCE_RUNPOD', profile: 'kilocode', defaultId: 'canonic-kilocode-opensource-runpod', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_OPENSOURCE_VAST', profile: 'kilocode', defaultId: 'canonic-kilocode-opensource-vast', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_RUNPOD_DEEPSEEK', profile: 'kilocode', defaultId: 'canonic-kilocode-runpod-deepseek', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_RUNPOD_QWEN', profile: 'kilocode', defaultId: 'canonic-kilocode-runpod-qwen', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_RUNPOD_GLM', profile: 'kilocode', defaultId: 'canonic-kilocode-runpod-glm', defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_VAST_DEEPSEEK', profile: 'kilocode', defaultId: 'canonic-kilocode-vast-deepseek', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_VAST_QWEN', profile: 'kilocode', defaultId: 'canonic-kilocode-vast-qwen', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
    { prefix: 'KILOCODE_VAST_GLM', profile: 'kilocode', defaultId: 'canonic-kilocode-vast-glm', defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'] },
  ];
  for (const spec of specs) {
    const entry = resolveGatewayAliasEntry(env, spec);
    if (entry) pushGatewayModel(out, seen, entry);
  }
  const lane = (env.LANE_PROVIDER || '').trim();
  if (lane) return out.filter(m => m.provider === lane);
  return out;
}

// ── Helpers for /v1/chat/completions ──

function normalizeResponseInputToMessages(input) {
  if (typeof input === 'string') return [{ role: 'user', content: input }];
  if (!Array.isArray(input)) return null;
  const out = [];
  for (const item of input) {
    if (!item) continue;
    if (typeof item.role === 'string' && item.content !== undefined) { const text = coerceContentToText(item.content); if (text) out.push({ role: item.role, content: text }); continue; }
    if (typeof item.text === 'string') { out.push({ role: 'user', content: item.text }); continue; }
    const text = coerceContentToText(item.content);
    if (text) out.push({ role: 'user', content: text });
  }
  return out.length ? out : null;
}

function stableIndexFromKey(key, len) {
  const n = Math.max(1, parseInt(len, 10) || 1);
  const s = String(key || '');
  if (!s) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; }
    return Math.floor(Math.random() * n);
  }
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) % n;
}

function parseModelCsv(raw) { return String(raw || '').trim().split(',').map(v => v.trim()).filter(Boolean); }

function resolveChatRequestedModel(body, env, registry) {
  const requested = (body && body.model ? String(body.model) : '').trim();
  if (requested) return { model: requested, assigned: false };
  const audience = String((body && (body.audience || body.suite)) || '').toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  const autoAssignAudience = (audience === 'user' || audience === 'patient' || audience === 'dev' || audience === 'experiment');
  if (!(autoAssignAudience || randomize)) return { model: '', assigned: false };
  const configured = audience === 'dev' ? parseModelCsv(env.BAKEOFF_DEV_MODELS) : (audience === 'user' || audience === 'patient') ? parseModelCsv(env.BAKEOFF_USER_MODELS) : parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS);
  const fallback = registry.filter(m => m.profile === 'chat').map(m => m.id);
  const source = configured.length ? configured : fallback;
  const known = new Set(registry.map(m => m.id));
  const candidates = source.filter(id => known.has(id));
  if (!candidates.length) return { model: '', assigned: false, error: 'No randomized models configured' };
  const key = String((body && (body.patient_id || body.user_id || body.session_id)) || '').trim();
  return { model: candidates[stableIndexFromKey(key, candidates.length)], assigned: true };
}

// ── Exported route handlers ──

export async function oaiModels(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');
  const models = listGatewayModels(env).map(m => ({ id: m.id, object: 'model', owned_by: 'canonic' }));
  return json({ object: 'list', data: models });
}

export async function oaiChatCompletions(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body;
  try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }

  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return oaiError(400, 'Missing messages');

  const reg = listGatewayModels(env);
  const selection = resolveChatRequestedModel(body, env, reg);
  if (selection.error) return oaiError(400, selection.error);
  const model = selection.model;
  if (!model) return oaiError(400, 'Missing model');
  const entry = reg.find(m => m.id === model) || null;
  if (!entry) return oaiError(400, `Unknown model: ${model || '(empty)'}`, 'invalid_request_error', 'model_not_found');
  const upstreamModel = (entry.upstream_model || entry.id || '').trim();
  if (!upstreamModel) return oaiError(500, `Model misconfigured: ${entry.id}`);

  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);
  const stream = !!(body && body.stream);
  if (body && body.n && parseInt(body.n, 10) !== 1) return oaiError(400, 'Only n=1 is supported');

  const messages = messagesIn.slice(-40).map(m => ({ role: String(m.role || '').trim(), content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
  if (!messages.length) return oaiError(400, 'No valid messages');

  const timeout_ms = parseIntEnv(env, 'OAI_GATEWAY_TIMEOUT_MS') ?? (stream ? 600000 : 120000);
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const started = Date.now();
  const allowed = ['temperature', 'top_p', 'presence_penalty', 'frequency_penalty', 'stop', 'seed'];
  const pass = {};
  for (const k of allowed) { if (body && body[k] !== undefined) pass[k] = body[k]; }

  // Route by provider
  if (entry.provider === 'anthropic') {
    if (!env.ANTHROPIC_API_KEY) return oaiError(500, 'ANTHROPIC_API_KEY not configured');
    const sys = messagesIn.filter(m => m && m.role === 'system').map(m => coerceContentToText(m.content)).filter(Boolean).join('\n\n');
    const anthMessages = messagesIn.filter(m => m && (m.role === 'user' || m.role === 'assistant')).slice(-40).map(m => ({ role: m.role, content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
    if (!anthMessages.length) return oaiError(400, 'No valid user/assistant messages');

    let res;
    try {
      res = await fetchWithTimeout(PROVIDERS.anthropic.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION },
        body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || undefined, messages: anthMessages }),
      }, parseIntEnv(env, 'OAI_GATEWAY_TIMEOUT_MS') ?? 25000);
    } catch (e) { return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, 'api_error'); }

    const text = await res.text();
    if (!res.ok) return oaiError(502, `Anthropic ${res.status}: ${clampString(redactSecrets(text), 900)}`, 'api_error');
    let data; try { data = JSON.parse(text); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(502, 'Anthropic returned invalid JSON', 'api_error'); }
    const content = data?.content?.[0]?.text ? String(data.content[0].text) : '';

    const h = addCors({ 'Content-Type': 'application/json' });
    h.set('x-canonic-trace-id', trace_id); h.set('x-canonic-model-profile', entry.profile || 'anthropic');
    h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
    if (selection.assigned) h.set('x-canonic-assigned-model', model);

    const out = { id: 'chatcmpl-canonic-' + trace_id, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop', logprobs: null }], usage: null };

    if (stream) {
      const sh = addCors({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' });
      sh.set('x-canonic-trace-id', trace_id); sh.set('x-canonic-model-profile', entry.profile || 'anthropic');
      sh.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
      if (selection.assigned) sh.set('x-canonic-assigned-model', model);
      const chunk = { id: out.id, object: 'chat.completion.chunk', created: out.created, model: out.model, choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] };
      const rs = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`)); controller.enqueue(new TextEncoder().encode(`data: [DONE]\n\n`)); controller.close(); } });
      return new Response(rs, { status: 200, headers: sh });
    }
    return new Response(JSON.stringify(out), { status: 200, headers: h });
  }

  if (entry.provider === 'openai' || entry.provider === 'deepseek') {
    const p = PROVIDERS[entry.provider];
    if (!p) return oaiError(500, `Unsupported provider: ${entry.provider}`);
    const providerError = p.validate?.(env);
    if (providerError) return oaiError(500, providerError, 'configuration_error');
    const providerUrl = entry.base_url ? completionsUrlFromBase(entry.base_url) : (typeof p.url === 'function' ? p.url(env) : p.url);
    if (!providerUrl) return oaiError(500, `Provider URL misconfigured: ${entry.provider}`, 'configuration_error');

    const payload = { model: upstreamModel, messages, max_tokens, stream, ...pass };
    const headers = { 'Content-Type': 'application/json' };
    if (entry.provider === 'openai') headers.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === 'deepseek') headers.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;

    let res;
    try { res = await fetchWithTimeout(providerUrl, { method: 'POST', headers, body: JSON.stringify(payload) }, timeout_ms); }
    catch (e) { return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, 'api_error'); }

    const h = addCors(res.headers);
    h.set('x-canonic-trace-id', trace_id); h.set('x-canonic-model-profile', entry.profile || entry.provider);
    h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
    if (selection.assigned) h.set('x-canonic-assigned-model', model);

    if (stream) return new Response(res.body, { status: res.status, headers: h });
    const text = await res.text();
    if (!res.ok) return oaiError(502, `${entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek'} ${res.status}: ${clampString(redactSecrets(text), 900)}`, 'api_error');
    return new Response(text, { status: 200, headers: h });
  }

  // OpenAI-compatible: runpod or vastai
  const baseUrl = (entry.base_url || '').replace(/\/+$/, '');
  if (!baseUrl) return oaiError(500, `Model misconfigured: ${entry.id}`);

  if (entry.provider === 'runpod') {
    if (!env.RUNPOD_API_KEY) return oaiError(500, 'RUNPOD_API_KEY not configured');
    if ((parseIntEnv(env, 'RUNPOD_PREFLIGHT_HEALTH') ?? 1) === 1) {
      const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
      if (endpointId) {
        const h = await runpodHealth(endpointId, env);
        const w = h?.workers;
        if (w && ((w.ready || 0) < 1 || (w.throttled || 0) > 0)) {
          const resp = oaiError(503, `Model warming up (ready=${w.ready || 0}, throttled=${w.throttled || 0}). Try again shortly.`, 'api_error');
          const hh = addCors(resp.headers); hh.set('Retry-After', '10');
          return new Response(resp.body, { status: resp.status, headers: hh });
        }
      } else if (isRunpodProxyBaseUrl(baseUrl)) {
        const pr = await runpodProxyReady(baseUrl, env);
        if (!pr || !pr.ok) {
          const resp = oaiError(503, `Model warming up (proxy_ready=${pr ? pr.status : 'no_response'}). Try again shortly.`, 'api_error');
          const hh = addCors(resp.headers); hh.set('Retry-After', '10');
          return new Response(resp.body, { status: resp.status, headers: hh });
        }
      }
    }
  }

  const payload = { model: upstreamModel, messages, max_tokens, stream, ...pass };
  const headers = { 'Content-Type': 'application/json' };
  if (entry.provider === 'runpod') headers.Authorization = 'Bearer ' + env.RUNPOD_API_KEY;
  else if (entry.provider === 'vastai') { const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim(); if (key) headers.Authorization = 'Bearer ' + key; }
  else return oaiError(500, `Unsupported provider: ${entry.provider}`);

  let res;
  try { res = await fetchWithTimeout(baseUrl + '/chat/completions', { method: 'POST', headers, body: JSON.stringify(payload) }, timeout_ms); }
  catch (e) { return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, 'api_error'); }

  const h = addCors(res.headers);
  h.set('x-canonic-trace-id', trace_id); h.set('x-canonic-model-profile', entry.profile);
  h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
  if (selection.assigned) h.set('x-canonic-assigned-model', model);

  if (stream) return new Response(res.body, { status: res.status, headers: h });
  const text = await res.text();
  if (!res.ok) return oaiError(502, `${entry.provider === 'runpod' ? 'Runpod' : 'VastAI'} ${res.status}: ${clampString(redactSecrets(text), 900)}`, 'api_error');
  return new Response(text, { status: 200, headers: h });
}

export async function oaiResponses(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body; try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }
  const model = (body?.model ? String(body.model) : '').trim();
  const audience = String((body && (body.audience || body.suite)) || '').toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  if (!model && !(randomize || ['user', 'patient', 'dev', 'experiment'].includes(audience))) return oaiError(400, 'Missing model');

  let messages = null;
  if (body && Array.isArray(body.messages) && body.messages.length) messages = body.messages;
  else if (body && body.input !== undefined) messages = normalizeResponseInputToMessages(body.input);
  if (!messages || !messages.length) return oaiError(400, 'Missing messages/input');

  const chatBody = { messages, max_tokens: body.max_output_tokens ?? body.max_tokens, temperature: body.temperature, top_p: body.top_p, presence_penalty: body.presence_penalty, frequency_penalty: body.frequency_penalty, stop: body.stop, seed: body.seed, stream: false, n: 1 };
  if (model) chatBody.model = model;
  if (audience) chatBody.audience = audience;
  if (randomize) chatBody.randomize_model = true;
  if (body?.user_id !== undefined) chatBody.user_id = body.user_id;
  if (body?.patient_id !== undefined) chatBody.patient_id = body.patient_id;
  if (body?.session_id !== undefined) chatBody.session_id = body.session_id;

  const r2 = new Request('https://api.canonic.org/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': request.headers.get('Authorization') || '' }, body: JSON.stringify(chatBody) });
  const chatRes = await oaiChatCompletions(r2, env);
  const text = await chatRes.text();
  if (chatRes.status !== 200) return new Response(text, { status: chatRes.status, headers: addCors(chatRes.headers) });

  let data; try { data = JSON.parse(text); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(502, 'Upstream returned invalid JSON', 'api_error'); }
  const content = data?.choices?.[0]?.message ? String(data.choices[0].message.content || '') : '';

  const out = {
    id: 'resp-canonic-' + (data.id ? String(data.id).replace(/^chatcmpl-/, '') : String(Date.now())),
    object: 'response', created: Math.floor(Date.now() / 1000), model,
    output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: content }] }],
    output_text: content, usage: data?.usage || null,
  };
  const h = addCors({ 'Content-Type': 'application/json' });
  const trace = chatRes.headers.get('x-canonic-trace-id'); if (trace) h.set('x-canonic-trace-id', trace);
  const prof = chatRes.headers.get('x-canonic-model-profile'); if (prof) h.set('x-canonic-model-profile', prof);
  const elapsed = chatRes.headers.get('x-canonic-upstream-elapsed-ms'); if (elapsed) h.set('x-canonic-upstream-elapsed-ms', elapsed);
  return new Response(JSON.stringify(out), { status: 200, headers: h });
}

export { listGatewayModels, checkGatewayKey, callGatewayModel, tokenBoundsForEntry, completionsUrlFromBase, resolveChatRequestedModel, parseModelCsv, stableIndexFromKey };

// callGatewayModel for bakeoff — kept here to avoid circular deps
async function callGatewayModel(entry, body, env, trace_id) {
  const started = Date.now();
  const model = entry.id;
  const upstreamModel = (entry.upstream_model || model || '').trim();
  if (!upstreamModel) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, elapsed_ms: Date.now() - started };

  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);

  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return { model, ok: false, status: 400, error: 'Missing messages', elapsed_ms: Date.now() - started };
  const messages = messagesIn.slice(-40).map(m => ({ role: String(m.role || '').trim(), content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
  if (!messages.length) return { model, ok: false, status: 400, error: 'No valid messages', elapsed_ms: Date.now() - started };

  const allowed = ['temperature', 'top_p', 'presence_penalty', 'frequency_penalty', 'stop', 'seed'];
  const pass = {};
  for (const k of allowed) { if (body && body[k] !== undefined) pass[k] = body[k]; }
  const gov_pre = { provider: entry.provider, profile: entry.profile || null, model, upstream_model: upstreamModel, max_tokens, tokens_min: lo, tokens_max: hi };

  if (entry.provider === 'anthropic') {
    if (!env.ANTHROPIC_API_KEY) return { model, ok: false, status: 500, error: 'ANTHROPIC_API_KEY not configured', gov_pre, elapsed_ms: Date.now() - started };
    const sys = messagesIn.filter(m => m?.role === 'system').map(m => coerceContentToText(m.content)).filter(Boolean).join('\n\n');
    const anthMessages = messagesIn.filter(m => m && (m.role === 'user' || m.role === 'assistant')).slice(-40).map(m => ({ role: m.role, content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
    if (!anthMessages.length) return { model, ok: false, status: 400, error: 'No valid user/assistant messages', gov_pre, elapsed_ms: Date.now() - started };
    const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 60000;
    try {
      const res = await fetchWithTimeout(PROVIDERS.anthropic.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION }, body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || undefined, messages: anthMessages, temperature: pass.temperature, top_p: pass.top_p, stop_sequences: pass.stop ? (Array.isArray(pass.stop) ? pass.stop : [pass.stop]) : undefined }) }, timeout_ms);
      const text = await res.text();
      if (!res.ok) return { model, ok: false, status: 502, error: `Anthropic ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      const data = JSON.parse(text);
      const content = data?.content?.[0]?.text ? String(data.content[0].text) : '';
      return { model, ok: true, status: 200, content, usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
    } catch (e) { return { model, ok: false, status: 502, error: `Anthropic error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started }; }
  }

  if (entry.provider === 'openai' || entry.provider === 'deepseek') {
    const p = PROVIDERS[entry.provider];
    if (!p) return { model, ok: false, status: 500, error: `Unsupported provider: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
    const providerError = p.validate?.(env);
    if (providerError) return { model, ok: false, status: 500, error: providerError, gov_pre, elapsed_ms: Date.now() - started };
    const providerUrl = entry.base_url ? completionsUrlFromBase(entry.base_url) : (typeof p.url === 'function' ? p.url(env) : p.url);
    if (!providerUrl) return { model, ok: false, status: 500, error: `Provider URL misconfigured: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
    const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 120000;
    const headers = { 'Content-Type': 'application/json' };
    if (entry.provider === 'openai') headers.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === 'deepseek') headers.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;
    try {
      const res = await fetchWithTimeout(providerUrl, { method: 'POST', headers, body: JSON.stringify({ model: upstreamModel, messages, max_tokens, stream: false, ...pass }) }, timeout_ms);
      const text = await res.text();
      if (!res.ok) return { model, ok: false, status: 502, error: `${entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek'} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      const data = JSON.parse(text);
      return { model, ok: true, status: 200, content: typeof data?.choices?.[0]?.message?.content === 'string' ? data.choices[0].message.content : '', usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
    } catch (e) { return { model, ok: false, status: 502, error: `${entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek'} error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started }; }
  }

  // runpod/vastai
  const bUrl = (entry.base_url || '').replace(/\/+$/, '');
  if (!bUrl) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, gov_pre, elapsed_ms: Date.now() - started };
  if (entry.provider === 'runpod' && !env.RUNPOD_API_KEY) return { model, ok: false, status: 500, error: 'RUNPOD_API_KEY not configured', gov_pre, elapsed_ms: Date.now() - started };
  if (entry.provider === 'runpod') {
    const endpointId = runpodEndpointIdFromBaseUrl(bUrl);
    if (endpointId) { const h = await runpodHealth(endpointId, env); const w = h?.workers; if (w && ((w.ready || 0) < 1 || (w.throttled || 0) > 0)) return { model, ok: false, status: 503, error: `warming (ready=${w.ready || 0}, throttled=${w.throttled || 0})`, gov_pre, health: h, elapsed_ms: Date.now() - started }; }
    else if (isRunpodProxyBaseUrl(bUrl)) { const pr = await runpodProxyReady(bUrl, env); if (!pr || !pr.ok) return { model, ok: false, status: 503, error: `warming (proxy_ready=${pr ? pr.status : 'no_response'})`, gov_pre, elapsed_ms: Date.now() - started }; }
  }
  const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 120000;
  const headers = { 'Content-Type': 'application/json' };
  if (entry.provider === 'runpod') headers.Authorization = 'Bearer ' + env.RUNPOD_API_KEY;
  else if (entry.provider === 'vastai') { const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim(); if (key) headers.Authorization = 'Bearer ' + key; }
  else return { model, ok: false, status: 500, error: `Unsupported provider: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
  try {
    const res = await fetchWithTimeout(bUrl + '/chat/completions', { method: 'POST', headers, body: JSON.stringify({ model: upstreamModel, messages, max_tokens, stream: false, ...pass }) }, timeout_ms);
    const text = await res.text();
    if (!res.ok) return { model, ok: false, status: 502, error: `${entry.provider === 'runpod' ? 'Runpod' : 'VastAI'} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
    const data = JSON.parse(text);
    return { model, ok: true, status: 200, content: typeof data?.choices?.[0]?.message?.content === 'string' ? data.choices[0].message.content : '', usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
  } catch (e) { return { model, ok: false, status: 502, error: `${entry.provider === 'runpod' ? 'Runpod' : 'VastAI'} error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started }; }
}

export async function oaiBakeoff(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');
  let body; try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }
  const reg = listGatewayModels(env);
  const models = Array.isArray(body.models) ? body.models.map(String).map(s => s.trim()).filter(Boolean) : [];
  const audience = String(body.audience || body.suite || '').toLowerCase().trim();
  const presetModels = audience === 'dev' ? parseModelCsv(env.BAKEOFF_DEV_MODELS) : audience === 'user' ? parseModelCsv(env.BAKEOFF_USER_MODELS) : audience === 'experiment' ? parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS) : [];
  const defaults = (() => { const chat = reg.find(m => m.id === 'canonic-chat') || reg.find(m => m.profile === 'chat') || reg[0]; const kilo = reg.find(m => m.id === 'canonic-kilocode') || reg.find(m => m.profile === 'kilocode'); const list = []; if (chat?.id) list.push(chat.id); if (kilo?.id) list.push(kilo.id); return list; })();
  const selected = models.length ? models : (presetModels.length ? presetModels : defaults);
  const entries = selected.map(String).map(s => s.trim()).filter(Boolean).map(id => reg.find(m => m.id === id) || null).filter(Boolean);
  if (!entries.length) return oaiError(400, 'No valid models requested');
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const parallel = body.parallel !== false;
  const calls = entries.map(e => callGatewayModel(e, body, env, trace_id));
  const results = parallel ? await Promise.all(calls) : (async () => { const out = []; for (const c of calls) out.push(await c); return out; })();
  return json({ object: 'bakeoff', trace_id, results });
}
