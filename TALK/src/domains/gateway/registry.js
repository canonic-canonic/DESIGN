/**
 * GATEWAY/REGISTRY — Model registry, lane routing, gateway key enforcement.
 * GOV: TALK/CANON.md
 */

import { requireIntEnv, parseIntEnv } from '../../kernel/env.js';
import { coerceContentToText } from '../../kernel/util.js';

// ── Gateway key enforcement ──

export function requireGatewayKey(env) { return !!(env && env.CANONIC_API_KEY); }

export function checkGatewayKey(request, env) {
  if (!requireGatewayKey(env)) return null;
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const tok = m ? m[1].trim() : '';
  if (!tok || tok !== String(env.CANONIC_API_KEY)) return 'Unauthorized';
  return null;
}

// ── Lane routing ──

export function laneProviderFromHostname(hostname) {
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

// ── Model registry helpers ──

export function completionsUrlFromBase(rawBase) {
  const raw = String(rawBase || '').trim(); if (!raw) return '';
  const base = raw.replace(/\/+$/, '');
  if (base.endsWith('/chat/completions')) return base;
  if (base.endsWith('/v1')) return base + '/chat/completions';
  return base + '/v1/chat/completions';
}

export function tokenBoundsForEntry(entry, env) {
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

export function resolveGatewayAliasEntry(env, spec) {
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

export function listGatewayModels(env) {
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

// ── Chat request helpers ──

export function normalizeResponseInputToMessages(input) {
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

export function stableIndexFromKey(key, len) {
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

export function parseModelCsv(raw) { return String(raw || '').trim().split(',').map(v => v.trim()).filter(Boolean); }

export function resolveChatRequestedModel(body, env, registry) {
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
