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
  if (h === 'anthropic.canonic.org' || h === 'api.canonic.org') return 'anthropic';
  return null;
}

export function envForLane(hostname, env) {
  const lane = laneProviderFromHostname(hostname);
  if (!lane) return env;
  const out = { ...env, LANE_PROVIDER: lane };
  out.PROVIDER = lane; out.FALLBACK_PROVIDER = lane; out.PROVIDER_CHAIN = lane;
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
  const hi = parseIntEnv(env, `${provider}_TOKENS_MAX`) ?? requireIntEnv(env, 'TOKENS_MAX', 'tokens');
  return { lo, hi };
}

function providerHasGatewayConfig(provider, env) {
  const p = String(provider || '').toLowerCase();
  if (p === 'anthropic') return !!(env.ANTHROPIC_API_KEY && (env.MODEL || '').trim());
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
  if (!prefix) return null;
  if (!required && !hasAliasConfig(env, prefix)) return null;

  const provider = 'anthropic';
  if (!providerHasGatewayConfig(provider, env)) return null;

  const id = String(env[`${prefix}_MODEL_ID`] || defaultId).trim();
  let upstreamModel = String(env[`${prefix}_UPSTREAM_MODEL`] || '').trim();

  const modelKey = profile === 'kilocode' ? 'ANTHROPIC_KILOCODE_MODEL' : 'MODEL';
  if (!upstreamModel) upstreamModel = String(env[modelKey] || env.MODEL || '').trim();

  if (!id || !upstreamModel) return null;
  return { id, provider, profile, upstream_model: upstreamModel };
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
    { prefix: 'CHAT', profile: 'chat', defaultId: 'canonic-chat', required: true, defaultProviderOrder: ['anthropic'] },
    { prefix: 'KILOCODE', profile: 'kilocode', defaultId: 'canonic-kilocode', required: true, defaultProviderOrder: ['anthropic'] },
    { prefix: 'CHAT_COMMERCIAL_ANTHROPIC', profile: 'chat', defaultId: 'canonic-chat-commercial-anthropic', defaultProviderOrder: ['anthropic'] },
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
