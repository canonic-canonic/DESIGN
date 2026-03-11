var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/kernel/cors.js
var CORS_DEFAULTS = {
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};
var _reqOrigin = "*";
function setReqOrigin(v) {
  _reqOrigin = v;
}
__name(setReqOrigin, "setReqOrigin");
function corsOrigin(request, env) {
  const raw = env && env.CORS_ALLOWED_ORIGINS ? String(env.CORS_ALLOWED_ORIGINS) : "*";
  const allowed = raw.split(",").map((s) => s.trim());
  if (allowed.includes("*")) return "*";
  const origin = request.headers.get("Origin") || "";
  for (const a of allowed) {
    if (a === origin) return origin;
    if (a.startsWith("https://*.") && origin.startsWith("https://") && origin.endsWith(a.slice(9))) return origin;
  }
  return null;
}
__name(corsOrigin, "corsOrigin");
function addCors(headers, origin) {
  const h = new Headers(headers || {});
  const o = origin !== void 0 ? origin : _reqOrigin;
  if (o) h.set("Access-Control-Allow-Origin", o);
  for (const [k, v] of Object.entries(CORS_DEFAULTS)) h.set(k, v);
  return h;
}
__name(addCors, "addCors");

// src/kernel/http.js
function json(data, status2 = 200) {
  const headers = { "Content-Type": "application/json", ...CORS_DEFAULTS };
  if (_reqOrigin) headers["Access-Control-Allow-Origin"] = _reqOrigin;
  return new Response(JSON.stringify(data), { status: status2, headers });
}
__name(json, "json");
function oaiError(status2, message, type = "invalid_request_error", code = null) {
  return json({ error: { message, type, param: null, code } }, status2);
}
__name(oaiError, "oaiError");
async function fetchWithTimeout(url, init, ms) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
  }
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}
__name(fetchWithTimeout, "fetchWithTimeout");
async function fetchWithRetry(url, opts = {}, { maxRetries = 3, baseMs = 500, timeoutMs = 1e4 } = {}) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...opts, signal: controller.signal });
      clearTimeout(timer);
      if (res.ok || res.status < 500 || attempt === maxRetries) return res;
    } catch (e) {
      clearTimeout(timer);
      if (attempt === maxRetries) throw e;
    }
    const delay = baseMs * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5);
    await new Promise((r) => setTimeout(r, delay));
  }
}
__name(fetchWithRetry, "fetchWithRetry");

// src/kernel/rate.js
async function checkRate(env, prefix, key, maxPerHour) {
  if (!env.TALK_KV) return false;
  const rateKey = `rate:${prefix}:${key}`;
  const count = parseInt(await env.TALK_KV.get(rateKey) || "0", 10);
  if (count >= maxPerHour) return true;
  await env.TALK_KV.put(rateKey, String(count + 1), { expirationTtl: 3600 });
  return false;
}
__name(checkRate, "checkRate");

// src/kernel/env.js
function requireEnv(env, key, context) {
  const v = env[key];
  if (v === void 0 || v === null || v === "")
    throw new Error(key + " not set in wrangler.toml [vars] (" + context + ")");
  return String(v).trim();
}
__name(requireEnv, "requireEnv");
function requireIntEnv(env, key, context) {
  const v = requireEnv(env, key, context);
  const n = parseInt(v, 10);
  if (isNaN(n)) throw new Error(key + " is not a valid integer (" + context + ")");
  return n;
}
__name(requireIntEnv, "requireIntEnv");
function parseIntEnv(env, key) {
  const v = env[key];
  if (v === void 0 || v === null || v === "") return null;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}
__name(parseIntEnv, "parseIntEnv");
function boolEnv(env, key, fallback = false) {
  const raw = String(env && env[key] !== void 0 ? env[key] : "").trim().toLowerCase();
  if (!raw) return !!fallback;
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}
__name(boolEnv, "boolEnv");
function intEnv(env, key, fallback) {
  const n = parseIntEnv(env, key);
  return Number.isFinite(n) ? n : fallback;
}
__name(intEnv, "intEnv");

// src/kernel/util.js
function clampInt(n, lo, hi) {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}
__name(clampInt, "clampInt");
function clampString(s, maxLen) {
  if (typeof s !== "string") return "";
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + "\u2026";
}
__name(clampString, "clampString");
function redactSecrets(s) {
  if (typeof s !== "string" || !s) return "";
  return s.replace(/Bearer\\s+[A-Za-z0-9._\\-]+/g, "Bearer [REDACTED]").replace(/sk-[A-Za-z0-9_\\-]+/g, "sk-[REDACTED]").replace(/re_[A-Za-z0-9_\\-]+/g, "re_[REDACTED]");
}
__name(redactSecrets, "redactSecrets");
function coerceContentToText(content) {
  if (typeof content === "string") return content;
  if (content && typeof content === "object" && typeof content.text === "string") return content.text;
  if (Array.isArray(content)) {
    const text = content.map((p) => {
      if (!p) return "";
      if (typeof p === "string") return p;
      if (typeof p.text === "string") return p.text;
      if (p.type === "text" && typeof p.text === "string") return p.text;
      if (p.type === "input_text" && typeof p.text === "string") return p.text;
      return "";
    }).filter(Boolean).join("");
    return text || "";
  }
  return "";
}
__name(coerceContentToText, "coerceContentToText");
function extractSessionToken(request) {
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  const url = new URL(request.url);
  return url.searchParams.get("token") || null;
}
__name(extractSessionToken, "extractSessionToken");

// src/domains/gateway/registry.js
function requireGatewayKey(env) {
  return !!(env && env.CANONIC_API_KEY);
}
__name(requireGatewayKey, "requireGatewayKey");
function checkGatewayKey(request, env) {
  if (!requireGatewayKey(env)) return null;
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const tok = m ? m[1].trim() : "";
  if (!tok || tok !== String(env.CANONIC_API_KEY)) return "Unauthorized";
  return null;
}
__name(checkGatewayKey, "checkGatewayKey");
function laneProviderFromHostname(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (h === "anthropic.canonic.org") return "anthropic";
  if (h === "runpod.canonic.org") return "runpod";
  if (h === "vast.canonic.org") return "vastai";
  if (h === "openai.canonic.org") return "openai";
  if (h === "deepseek.canonic.org") return "deepseek";
  return null;
}
__name(laneProviderFromHostname, "laneProviderFromHostname");
function envForLane(hostname, env) {
  const lane = laneProviderFromHostname(hostname);
  if (!lane) return env;
  const out = { ...env, LANE_PROVIDER: lane };
  out.PROVIDER = lane;
  out.FALLBACK_PROVIDER = lane;
  out.PROVIDER_CHAIN = lane;
  if (lane === "runpod") out.MODEL = env.RUNPOD_MODEL || env.MODEL;
  if (lane === "vastai") out.MODEL = env.VASTAI_MODEL || env.MODEL;
  if (lane === "openai") out.MODEL = env.OPENAI_MODEL || env.MODEL;
  if (lane === "deepseek") out.MODEL = env.DEEPSEEK_MODEL || env.MODEL;
  return out;
}
__name(envForLane, "envForLane");
function completionsUrlFromBase(rawBase) {
  const raw = String(rawBase || "").trim();
  if (!raw) return "";
  const base = raw.replace(/\/+$/, "");
  if (base.endsWith("/chat/completions")) return base;
  if (base.endsWith("/v1")) return base + "/chat/completions";
  return base + "/v1/chat/completions";
}
__name(completionsUrlFromBase, "completionsUrlFromBase");
function tokenBoundsForEntry(entry, env) {
  const provider = String(entry && entry.provider || "").toUpperCase();
  const profile2 = String(entry && entry.profile || "talk").toLowerCase();
  const lo = parseIntEnv(env, `${provider}_TOKENS_MIN`) ?? requireIntEnv(env, "TOKENS_MIN", "tokens");
  const hi = parseIntEnv(env, `${provider}_${profile2 === "kilocode" ? "KILOCODE_TOKENS_MAX" : "TOKENS_MAX"}`) ?? parseIntEnv(env, `${provider}_TOKENS_MAX`) ?? (provider === "RUNPOD" ? 512 : requireIntEnv(env, "TOKENS_MAX", "tokens"));
  return { lo, hi };
}
__name(tokenBoundsForEntry, "tokenBoundsForEntry");
function providerHasGatewayConfig(provider, env) {
  const p = String(provider || "").toLowerCase();
  if (p === "anthropic") return !!(env.ANTHROPIC_API_KEY && (env.MODEL || "").trim());
  if (p === "openai") return !!(env.OPENAI_API_KEY && (env.OPENAI_MODEL || env.OPENAI_KILOCODE_MODEL || "").trim());
  if (p === "deepseek") return !!(env.DEEPSEEK_API_KEY && (env.DEEPSEEK_MODEL || env.DEEPSEEK_KILOCODE_MODEL || "").trim());
  if (p === "runpod") return !!(env.RUNPOD_API_KEY && (env.RUNPOD_BASE_URL || env.RUNPOD_KILOCODE_BASE_URL || "").trim() && (env.RUNPOD_MODEL || env.RUNPOD_KILOCODE_MODEL || "").trim());
  if (p === "vastai") return !!(env.VASTAI_BASE_URL || env.VASTAI_KILOCODE_BASE_URL || "").trim() && !!(env.VASTAI_MODEL || env.VASTAI_KILOCODE_MODEL || "").trim();
  return false;
}
__name(providerHasGatewayConfig, "providerHasGatewayConfig");
function hasAliasConfig(env, prefix) {
  for (const k of ["MODEL_ID", "PROVIDER", "UPSTREAM_MODEL", "BASE_URL"]) {
    if (String(env[`${prefix}_${k}`] || "").trim()) return true;
  }
  return false;
}
__name(hasAliasConfig, "hasAliasConfig");
function resolveGatewayAliasEntry(env, spec) {
  const prefix = String(spec?.prefix || "").toUpperCase();
  const profile2 = spec?.profile === "kilocode" ? "kilocode" : "chat";
  const required = !!spec?.required;
  const defaultId = String(spec?.defaultId || `canonic-${profile2}`).trim();
  const defaultProviderOrder = Array.isArray(spec?.defaultProviderOrder) ? spec.defaultProviderOrder : profile2 === "kilocode" ? ["runpod", "deepseek", "openai", "anthropic", "vastai"] : ["deepseek", "anthropic", "openai", "runpod", "vastai"];
  if (!prefix) return null;
  if (!required && !hasAliasConfig(env, prefix)) return null;
  const requestedProvider = String(env[`${prefix}_PROVIDER`] || defaultProviderOrder[0]).toLowerCase().trim();
  const provider = providerHasGatewayConfig(requestedProvider, env) ? requestedProvider : defaultProviderOrder.find((p) => providerHasGatewayConfig(p, env)) || requestedProvider;
  const id = String(env[`${prefix}_MODEL_ID`] || defaultId).trim();
  let upstreamModel = String(env[`${prefix}_UPSTREAM_MODEL`] || "").trim();
  let baseUrl = String(env[`${prefix}_BASE_URL`] || "").trim();
  const providerKeys = {
    anthropic: { model: profile2 === "kilocode" ? "ANTHROPIC_KILOCODE_MODEL" : "MODEL", fallback: "MODEL", baseUrl: "" },
    openai: { model: profile2 === "kilocode" ? "OPENAI_KILOCODE_MODEL" : "OPENAI_MODEL", fallback: "OPENAI_MODEL", base: profile2 === "kilocode" ? "OPENAI_KILOCODE_BASE_URL" : "OPENAI_BASE_URL", baseFallback: "OPENAI_BASE_URL" },
    deepseek: { model: profile2 === "kilocode" ? "DEEPSEEK_KILOCODE_MODEL" : "DEEPSEEK_MODEL", fallback: "DEEPSEEK_MODEL", base: profile2 === "kilocode" ? "DEEPSEEK_KILOCODE_BASE_URL" : "DEEPSEEK_BASE_URL", baseFallback: "DEEPSEEK_BASE_URL" },
    runpod: { model: profile2 === "kilocode" ? "RUNPOD_KILOCODE_MODEL" : "RUNPOD_MODEL", fallback: "RUNPOD_MODEL", base: profile2 === "kilocode" ? "RUNPOD_KILOCODE_BASE_URL" : "RUNPOD_BASE_URL", baseFallback: "RUNPOD_BASE_URL" },
    vastai: { model: profile2 === "kilocode" ? "VASTAI_KILOCODE_MODEL" : "VASTAI_MODEL", fallback: "VASTAI_MODEL", base: profile2 === "kilocode" ? "VASTAI_KILOCODE_BASE_URL" : "VASTAI_BASE_URL", baseFallback: "VASTAI_BASE_URL" }
  };
  const pk = providerKeys[provider];
  if (pk) {
    if (!upstreamModel) upstreamModel = String(env[pk.model] || env[pk.fallback] || "").trim();
    if (provider === "anthropic") {
      baseUrl = "";
    } else if (!baseUrl && pk.base) {
      baseUrl = String(env[pk.base] || env[pk.baseFallback] || "").trim();
    }
  }
  if (!id || !upstreamModel) return null;
  const entry = { id, provider, profile: profile2, upstream_model: upstreamModel };
  if (baseUrl) entry.base_url = baseUrl;
  return entry;
}
__name(resolveGatewayAliasEntry, "resolveGatewayAliasEntry");
function pushGatewayModel(out, seen, entry) {
  if (!entry || typeof entry !== "object") return;
  const id = String(entry.id || "").trim();
  const provider = String(entry.provider || "").trim();
  if (!id || !provider || seen.has(id)) return;
  seen.add(id);
  out.push({ ...entry, id, provider });
}
__name(pushGatewayModel, "pushGatewayModel");
function listGatewayModels(env) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  const specs = [
    { prefix: "CHAT", profile: "chat", defaultId: "canonic-chat", required: true, defaultProviderOrder: ["deepseek", "anthropic", "openai", "runpod", "vastai"] },
    { prefix: "KILOCODE", profile: "kilocode", defaultId: "canonic-kilocode", required: true, defaultProviderOrder: ["runpod", "deepseek", "openai", "anthropic", "vastai"] },
    { prefix: "CHAT_COMMERCIAL", profile: "chat", defaultId: "canonic-chat-commercial", defaultProviderOrder: ["deepseek", "anthropic", "openai", "runpod", "vastai"] },
    { prefix: "CHAT_COMMERCIAL_OPENAI", profile: "chat", defaultId: "canonic-chat-commercial-openai", defaultProviderOrder: ["openai", "deepseek", "anthropic", "runpod", "vastai"] },
    { prefix: "CHAT_COMMERCIAL_ANTHROPIC", profile: "chat", defaultId: "canonic-chat-commercial-anthropic", defaultProviderOrder: ["anthropic", "deepseek", "openai", "runpod", "vastai"] },
    { prefix: "CHAT_OPENSOURCE_RUNPOD", profile: "chat", defaultId: "canonic-chat-opensource-runpod", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_OPENSOURCE_VAST", profile: "chat", defaultId: "canonic-chat-opensource-vast", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_RUNPOD_DEEPSEEK", profile: "chat", defaultId: "canonic-chat-runpod-deepseek", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_RUNPOD_QWEN", profile: "chat", defaultId: "canonic-chat-runpod-qwen", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_RUNPOD_MISTRAL", profile: "chat", defaultId: "canonic-chat-runpod-mistral", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_RUNPOD_LLAMA", profile: "chat", defaultId: "canonic-chat-runpod-llama", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_RUNPOD_GLM", profile: "chat", defaultId: "canonic-chat-runpod-glm", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_VAST_DEEPSEEK", profile: "chat", defaultId: "canonic-chat-vast-deepseek", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_VAST_QWEN", profile: "chat", defaultId: "canonic-chat-vast-qwen", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_VAST_MISTRAL", profile: "chat", defaultId: "canonic-chat-vast-mistral", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_VAST_LLAMA", profile: "chat", defaultId: "canonic-chat-vast-llama", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "CHAT_VAST_GLM", profile: "chat", defaultId: "canonic-chat-vast-glm", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_COMMERCIAL", profile: "kilocode", defaultId: "canonic-kilocode-commercial", defaultProviderOrder: ["openai", "deepseek", "anthropic", "runpod", "vastai"] },
    { prefix: "KILOCODE_OPENSOURCE_RUNPOD", profile: "kilocode", defaultId: "canonic-kilocode-opensource-runpod", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_OPENSOURCE_VAST", profile: "kilocode", defaultId: "canonic-kilocode-opensource-vast", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_RUNPOD_DEEPSEEK", profile: "kilocode", defaultId: "canonic-kilocode-runpod-deepseek", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_RUNPOD_QWEN", profile: "kilocode", defaultId: "canonic-kilocode-runpod-qwen", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_RUNPOD_GLM", profile: "kilocode", defaultId: "canonic-kilocode-runpod-glm", defaultProviderOrder: ["runpod", "vastai", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_VAST_DEEPSEEK", profile: "kilocode", defaultId: "canonic-kilocode-vast-deepseek", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_VAST_QWEN", profile: "kilocode", defaultId: "canonic-kilocode-vast-qwen", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] },
    { prefix: "KILOCODE_VAST_GLM", profile: "kilocode", defaultId: "canonic-kilocode-vast-glm", defaultProviderOrder: ["vastai", "runpod", "deepseek", "openai", "anthropic"] }
  ];
  for (const spec of specs) {
    const entry = resolveGatewayAliasEntry(env, spec);
    if (entry) pushGatewayModel(out, seen, entry);
  }
  const lane = (env.LANE_PROVIDER || "").trim();
  if (lane) return out.filter((m) => m.provider === lane);
  return out;
}
__name(listGatewayModels, "listGatewayModels");
function normalizeResponseInputToMessages(input) {
  if (typeof input === "string") return [{ role: "user", content: input }];
  if (!Array.isArray(input)) return null;
  const out = [];
  for (const item of input) {
    if (!item) continue;
    if (typeof item.role === "string" && item.content !== void 0) {
      const text2 = coerceContentToText(item.content);
      if (text2) out.push({ role: item.role, content: text2 });
      continue;
    }
    if (typeof item.text === "string") {
      out.push({ role: "user", content: item.text });
      continue;
    }
    const text = coerceContentToText(item.content);
    if (text) out.push({ role: "user", content: text });
  }
  return out.length ? out : null;
}
__name(normalizeResponseInputToMessages, "normalizeResponseInputToMessages");
function stableIndexFromKey(key, len) {
  const n = Math.max(1, parseInt(len, 10) || 1);
  const s = String(key || "");
  if (!s) {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      const a = new Uint32Array(1);
      crypto.getRandomValues(a);
      return a[0] % n;
    }
    return Math.floor(Math.random() * n);
  }
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) % n;
}
__name(stableIndexFromKey, "stableIndexFromKey");
function parseModelCsv(raw) {
  return String(raw || "").trim().split(",").map((v) => v.trim()).filter(Boolean);
}
__name(parseModelCsv, "parseModelCsv");
function resolveChatRequestedModel(body, env, registry) {
  const requested = (body && body.model ? String(body.model) : "").trim();
  if (requested) return { model: requested, assigned: false };
  const audience = String(body && (body.audience || body.suite) || "").toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  const autoAssignAudience = audience === "user" || audience === "patient" || audience === "dev" || audience === "experiment";
  if (!(autoAssignAudience || randomize)) return { model: "", assigned: false };
  const configured = audience === "dev" ? parseModelCsv(env.BAKEOFF_DEV_MODELS) : audience === "user" || audience === "patient" ? parseModelCsv(env.BAKEOFF_USER_MODELS) : parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS);
  const fallback = registry.filter((m) => m.profile === "chat").map((m) => m.id);
  const source = configured.length ? configured : fallback;
  const known = new Set(registry.map((m) => m.id));
  const candidates = source.filter((id) => known.has(id));
  if (!candidates.length) return { model: "", assigned: false, error: "No randomized models configured" };
  const key = String(body && (body.patient_id || body.user_id || body.session_id) || "").trim();
  return { model: candidates[stableIndexFromKey(key, candidates.length)], assigned: true };
}
__name(resolveChatRequestedModel, "resolveChatRequestedModel");

// src/domains/providers.js
function maxTokens(env) {
  const lo = requireIntEnv(env, "TOKENS_MIN", "tokens");
  const hi = requireIntEnv(env, "TOKENS_MAX", "tokens");
  const req = parseIntEnv(env, "MAX_TOKENS") ?? hi;
  return clampInt(req, lo, hi);
}
__name(maxTokens, "maxTokens");
function maxTokensFor(providerName, env) {
  const prefix = String(providerName || "").toUpperCase();
  const lo = parseIntEnv(env, `${prefix}_TOKENS_MIN`) ?? requireIntEnv(env, "TOKENS_MIN", "tokens");
  const hi = parseIntEnv(env, `${prefix}_TOKENS_MAX`) ?? requireIntEnv(env, "TOKENS_MAX", "tokens");
  const req = parseIntEnv(env, "MAX_TOKENS") ?? hi;
  return clampInt(req, lo, hi);
}
__name(maxTokensFor, "maxTokensFor");
function timeoutMsFor(providerName, env) {
  if (providerName === "runpod") return requireIntEnv(env, "RUNPOD_TIMEOUT_MS", "runpod");
  if (providerName === "vastai") return parseIntEnv(env, "VASTAI_TIMEOUT_MS") ?? requireIntEnv(env, "PROVIDER_TIMEOUT_MS", "timeout");
  return requireIntEnv(env, "PROVIDER_TIMEOUT_MS", "timeout");
}
__name(timeoutMsFor, "timeoutMsFor");
function parseAnthropicRateLimits(headers) {
  const rl = {};
  const rr = headers.get("anthropic-ratelimit-requests-remaining");
  const rlim = headers.get("anthropic-ratelimit-requests-limit");
  const tr = headers.get("anthropic-ratelimit-tokens-remaining");
  const tlim = headers.get("anthropic-ratelimit-tokens-limit");
  if (rr !== null) rl.requests_remaining = parseInt(rr, 10);
  if (rlim !== null) rl.requests_limit = parseInt(rlim, 10);
  if (tr !== null) rl.tokens_remaining = parseInt(tr, 10);
  if (tlim !== null) rl.tokens_limit = parseInt(tlim, 10);
  const rReset = headers.get("anthropic-ratelimit-requests-reset");
  const tReset = headers.get("anthropic-ratelimit-tokens-reset");
  if (rReset) rl.requests_reset = rReset;
  if (tReset) rl.tokens_reset = tReset;
  return rl;
}
__name(parseAnthropicRateLimits, "parseAnthropicRateLimits");
function parseOpenAIRateLimits(headers) {
  const rl = {};
  const rr = headers.get("x-ratelimit-remaining-requests");
  const rlim = headers.get("x-ratelimit-limit-requests");
  const tr = headers.get("x-ratelimit-remaining-tokens");
  const tlim = headers.get("x-ratelimit-limit-tokens");
  if (rr !== null) rl.requests_remaining = parseInt(rr, 10);
  if (rlim !== null) rl.requests_limit = parseInt(rlim, 10);
  if (tr !== null) rl.tokens_remaining = parseInt(tr, 10);
  if (tlim !== null) rl.tokens_limit = parseInt(tlim, 10);
  const rReset = headers.get("x-ratelimit-reset-requests");
  const tReset = headers.get("x-ratelimit-reset-tokens");
  if (rReset) rl.requests_reset = rReset;
  if (tReset) rl.tokens_reset = tReset;
  return rl;
}
__name(parseOpenAIRateLimits, "parseOpenAIRateLimits");
function preflightDegraded(rl) {
  if (rl.requests_remaining !== void 0 && rl.requests_limit > 0) {
    if (rl.requests_remaining / rl.requests_limit < 0.05) return "requests_low";
  }
  if (rl.tokens_remaining !== void 0 && rl.tokens_limit > 0) {
    if (rl.tokens_remaining / rl.tokens_limit < 0.05) return "tokens_low";
  }
  return null;
}
__name(preflightDegraded, "preflightDegraded");
function runpodEndpointIdFromBaseUrl(baseUrl) {
  if (!baseUrl) return null;
  const m = String(baseUrl).match(/\/v2\/([^/]+)\/openai\/v1\/?$/);
  return m ? m[1] : null;
}
__name(runpodEndpointIdFromBaseUrl, "runpodEndpointIdFromBaseUrl");
function isRunpodProxyBaseUrl(baseUrl) {
  if (!baseUrl) return false;
  return /\.proxy\.runpod\.net\/v1$/.test(String(baseUrl).replace(/\/+$/, ""));
}
__name(isRunpodProxyBaseUrl, "isRunpodProxyBaseUrl");
async function runpodProxyReady(baseUrl, env) {
  const b = String(baseUrl || "").replace(/\/+$/, "");
  if (!b) return null;
  try {
    const r = await fetchWithTimeout(b + "/models", { headers: { "Accept": "application/json" } }, requireIntEnv(env, "RUNPOD_HEALTH_TIMEOUT_MS", "health"));
    return { ok: r.ok, status: r.status };
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return null;
  }
}
__name(runpodProxyReady, "runpodProxyReady");
async function runpodHealth(endpointId, env) {
  const id = String(endpointId || "").trim();
  if (!id) return null;
  try {
    const r = await fetchWithTimeout(`https://api.runpod.ai/v2/${id}/health`, {
      headers: { "Accept": "application/json", "Authorization": String(env.RUNPOD_API_KEY || "") }
    }, requireIntEnv(env, "RUNPOD_HEALTH_TIMEOUT_MS", "health"));
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return null;
  }
}
__name(runpodHealth, "runpodHealth");
var PROVIDERS = {
  anthropic: {
    url: "https://api.anthropic.com/v1/messages",
    validate(env) {
      return env.ANTHROPIC_API_KEY ? null : "ANTHROPIC_API_KEY not configured";
    },
    build(env, system, messages) {
      return {
        headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": env.ANTHROPIC_VERSION },
        body: { model: env.MODEL, max_tokens: maxTokens(env), system, messages }
      };
    },
    parse(data) {
      return data.content?.[0]?.text;
    },
    async preflight(env) {
      const started = Date.now();
      const model = requireEnv(env, "MODEL", "chat");
      if (!env.ANTHROPIC_API_KEY) return { status: "error", key_valid: false, model, error: "ANTHROPIC_API_KEY not configured", elapsed_ms: 0 };
      const timeout = intEnv(env, "PREFLIGHT_TIMEOUT_MS", 5e3);
      try {
        const res = await fetchWithTimeout("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": env.ANTHROPIC_VERSION || "2023-06-01" },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: "user", content: "ping" }] })
        }, timeout);
        const rl = parseAnthropicRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text();
          const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try {
            const j = JSON.parse(text);
            if (j.error && j.error.message) detail = j.error.message;
          } catch (e) {
            console.error("[TALK]", e.message || e);
          }
          const isCredit = res.status === 400 && detail.toLowerCase().includes("credit");
          return { status: isAuth || isCredit ? "error" : "degraded", key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? "degraded" : "ok", key_valid: true, model, ...rl, error: deg || void 0, elapsed_ms: Date.now() - started };
      } catch (e) {
        return { status: "error", key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started };
      }
    }
  },
  openai: {
    url(env) {
      const raw = (env.OPENAI_BASE_URL || "https://api.openai.com/v1").trim();
      if (!raw) return "";
      const base = raw.replace(/\/+$/, "");
      if (base.endsWith("/chat/completions")) return base;
      if (base.endsWith("/v1")) return base + "/chat/completions";
      return base + "/v1/chat/completions";
    },
    validate(env) {
      if (!env.OPENAI_API_KEY) return "OPENAI_API_KEY not configured";
      if ((env.LANE_PROVIDER || "") === "openai" && !(env.OPENAI_MODEL || "").trim()) return "OPENAI_MODEL not configured";
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.OPENAI_API_KEY}` },
        body: { model: env.OPENAI_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: "system", content: system }, ...messages] }
      };
    },
    parse(data) {
      return data.choices?.[0]?.message?.content;
    },
    async preflight(env) {
      const started = Date.now();
      const model = env.OPENAI_MODEL || requireEnv(env, "MODEL", "openai");
      if (!env.OPENAI_API_KEY) return { status: "error", key_valid: false, model, error: "OPENAI_API_KEY not configured", elapsed_ms: 0 };
      const timeout = intEnv(env, "PREFLIGHT_TIMEOUT_MS", 5e3);
      try {
        const url = typeof PROVIDERS.openai.url === "function" ? PROVIDERS.openai.url(env) : PROVIDERS.openai.url;
        const res = await fetchWithTimeout(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.OPENAI_API_KEY}` },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: "user", content: "ping" }] })
        }, timeout);
        const rl = parseOpenAIRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text();
          const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try {
            const j = JSON.parse(text);
            if (j.error && j.error.message) detail = j.error.message;
          } catch (e) {
            console.error("[TALK]", e.message || e);
          }
          return { status: isAuth ? "error" : "degraded", key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? "degraded" : "ok", key_valid: true, model, ...rl, error: deg || void 0, elapsed_ms: Date.now() - started };
      } catch (e) {
        return { status: "error", key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started };
      }
    }
  },
  deepseek: {
    url(env) {
      const raw = (env.DEEPSEEK_BASE_URL || "https://api.deepseek.com/v1").trim();
      if (!raw) return "";
      const base = raw.replace(/\/+$/, "");
      if (base.endsWith("/chat/completions")) return base;
      if (base.endsWith("/v1")) return base + "/chat/completions";
      return base + "/v1/chat/completions";
    },
    validate(env) {
      if (!env.DEEPSEEK_API_KEY) return "DEEPSEEK_API_KEY not configured";
      if ((env.LANE_PROVIDER || "") === "deepseek" && !(env.DEEPSEEK_MODEL || "").trim()) return "DEEPSEEK_MODEL not configured";
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.DEEPSEEK_API_KEY}` },
        body: { model: env.DEEPSEEK_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: "system", content: system }, ...messages] }
      };
    },
    parse(data) {
      return data.choices?.[0]?.message?.content;
    },
    async preflight(env) {
      const started = Date.now();
      const model = env.DEEPSEEK_MODEL || requireEnv(env, "MODEL", "deepseek");
      if (!env.DEEPSEEK_API_KEY) return { status: "error", key_valid: false, model, error: "DEEPSEEK_API_KEY not configured", elapsed_ms: 0 };
      const timeout = intEnv(env, "PREFLIGHT_TIMEOUT_MS", 5e3);
      try {
        const url = typeof PROVIDERS.deepseek.url === "function" ? PROVIDERS.deepseek.url(env) : PROVIDERS.deepseek.url;
        const res = await fetchWithTimeout(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.DEEPSEEK_API_KEY}` },
          body: JSON.stringify({ model, max_tokens: 1, messages: [{ role: "user", content: "ping" }] })
        }, timeout);
        const rl = parseOpenAIRateLimits(res.headers);
        if (!res.ok) {
          const text = await res.text();
          const isAuth = res.status === 401 || res.status === 403;
          let detail = `HTTP ${res.status}`;
          try {
            const j = JSON.parse(text);
            if (j.error && j.error.message) detail = j.error.message;
          } catch (e) {
            console.error("[TALK]", e.message || e);
          }
          return { status: isAuth ? "error" : "degraded", key_valid: !isAuth, model, ...rl, error: clampString(redactSecrets(detail), 200), elapsed_ms: Date.now() - started };
        }
        const deg = preflightDegraded(rl);
        return { status: deg ? "degraded" : "ok", key_valid: true, model, ...rl, error: deg || void 0, elapsed_ms: Date.now() - started };
      } catch (e) {
        return { status: "error", key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started };
      }
    }
  },
  runpod: {
    url(env) {
      const raw = (env.RUNPOD_BASE_URL || "").trim();
      if (!raw) return "";
      const base = raw.replace(/\/+$/, "");
      if (base.endsWith("/chat/completions")) return base;
      return base + "/chat/completions";
    },
    validate(env) {
      if (!env.RUNPOD_API_KEY) return "RUNPOD_API_KEY not configured";
      if (!env.RUNPOD_BASE_URL) return "RUNPOD_BASE_URL not configured";
      return null;
    },
    build(env, system, messages) {
      return {
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.RUNPOD_API_KEY },
        body: { model: env.RUNPOD_MODEL || env.MODEL, max_tokens: maxTokensFor("RUNPOD", env), messages: [{ role: "system", content: system }, ...messages] }
      };
    },
    parse(data) {
      return data.choices?.[0]?.message?.content;
    },
    async preflight(env) {
      const started = Date.now();
      const model = env.RUNPOD_MODEL || env.MODEL;
      if (!env.RUNPOD_API_KEY) return { status: "error", key_valid: false, model, error: "RUNPOD_API_KEY not configured", elapsed_ms: 0 };
      const baseUrl = (env.RUNPOD_BASE_URL || "").trim();
      if (!baseUrl) return { status: "error", key_valid: true, model, error: "RUNPOD_BASE_URL not configured", elapsed_ms: 0 };
      const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
      if (endpointId) {
        const h = await runpodHealth(endpointId, env);
        const w = h && h.workers ? h.workers : null;
        if (!w) return { status: "error", key_valid: true, model, error: "health endpoint unreachable", elapsed_ms: Date.now() - started };
        return { status: (w.ready || 0) >= 1 && (w.throttled || 0) === 0 ? "ok" : "degraded", key_valid: true, model, workers_ready: w.ready || 0, workers_throttled: w.throttled || 0, elapsed_ms: Date.now() - started };
      }
      if (isRunpodProxyBaseUrl(baseUrl)) {
        const pr = await runpodProxyReady(baseUrl, env);
        return { status: pr && pr.ok ? "ok" : "degraded", key_valid: true, model, proxy_ready: pr ? pr.ok : false, elapsed_ms: Date.now() - started };
      }
      return { status: "degraded", key_valid: true, model, error: "unknown endpoint format", elapsed_ms: Date.now() - started };
    }
  },
  vastai: {
    url(env) {
      const raw = (env.VASTAI_BASE_URL || "").trim();
      if (!raw) return "";
      const base = raw.replace(/\/+$/, "");
      if (base.endsWith("/chat/completions")) return base;
      return base + "/chat/completions";
    },
    validate(env) {
      return env.VASTAI_BASE_URL ? null : "VASTAI_BASE_URL not configured";
    },
    build(env, system, messages) {
      const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || "").trim();
      const headers = { "Content-Type": "application/json" };
      if (key) headers.Authorization = "Bearer " + key;
      return { headers, body: { model: env.VASTAI_MODEL || env.MODEL, max_tokens: maxTokensFor("VASTAI", env), messages: [{ role: "system", content: system }, ...messages] } };
    },
    parse(data) {
      return data.choices?.[0]?.message?.content;
    },
    async preflight(env) {
      const started = Date.now();
      const model = env.VASTAI_MODEL || env.MODEL;
      const baseUrl = (env.VASTAI_BASE_URL || "").trim();
      if (!baseUrl) return { status: "error", key_valid: false, model, error: "VASTAI_BASE_URL not configured", elapsed_ms: 0 };
      const timeout = intEnv(env, "PREFLIGHT_TIMEOUT_MS", 5e3);
      const b = baseUrl.replace(/\/+$/, "");
      try {
        const headers = { "Accept": "application/json" };
        const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || "").trim();
        if (key) headers.Authorization = "Bearer " + key;
        const r = await fetchWithTimeout(b + "/models", { headers }, timeout);
        return { status: r.ok ? "ok" : "degraded", key_valid: true, model, proxy_ready: r.ok, elapsed_ms: Date.now() - started };
      } catch (e) {
        return { status: "error", key_valid: false, model, error: clampString(String(e.message || e), 200), elapsed_ms: Date.now() - started };
      }
    }
  }
};
async function preflightAllProviders(env) {
  const chain = env.PROVIDER_CHAIN ? String(env.PROVIDER_CHAIN).split(",").map((s) => s.trim()).filter(Boolean) : [env.PROVIDER];
  const seen = /* @__PURE__ */ new Set();
  const toCheck = [];
  const primaryName = env.PROVIDER;
  if (primaryName && PROVIDERS[primaryName] && PROVIDERS[primaryName].preflight) {
    seen.add(primaryName);
    toCheck.push({ name: primaryName, provider: PROVIDERS[primaryName] });
  }
  for (const name of chain) {
    if (seen.has(name)) continue;
    seen.add(name);
    const p = PROVIDERS[name];
    if (!p || !p.preflight) continue;
    if (!boolEnv(env, `${name.toUpperCase()}_PREFLIGHT_HEALTH`, false)) continue;
    toCheck.push({ name, provider: p });
  }
  const results = {};
  const settled = await Promise.allSettled(toCheck.map(async ({ name, provider }) => ({ name, result: await provider.preflight(env) })));
  for (const s of settled) {
    if (s.status === "fulfilled") results[s.value.name] = s.value.result;
    else results["unknown"] = { status: "error", key_valid: false, model: null, error: String(s.reason), elapsed_ms: 0 };
  }
  const statuses = Object.values(results).map((r) => r.status);
  const overall = statuses.every((s) => s === "ok") ? "ok" : statuses.some((s) => s === "ok") ? "degraded" : "error";
  return { service: "TALK_PREFLIGHT", status: overall, providers: results };
}
__name(preflightAllProviders, "preflightAllProviders");

// src/domains/gateway/dispatch.js
async function oaiModels(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, "authentication_error");
  const models = listGatewayModels(env).map((m) => ({ id: m.id, object: "model", owned_by: "canonic" }));
  return json({ object: "list", data: models });
}
__name(oaiModels, "oaiModels");
async function oaiChatCompletions(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, "authentication_error");
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return oaiError(400, "Invalid JSON");
  }
  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return oaiError(400, "Missing messages");
  const reg = listGatewayModels(env);
  const selection = resolveChatRequestedModel(body, env, reg);
  if (selection.error) return oaiError(400, selection.error);
  const model = selection.model;
  if (!model) return oaiError(400, "Missing model");
  const entry = reg.find((m) => m.id === model) || null;
  if (!entry) return oaiError(400, `Unknown model: ${model || "(empty)"}`, "invalid_request_error", "model_not_found");
  const upstreamModel = (entry.upstream_model || entry.id || "").trim();
  if (!upstreamModel) return oaiError(500, `Model misconfigured: ${entry.id}`);
  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);
  const stream = !!(body && body.stream);
  if (body && body.n && parseInt(body.n, 10) !== 1) return oaiError(400, "Only n=1 is supported");
  const messages = messagesIn.slice(-40).map((m) => ({ role: String(m.role || "").trim(), content: coerceContentToText(m.content) })).filter((m) => m.role && m.content);
  if (!messages.length) return oaiError(400, "No valid messages");
  const timeout_ms = parseIntEnv(env, "OAI_GATEWAY_TIMEOUT_MS") ?? (stream ? 6e5 : 12e4);
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const started = Date.now();
  const allowed = ["temperature", "top_p", "presence_penalty", "frequency_penalty", "stop", "seed"];
  const pass = {};
  for (const k of allowed) {
    if (body && body[k] !== void 0) pass[k] = body[k];
  }
  if (entry.provider === "anthropic") {
    if (!env.ANTHROPIC_API_KEY) return oaiError(500, "ANTHROPIC_API_KEY not configured");
    const sys = messagesIn.filter((m) => m && m.role === "system").map((m) => coerceContentToText(m.content)).filter(Boolean).join("\n\n");
    const anthMessages = messagesIn.filter((m) => m && (m.role === "user" || m.role === "assistant")).slice(-40).map((m) => ({ role: m.role, content: coerceContentToText(m.content) })).filter((m) => m.role && m.content);
    if (!anthMessages.length) return oaiError(400, "No valid user/assistant messages");
    let res2;
    try {
      res2 = await fetchWithTimeout(PROVIDERS.anthropic.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": env.ANTHROPIC_VERSION },
        body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || void 0, messages: anthMessages })
      }, parseIntEnv(env, "OAI_GATEWAY_TIMEOUT_MS") ?? 25e3);
    } catch (e) {
      return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, "api_error");
    }
    const text2 = await res2.text();
    if (!res2.ok) return oaiError(502, `Anthropic ${res2.status}: ${clampString(redactSecrets(text2), 900)}`, "api_error");
    let data;
    try {
      data = JSON.parse(text2);
    } catch (e) {
      console.error("[TALK]", e.message || e);
      return oaiError(502, "Anthropic returned invalid JSON", "api_error");
    }
    const content = data?.content?.[0]?.text ? String(data.content[0].text) : "";
    const h2 = addCors({ "Content-Type": "application/json" });
    h2.set("x-canonic-trace-id", trace_id);
    h2.set("x-canonic-model-profile", entry.profile || "anthropic");
    h2.set("x-canonic-upstream-elapsed-ms", String(Date.now() - started));
    if (selection.assigned) h2.set("x-canonic-assigned-model", model);
    const out = { id: "chatcmpl-canonic-" + trace_id, object: "chat.completion", created: Math.floor(Date.now() / 1e3), model, choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop", logprobs: null }], usage: null };
    if (stream) {
      const sh = addCors({ "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache" });
      sh.set("x-canonic-trace-id", trace_id);
      sh.set("x-canonic-model-profile", entry.profile || "anthropic");
      sh.set("x-canonic-upstream-elapsed-ms", String(Date.now() - started));
      if (selection.assigned) sh.set("x-canonic-assigned-model", model);
      const chunk = { id: out.id, object: "chat.completion.chunk", created: out.created, model: out.model, choices: [{ index: 0, delta: { role: "assistant", content }, finish_reason: null }] };
      const rs = new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}

`));
        controller.enqueue(new TextEncoder().encode(`data: [DONE]

`));
        controller.close();
      } });
      return new Response(rs, { status: 200, headers: sh });
    }
    return new Response(JSON.stringify(out), { status: 200, headers: h2 });
  }
  if (entry.provider === "openai" || entry.provider === "deepseek") {
    const p = PROVIDERS[entry.provider];
    if (!p) return oaiError(500, `Unsupported provider: ${entry.provider}`);
    const providerError = p.validate?.(env);
    if (providerError) return oaiError(500, providerError, "configuration_error");
    const providerUrl = entry.base_url ? completionsUrlFromBase(entry.base_url) : typeof p.url === "function" ? p.url(env) : p.url;
    if (!providerUrl) return oaiError(500, `Provider URL misconfigured: ${entry.provider}`, "configuration_error");
    const payload2 = { model: upstreamModel, messages, max_tokens, stream, ...pass };
    const headers2 = { "Content-Type": "application/json" };
    if (entry.provider === "openai") headers2.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === "deepseek") headers2.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;
    let res2;
    try {
      res2 = await fetchWithTimeout(providerUrl, { method: "POST", headers: headers2, body: JSON.stringify(payload2) }, timeout_ms);
    } catch (e) {
      return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, "api_error");
    }
    const h2 = addCors(res2.headers);
    h2.set("x-canonic-trace-id", trace_id);
    h2.set("x-canonic-model-profile", entry.profile || entry.provider);
    h2.set("x-canonic-upstream-elapsed-ms", String(Date.now() - started));
    if (selection.assigned) h2.set("x-canonic-assigned-model", model);
    if (stream) return new Response(res2.body, { status: res2.status, headers: h2 });
    const text2 = await res2.text();
    if (!res2.ok) return oaiError(502, `${entry.provider === "openai" ? "OpenAI" : "DeepSeek"} ${res2.status}: ${clampString(redactSecrets(text2), 900)}`, "api_error");
    return new Response(text2, { status: 200, headers: h2 });
  }
  const baseUrl = (entry.base_url || "").replace(/\/+$/, "");
  if (!baseUrl) return oaiError(500, `Model misconfigured: ${entry.id}`);
  if (entry.provider === "runpod") {
    if (!env.RUNPOD_API_KEY) return oaiError(500, "RUNPOD_API_KEY not configured");
    if ((parseIntEnv(env, "RUNPOD_PREFLIGHT_HEALTH") ?? 1) === 1) {
      const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
      if (endpointId) {
        const h2 = await runpodHealth(endpointId, env);
        const w = h2?.workers;
        if (w && ((w.ready || 0) < 1 || (w.throttled || 0) > 0)) {
          const resp = oaiError(503, `Model warming up (ready=${w.ready || 0}, throttled=${w.throttled || 0}). Try again shortly.`, "api_error");
          const hh = addCors(resp.headers);
          hh.set("Retry-After", "10");
          return new Response(resp.body, { status: resp.status, headers: hh });
        }
      } else if (isRunpodProxyBaseUrl(baseUrl)) {
        const pr = await runpodProxyReady(baseUrl, env);
        if (!pr || !pr.ok) {
          const resp = oaiError(503, `Model warming up (proxy_ready=${pr ? pr.status : "no_response"}). Try again shortly.`, "api_error");
          const hh = addCors(resp.headers);
          hh.set("Retry-After", "10");
          return new Response(resp.body, { status: resp.status, headers: hh });
        }
      }
    }
  }
  const payload = { model: upstreamModel, messages, max_tokens, stream, ...pass };
  const headers = { "Content-Type": "application/json" };
  if (entry.provider === "runpod") headers.Authorization = "Bearer " + env.RUNPOD_API_KEY;
  else if (entry.provider === "vastai") {
    const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || "").trim();
    if (key) headers.Authorization = "Bearer " + key;
  } else return oaiError(500, `Unsupported provider: ${entry.provider}`);
  let res;
  try {
    res = await fetchWithTimeout(baseUrl + "/chat/completions", { method: "POST", headers, body: JSON.stringify(payload) }, timeout_ms);
  } catch (e) {
    return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, "api_error");
  }
  const h = addCors(res.headers);
  h.set("x-canonic-trace-id", trace_id);
  h.set("x-canonic-model-profile", entry.profile);
  h.set("x-canonic-upstream-elapsed-ms", String(Date.now() - started));
  if (selection.assigned) h.set("x-canonic-assigned-model", model);
  if (stream) return new Response(res.body, { status: res.status, headers: h });
  const text = await res.text();
  if (!res.ok) return oaiError(502, `${entry.provider === "runpod" ? "Runpod" : "VastAI"} ${res.status}: ${clampString(redactSecrets(text), 900)}`, "api_error");
  return new Response(text, { status: 200, headers: h });
}
__name(oaiChatCompletions, "oaiChatCompletions");
async function oaiResponses(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, "authentication_error");
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return oaiError(400, "Invalid JSON");
  }
  const model = (body?.model ? String(body.model) : "").trim();
  const audience = String(body && (body.audience || body.suite) || "").toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  if (!model && !(randomize || ["user", "patient", "dev", "experiment"].includes(audience))) return oaiError(400, "Missing model");
  let messages = null;
  if (body && Array.isArray(body.messages) && body.messages.length) messages = body.messages;
  else if (body && body.input !== void 0) messages = normalizeResponseInputToMessages(body.input);
  if (!messages || !messages.length) return oaiError(400, "Missing messages/input");
  const chatBody = { messages, max_tokens: body.max_output_tokens ?? body.max_tokens, temperature: body.temperature, top_p: body.top_p, presence_penalty: body.presence_penalty, frequency_penalty: body.frequency_penalty, stop: body.stop, seed: body.seed, stream: false, n: 1 };
  if (model) chatBody.model = model;
  if (audience) chatBody.audience = audience;
  if (randomize) chatBody.randomize_model = true;
  if (body?.user_id !== void 0) chatBody.user_id = body.user_id;
  if (body?.patient_id !== void 0) chatBody.patient_id = body.patient_id;
  if (body?.session_id !== void 0) chatBody.session_id = body.session_id;
  const r2 = new Request("https://api.canonic.org/v1/chat/completions", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": request.headers.get("Authorization") || "" }, body: JSON.stringify(chatBody) });
  const chatRes = await oaiChatCompletions(r2, env);
  const text = await chatRes.text();
  if (chatRes.status !== 200) return new Response(text, { status: chatRes.status, headers: addCors(chatRes.headers) });
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return oaiError(502, "Upstream returned invalid JSON", "api_error");
  }
  const content = data?.choices?.[0]?.message ? String(data.choices[0].message.content || "") : "";
  const out = {
    id: "resp-canonic-" + (data.id ? String(data.id).replace(/^chatcmpl-/, "") : String(Date.now())),
    object: "response",
    created: Math.floor(Date.now() / 1e3),
    model,
    output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: content }] }],
    output_text: content,
    usage: data?.usage || null
  };
  const h = addCors({ "Content-Type": "application/json" });
  const trace = chatRes.headers.get("x-canonic-trace-id");
  if (trace) h.set("x-canonic-trace-id", trace);
  const prof = chatRes.headers.get("x-canonic-model-profile");
  if (prof) h.set("x-canonic-model-profile", prof);
  const elapsed = chatRes.headers.get("x-canonic-upstream-elapsed-ms");
  if (elapsed) h.set("x-canonic-upstream-elapsed-ms", elapsed);
  return new Response(JSON.stringify(out), { status: 200, headers: h });
}
__name(oaiResponses, "oaiResponses");
async function callGatewayModel(entry, body, env, trace_id) {
  const started = Date.now();
  const model = entry.id;
  const upstreamModel = (entry.upstream_model || model || "").trim();
  if (!upstreamModel) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, elapsed_ms: Date.now() - started };
  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);
  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return { model, ok: false, status: 400, error: "Missing messages", elapsed_ms: Date.now() - started };
  const messages = messagesIn.slice(-40).map((m) => ({ role: String(m.role || "").trim(), content: coerceContentToText(m.content) })).filter((m) => m.role && m.content);
  if (!messages.length) return { model, ok: false, status: 400, error: "No valid messages", elapsed_ms: Date.now() - started };
  const allowed = ["temperature", "top_p", "presence_penalty", "frequency_penalty", "stop", "seed"];
  const pass = {};
  for (const k of allowed) {
    if (body && body[k] !== void 0) pass[k] = body[k];
  }
  const gov_pre = { provider: entry.provider, profile: entry.profile || null, model, upstream_model: upstreamModel, max_tokens, tokens_min: lo, tokens_max: hi };
  if (entry.provider === "anthropic") {
    if (!env.ANTHROPIC_API_KEY) return { model, ok: false, status: 500, error: "ANTHROPIC_API_KEY not configured", gov_pre, elapsed_ms: Date.now() - started };
    const sys = messagesIn.filter((m) => m?.role === "system").map((m) => coerceContentToText(m.content)).filter(Boolean).join("\n\n");
    const anthMessages = messagesIn.filter((m) => m && (m.role === "user" || m.role === "assistant")).slice(-40).map((m) => ({ role: m.role, content: coerceContentToText(m.content) })).filter((m) => m.role && m.content);
    if (!anthMessages.length) return { model, ok: false, status: 400, error: "No valid user/assistant messages", gov_pre, elapsed_ms: Date.now() - started };
    const timeout_ms2 = parseIntEnv(env, "BAKEOFF_TIMEOUT_MS") ?? 6e4;
    try {
      const res = await fetchWithTimeout(PROVIDERS.anthropic.url, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": env.ANTHROPIC_VERSION }, body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || void 0, messages: anthMessages, temperature: pass.temperature, top_p: pass.top_p, stop_sequences: pass.stop ? Array.isArray(pass.stop) ? pass.stop : [pass.stop] : void 0 }) }, timeout_ms2);
      const text = await res.text();
      if (!res.ok) return { model, ok: false, status: 502, error: `Anthropic ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      const data = JSON.parse(text);
      const content = data?.content?.[0]?.text ? String(data.content[0].text) : "";
      return { model, ok: true, status: 200, content, usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
    } catch (e) {
      return { model, ok: false, status: 502, error: `Anthropic error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
    }
  }
  if (entry.provider === "openai" || entry.provider === "deepseek") {
    const p = PROVIDERS[entry.provider];
    if (!p) return { model, ok: false, status: 500, error: `Unsupported provider: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
    const providerError = p.validate?.(env);
    if (providerError) return { model, ok: false, status: 500, error: providerError, gov_pre, elapsed_ms: Date.now() - started };
    const providerUrl = entry.base_url ? completionsUrlFromBase(entry.base_url) : typeof p.url === "function" ? p.url(env) : p.url;
    if (!providerUrl) return { model, ok: false, status: 500, error: `Provider URL misconfigured: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
    const timeout_ms2 = parseIntEnv(env, "BAKEOFF_TIMEOUT_MS") ?? 12e4;
    const headers2 = { "Content-Type": "application/json" };
    if (entry.provider === "openai") headers2.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === "deepseek") headers2.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;
    try {
      const res = await fetchWithTimeout(providerUrl, { method: "POST", headers: headers2, body: JSON.stringify({ model: upstreamModel, messages, max_tokens, stream: false, ...pass }) }, timeout_ms2);
      const text = await res.text();
      if (!res.ok) return { model, ok: false, status: 502, error: `${entry.provider === "openai" ? "OpenAI" : "DeepSeek"} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      const data = JSON.parse(text);
      return { model, ok: true, status: 200, content: typeof data?.choices?.[0]?.message?.content === "string" ? data.choices[0].message.content : "", usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
    } catch (e) {
      return { model, ok: false, status: 502, error: `${entry.provider === "openai" ? "OpenAI" : "DeepSeek"} error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
    }
  }
  const bUrl = (entry.base_url || "").replace(/\/+$/, "");
  if (!bUrl) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, gov_pre, elapsed_ms: Date.now() - started };
  if (entry.provider === "runpod" && !env.RUNPOD_API_KEY) return { model, ok: false, status: 500, error: "RUNPOD_API_KEY not configured", gov_pre, elapsed_ms: Date.now() - started };
  if (entry.provider === "runpod") {
    const endpointId = runpodEndpointIdFromBaseUrl(bUrl);
    if (endpointId) {
      const h = await runpodHealth(endpointId, env);
      const w = h?.workers;
      if (w && ((w.ready || 0) < 1 || (w.throttled || 0) > 0)) return { model, ok: false, status: 503, error: `warming (ready=${w.ready || 0}, throttled=${w.throttled || 0})`, gov_pre, health: h, elapsed_ms: Date.now() - started };
    } else if (isRunpodProxyBaseUrl(bUrl)) {
      const pr = await runpodProxyReady(bUrl, env);
      if (!pr || !pr.ok) return { model, ok: false, status: 503, error: `warming (proxy_ready=${pr ? pr.status : "no_response"})`, gov_pre, elapsed_ms: Date.now() - started };
    }
  }
  const timeout_ms = parseIntEnv(env, "BAKEOFF_TIMEOUT_MS") ?? 12e4;
  const headers = { "Content-Type": "application/json" };
  if (entry.provider === "runpod") headers.Authorization = "Bearer " + env.RUNPOD_API_KEY;
  else if (entry.provider === "vastai") {
    const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || "").trim();
    if (key) headers.Authorization = "Bearer " + key;
  } else return { model, ok: false, status: 500, error: `Unsupported provider: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };
  try {
    const res = await fetchWithTimeout(bUrl + "/chat/completions", { method: "POST", headers, body: JSON.stringify({ model: upstreamModel, messages, max_tokens, stream: false, ...pass }) }, timeout_ms);
    const text = await res.text();
    if (!res.ok) return { model, ok: false, status: 502, error: `${entry.provider === "runpod" ? "Runpod" : "VastAI"} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
    const data = JSON.parse(text);
    return { model, ok: true, status: 200, content: typeof data?.choices?.[0]?.message?.content === "string" ? data.choices[0].message.content : "", usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
  } catch (e) {
    return { model, ok: false, status: 502, error: `${entry.provider === "runpod" ? "Runpod" : "VastAI"} error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
  }
}
__name(callGatewayModel, "callGatewayModel");

// src/domains/gateway/bakeoff.js
async function oaiBakeoff(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, "authentication_error");
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return oaiError(400, "Invalid JSON");
  }
  const reg = listGatewayModels(env);
  const models = Array.isArray(body.models) ? body.models.map(String).map((s) => s.trim()).filter(Boolean) : [];
  const audience = String(body.audience || body.suite || "").toLowerCase().trim();
  const presetModels = audience === "dev" ? parseModelCsv(env.BAKEOFF_DEV_MODELS) : audience === "user" ? parseModelCsv(env.BAKEOFF_USER_MODELS) : audience === "experiment" ? parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS) : [];
  const defaults = (() => {
    const chat2 = reg.find((m) => m.id === "canonic-chat") || reg.find((m) => m.profile === "chat") || reg[0];
    const kilo = reg.find((m) => m.id === "canonic-kilocode") || reg.find((m) => m.profile === "kilocode");
    const list = [];
    if (chat2?.id) list.push(chat2.id);
    if (kilo?.id) list.push(kilo.id);
    return list;
  })();
  const selected = models.length ? models : presetModels.length ? presetModels : defaults;
  const entries = selected.map(String).map((s) => s.trim()).filter(Boolean).map((id) => reg.find((m) => m.id === id) || null).filter(Boolean);
  if (!entries.length) return oaiError(400, "No valid models requested");
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const parallel = body.parallel !== false;
  const calls = entries.map((e) => callGatewayModel(e, body, env, trace_id));
  const results = parallel ? await Promise.all(calls) : (async () => {
    const out = [];
    for (const c of calls) out.push(await c);
    return out;
  })();
  return json({ object: "bakeoff", trace_id, results });
}
__name(oaiBakeoff, "oaiBakeoff");

// src/domains/chat.js
async function chat(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { message, history = [], system, scope } = body;
  if (!message) return json({ error: "Missing message" }, 400);
  const messages = [];
  for (const msg of history.slice(-10)) {
    if (msg.role && msg.content) messages.push({ role: msg.role, content: msg.content });
  }
  if (!messages.length || messages[messages.length - 1].content !== message) {
    messages.push({ role: "user", content: message });
  }
  const systemPrompt = system || `TALK. Scope: ${scope || "UNGOVERNED"}.`;
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const primary = env.PROVIDER;
  const fallback = requireEnv(env, "FALLBACK_PROVIDER", "chat");
  const chain = env.PROVIDER_CHAIN ? String(env.PROVIDER_CHAIN).split(",").map((s) => s.trim()).filter(Boolean) : primary === "runpod" ? [primary, fallback] : [primary];
  const attempts = [];
  const startedAt = Date.now();
  for (let i = 0; i < chain.length; i++) {
    const name = chain[i];
    const provider = PROVIDERS[name];
    if (!provider) {
      attempts.push({ provider: name, ok: false, error: `Unknown provider: ${name}` });
      continue;
    }
    const providerError = provider.validate?.(env);
    if (providerError) {
      attempts.push({ provider: name, ok: false, error: providerError });
      continue;
    }
    const { headers, body: reqBody } = provider.build(env, systemPrompt, messages);
    const providerUrl = typeof provider.url === "function" ? provider.url(env) : provider.url;
    const ms = timeoutMsFor(name, env);
    const attemptStart = Date.now();
    const gov_pre = {
      provider: name,
      url: providerUrl,
      timeout_ms: ms,
      model: reqBody?.model || null,
      max_tokens: reqBody?.max_tokens || null,
      messages: Array.isArray(reqBody?.messages) ? reqBody.messages.length : null,
      tokens_min: requireIntEnv(env, "TOKENS_MIN", "tokens"),
      tokens_max: requireIntEnv(env, "TOKENS_MAX", "tokens"),
      provider_tokens_max: parseIntEnv(env, `${String(name || "").toUpperCase()}_TOKENS_MAX`)
    };
    let res;
    try {
      const maxTries = name === "runpod" ? parseIntEnv(env, "RUNPOD_TRIES") ?? 2 : name === "vastai" ? parseIntEnv(env, "VASTAI_TRIES") ?? 1 : 1;
      const retryDelayMs = name === "runpod" ? parseIntEnv(env, "RUNPOD_RETRY_DELAY_MS") ?? 750 : name === "vastai" ? parseIntEnv(env, "VASTAI_RETRY_DELAY_MS") ?? 0 : 0;
      let lastErr = null;
      for (let t = 0; t < maxTries; t++) {
        try {
          res = await fetchWithTimeout(providerUrl, { method: "POST", headers, body: JSON.stringify(reqBody) }, ms);
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e;
          if (t + 1 < maxTries && retryDelayMs > 0) await new Promise((r) => setTimeout(r, retryDelayMs));
        }
      }
      if (lastErr) throw lastErr;
    } catch (e) {
      attempts.push({ provider: name, ok: false, elapsed_ms: Date.now() - attemptStart, error: clampString(redactSecrets(String(e?.message || e)), 220), gov_pre });
      continue;
    }
    if (!res || !res.ok) {
      const status2 = res ? res.status : 0;
      const errBody = res ? await res.text() : "";
      const safeErr = redactSecrets(errBody);
      attempts.push({ provider: name, ok: false, elapsed_ms: Date.now() - attemptStart, status: status2, detail: clampString(safeErr, 600), gov_pre, gov_post: { ok: false, status: status2, elapsed_ms: Date.now() - attemptStart } });
      if (status2 >= 500 || status2 === 429 || status2 === 0) continue;
      return json({ error: `${name} ${status2}`, detail: clampString(safeErr, 600), scope, trace_id }, 502);
    }
    const data = await res.json();
    const parsed = provider.parse(data) || "";
    attempts.push({
      provider: name,
      ok: true,
      elapsed_ms: Date.now() - attemptStart,
      gov_pre,
      gov_post: { ok: true, status: res.status, elapsed_ms: Date.now() - attemptStart, usage: data?.usage || null, parsed_chars: typeof parsed === "string" ? parsed.length : 0, schema_ok: typeof parsed === "string" && parsed.length > 0 }
    });
    console.log(JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), path: "/chat", provider: name, status: 200, latency_ms: Date.now() - startedAt, scope, trace_id }));
    return json({
      message: parsed || "No response.",
      scope,
      provider_requested: primary,
      provider_used: name,
      provider_chain: chain,
      attempts,
      usage: data?.usage || null,
      elapsed_ms: Date.now() - startedAt,
      trace_id
    });
  }
  console.log(JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), path: "/chat", provider: "NONE", status: 502, latency_ms: Date.now() - startedAt, scope, trace_id, chain }));
  return json({ error: "All providers failed", scope, provider_chain: chain, attempts, elapsed_ms: Date.now() - startedAt, trace_id }, 502);
}
__name(chat, "chat");

// src/domains/health.js
async function deepHealth(env) {
  const privateSet = new Set((env.GOV_PRIVATE_SCOPES || "").split(",").filter(Boolean));
  const vanity = (env.GOV_VANITY_DOMAINS || "").split(",").filter(Boolean);
  const CACHE_TTL = requireIntEnv(env, "HEALTH_CACHE_TTL_S", "health") * 1e3;
  const BUDGET = requireIntEnv(env, "HEALTH_BUDGET", "health");
  const CACHE_KEY = "health:deep:cache";
  const fleetRoots = requireEnv(env, "GOV_FLEET_ROOTS", "health").split(",").filter(Boolean);
  const sitemap = [];
  const allChecks = [];
  const seen = /* @__PURE__ */ new Set();
  for (const base of fleetRoots) {
    const fleet = new URL(base).hostname.split(".")[0];
    let discovered = false;
    try {
      const resp = await fetch(`${base}/surfaces.json`, { headers: { "User-Agent": "canonic-health/1.0" } });
      if (resp.ok) {
        for (const s of await resp.json()) {
          const url = base + s.path;
          if (seen.has(url)) continue;
          seen.add(url);
          const entry = { scope: s.scope, fleet, urls: [url] };
          if (s.surface_type) entry.surface_type = s.surface_type;
          if (privateSet.has(s.scope)) {
            entry.private = true;
            sitemap.push(entry);
            continue;
          }
          sitemap.push(entry);
          allChecks.push({ url, scope: s.scope });
        }
        discovered = true;
      }
    } catch (e) {
      console.error("[TALK]", e.message || e);
    }
    if (!discovered) {
      const envKey = fleet === "hadleylab" ? "GOV_HADLEYLAB_SCOPES" : "GOV_CANONIC_SCOPES";
      const scopes = (env[envKey] || "").split(",").filter(Boolean);
      const prefix = fleet === "hadleylab" ? `${base}/SERVICES/` : `${base}/`;
      for (const scope of scopes) {
        const url = `${prefix}${scope}/`;
        if (seen.has(url)) continue;
        seen.add(url);
        const entry = { scope, fleet, urls: [url] };
        if (privateSet.has(scope)) {
          entry.private = true;
          sitemap.push(entry);
          continue;
        }
        sitemap.push(entry);
        allChecks.push({ url, scope });
      }
      if (fleet === "hadleylab") {
        for (const rawUrl of (env.GOV_EXTRA_SURFACES || "").split(",").filter(Boolean)) {
          const u = rawUrl.endsWith("/") ? rawUrl : rawUrl + "/";
          if (seen.has(u)) continue;
          seen.add(u);
          const scope = u.replace(/\/$/, "").split("/").pop();
          allChecks.push({ url: u, scope });
          sitemap.push({ scope, fleet, urls: [u] });
        }
      }
    }
  }
  for (const v of vanity) {
    const u = v.endsWith("/") ? v : v + "/";
    if (!seen.has(u)) {
      allChecks.push({ url: u, scope: "_vanity" });
      seen.add(u);
    }
  }
  let cached = {};
  try {
    const raw = env.TALK_KV ? await env.TALK_KV.get(CACHE_KEY) : null;
    if (raw) cached = JSON.parse(raw);
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  const now = Date.now();
  const stale = [];
  const fresh = [];
  for (const c of allChecks) {
    const entry = cached[c.url];
    if (entry && now - entry.ts < CACHE_TTL) fresh.push(entry);
    else stale.push(c);
  }
  const toCheck = stale.slice(0, BUDGET);
  const freshResults = [];
  let aborted = false;
  for (let i = 0; i < toCheck.length; i += 3) {
    if (aborted) break;
    const results = await Promise.allSettled(toCheck.slice(i, i + 3).map(async ({ url, scope }) => {
      try {
        const resp = await fetch(url, { method: "HEAD", headers: { "User-Agent": "canonic-health/1.0" }, redirect: "follow" });
        const code = resp.status;
        return { url, scope, status: code < 400 ? "ok" : "error", detail: code < 400 ? null : `HTTP ${code}`, ts: now };
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes("Too many subrequests")) aborted = true;
        return { url, scope, status: "unreachable", detail: msg, ts: now };
      }
    }));
    for (const r of results) {
      if (r.status === "fulfilled") freshResults.push(r.value);
    }
  }
  for (const r of freshResults) cached[r.url] = r;
  for (const key of Object.keys(cached)) {
    if (now - cached[key].ts > CACHE_TTL * 2) delete cached[key];
  }
  try {
    if (env.TALK_KV) await env.TALK_KV.put(CACHE_KEY, JSON.stringify(cached), { expirationTtl: Math.ceil(CACHE_TTL * 2 / 1e3) });
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  const surfaces = [];
  const checkedUrls = new Set(freshResults.map((r) => r.url));
  for (const r of freshResults) surfaces.push({ url: r.url, scope: r.scope, status: r.status, detail: r.detail || void 0 });
  for (const f of fresh) {
    if (!checkedUrls.has(f.url)) surfaces.push({ url: f.url, scope: f.scope, status: f.status, detail: f.detail || void 0, cached: `${Math.round((now - f.ts) / 1e3)}s ago` });
  }
  for (const sm of sitemap) {
    if (sm.private) surfaces.push({ url: sm.urls[0], scope: sm.scope, status: "private", detail: "no public surface (by design)" });
  }
  const allCovered = new Set(surfaces.map((s) => s.url));
  for (const c of allChecks) {
    if (!allCovered.has(c.url)) surfaces.push({ url: c.url, scope: c.scope, status: "pending", detail: "queued for next rotation" });
  }
  const services2 = [];
  const svcViolations = [];
  const primary = env.PROVIDER;
  const primaryProvider = PROVIDERS[primary];
  if (!primaryProvider) {
    services2.push({ service: "TALK", status: "error", detail: `Unknown provider: ${primary}` });
    svcViolations.push({ type: "SERVICE_ERROR", service: "TALK", detail: `Unknown provider: ${primary}` });
  } else {
    const valErr = primaryProvider.validate?.(env);
    if (valErr) {
      services2.push({ service: "TALK", status: "error", detail: valErr });
      svcViolations.push({ type: "SERVICE_ERROR", service: "TALK", detail: valErr });
    } else services2.push({ service: "TALK", status: "ok", provider: primary, model: env.MODEL });
  }
  const chain = env.PROVIDER_CHAIN ? String(env.PROVIDER_CHAIN).split(",").map((s) => s.trim()).filter(Boolean) : [primary];
  const chainStatus = chain.map((name) => {
    const p = PROVIDERS[name];
    if (!p) return { provider: name, status: "error", detail: "unknown provider" };
    const err = p.validate?.(env);
    return err ? { provider: name, status: "error", detail: err } : { provider: name, status: "ok" };
  });
  services2.push({ service: "TALK_CHAIN", status: chainStatus.every((c) => c.status === "ok") ? "ok" : chainStatus.some((c) => c.status === "ok") ? "degraded" : "error", chain: chainStatus });
  for (const c of chainStatus) {
    if (c.status === "error") svcViolations.push({ type: "SERVICE_ERROR", service: `TALK_CHAIN/${c.provider}`, detail: c.detail });
  }
  if (boolEnv(env, "PREFLIGHT_HEALTH", false)) {
    const PREFLIGHT_CACHE_KEY = "health:preflight:cache";
    const PREFLIGHT_TTL = requireIntEnv(env, "PREFLIGHT_CACHE_TTL_S", "preflight") * 1e3;
    let preflightResult = null;
    try {
      const raw = env.TALK_KV ? await env.TALK_KV.get(PREFLIGHT_CACHE_KEY) : null;
      if (raw) {
        const c = JSON.parse(raw);
        if (c?.ts && now - c.ts < PREFLIGHT_TTL) {
          preflightResult = c;
          preflightResult._cached = true;
          preflightResult._cached_age_s = Math.round((now - c.ts) / 1e3);
        }
      }
    } catch (e) {
      console.error("[TALK_KV]", e.message || e);
    }
    if (!preflightResult) {
      try {
        preflightResult = await preflightAllProviders(env);
        preflightResult.ts = now;
        if (env.TALK_KV) try {
          await env.TALK_KV.put(PREFLIGHT_CACHE_KEY, JSON.stringify(preflightResult), { expirationTtl: Math.ceil(PREFLIGHT_TTL * 2 / 1e3) });
        } catch (e) {
          console.error("[TALK_KV]", e.message || e);
        }
      } catch (e) {
        preflightResult = { service: "TALK_PREFLIGHT", status: "error", error: String(e.message || e) };
      }
    }
    services2.push(preflightResult);
    if (preflightResult.providers) {
      for (const [pName, pResult] of Object.entries(preflightResult.providers)) {
        if (pResult.status === "error") svcViolations.push({ type: "PREFLIGHT_ERROR", service: `TALK_PREFLIGHT/${pName}`, detail: pResult.error || `${pName} preflight failed` });
      }
    }
  }
  try {
    if (env.TALK_KV) {
      const tk = "health:kv:probe";
      await env.TALK_KV.put(tk, "1", { expirationTtl: 60 });
      const v = await env.TALK_KV.get(tk);
      services2.push({ service: "KV", status: v === "1" ? "ok" : "error", detail: v === "1" ? null : "read-back mismatch" });
    } else {
      services2.push({ service: "KV", status: "error", detail: "TALK_KV binding missing" });
      svcViolations.push({ type: "SERVICE_ERROR", service: "KV", detail: "TALK_KV binding missing" });
    }
  } catch (e) {
    services2.push({ service: "KV", status: "error", detail: String(e.message || e) });
    svcViolations.push({ type: "SERVICE_ERROR", service: "KV", detail: String(e.message || e) });
  }
  if (env.GITHUB_CLIENT_ID) services2.push({ service: "AUTH", status: "ok" });
  else {
    services2.push({ service: "AUTH", status: "error", detail: "GITHUB_CLIENT_ID missing" });
    svcViolations.push({ type: "SERVICE_ERROR", service: "AUTH", detail: "GITHUB_CLIENT_ID missing" });
  }
  if (env.RESEND_API_KEY) services2.push({ service: "EMAIL", status: "ok" });
  else {
    services2.push({ service: "EMAIL", status: "error", detail: "RESEND_API_KEY missing" });
    svcViolations.push({ type: "SERVICE_ERROR", service: "EMAIL", detail: "RESEND_API_KEY missing" });
  }
  if (env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET) services2.push({ service: "SHOP", status: "ok" });
  else {
    const missing = [!env.STRIPE_SECRET_KEY && "STRIPE_SECRET_KEY", !env.STRIPE_WEBHOOK_SECRET && "STRIPE_WEBHOOK_SECRET"].filter(Boolean);
    services2.push({ service: "SHOP", status: "error", detail: `Missing: ${missing.join(", ")}` });
    svcViolations.push({ type: "SERVICE_ERROR", service: "SHOP", detail: `Missing: ${missing.join(", ")}` });
  }
  const allPublicScopes = allChecks.map((c) => c.scope).filter((s) => s !== "_vanity");
  services2.push({ service: "TALK_SCOPES", status: "ok", count: allPublicScopes.length, scopes: allPublicScopes.map((s) => ({ scope: s, status: "ok" })) });
  const INTEL_TTL = requireIntEnv(env, "HEALTH_INTEL_TTL_S", "intel") * 1e3;
  const INTEL_CACHE_KEY = "health:intel:cache";
  let intelCached = {};
  try {
    const raw = env.TALK_KV ? await env.TALK_KV.get(INTEL_CACHE_KEY) : null;
    if (raw) intelCached = JSON.parse(raw);
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  const accessibleUrls = surfaces.filter((s) => s.status === "ok" || s.cached && s.status === "ok").map((s) => s.url);
  const intelStale = [];
  for (const url of accessibleUrls) {
    const entry = intelCached[url];
    if (entry && now - entry.ts < INTEL_TTL) continue;
    intelStale.push(url);
  }
  const intelFresh = [];
  for (const surfaceUrl of intelStale) {
    const canonUrl = surfaceUrl + "CANON.json";
    const scope = surfaceUrl.replace(/\/$/, "").split("/").pop();
    try {
      const resp = await fetch(canonUrl, { headers: { "User-Agent": "canonic-health/1.0" } });
      if (!resp.ok) {
        intelFresh.push({ url: surfaceUrl, scope, status: "skip", detail: `CANON.json HTTP ${resp.status}`, ts: now });
        continue;
      }
      const canon = await resp.json();
      const controls = canon.controls || {};
      const render = { surface_type: canon.surface_type || "unknown", view: controls.view || "web", talk: controls.talk || "side", gate: controls.gate || void 0, downloads: [] };
      for (const dl of controls.downloads || []) {
        try {
          const dlResp = await fetch(new URL(dl.href, surfaceUrl).href, { method: "HEAD", headers: { "User-Agent": "canonic-health/1.0" } });
          render.downloads.push({ label: dl.label, href: dl.href, status: dlResp.ok ? "ok" : "error", detail: dlResp.ok ? void 0 : `HTTP ${dlResp.status}` });
        } catch (e) {
          render.downloads.push({ label: dl.label, href: dl.href, status: "error", detail: String(e.message || e) });
        }
      }
      if (!canon.systemPrompt || !canon.scope) {
        intelFresh.push({ url: surfaceUrl, scope, status: "invalid", detail: "missing systemPrompt or scope", render, ts: now });
        continue;
      }
      const welcome = canon.welcome || "";
      const genericWelcome = `Welcome to **${canon.scope}**`;
      const welcomeInContext = welcome.length > 0 && (welcome.length > genericWelcome.length + 80 || /\[.*\]\(|evidence|govern|sourced|clinical|trial|NCT|BI-RADS|mCODE/i.test(welcome));
      if (!canon.test || !canon.test.prompts || !canon.test.prompts.length) {
        intelFresh.push({ url: surfaceUrl, scope, status: "no_test", render, ts: now });
        continue;
      }
      const prompts = canon.test.prompts;
      const promptResults = [];
      let scopeElapsed = 0;
      let subrequestExhausted = false;
      for (const fixture of prompts) {
        try {
          const chatReq = new Request("https://internal/chat", { method: "POST", body: JSON.stringify({ message: fixture.prompt, scope: canon.scope, system: canon.systemPrompt }), headers: { "Content-Type": "application/json" } });
          const chatStart = Date.now();
          const chatResp = await chat(chatReq, env);
          const elapsed_ms = Date.now() - chatStart;
          scopeElapsed += elapsed_ms;
          if (!chatResp.ok) {
            promptResults.push({ prompt: fixture.prompt, status: "chat_error", elapsed_ms });
            continue;
          }
          const chatData = await chatResp.json();
          const responseText = (chatData.message || "").toLowerCase();
          const expectHit = fixture.expect.filter((e) => responseText.includes(e.toLowerCase())).length;
          const crossArr = fixture.cross || [];
          const crossHit = crossArr.filter((c) => responseText.includes(c.toLowerCase())).length;
          const threshold = Math.ceil(fixture.expect.length * 0.5);
          const pStatus = expectHit >= threshold ? crossArr.length === 0 || crossHit >= 1 ? "ok" : "weak" : "fail";
          promptResults.push({ prompt: fixture.prompt, status: pStatus, expect_hit: expectHit, expect_total: fixture.expect.length, cross_hit: crossHit, cross_total: crossArr.length, missing: fixture.expect.filter((e) => !responseText.includes(e.toLowerCase())).length ? fixture.expect.filter((e) => !responseText.includes(e.toLowerCase())) : void 0, missing_cross: crossArr.filter((c) => !responseText.includes(c.toLowerCase())).length ? crossArr.filter((c) => !responseText.includes(c.toLowerCase())) : void 0, elapsed_ms });
        } catch (promptErr) {
          const pmsg = String(promptErr.message || promptErr);
          if (pmsg.includes("Too many subrequests")) {
            subrequestExhausted = true;
            break;
          }
          promptResults.push({ prompt: fixture.prompt, status: "chat_error", detail: pmsg });
        }
      }
      const hasFail = promptResults.some((p) => p.status === "fail");
      const hasWeak = promptResults.some((p) => p.status === "weak");
      const hasError = promptResults.some((p) => p.status === "chat_error");
      let intelStatus = hasFail ? "fail" : hasWeak ? "weak" : hasError ? "chat_error" : "ok";
      if (intelStatus === "ok" && !welcomeInContext) intelStatus = "weak";
      const detailParts = [];
      if (intelStatus !== "ok") {
        for (const p of promptResults) {
          if (p.missing) detailParts.push(...p.missing);
          if (p.missing_cross) detailParts.push(...p.missing_cross.map((c) => `cross:${c}`));
        }
      }
      if (!welcomeInContext) detailParts.push("welcome:generic");
      intelFresh.push({
        url: surfaceUrl,
        scope,
        status: promptResults.length ? intelStatus : "error",
        render,
        prompts_tested: promptResults.length,
        prompts_total: prompts.length,
        prompts_passed: promptResults.filter((p) => p.status === "ok").length,
        expect_hit: promptResults.reduce((s, p) => s + (p.expect_hit || 0), 0),
        expect_total: promptResults.reduce((s, p) => s + (p.expect_total || 0), 0),
        cross_hit: promptResults.reduce((s, p) => s + (p.cross_hit || 0), 0),
        cross_total: promptResults.reduce((s, p) => s + (p.cross_total || 0), 0),
        welcome_in_context: welcomeInContext,
        detail: detailParts.length ? `missing: ${[...new Set(detailParts)].join(", ")}` : void 0,
        prompt_details: promptResults,
        elapsed_ms: scopeElapsed,
        ts: now
      });
      if (subrequestExhausted) break;
    } catch (e) {
      if (String(e.message || e).includes("Too many subrequests")) break;
      intelFresh.push({ url: surfaceUrl, scope, status: "error", detail: String(e.message || e), ts: now });
    }
  }
  for (const r of intelFresh) {
    if (r.prompts_total && r.prompts_tested < r.prompts_total) continue;
    intelCached[r.url] = r;
  }
  for (const key of Object.keys(intelCached)) {
    if (now - intelCached[key].ts > INTEL_TTL * 2) delete intelCached[key];
  }
  try {
    if (env.TALK_KV) await env.TALK_KV.put(INTEL_CACHE_KEY, JSON.stringify(intelCached), { expirationTtl: Math.ceil(INTEL_TTL * 2 / 1e3) });
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  const intelChecks = [];
  const intelDiscovered = /* @__PURE__ */ new Set();
  for (const r of intelFresh) {
    if (r.status === "no_test" || r.status === "skip") continue;
    intelChecks.push({ scope: r.scope, status: r.status, prompts_tested: r.prompts_tested, prompts_total: r.prompts_total, prompts_passed: r.prompts_passed, expect_hit: r.expect_hit, expect_total: r.expect_total, cross_hit: r.cross_hit, cross_total: r.cross_total, welcome_in_context: r.welcome_in_context, detail: r.detail, prompt_details: r.prompt_details, elapsed_ms: r.elapsed_ms });
    intelDiscovered.add(r.url);
  }
  for (const [url, entry] of Object.entries(intelCached)) {
    if (intelFresh.some((r) => r.url === url)) continue;
    if (entry.status === "no_test" || entry.status === "skip") continue;
    if (now - entry.ts < INTEL_TTL) {
      intelChecks.push({ scope: entry.scope, status: entry.status, prompts_tested: entry.prompts_tested, prompts_total: entry.prompts_total, prompts_passed: entry.prompts_passed, expect_hit: entry.expect_hit, expect_total: entry.expect_total, cross_hit: entry.cross_hit, cross_total: entry.cross_total, welcome_in_context: entry.welcome_in_context, detail: entry.detail, prompt_details: entry.prompt_details, cached: `${Math.round((now - entry.ts) / 1e3)}s ago`, elapsed_ms: entry.elapsed_ms });
      intelDiscovered.add(url);
    }
  }
  const renderChecks = [];
  for (const [, entry] of Object.entries(intelCached)) {
    if (!entry.render) continue;
    const r = entry.render;
    const dlBroken = (r.downloads || []).filter((d) => d.status !== "ok");
    renderChecks.push({ scope: entry.scope, surface_type: r.surface_type, view: r.view, talk: r.talk, gate: r.gate || void 0, downloads: r.downloads.length, downloads_ok: r.downloads.filter((d) => d.status === "ok").length, downloads_broken: dlBroken.length ? dlBroken : void 0 });
  }
  const probed = surfaces.filter((s) => s.status !== "private" && s.status !== "pending");
  const okCount = probed.filter((s) => s.status === "ok").length;
  const pending = surfaces.filter((s) => s.status === "pending").length;
  const privateCount = surfaces.filter((s) => s.status === "private").length;
  const noTestCount = Object.values(intelCached).filter((e) => e.status === "no_test" && now - e.ts < INTEL_TTL).length;
  const violations = [
    ...probed.filter((s) => s.status === "error" || s.status === "unreachable").map((s) => ({ type: "SURFACE_ERROR", scope: s.scope, url: s.url, detail: s.detail })),
    ...svcViolations,
    ...intelChecks.filter((c) => c.status === "fail").map((c) => ({ type: "INTEL_FAIL", scope: c.scope, detail: c.detail })),
    ...renderChecks.filter((r) => r.downloads_broken?.length).map((r) => ({ type: "DOWNLOAD_BROKEN", scope: r.scope, detail: r.downloads_broken.map((d) => `${d.label}: ${d.detail}`).join(", ") }))
  ];
  const overall = violations.length > 0 ? "degraded" : pending > 0 ? "warming" : "ok";
  return json({
    status: overall,
    provider: env.PROVIDER,
    model: env.MODEL,
    ts: now,
    total: allChecks.length + privateCount,
    checked: probed.length,
    ok: okCount,
    private: privateCount || void 0,
    pending: pending || void 0,
    services: { total: services2.length, ok: services2.filter((s) => s.status === "ok").length, checks: services2 },
    intel: { total: accessibleUrls.length, tested: intelChecks.filter((c) => ["ok", "weak", "fail"].includes(c.status)).length, passed: intelChecks.filter((c) => c.status === "ok").length, weak: intelChecks.filter((c) => c.status === "weak").length || void 0, failed: intelChecks.filter((c) => c.status === "fail").length || void 0, pending: accessibleUrls.length - intelDiscovered.size - noTestCount > 0 ? accessibleUrls.length - intelDiscovered.size - noTestCount : void 0, checks: intelChecks.length ? intelChecks : void 0 },
    render: { total: renderChecks.length, checks: renderChecks.length ? renderChecks : void 0 },
    sitemap,
    surfaces,
    violations: violations.length ? violations : void 0
  });
}
__name(deepHealth, "deepHealth");

// src/kernel/crypto.js
async function sha256(message) {
  const data = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256, "sha256");
function sanitize(str) {
  if (!str || typeof str !== "string") return str;
  return str.replace(/<[^>]*>/g, "").trim();
}
__name(sanitize, "sanitize");

// src/kernel/ledger.js
async function appendToLedger(env, type, scope, fields, { key: overrideKey } = {}) {
  if (!env.TALK_KV) return null;
  const key = overrideKey || `ledger:${type}:${scope}`;
  let ledger2 = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger2 = JSON.parse(raw);
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  const ts = (/* @__PURE__ */ new Date()).toISOString();
  const prev = ledger2.length ? ledger2[ledger2.length - 1].id : "000000000000";
  const id = await sha256(`${ts}:${type}:${scope}:${prev}:${JSON.stringify(fields)}`);
  const entry = { id, prev, ts, type, scope, ...fields };
  ledger2.push(entry);
  if (ledger2.length > 1e3) {
    const epoch = Math.floor(Date.now() / 1e3);
    const overflow = ledger2.slice(0, ledger2.length - 1e3);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(overflow));
    ledger2 = ledger2.slice(-1e3);
  }
  await env.TALK_KV.put(key, JSON.stringify(ledger2));
  return { id, ts, entries: ledger2.length };
}
__name(appendToLedger, "appendToLedger");

// src/domains/auth.js
function authConfig(env) {
  if (!env.GITHUB_CLIENT_ID) return json({ error: "GITHUB_CLIENT_ID not configured" }, 500);
  return json({ github_client_id: env.GITHUB_CLIENT_ID, scopes: "read:user" });
}
__name(authConfig, "authConfig");
async function authGitHub(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { code, redirect_uri } = body;
  if (!code) return json({ error: "Missing code" }, 400);
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return json({ error: "GitHub OAuth not configured" }, 500);
  const tokenRes = await fetchWithRetry("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri })
  }, { maxRetries: 2, timeoutMs: 1e4 });
  const tokenData = await tokenRes.json();
  if (tokenData.error) return json({ error: tokenData.error_description || tokenData.error }, 401);
  const userRes = await fetchWithRetry("https://api.github.com/user", {
    headers: { "Authorization": `Bearer ${tokenData.access_token}`, "User-Agent": "CANONIC-KYC", "Accept": "application/json" }
  }, { maxRetries: 2, timeoutMs: 1e4 });
  if (!userRes.ok) return json({ error: "Failed to fetch GitHub user" }, 502);
  const user = await userRes.json();
  const sessionToken = crypto.randomUUID();
  const session = {
    user: user.login,
    github_uid: user.id,
    name: user.name,
    avatar_url: user.avatar_url,
    org: "hadleylab",
    ts: (/* @__PURE__ */ new Date()).toISOString(),
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1e3).toISOString()
  };
  if (env.TALK_KV) {
    await env.TALK_KV.put(`session:${sessionToken}`, JSON.stringify(session), { expirationTtl: 7 * 24 * 60 * 60 });
    await appendToLedger(env, "AUTH", "AUTH", { event: "login", user: user.login, github_uid: user.id, provider: "github", work_ref: `login:${user.login}` });
  }
  return json({
    session_token: sessionToken,
    user: user.login,
    name: user.name,
    avatar_url: user.avatar_url,
    provenance: { provider: "github", uid: user.id, verified_at: session.ts, gate: "MAGIC-KYC" }
  });
}
__name(authGitHub, "authGitHub");
async function authSession(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: "Missing session token" }, 401);
  if (!env.TALK_KV) return json({ error: "KV not configured" }, 500);
  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ error: "Invalid or expired session" }, 401);
  const session = JSON.parse(raw);
  if (new Date(session.expires) < /* @__PURE__ */ new Date()) {
    await env.TALK_KV.delete(`session:${token}`);
    return json({ error: "Session expired" }, 401);
  }
  return json({
    user: session.user,
    github_uid: session.github_uid,
    name: session.name,
    avatar_url: session.avatar_url,
    org: session.org,
    ts: session.ts,
    expires: session.expires
  });
}
__name(authSession, "authSession");
async function authLogout(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: "Missing session token" }, 401);
  if (env.TALK_KV) {
    const raw = await env.TALK_KV.get(`session:${token}`);
    if (raw) {
      const session = JSON.parse(raw);
      await env.TALK_KV.delete(`session:${token}`);
      await appendToLedger(env, "AUTH", "AUTH", { event: "logout", user: session.user, work_ref: `logout:${session.user}` });
    }
  }
  return json({ ok: true });
}
__name(authLogout, "authLogout");
async function authGrants(request, env) {
  const url = new URL(request.url);
  const scope = url.searchParams.get("scope");
  if (!scope) return json({ error: "Missing scope parameter" }, 400);
  const token = extractSessionToken(request);
  if (!token) return json({ granted: false, reason: "no_session" });
  if (!env.TALK_KV) return json({ error: "KV not configured" }, 500);
  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ granted: false, reason: "invalid_session" });
  const session = JSON.parse(raw);
  if (new Date(session.expires) < /* @__PURE__ */ new Date()) return json({ granted: false, reason: "expired_session" });
  const canonRaw = await env.TALK_KV.get(`canon:${scope}`);
  if (!canonRaw) return json({ granted: true, user: session.user, reason: "org_member_default" });
  const canon = JSON.parse(canonRaw);
  if (!canon.privacy || canon.privacy === "PUBLIC") return json({ granted: true, user: session.user, reason: "public_scope" });
  const readers = canon.readers || [];
  if (readers.length === 0) return json({ granted: true, user: session.user, reason: "org_member" });
  if (readers.includes("*") || readers.includes(session.user)) return json({ granted: true, user: session.user, reason: "reader" });
  if (env.TALK_KV) {
    await env.TALK_KV.put(
      `auth:deny:${session.user}:${scope}:${Date.now()}`,
      JSON.stringify({ user: session.user, scope, ts: (/* @__PURE__ */ new Date()).toISOString() }),
      { expirationTtl: 30 * 24 * 60 * 60 }
    );
  }
  return json({ granted: false, user: session.user, reason: "not_reader" });
}
__name(authGrants, "authGrants");
async function galaxyAuth(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: "unauthorized" }, 401);
  const sessRaw = await env.TALK_KV.get(`session:${token}`);
  if (!sessRaw) return json({ error: "unauthorized" }, 401);
  const sess = JSON.parse(sessRaw);
  if (new Date(sess.expires) < /* @__PURE__ */ new Date()) return json({ error: "session expired" }, 401);
  const raw = await env.TALK_KV.get("galaxy:auth");
  if (!raw) return json({ nodes: [], edges: [] });
  const data = JSON.parse(raw);
  const user = sess.user;
  const visible = data.nodes.filter((n) => {
    const readers = n.readers || [];
    return readers.length === 0 || readers.includes("*") || readers.includes(user);
  });
  const visIds = new Set(visible.map((n) => n.id));
  const visEdges = data.edges.filter((e) => visIds.has(e.from) || visIds.has(e.to));
  return json({ nodes: visible, edges: visEdges });
}
__name(galaxyAuth, "galaxyAuth");
async function requireSession(request, env) {
  const token = extractSessionToken(request);
  if (!token) return { error: json({ error: "Missing session token" }, 401) };
  const sessRaw = await env.TALK_KV.get(`session:${token}`);
  if (!sessRaw) return { error: json({ error: "Invalid or expired session" }, 401) };
  const sess = JSON.parse(sessRaw);
  if (new Date(sess.expires) < /* @__PURE__ */ new Date()) return { error: json({ error: "Session expired" }, 401) };
  return { session: sess };
}
__name(requireSession, "requireSession");

// src/kernel/email.js
async function sendEmail(env, { from, to, subject, html, cc, bcc, reply_to, attachments }) {
  if (!env.RESEND_API_KEY) return { ok: false, error: "RESEND_API_KEY not configured" };
  const sender = from || env.EMAIL_FROM || "founder@canonic.org";
  const recipient = Array.isArray(to) ? to : [to];
  const payload = { from: sender, to: recipient, subject, html };
  if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];
  const senderAddr = sender.includes("<") ? sender.match(/<([^>]+)>/)?.[1] || sender : sender;
  const bccList = bcc ? Array.isArray(bcc) ? [...bcc] : [bcc] : [];
  if (!bccList.includes(senderAddr)) bccList.push(senderAddr);
  payload.bcc = bccList;
  if (reply_to) payload.reply_to = reply_to;
  if (attachments) payload.attachments = attachments;
  try {
    const res = await fetchWithRetry("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.RESEND_API_KEY}` },
      body: JSON.stringify(payload)
    }, { maxRetries: 2, timeoutMs: 1e4 });
    if (!res.ok) return { ok: false, status: res.status, error: await res.text() };
    const data = await res.json();
    return { ok: true, id: data.id };
  } catch (e) {
    console.error("[EMAIL]", e.message || e);
    return { ok: false, error: String(e.message || e) };
  }
}
__name(sendEmail, "sendEmail");

// src/domains/email.js
async function handle(request, env) {
  if (!env.RESEND_API_KEY) return json({ error: "RESEND_API_KEY not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { to, subject, html, from, cc, bcc, reply_to } = body;
  if (!to || !subject || !html) return json({ error: "Missing to, subject, or html" }, 400);
  const result = await sendEmail(env, { from, to, subject, html, cc, bcc, reply_to, attachments: body.attachments });
  if (!result.ok) return json({ error: `Resend ${result.status || "error"}`, detail: result.error }, 502);
  const recipient = Array.isArray(to) ? to[0] : to;
  const sender = from || env.EMAIL_FROM || "founder@canonic.org";
  const ledgerResult = await appendToLedger(env, "EMAIL", body.scope || "EMAIL", {
    to: recipient,
    subject,
    from: sender,
    work_ref: result.id
  });
  return json({ sent: true, id: result.id, to: recipient, subject, ledger: ledgerResult });
}
__name(handle, "handle");

// src/domains/shop.js
function stripeApiBase(env) {
  return String(env.STRIPE_API_BASE || "https://api.stripe.com").replace(/\/+$/, "");
}
__name(stripeApiBase, "stripeApiBase");
async function stripeApiRequest(env, method, path, formFields) {
  if (!env.STRIPE_SECRET_KEY) return { ok: false, status: 500, error: "STRIPE_SECRET_KEY not configured" };
  const headers = { "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}` };
  let body = null;
  if (formFields && typeof formFields === "object") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(formFields)) {
      if (v === void 0 || v === null || v === "") continue;
      params.set(k, String(v));
    }
    body = params.toString();
  }
  try {
    const res = await fetchWithRetry(stripeApiBase(env) + path, { method, headers, body }, { maxRetries: 2, timeoutMs: 15e3 });
    const raw = await res.text();
    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      console.error("[TALK]", e.message || e);
      data = { raw };
    }
    if (!res.ok) {
      const msg = data && data.error && data.error.message ? data.error.message : `Stripe ${res.status}`;
      return { ok: false, status: res.status, error: msg, data };
    }
    return { ok: true, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 502, error: `Stripe fetch error: ${String(e && e.message ? e.message : e)}` };
  }
}
__name(stripeApiRequest, "stripeApiRequest");
function stripeSignatureParts(headerValue) {
  const out = { t: "", v1: [] };
  const h = String(headerValue || "").trim();
  if (!h) return out;
  for (const part of h.split(",")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === "t") out.t = val;
    if (key === "v1" && val) out.v1.push(val);
  }
  return out;
}
__name(stripeSignatureParts, "stripeSignatureParts");
function timingSafeEqHex(a, b) {
  const x = String(a || "");
  const y = String(b || "");
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
__name(timingSafeEqHex, "timingSafeEqHex");
async function stripeVerifyWebhookSignature(rawBody, sigHeader, secret, toleranceSec) {
  if (!secret) return { ok: false, error: "STRIPE_WEBHOOK_SECRET not configured" };
  const parts = stripeSignatureParts(sigHeader);
  if (!parts.t || !parts.v1.length) return { ok: false, error: "Missing Stripe signature fields" };
  const ts = parseInt(parts.t, 10);
  if (!Number.isFinite(ts)) return { ok: false, error: "Invalid Stripe signature timestamp" };
  if (Math.abs(Math.floor(Date.now() / 1e3) - ts) > toleranceSec) return { ok: false, error: "Stripe signature timestamp out of tolerance" };
  const payload = `${parts.t}.${rawBody}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const sigHex = Array.from(new Uint8Array(sigBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const matched = parts.v1.some((v) => timingSafeEqHex(v.toLowerCase(), sigHex.toLowerCase()));
  if (!matched) return { ok: false, error: "Stripe signature mismatch" };
  return { ok: true };
}
__name(stripeVerifyWebhookSignature, "stripeVerifyWebhookSignature");
function normalizeShopEvent(v) {
  const s = String(v || "").trim().toUpperCase();
  return s === "SALE" || s === "DONATION" || s === "INVEST" || s === "BILL" || s === "CLOSE" ? s : "";
}
__name(normalizeShopEvent, "normalizeShopEvent");
function normalizeShopProduct(v) {
  const s = String(v || "").trim().toUpperCase();
  if (!s) return "GENERAL";
  if (!/^[A-Z0-9][A-Z0-9-]{0,47}$/.test(s)) return "GENERAL";
  return s;
}
__name(normalizeShopProduct, "normalizeShopProduct");
function isoFromUnix(tsSec) {
  if (!Number.isFinite(tsSec)) return (/* @__PURE__ */ new Date()).toISOString();
  return new Date(tsSec * 1e3).toISOString();
}
__name(isoFromUnix, "isoFromUnix");
function initWalletSummary() {
  return {
    canon: "WALLET.v1",
    source: "stripe",
    currency: "COIN",
    work_equals_coin: true,
    events: 0,
    balance: 0,
    last_close: "",
    updated_at: (/* @__PURE__ */ new Date()).toISOString(),
    totals: { SALE: 0, DONATION: 0, INVEST: 0, BILL: 0, CLOSE: 0, credit: 0, debit: 0, net: 0 },
    services: {},
    products: {},
    recent: []
  };
}
__name(initWalletSummary, "initWalletSummary");
function applyWalletDelta(bucket, key, delta) {
  const k = String(key || "GENERAL").toUpperCase();
  if (!bucket[k]) bucket[k] = { credit: 0, debit: 0, net: 0 };
  if (delta >= 0) bucket[k].credit += delta;
  else bucket[k].debit += Math.abs(delta);
  bucket[k].net = bucket[k].credit - bucket[k].debit;
}
__name(applyWalletDelta, "applyWalletDelta");
function sortedWalletBucket(bucket, topN) {
  const rows = Object.entries(bucket).map(([k, row]) => ({
    k,
    credit: row.credit || 0,
    debit: row.debit || 0,
    net: row.net || 0
  }));
  rows.sort((a, b) => b.net - a.net || b.credit - a.credit || a.debit - b.debit || a.k.localeCompare(b.k));
  return topN > 0 ? rows.slice(0, topN) : rows;
}
__name(sortedWalletBucket, "sortedWalletBucket");
function walletEventFromStripeSession(session, coinToCents) {
  if (!session || session.status !== "complete" || session.payment_status !== "paid") return null;
  const md = session.metadata || {};
  const eventType = normalizeShopEvent(md.event || md.type || "SALE") || "SALE";
  const amountCoinRaw = parseInt(md.amount_coin || "", 10);
  const amountCoin = Number.isFinite(amountCoinRaw) && amountCoinRaw > 0 ? amountCoinRaw : Math.max(1, Math.round(Number(session.amount_total || 0) / Math.max(1, coinToCents)));
  const product = normalizeShopProduct(md.product || "GENERAL");
  const service = normalizeShopProduct(md.service || "BOOK");
  const delta = eventType === "BILL" ? -amountCoin : eventType === "CLOSE" ? 0 : amountCoin;
  return { id: String(session.id || ""), ts: isoFromUnix(Number(session.created || 0)), type: eventType, service, product, amount: amountCoin, delta };
}
__name(walletEventFromStripeSession, "walletEventFromStripeSession");
async function shopCheckout(request, env) {
  if (!env.STRIPE_SECRET_KEY) return json({ error: "STRIPE_SECRET_KEY not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const eventType = normalizeShopEvent(body && body.event) || "";
  if (!eventType || !["SALE", "DONATION", "INVEST"].includes(eventType)) return json({ error: "event must be SALE, DONATION, or INVEST" }, 400);
  const amountCoin = parseInt(body && body.amount_coin, 10);
  if (!Number.isFinite(amountCoin) || amountCoin < 1 || amountCoin > 1e6) return json({ error: "amount_coin must be an integer between 1 and 1000000" }, 400);
  const product = normalizeShopProduct(body && body.product);
  const service = normalizeShopProduct(body && body.service || "BOOK");
  const channel = normalizeShopProduct(body && body.channel || "SHOP");
  const note = clampString(String(body && body.note || ""), 500);
  const name = clampString(String(body && body.name || ""), 120);
  const email = clampString(String(body && body.email || ""), 240);
  const coinToCents = Math.max(1, intEnv(env, "SHOP_COIN_USD_CENTS", 100));
  const currency = requireEnv(env, "SHOP_CURRENCY", "shop").toLowerCase();
  const unitAmount = amountCoin * coinToCents;
  const origin = requireEnv(env, "SHOP_ORIGIN", "shop").replace(/\/+$/, "");
  const successPath = requireEnv(env, "SHOP_SUCCESS_PATH", "shop");
  const cancelPath = requireEnv(env, "SHOP_CANCEL_PATH", "shop");
  const successUrl = String(body && body.success_url || env.SHOP_SUCCESS_URL || `${origin}${successPath}`).trim();
  const cancelUrl = String(body && body.cancel_url || env.SHOP_CANCEL_URL || `${origin}${cancelPath}`).trim();
  if (!/^https?:\/\//i.test(successUrl) || !/^https?:\/\//i.test(cancelUrl)) return json({ error: "success_url and cancel_url must be absolute HTTP URLs" }, 400);
  const titleByType = { SALE: `${product} Reserve`, DONATION: `${product} Donation`, INVEST: `${product} Investor Commitment` };
  const fields = {
    mode: "payment",
    success_url: successUrl,
    cancel_url: cancelUrl,
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": currency,
    "line_items[0][price_data][unit_amount]": String(unitAmount),
    "line_items[0][price_data][product_data][name]": titleByType[eventType] || `${product} ${eventType}`,
    "metadata[event]": eventType,
    "metadata[type]": eventType,
    "metadata[service]": service,
    "metadata[product]": product,
    "metadata[channel]": channel,
    "metadata[amount_coin]": String(amountCoin),
    "metadata[note]": note,
    "metadata[name]": name,
    "metadata[email]": email,
    "payment_intent_data[metadata][event]": eventType,
    "payment_intent_data[metadata][service]": service,
    "payment_intent_data[metadata][product]": product,
    "payment_intent_data[metadata][channel]": channel,
    "payment_intent_data[metadata][amount_coin]": String(amountCoin)
  };
  if (email) fields.customer_email = email;
  const created = await stripeApiRequest(env, "POST", "/v1/checkout/sessions", fields);
  if (!created.ok) return json({ error: created.error || "Stripe checkout create failed" }, created.status || 502);
  const session = created.data || {};
  return json({ ok: true, session_id: session.id, url: session.url, event: eventType, product, amount_coin: amountCoin, amount_minor: unitAmount, currency });
}
__name(shopCheckout, "shopCheckout");
async function shopStripeWebhook(request, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: "STRIPE_WEBHOOK_SECRET not configured" }, 500);
  const raw = await request.text();
  const sig = request.headers.get("stripe-signature") || "";
  const toleranceSec = Math.max(10, intEnv(env, "SHOP_WEBHOOK_TOLERANCE_SEC", 300));
  const verified = await stripeVerifyWebhookSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET, toleranceSec);
  if (!verified.ok) return json({ error: verified.error || "Invalid Stripe signature" }, 401);
  let evt;
  try {
    evt = JSON.parse(raw);
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid Stripe event JSON" }, 400);
  }
  const typ = String(evt && evt.type || "");
  const obj = evt && evt.data && evt.data.object ? evt.data.object : {};
  const coinToCents = Math.max(1, intEnv(env, "SHOP_COIN_USD_CENTS", 100));
  const mapped = walletEventFromStripeSession(obj, coinToCents);
  const relay = String(env.SHOP_STRIPE_EVENT_WEBHOOK_URL || "").trim();
  let relayed = false;
  if (relay && /^https?:\/\//i.test(relay)) {
    try {
      await fetch(relay, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: "stripe",
          stripe_event_id: evt && evt.id ? evt.id : "",
          stripe_type: typ,
          wallet_event: mapped,
          raw: { id: obj.id || "", status: obj.status || "", payment_status: obj.payment_status || "" }
        })
      });
      relayed = true;
    } catch (e) {
      console.error("[TALK]", e.message || e);
    }
  }
  const ledgerResult = await appendToLedger(env, "SHOP", "SHOP", {
    stripe_event_id: evt && evt.id ? evt.id : "",
    stripe_type: typ,
    session_id: obj.id || "",
    status: obj.status || "",
    payment_status: obj.payment_status || "",
    wallet_event: mapped,
    work_ref: evt && evt.id ? evt.id : ""
  });
  return json({ ok: true, stripe_event_id: evt && evt.id ? evt.id : "", stripe_type: typ, wallet_event: mapped, relayed, ledger: ledgerResult });
}
__name(shopStripeWebhook, "shopStripeWebhook");
async function shopWallet(request, env) {
  if (!env.STRIPE_SECRET_KEY) {
    if (boolEnv(env, "SHOP_WALLET_STRIPE_REQUIRED", true)) return json({ error: "STRIPE_SECRET_KEY not configured" }, 500);
    return json({ wallet: initWalletSummary(), source: "empty" });
  }
  const url = new URL(request.url);
  const top = Math.max(1, Math.min(100, parseInt(url.searchParams.get("top") || "12", 10) || 12));
  const perPage = Math.max(1, Math.min(100, parseInt(url.searchParams.get("limit") || String(intEnv(env, "SHOP_WALLET_PAGE_LIMIT", 100)), 10) || 100));
  const maxPages = Math.max(1, Math.min(20, parseInt(url.searchParams.get("pages") || String(intEnv(env, "SHOP_WALLET_MAX_PAGES", 3)), 10) || 3));
  const coinToCents = Math.max(1, intEnv(env, "SHOP_COIN_USD_CENTS", 100));
  const wallet = initWalletSummary();
  let startingAfter = "";
  let fetched = 0;
  for (let page = 0; page < maxPages; page++) {
    const qs = new URLSearchParams();
    qs.set("limit", String(perPage));
    if (startingAfter) qs.set("starting_after", startingAfter);
    const listed = await stripeApiRequest(env, "GET", `/v1/checkout/sessions?${qs.toString()}`);
    if (!listed.ok) return json({ error: listed.error || "Stripe list sessions failed" }, listed.status || 502);
    const data = listed.data || {};
    const rows = Array.isArray(data.data) ? data.data : [];
    fetched += rows.length;
    if (!rows.length) break;
    for (const session of rows) {
      const evt = walletEventFromStripeSession(session, coinToCents);
      if (!evt) continue;
      wallet.events += 1;
      wallet.balance += evt.delta;
      if (wallet.totals[evt.type] !== void 0) wallet.totals[evt.type] += evt.amount;
      if (evt.delta >= 0) wallet.totals.credit += evt.delta;
      else wallet.totals.debit += Math.abs(evt.delta);
      wallet.totals.net = wallet.totals.credit - wallet.totals.debit;
      applyWalletDelta(wallet.services, evt.service, evt.delta);
      applyWalletDelta(wallet.products, evt.product, evt.delta);
      wallet.recent.push({ id: evt.id, ts: evt.ts, type: evt.type, service: evt.service, product: evt.product, amount: evt.amount, delta: evt.delta });
    }
    if (!data.has_more) break;
    startingAfter = rows[rows.length - 1] && rows[rows.length - 1].id ? rows[rows.length - 1].id : "";
    if (!startingAfter) break;
  }
  wallet.services = sortedWalletBucket(wallet.services, top);
  wallet.products = sortedWalletBucket(wallet.products, top);
  wallet.recent = wallet.recent.sort((a, b) => String(b.ts).localeCompare(String(a.ts))).slice(0, top);
  wallet.updated_at = (/* @__PURE__ */ new Date()).toISOString();
  return json({ wallet, source: "stripe", fetched_sessions: fetched, coin_to_cents: coinToCents });
}
__name(shopWallet, "shopWallet");

// src/kernel/kv.js
async function kvGet(kv, key, fallback = null) {
  if (!kv) return fallback;
  try {
    const raw = await kv.get(key);
    if (raw) return JSON.parse(raw);
  } catch (e) {
    console.error("[TALK_KV]", e.message || e);
  }
  return fallback;
}
__name(kvGet, "kvGet");
async function kvPut(kv, key, value, opts) {
  if (!kv) return;
  await kv.put(key, JSON.stringify(value), opts);
}
__name(kvPut, "kvPut");

// src/domains/talk.js
async function ledgerWrite(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { scope, trace_id, provider_used, elapsed_ms } = body;
  const user_message = sanitize(body.user_message);
  const assistant_message = sanitize(body.assistant_message);
  if (!scope || !user_message) return json({ error: "Missing scope or user_message" }, 400);
  if (await checkRate(env, "ledger", scope, 100)) return json({ error: "Rate limited", scope }, 429);
  const result = await appendToLedger(env, "TALK", scope, {
    trace_id: trace_id || null,
    user: user_message,
    assistant: assistant_message || null,
    provider: provider_used || null,
    elapsed_ms: elapsed_ms || null
  }, { key: `ledger:${scope}` });
  const notify = Array.isArray(body.notify) ? body.notify : [];
  for (const target of notify) {
    if (!target || typeof target !== "string") continue;
    const inboxKey = `inbox:${target}`;
    let inbox2 = await kvGet(env.TALK_KV, inboxKey, []);
    inbox2.push({ id: result.id, ts: result.ts, from: scope, to: target, message: user_message, context: assistant_message || null, read: false });
    if (inbox2.length > 500) inbox2 = inbox2.slice(-500);
    await kvPut(env.TALK_KV, inboxKey, inbox2);
  }
  return json({ ok: true, id: result.id, scope, entries: result.entries, ts: result.ts, notified: notify });
}
__name(ledgerWrite, "ledgerWrite");
async function ledgerRead(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get("scope");
  if (!scope) return json({ error: "Missing scope param" }, 400);
  const ledger2 = await kvGet(env.TALK_KV, `ledger:${scope}`, []);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
  const offset = parseInt(url.searchParams.get("offset") || "0", 10);
  const slice = ledger2.slice(-(offset + limit), offset ? -offset : void 0);
  return json({ scope, total: ledger2.length, entries: slice });
}
__name(ledgerRead, "ledgerRead");
async function send(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { from, to, message, context } = body;
  if (!from || !to || !message) return json({ error: "Missing from, to, or message" }, 400);
  const ts = (/* @__PURE__ */ new Date()).toISOString();
  const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const entry = { id, ts, from, to, message, context: context || null, read: false };
  let inbox2 = await kvGet(env.TALK_KV, `inbox:${to}`, []);
  inbox2.push(entry);
  if (inbox2.length > 500) inbox2 = inbox2.slice(-500);
  await kvPut(env.TALK_KV, `inbox:${to}`, inbox2);
  let outbox = await kvGet(env.TALK_KV, `outbox:${from}`, []);
  outbox.push(entry);
  if (outbox.length > 500) outbox = outbox.slice(-500);
  await kvPut(env.TALK_KV, `outbox:${from}`, outbox);
  await appendToLedger(env, "TALK", `MSG:${from}:${to}`, { from, to, message_id: id, work_ref: id });
  return json({ ok: true, id, from, to, ts });
}
__name(send, "send");
async function inbox(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get("scope");
  if (!scope) return json({ error: "Missing scope param" }, 400);
  const inboxData = await kvGet(env.TALK_KV, `inbox:${scope}`, []);
  const unreadOnly = url.searchParams.get("unread") === "true";
  const messages = unreadOnly ? inboxData.filter((m) => !m.read) : inboxData;
  return json({ scope, total: inboxData.length, unread: inboxData.filter((m) => !m.read).length, messages });
}
__name(inbox, "inbox");
async function ack(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { scope, message_ids } = body;
  if (!scope || !Array.isArray(message_ids)) return json({ error: "Missing scope or message_ids" }, 400);
  const inboxData = await kvGet(env.TALK_KV, `inbox:${scope}`, []);
  const idSet = new Set(message_ids);
  let acked = 0;
  for (const msg of inboxData) {
    if (idSet.has(msg.id) && !msg.read) {
      msg.read = true;
      acked++;
    }
  }
  await kvPut(env.TALK_KV, `inbox:${scope}`, inboxData);
  return json({ ok: true, scope, acked });
}
__name(ack, "ack");

// src/domains/contribute.js
async function contribute(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    console.error("[TALK]", e.message || e);
    return json({ error: "Invalid JSON" }, 400);
  }
  const { scope, contributor, email, affiliation, chapter, source } = body;
  const story = sanitize(body.story);
  if (!scope || !story) return json({ error: "Missing scope or story" }, 400);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (await checkRate(env, "contribute", ip, 10)) return json({ error: "Rate limited" }, 429);
  const result = await appendToLedger(env, "CONTRIBUTE", scope, {
    contributor: contributor || "Anonymous",
    email: email || null,
    affiliation: affiliation || null,
    chapter: chapter || null,
    story,
    source: source || null,
    coin_event: "MINT:CONTRIBUTE"
  }, { key: `contributions:${scope}` });
  if (email && env.RESEND_API_KEY) {
    try {
      const name = contributor || "Friend";
      const receiptShort = result.id.slice(0, 8);
      const storyPreview = story.length > 200 ? story.slice(0, 200) + "..." : story;
      const emailHtml = `
<div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#e5e5e5;padding:40px;border:1px solid #222;">
  <div style="text-align:center;margin-bottom:32px;">
    <div style="font-size:28px;font-weight:800;letter-spacing:2px;color:#d4a855;">COIN MINTED</div>
    <div style="font-size:13px;color:#888;margin-top:4px;">${scope}</div>
  </div>
  <div style="margin-bottom:24px;"><span style="color:#d4a855;">Dear ${name},</span></div>
  <div style="margin-bottom:24px;line-height:1.6;">Your contribution has been recorded on the governed ledger. Every contribution is WORK. Every WORK mints COIN.</div>
  <div style="background:#111;border:1px solid #333;padding:20px;margin-bottom:24px;font-family:monospace;font-size:13px;">
    <div><span style="color:#888;">Receipt:</span> <span style="color:#d4a855;">${receiptShort}</span></div>
    <div><span style="color:#888;">Event:</span> MINT:CONTRIBUTE</div>
    <div><span style="color:#888;">Scope:</span> ${scope}</div>
    <div><span style="color:#888;">Time:</span> ${result.ts}</div>
    ${chapter ? '<div><span style="color:#888;">Chapter:</span> ' + chapter + "</div>" : ""}
    ${source ? '<div><span style="color:#888;">Source:</span> ' + source + "</div>" : ""}
  </div>
  <div style="margin-bottom:24px;line-height:1.6;"><span style="color:#888;">Your words:</span><br><em>&ldquo;${storyPreview}&rdquo;</em></div>
  <div style="text-align:center;margin:32px 0;">
    <a href="https://hadleylab-canonic.github.io/SHOP/" style="background:#d4a855;color:#000;padding:12px 32px;text-decoration:none;font-weight:700;font-size:14px;letter-spacing:1px;">CLAIM YOUR COIN</a>
  </div>
  <div style="margin-bottom:24px;line-height:1.6;font-size:14px;">Your COIN is waiting. Every contribution is work. Every work has value. Claim yours.</div>
  <div style="border-top:1px solid #222;padding-top:20px;font-size:12px;color:#666;text-align:center;">
    Every contribution governed. Every provenance traced.<br><br>
    <a href="https://canonic.org" style="color:#d4a855;text-decoration:none;">CANONIC</a>
  </div>
</div>`;
      await sendEmail(env, {
        from: "CANONIC <canonic@canonic.org>",
        to: email,
        subject: `COIN MINTED \u2014 Your ${scope} contribution (${receiptShort})`,
        html: emailHtml
      });
    } catch (e) {
      console.error("[TALK]", e.message || e);
    }
  }
  return json({ ok: true, id: result.id, scope, ts: result.ts, coin_event: "MINT:CONTRIBUTE", entries: result.entries });
}
__name(contribute, "contribute");
async function contributeRead(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const scope = url.searchParams.get("scope");
  if (!scope) return json({ error: "Missing scope param" }, 400);
  const ledger2 = await kvGet(env.TALK_KV, `contributions:${scope}`, []);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
  const offset = parseInt(url.searchParams.get("offset") || "0", 10);
  const slice = ledger2.slice(-(offset + limit), offset ? -offset : void 0);
  return json({ scope, total: ledger2.length, entries: slice });
}
__name(contributeRead, "contributeRead");

// src/domains/omics.js
var OMICS_UPSTREAMS = {
  "/omics/ncbi/": "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/",
  "/omics/pharmgkb/": "https://api.pharmgkb.org/v1/data/"
};
async function handle2(request, env, ctx, url) {
  if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
  const path = url.pathname;
  for (const [prefix, upstream] of Object.entries(OMICS_UPSTREAMS)) {
    if (path.startsWith(prefix)) {
      const rest = path.slice(prefix.length);
      const target = upstream + rest + url.search;
      const res = await fetch(target, { cf: { cacheTtl: 3600 } });
      const body = await res.arrayBuffer();
      const headers = addCors({
        "Content-Type": res.headers.get("Content-Type") || "application/json",
        "Cache-Control": "public, max-age=3600"
      }, _reqOrigin);
      const source = prefix.includes("ncbi") ? "ncbi" : "pharmgkb";
      appendToLedger(env, "OMICS", `OMICS:${source}`, {
        source,
        query_path: rest,
        query_params: url.search,
        upstream_status: res.status,
        ip: request.headers.get("CF-Connecting-IP") || "unknown",
        work_ref: `omics:${source}:${Date.now()}`
      }).catch((e) => console.error("[TALK]", e.message || e));
      return new Response(body, { status: res.status, headers });
    }
  }
  return json({ error: "Unknown omics upstream" }, 404);
}
__name(handle2, "handle");

// src/domains/star.js
async function status(request, env) {
  return json({ status: "ok", service: "STAR", star_kv: !!env.STAR_KV, talk_kv: !!env.TALK_KV, ts: (/* @__PURE__ */ new Date()).toISOString() });
}
__name(status, "status");
async function gov(request, env) {
  let scopes = [];
  try {
    const raw = await (env.STAR_KV || env.TALK_KV).get("star:gov");
    if (raw) scopes = JSON.parse(raw);
  } catch (e) {
    console.error("[STAR] gov read:", e.message || e);
  }
  return json({ total: scopes.length, scopes });
}
__name(gov, "gov");
async function timeline(request, env, session) {
  const url = new URL(request.url);
  const principal = session.user?.toUpperCase() || "";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), parseInt(env.STAR_TIMELINE_LIMIT, 10));
  const streamFilter = url.searchParams.get("stream")?.toUpperCase() || null;
  const primitiveFilter = url.searchParams.get("primitive")?.toUpperCase() || null;
  const offset = parseInt(url.searchParams.get("offset") || "0", 10);
  let tl = [];
  try {
    const cached = await (env.STAR_KV || env.TALK_KV).get(`star:timeline:${principal}`);
    if (cached) {
      const data = JSON.parse(cached);
      tl = data.entries || data || [];
    }
  } catch (e) {
    console.error("[STAR] timeline read:", e.message || e);
  }
  if (streamFilter) tl = tl.filter((e) => e.stream === streamFilter);
  if (primitiveFilter) tl = tl.filter((e) => e.primitive === primitiveFilter);
  return json({ principal, total: tl.length, offset, limit, entries: tl.slice(offset, offset + limit) });
}
__name(timeline, "timeline");
async function readStarKV(env, key) {
  try {
    const raw = await (env.STAR_KV || env.TALK_KV).get(key);
    if (raw) return JSON.parse(raw);
  } catch (e) {
    console.error("[STAR] read:", e.message || e);
  }
  return null;
}
__name(readStarKV, "readStarKV");
async function services(request, env, session) {
  const principal = session.user?.toUpperCase() || "";
  const data = await readStarKV(env, "star:services:" + principal) || [];
  return json({ principal, total: data.length, services: data });
}
__name(services, "services");
async function intel(request, env, session) {
  const principal = session.user?.toUpperCase() || "";
  const data = await readStarKV(env, "star:intel:" + principal) || [];
  return json({ principal, total: data.length, patterns: data });
}
__name(intel, "intel");
async function econ(request, env, session) {
  const principal = session.user?.toUpperCase() || "";
  const data = await readStarKV(env, "star:econ:" + principal) || {};
  return json({ principal, ...data });
}
__name(econ, "econ");
async function identity(request, env, session) {
  const principal = session.user?.toUpperCase() || "";
  const data = await readStarKV(env, "star:identity:" + principal) || {};
  return json({ principal, ...data });
}
__name(identity, "identity");
async function media(request, env, session) {
  const principal = session.user?.toUpperCase() || "";
  const data = await readStarKV(env, "star:media:" + principal) || [];
  return json({ principal, total: data.length, media: data });
}
__name(media, "media");

// src/domains/runner/notify.js
async function notifyVendors(env, kv, task) {
  const runnerIds = await kvGet(kv, "runner:role:runner", []);
  const kycReq = KYC_REQUIRED[task.type];
  for (const id of runnerIds) {
    const vendor = await kvGet(kv, `runner:user:${id}`);
    if (!vendor || !vendor.email) continue;
    if (kycReq) {
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== "verified") continue;
    }
    await sendEmail(env, {
      to: vendor.email,
      subject: `RUNNER: New ${task.title} task \u2014 ${task.fee_coin} COIN`,
      html: `<p>A new task has been posted on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || "TBD"}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">ID</td><td style="padding:4px 12px;font-family:monospace;">${task.id}</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Claim on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC \xB7 Every task ledgered.</p>`
    });
  }
}
__name(notifyVendors, "notifyVendors");
async function notifyAgent(env, kv, task) {
  if (!task.requester_id) return;
  const agent = await kvGet(kv, `runner:user:${task.requester_id}`);
  if (!agent || !agent.email) return;
  let vendorName = "A vendor";
  if (task.runner_id) {
    const vendor = await kvGet(kv, `runner:user:${task.runner_id}`);
    if (vendor) vendorName = vendor.name || vendorName;
  }
  await sendEmail(env, {
    to: agent.email,
    subject: `RUNNER: ${vendorName} claimed your ${task.title} task`,
    html: `<p><strong>${vendorName}</strong> has claimed your task on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || "TBD"}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Vendor</td><td style="padding:4px 12px;">${vendorName}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">View on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC \xB7 Every task ledgered.</p>`
  });
}
__name(notifyAgent, "notifyAgent");

// src/domains/runner/tasks.js
async function createTask(body, env, kv) {
  if (!body.requester_id) return json({ error: "requester_id is required" }, 400);
  const taskType = body.type || "lockbox_install";
  const feeCoin = TASK_PRICES[taskType] || Math.max(1, parseInt(body.offered_fee_usd) || 50);
  const bal = parseInt(await kv.get(`runner:balance:${body.requester_id}`) || "0", 10);
  if (bal < feeCoin) return json({ error: "Insufficient COIN", balance: bal, required: feeCoin }, 402);
  const tid = "T" + uid();
  const task = {
    id: tid,
    requester_id: body.requester_id,
    runner_id: null,
    type: taskType,
    title: body.title || taskType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
    status: "posted",
    location: { address: (body.location || {}).address || body.address || "" },
    scheduled_time: body.scheduled_time || "",
    fee_coin: feeCoin,
    offered_fee_usd: parseInt(body.offered_fee_usd) || 50,
    notes: body.notes || "",
    proof_url: null,
    proof_note: null,
    rating: null,
    tip_coin: 0,
    created_at: (/* @__PURE__ */ new Date()).toISOString(),
    updated_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  await kv.put(`runner:balance:${body.requester_id}`, String(bal - feeCoin));
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  allTasks.push(task);
  await kv.put("runner:tasks:all", JSON.stringify(allTasks));
  await appendToLedger(env, "RUNNER", "RUNNER", { event: "TASK_POSTED", task_id: tid, task_type: taskType, requester_id: body.requester_id, fee_coin: feeCoin, address: task.location.address });
  if (env.RESEND_API_KEY) notifyVendors(env, kv, task).catch((e) => console.error("[RUNNER:NOTIFY]", e.message || e));
  return json({ success: true, task, balance: bal - feeCoin });
}
__name(createTask, "createTask");
async function listTasks(url, kv) {
  const role = url.searchParams.get("role") || "";
  const userId = url.searchParams.get("user_id") || "";
  let tasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  if (role === "Requester" && userId) tasks = tasks.filter((t) => t.requester_id === userId);
  else if (role === "Runner" && userId) tasks = tasks.filter((t) => t.status === "posted" || t.runner_id === userId);
  tasks.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  return json({ tasks });
}
__name(listTasks, "listTasks");
async function handleTaskAction(taskId, action, request, env, kv) {
  const method = request.method;
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const task = allTasks.find((t) => t.id === taskId);
  if (!task) return json({ error: "task not found" }, 404);
  if (action === "accept" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: "runner_id required" }, 400);
    if (!["posted", "assigned"].includes(task.status)) return json({ error: `cannot accept in status: ${task.status}` }, 400);
    const kycReq = KYC_REQUIRED[task.type];
    if (kycReq) {
      const vendor = await kvGet(kv, `runner:user:${body.runner_id}`, {});
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== "verified") return json({ error: "Credential verification required", task_type: task.type, required_credential: kycReq, vendor_id: body.runner_id }, 403);
    }
    task.runner_id = body.runner_id;
    task.status = "accepted";
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "VENDOR_CLAIMED", task_id: taskId, task_type: task.type, runner_id: body.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin });
    if (env.RESEND_API_KEY) notifyAgent(env, kv, task).catch((e) => console.error("[RUNNER:NOTIFY]", e.message || e));
    return json({ success: true, task });
  }
  if (action === "assign" && method === "PATCH") {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: "runner_id required" }, 400);
    if (task.status !== "posted") return json({ error: `cannot assign in status: ${task.status}` }, 400);
    task.runner_id = body.runner_id;
    task.status = "assigned";
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    return json({ success: true, task });
  }
  if (action === "proof" && method === "POST") {
    if (!["accepted", "in_progress"].includes(task.status)) return json({ error: `cannot upload proof in status: ${task.status}` }, 400);
    let body, fileHash = null, fileKey = null;
    const ct = request.headers.get("content-type") || "";
    if (ct.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file");
      const note = formData.get("note") || "Task completed as requested";
      if (file && file.size > 0) {
        const buf = await file.arrayBuffer();
        const hashBuf = await crypto.subtle.digest("SHA-256", buf);
        fileHash = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
        fileKey = `runner:evidence:${taskId}:${fileHash.slice(0, 12)}`;
        await kv.put(fileKey, buf, { metadata: { task_id: taskId, filename: file.name || "evidence", content_type: file.type || "application/octet-stream", hash: fileHash, uploaded_at: (/* @__PURE__ */ new Date()).toISOString() } });
      }
      body = { note };
    } else {
      body = await request.json().catch(() => ({}));
      fileHash = body.proof_hash || null;
    }
    task.status = "in_progress";
    task.proof_note = body.note || "Task completed as requested";
    task.proof_hash = fileHash;
    task.proof_key = fileKey;
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "EVIDENCE_UPLOADED", task_id: taskId, task_type: task.type, runner_id: task.runner_id, proof_hash: fileHash, proof_note: task.proof_note });
    return json({ success: true, task, proof_hash: fileHash });
  }
  if (action === "complete" && method === "POST") {
    if (!["in_progress", "accepted"].includes(task.status)) return json({ error: `cannot complete in status: ${task.status}` }, 400);
    task.status = "completed";
    task.completed_at = (/* @__PURE__ */ new Date()).toISOString();
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    if (task.runner_id && task.fee_coin) {
      const vendorBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || "0", 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(vendorBal + task.fee_coin));
    }
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "TASK_COMPLETED", task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin, coin_credited_to: task.runner_id });
    return json({ success: true, task });
  }
  if (action === "rate" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (task.status !== "completed") return json({ error: `cannot rate in status: ${task.status}` }, 400);
    task.rating = Math.max(1, Math.min(5, parseInt(body.rating) || 5));
    task.tip_coin = Math.max(0, parseInt(body.tip_usd || body.tip_coin) || 0);
    task.status = "rated";
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    if (task.tip_coin > 0 && task.runner_id) {
      const tipBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || "0", 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(tipBal + task.tip_coin));
    }
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "DEAL_CLOSED", task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, rating: task.rating, tip_coin: task.tip_coin, fee_coin: task.fee_coin });
    return json({ success: true, task });
  }
  if (action === "cancel" && method === "POST") {
    if (["completed", "rated"].includes(task.status)) return json({ error: `cannot cancel in status: ${task.status}` }, 400);
    const prevStatus = task.status;
    task.status = "cancelled";
    task.updated_at = (/* @__PURE__ */ new Date()).toISOString();
    if (task.fee_coin && task.requester_id) {
      const refBal = parseInt(await kv.get(`runner:balance:${task.requester_id}`) || "0", 10);
      await kv.put(`runner:balance:${task.requester_id}`, String(refBal + task.fee_coin));
    }
    await kv.put("runner:tasks:all", JSON.stringify(allTasks));
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "TASK_CANCELLED", task_id: taskId, task_type: task.type, requester_id: task.requester_id, fee_coin: task.fee_coin, prev_status: prevStatus });
    return json({ success: true, task });
  }
  return json({ error: "unknown action" }, 404);
}
__name(handleTaskAction, "handleTaskAction");

// src/domains/runner/constants.generated.js
var TASK_PRICES = {
  "lockbox_install": 3,
  "lockbox_remove": 3,
  "yard_sign_install": 3,
  "yard_sign_remove": 3,
  "photo_shoot": 10,
  "staging": 8,
  "inspection": 10,
  "appraisal": 10,
  "title": 10,
  "open_house": 8,
  "showing": 5,
  "cma": 5,
  "contract": 15,
  "closing": 25,
  "flyer_delivery": 3,
  "vendor_meetup": 5,
  "key_run": 3
};
var KYC_REQUIRED = {
  "photo_shoot": "business_license",
  "staging": "business_license",
  "inspection": "FL_468",
  "appraisal": "FL_FREAB_USPAP",
  "title": "FL_626",
  "closing": "FL_626_NMLS"
};
var STAGE_TASKS = {
  "inquiry": [
    "cma"
  ],
  "match": [
    "yard_sign_install",
    "lockbox_install"
  ],
  "show": [
    "showing",
    "photo_shoot"
  ],
  "offer": [
    "contract",
    "inspection",
    "appraisal"
  ],
  "negotiate": [
    "title"
  ],
  "close": [
    "closing"
  ]
};
var ROLES = ["Requester", "Runner", "Ops"];

// src/domains/runner/referral.js
async function handleReferral(request, env, kv) {
  const body = await request.json().catch(() => ({}));
  const { requester_id, address, stage, deal_id, source } = body;
  if (!requester_id || !address) return json({ error: "requester_id and address required" }, 400);
  const dealStage = (stage || "inquiry").toLowerCase();
  const taskTypes = STAGE_TASKS[dealStage] || STAGE_TASKS.inquiry;
  const totalCoin = taskTypes.reduce((s, t) => s + (TASK_PRICES[t] || 5), 0);
  let bal = parseInt(await kv.get(`runner:balance:${requester_id}`) || "0", 10);
  if (bal < totalCoin) return json({ error: "Insufficient COIN for referral batch", balance: bal, required: totalCoin }, 402);
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const created = [];
  for (const taskType of taskTypes) {
    const feeCoin = TASK_PRICES[taskType] || 5;
    const tid = "T" + uid();
    const task = {
      id: tid,
      requester_id,
      runner_id: null,
      type: taskType,
      title: taskType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      status: "posted",
      location: { address },
      scheduled_time: "",
      fee_coin: feeCoin,
      offered_fee_usd: 50,
      notes: `Auto-staged from ${source || "NONA"} ${dealStage} (deal: ${deal_id || "n/a"})`,
      proof_url: null,
      proof_note: null,
      rating: null,
      tip_coin: 0,
      created_at: (/* @__PURE__ */ new Date()).toISOString(),
      updated_at: (/* @__PURE__ */ new Date()).toISOString()
    };
    bal -= feeCoin;
    allTasks.push(task);
    created.push(task);
    await appendToLedger(env, "RUNNER", "RUNNER", { event: "TASK_POSTED", task_id: tid, task_type: taskType, requester_id, fee_coin: feeCoin, address, referral_source: source || "NONA", referral_stage: dealStage, deal_id: deal_id || null });
  }
  await kv.put(`runner:balance:${requester_id}`, String(bal));
  await kv.put("runner:tasks:all", JSON.stringify(allTasks));
  await appendToLedger(env, "RUNNER", "RUNNER", { event: "REFERRAL_STAGED", source: source || "NONA", stage: dealStage, deal_id: deal_id || null, requester_id, address, tasks_created: created.length, total_coin: totalCoin });
  return json({ success: true, stage: dealStage, tasks: created, balance: bal, deal_id });
}
__name(handleReferral, "handleReferral");

// src/domains/runner/credentials.js
async function handleCredentialSubmit(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || "").trim();
  const credType = (body.type || "").trim();
  const licenseNumber = (body.license_number || "").trim();
  if (!userId || !credType || !licenseNumber) return json({ error: "user_id, type, and license_number required" }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: "user not found" }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  creds[credType] = { license_number: licenseNumber, issuing_authority: body.issuing_authority || "", expiry: body.expiry || "", status: "pending", submitted_at: (/* @__PURE__ */ new Date()).toISOString() };
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, "RUNNER", "RUNNER", { event: "CREDENTIAL_SUBMITTED", user_id: userId, credential_type: credType, license_number: licenseNumber });
  return json({ success: true, user_id: userId, credential: creds[credType] });
}
__name(handleCredentialSubmit, "handleCredentialSubmit");
async function handleCredentialVerify(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || "").trim();
  const credType = (body.type || "").trim();
  const verdict = body.verified === true ? "verified" : "rejected";
  if (!userId || !credType) return json({ error: "user_id and type required" }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: "user not found" }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  if (!creds[credType]) return json({ error: "credential not found" }, 404);
  creds[credType].status = verdict;
  creds[credType].verified_at = (/* @__PURE__ */ new Date()).toISOString();
  creds[credType].verified_by = body.verified_by || "ops";
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, "RUNNER", "RUNNER", { event: "CREDENTIAL_VERIFIED", user_id: userId, credential_type: credType, verdict, verified_by: body.verified_by || "ops" });
  if (user.email && env.RESEND_API_KEY) {
    const statusText = verdict === "verified" ? "approved" : "rejected";
    sendEmail(env, {
      to: user.email,
      subject: `RUNNER: Your ${credType} credential has been ${statusText}`,
      html: `<p>Your <strong>${credType}</strong> credential (${creds[credType].license_number}) has been <strong>${statusText}</strong> on RUNNER.</p>
${verdict === "verified" ? "<p>You can now claim tasks that require this credential.</p>" : "<p>Please resubmit with a valid license number.</p>"}
<p><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Go to RUNNER</a></p>`
    }).catch(() => {
    });
  }
  return json({ success: true, user_id: userId, credential: creds[credType] });
}
__name(handleCredentialVerify, "handleCredentialVerify");

// src/domains/runner/calendar.js
async function handleCalendar(url, kv) {
  const userId = url.searchParams.get("user_id") || "";
  const dateStr = url.searchParams.get("date") || (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  const range = url.searchParams.get("range") || "week";
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const base = /* @__PURE__ */ new Date(dateStr + "T00:00:00Z");
  let rangeStart, rangeEnd;
  if (range === "day") {
    rangeStart = rangeEnd = dateStr;
  } else if (range === "month") {
    rangeStart = dateStr.slice(0, 8) + "01";
    rangeEnd = dateStr.slice(0, 8) + String(new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() + 1, 0)).getUTCDate()).padStart(2, "0");
  } else {
    const dow = base.getUTCDay() || 7;
    const mon = new Date(base.getTime() - (dow - 1) * 864e5);
    rangeStart = mon.toISOString().slice(0, 10);
    rangeEnd = new Date(mon.getTime() + 6 * 864e5).toISOString().slice(0, 10);
  }
  const events = allTasks.filter((t) => {
    if (userId && t.requester_id !== userId && t.runner_id !== userId) return false;
    const d = (t.scheduled_time || t.created_at || "").slice(0, 10);
    return d >= rangeStart && d <= rangeEnd;
  }).map((t) => ({
    id: t.id,
    type: t.type,
    title: t.title,
    status: t.status,
    date: (t.scheduled_time || t.created_at || "").slice(0, 10),
    time: (t.scheduled_time || "").slice(11, 16) || null,
    address: t.location && t.location.address || "",
    fee_coin: t.fee_coin
  })).sort((a, b) => (a.date + (a.time || "")).localeCompare(b.date + (b.time || "")));
  let availability = null;
  if (userId) {
    const avRaw = await kv.get(`runner:availability:${userId}`);
    if (avRaw) availability = JSON.parse(avRaw);
  }
  return json({ range: { start: rangeStart, end: rangeEnd, type: range }, events, availability });
}
__name(handleCalendar, "handleCalendar");

// src/domains/runner/queries.js
async function listRunners(kv) {
  const ids = JSON.parse(await kv.get("runner:role:runner") || "[]");
  const runners = [];
  for (const id of ids) {
    const raw = await kv.get(`runner:user:${id}`);
    if (raw) runners.push(JSON.parse(raw));
  }
  return json({ runners });
}
__name(listRunners, "listRunners");
async function profile(url, kv) {
  const userId = url.searchParams.get("user_id") || "";
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: "user not found" }, 404);
  const user = JSON.parse(raw);
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const completed = allTasks.filter((t) => t.runner_id === userId && ["completed", "rated"].includes(t.status));
  const totalEarned = completed.reduce((s, t) => s + (t.fee_coin || 0), 0);
  const ratings = completed.filter((t) => t.rating).map((t) => t.rating);
  const avgRating = ratings.length ? Math.round(ratings.reduce((a, b) => a + b, 0) / ratings.length * 10) / 10 : 0;
  return json({ runner: { ...user, completed_tasks: completed.length, total_earned_coin: totalEarned, avg_rating: avgRating } });
}
__name(profile, "profile");
async function stats(kv) {
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const reqIds = JSON.parse(await kv.get("runner:role:requester") || "[]");
  const runIds = JSON.parse(await kv.get("runner:role:runner") || "[]");
  const active = allTasks.filter((t) => ["posted", "assigned", "accepted", "in_progress"].includes(t.status));
  const done = allTasks.filter((t) => ["completed", "rated"].includes(t.status));
  return json({
    total_tasks: allTasks.length,
    active_tasks: active.length,
    completed_tasks: done.length,
    total_coin: done.reduce((s, t) => s + (t.fee_coin || 0), 0),
    total_users: reqIds.length + runIds.length,
    total_runners: runIds.length,
    total_requesters: reqIds.length
  });
}
__name(stats, "stats");
async function balance(url, kv) {
  const userId = url.searchParams.get("user_id") || "";
  if (!userId) return json({ error: "user_id required" }, 400);
  return json({ balance: parseInt(await kv.get(`runner:balance:${userId}`) || "0", 10), user_id: userId });
}
__name(balance, "balance");
async function evidence(taskId, kv) {
  const keys = await kv.list({ prefix: `runner:evidence:${taskId}:` });
  if (!keys.keys.length) return json({ error: "no evidence found" }, 404);
  const key = keys.keys[0];
  const { value, metadata } = await kv.getWithMetadata(key.name, { type: "arrayBuffer" });
  if (!value) return json({ error: "evidence data missing" }, 404);
  return new Response(value, {
    headers: {
      "Content-Type": metadata && metadata.content_type || "application/octet-stream",
      "X-Evidence-Hash": metadata && metadata.hash || "",
      "X-Task-Id": taskId,
      "Cache-Control": "public, max-age=31536000, immutable"
    }
  });
}
__name(evidence, "evidence");
async function ledger(url, kv) {
  const raw = await kv.get("ledger:RUNNER:RUNNER");
  const entries = raw ? JSON.parse(raw) : [];
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
  const since = url.searchParams.get("since") || "";
  const filtered = since ? entries.filter((e) => e.ts > since) : entries;
  return json({ entries: filtered.slice(-limit), total: entries.length });
}
__name(ledger, "ledger");
async function board(url, kv) {
  const address = (url.searchParams.get("address") || "").trim().toLowerCase();
  if (!address) return json({ error: "address required" }, 400);
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const matched = allTasks.filter((t) => t.location && t.location.address && t.location.address.toLowerCase().includes(address));
  const b = { posted: [], accepted: [], in_progress: [], completed: [], rated: [], cancelled: [] };
  for (const t of matched) {
    if (b[t.status]) b[t.status].push(t);
  }
  const totalCoin = matched.reduce((s, t) => s + (t.fee_coin || 0), 0);
  const completedCoin = matched.filter((t) => ["completed", "rated"].includes(t.status)).reduce((s, t) => s + (t.fee_coin || 0), 0);
  return json({ address: url.searchParams.get("address"), total_tasks: matched.length, total_coin: totalCoin, completed_coin: completedCoin, board: b });
}
__name(board, "board");
async function listings(url, kv) {
  const userId = url.searchParams.get("user_id") || "";
  if (!userId) return json({ error: "user_id required" }, 400);
  const allTasks = JSON.parse(await kv.get("runner:tasks:all") || "[]");
  const userTasks = allTasks.filter((t) => t.requester_id === userId);
  const addrMap = {};
  for (const t of userTasks) {
    const addr = t.location && t.location.address || "Unknown";
    if (!addrMap[addr]) addrMap[addr] = { address: addr, tasks: 0, coin: 0, active: 0, completed: 0 };
    addrMap[addr].tasks++;
    addrMap[addr].coin += t.fee_coin || 0;
    if (["completed", "rated"].includes(t.status)) addrMap[addr].completed++;
    else if (!["cancelled"].includes(t.status)) addrMap[addr].active++;
  }
  return json({ listings: Object.values(addrMap) });
}
__name(listings, "listings");

// src/domains/runner/index.js
function uid() {
  return Array.from(crypto.getRandomValues(new Uint8Array(6))).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}
__name(uid, "uid");
async function handle3(subpath, request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: "KV not configured" }, 500);
  const method = request.method;
  const url = new URL(request.url);
  if (subpath === "auth" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const name = (body.name || "").trim();
    const email = (body.email || "").trim();
    const role = body.role || "Requester";
    if (!name) return json({ error: "name is required" }, 400);
    if (!ROLES.includes(role)) return json({ error: "invalid role" }, 400);
    if (email) {
      const existing = await kv.get(`runner:email:${email.toLowerCase()}`);
      if (existing) {
        const user2 = JSON.parse(existing);
        const bal = parseInt(await kv.get(`runner:balance:${user2.id}`) || "0", 10);
        return json({ success: true, user: user2, balance: bal });
      }
    }
    const id = "U" + uid();
    const startupCoin = intEnv(env, "RUNNER_STARTUP_COIN", 50);
    const user = { id, name, email, role, created_at: (/* @__PURE__ */ new Date()).toISOString(), status: "active" };
    await kv.put(`runner:user:${id}`, JSON.stringify(user));
    if (email) await kv.put(`runner:email:${email.toLowerCase()}`, JSON.stringify(user));
    await kv.put(`runner:balance:${id}`, String(startupCoin));
    const roleKey = `runner:role:${role.toLowerCase()}`;
    const roleList = JSON.parse(await kv.get(roleKey) || "[]");
    roleList.push(id);
    await kv.put(roleKey, JSON.stringify(roleList));
    return json({ success: true, user, balance: startupCoin });
  }
  if (subpath === "tasks" && method === "GET") return listTasks(url, kv);
  if (subpath === "tasks" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    return createTask(body, env, kv);
  }
  const taskMatch = subpath.match(/^tasks\/([A-Z0-9]+)\/(\w+)$/);
  if (taskMatch) return handleTaskAction(taskMatch[1], taskMatch[2], request, env, kv);
  if (subpath === "list" && method === "GET") return listRunners(kv);
  if (subpath === "profile" && method === "GET") return profile(url, kv);
  if (subpath === "stats" && method === "GET") return stats(kv);
  if (subpath === "balance" && method === "GET") return balance(url, kv);
  if (subpath === "checkout" && method === "POST") {
    if (!env.STRIPE_SECRET_KEY) return json({ error: "Stripe not configured" }, 500);
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || "").trim();
    if (!userId) return json({ error: "user_id required" }, 400);
    const amountCoin = parseInt(body.amount_coin, 10);
    if (!Number.isFinite(amountCoin) || amountCoin < 10 || amountCoin > 1e4) return json({ error: "amount_coin must be 10\u201310000" }, 400);
    const coinToCents = Math.max(1, intEnv(env, "RUNNER_COIN_USD_CENTS", 100));
    const fields = {
      mode: "payment",
      success_url: (body.success_url || "https://gorunner.pro/?checkout=success").trim(),
      cancel_url: (body.cancel_url || "https://gorunner.pro/?checkout=cancel").trim(),
      "line_items[0][quantity]": "1",
      "line_items[0][price_data][currency]": "usd",
      "line_items[0][price_data][unit_amount]": String(amountCoin * coinToCents),
      "line_items[0][price_data][product_data][name]": `RUNNER \u2014 ${amountCoin} COIN`,
      "metadata[service]": "RUNNER",
      "metadata[user_id]": userId,
      "metadata[amount_coin]": String(amountCoin),
      "payment_intent_data[metadata][service]": "RUNNER",
      "payment_intent_data[metadata][user_id]": userId,
      "payment_intent_data[metadata][amount_coin]": String(amountCoin)
    };
    const created = await stripeApiRequest(env, "POST", "/v1/checkout/sessions", fields);
    if (!created.ok) return json({ error: created.error || "Stripe checkout failed" }, created.status || 502);
    return json({ ok: true, session_id: (created.data || {}).id, url: (created.data || {}).url, amount_coin: amountCoin });
  }
  if (subpath === "credit" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || "").trim();
    const amount = parseInt(body.amount_coin, 10);
    if (!userId || !Number.isFinite(amount) || amount < 1) return json({ error: "user_id and amount_coin required" }, 400);
    const bal = parseInt(await kv.get(`runner:balance:${userId}`) || "0", 10);
    const newBal = bal + amount;
    await kv.put(`runner:balance:${userId}`, String(newBal));
    return json({ ok: true, balance: newBal, credited: amount });
  }
  const evidenceMatch = subpath.match(/^evidence\/([A-Z0-9]+)$/);
  if (evidenceMatch && method === "GET") return evidence(evidenceMatch[1], kv);
  if (subpath === "ledger" && method === "GET") return ledger(url, kv);
  if (subpath === "referral" && method === "POST") return handleReferral(request, env, kv);
  if (subpath === "credentials" && method === "POST") return handleCredentialSubmit(request, kv, env);
  if (subpath === "credentials/verify" && method === "POST") return handleCredentialVerify(request, kv, env);
  if (subpath === "credentials" && method === "GET") {
    const userId = url.searchParams.get("user_id") || "";
    if (!userId) return json({ error: "user_id required" }, 400);
    const raw = await kv.get(`runner:user:${userId}`);
    if (!raw) return json({ error: "user not found" }, 404);
    return json({ user_id: userId, credentials: JSON.parse(raw).credentials || {} });
  }
  if (subpath === "availability" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const userId = (body.user_id || "").trim();
    if (!userId) return json({ error: "user_id required" }, 400);
    if (!Array.isArray(body.slots)) return json({ error: "slots array required" }, 400);
    await kv.put(`runner:availability:${userId}`, JSON.stringify({ user_id: userId, slots: body.slots, updated_at: (/* @__PURE__ */ new Date()).toISOString(), timezone: body.timezone || "America/New_York" }));
    return json({ success: true, user_id: userId, slots: body.slots });
  }
  if (subpath === "availability" && method === "GET") {
    const userId = url.searchParams.get("user_id") || "";
    if (!userId) return json({ error: "user_id required" }, 400);
    const raw = await kv.get(`runner:availability:${userId}`);
    return json(raw ? JSON.parse(raw) : { user_id: userId, slots: [] });
  }
  if (subpath === "calendar" && method === "GET") return handleCalendar(url, kv);
  if (subpath === "board" && method === "GET") return board(url, kv);
  if (subpath === "listings" && method === "GET") return listings(url, kv);
  return json({ error: "unknown runner route" }, 404);
}
__name(handle3, "handle");

// src/domains/federation.js
async function digestWrite(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;
  const body = await request.json();
  if (!body.org || !body.head || !body.signer || !body.signature) return json({ error: "Missing required fields: org, head, signer, signature" }, 400);
  if (typeof body.event_count !== "number" || typeof body.coin_total !== "number") return json({ error: "event_count and coin_total must be numbers" }, 400);
  const digest = {
    type: "DIGEST",
    org: body.org,
    head: body.head,
    event_count: body.event_count,
    coin_total: body.coin_total,
    balances: body.balances || {},
    ts: body.ts || (/* @__PURE__ */ new Date()).toISOString(),
    signer: body.signer,
    signature: body.signature
  };
  await kvPut(env.TALK_KV, `digest:${body.org}`, digest);
  return json({ ok: true, org: body.org, type: "DIGEST" });
}
__name(digestWrite, "digestWrite");
async function digestRead(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get("org");
  if (!org) return json({ error: "Missing org param" }, 400);
  const digest = await kvGet(env.TALK_KV, `digest:${org}`);
  if (!digest) return json({ error: "No digest found", org }, 404);
  return json(digest);
}
__name(digestRead, "digestRead");
async function witnessWrite(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const auth = await requireSession(request, env);
  if (auth.error) return auth.error;
  const body = await request.json();
  if (!body.org || !body.witness_org || !body.witness_user || !body.digest_hash || !body.signature)
    return json({ error: "Missing required fields: org, witness_org, witness_user, digest_hash, signature" }, 400);
  const digest = await kvGet(env.TALK_KV, `digest:${body.org}`);
  if (!digest) return json({ error: "No digest found for org \u2014 publish digest first" }, 404);
  const witness = {
    type: "WITNESS",
    digest_hash: body.digest_hash,
    org: body.org,
    witness_org: body.witness_org,
    witness_user: body.witness_user,
    ts: body.ts || (/* @__PURE__ */ new Date()).toISOString(),
    signature: body.signature
  };
  await kvPut(env.TALK_KV, `witness:${body.org}:${body.witness_org}`, witness);
  return json({ ok: true, org: body.org, witness_org: body.witness_org, type: "WITNESS" });
}
__name(witnessWrite, "witnessWrite");
async function witnessRead(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get("org");
  if (!org) return json({ error: "Missing org param" }, 400);
  const list = await env.TALK_KV.list({ prefix: `witness:${org}:` });
  const witnesses = [];
  for (const key of list.keys) {
    const w = await kvGet(env.TALK_KV, key.name);
    if (w) witnesses.push(w);
  }
  return json({ org, witnesses, count: witnesses.length });
}
__name(witnessRead, "witnessRead");
async function verify(request, env) {
  if (!env.TALK_KV) return json({ error: "TALK_KV not configured" }, 500);
  const url = new URL(request.url);
  const org = url.searchParams.get("org");
  if (!org) return json({ error: "Missing org param" }, 400);
  const digest = await kvGet(env.TALK_KV, `digest:${org}`);
  if (!digest) return json({ error: "No digest found", org }, 404);
  const list = await env.TALK_KV.list({ prefix: `witness:${org}:` });
  const witnesses = [];
  for (const key of list.keys) {
    const w = await kvGet(env.TALK_KV, key.name);
    if (w) witnesses.push(w);
  }
  const matching = witnesses.filter((w) => w.digest_hash && w.org === org);
  return json({
    org,
    digest: {
      head: digest.head,
      event_count: digest.event_count,
      coin_total: digest.coin_total,
      signer: digest.signer,
      ts: digest.ts,
      signed: !!digest.signature
    },
    witnesses: matching.map((w) => ({ witness_org: w.witness_org, witness_user: w.witness_user, ts: w.ts, signed: !!w.signature })),
    witness_count: matching.length
  });
}
__name(verify, "verify");

// src/worker.js
function rateGuard(env, bucket, request, limit) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return checkRate(env, bucket, ip, limit);
}
__name(rateGuard, "rateGuard");
var worker_default = {
  async fetch(request, env) {
    const _t0 = Date.now();
    setReqOrigin(corsOrigin(request, env));
    if (request.method === "OPTIONS") {
      const h = { ...CORS_DEFAULTS };
      const origin = corsOrigin(request, env);
      if (origin) h["Access-Control-Allow-Origin"] = origin;
      return new Response(null, { status: 204, headers: h });
    }
    const url = new URL(request.url);
    let path = url.pathname;
    if (path.startsWith("/v1/v1/")) path = path.slice(3);
    const method = request.method;
    const _ip = request.headers.get("CF-Connecting-IP") || "unknown";
    env = envForLane(url.hostname, env);
    if (path === "/health") {
      if (url.searchParams.get("deep") === "true") return deepHealth(env);
      return json({ status: "ok", provider: env.PROVIDER, model: env.MODEL, ts: Date.now() });
    }
    if ((path === "/v1/models" || path === "/models") && method === "GET")
      return oaiModels(request, env);
    if ((path === "/v1/chat/completions" || path === "/chat/completions") && method === "POST") {
      if (await rateGuard(env, "oai", request, 120)) return json({ error: "Rate limited" }, 429);
      return oaiChatCompletions(request, env);
    }
    if ((path === "/v1/responses" || path === "/responses") && method === "POST")
      return oaiResponses(request, env);
    if (path === "/v1/bakeoff" && method === "POST")
      return oaiBakeoff(request, env);
    if (path === "/auth/config")
      return authConfig(env);
    if (path === "/api/v1/auth/github/callback" && method === "GET") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) return json({ error: "Missing code or state" }, 400);
      try {
        const returnUrl = new URL(state);
        returnUrl.searchParams.set("code", code);
        return new Response(null, { status: 302, headers: { "Location": returnUrl.toString() } });
      } catch (_) {
        return json({ error: "Invalid state URL" }, 400);
      }
    }
    if (path === "/auth/github" && method === "POST") {
      if (await rateGuard(env, "auth", request, 20)) return json({ error: "Rate limited" }, 429);
      return authGitHub(request, env);
    }
    if (path === "/auth/session" && method === "GET")
      return authSession(request, env);
    if (path === "/auth/logout" && method === "POST")
      return authLogout(request, env);
    if (path === "/auth/grants" && method === "GET")
      return authGrants(request, env);
    if (path === "/galaxy/auth" && method === "GET")
      return galaxyAuth(request, env);
    if (path === "/chat" && method === "POST") {
      if (await rateGuard(env, "chat", request, 60)) return json({ error: "Rate limited" }, 429);
      return chat(request, env);
    }
    if (path === "/email/send" && method === "POST") {
      if (await rateGuard(env, "email", request, 10)) return json({ error: "Rate limited" }, 429);
      return handle(request, env);
    }
    if (path === "/shop/checkout" && method === "POST") {
      if (await rateGuard(env, "checkout", request, 20)) return json({ error: "Rate limited" }, 429);
      return shopCheckout(request, env);
    }
    if (path === "/shop/webhook/stripe" && method === "POST")
      return shopStripeWebhook(request, env);
    if (path === "/shop/wallet" && method === "GET")
      return shopWallet(request, env);
    if (path === "/talk/ledger" && method === "POST") return ledgerWrite(request, env);
    if (path === "/talk/ledger" && method === "GET") return ledgerRead(request, env);
    if (path === "/talk/send" && method === "POST") return send(request, env);
    if (path === "/talk/inbox" && method === "GET") return inbox(request, env);
    if (path === "/talk/ack" && method === "POST") return ack(request, env);
    if (path === "/contribute" && method === "POST") return contribute(request, env);
    if (path === "/contribute" && method === "GET") return contributeRead(request, env);
    if (path.startsWith("/omics/")) {
      if (await rateGuard(env, "omics", request, 200)) return json({ error: "Rate limited" }, 429);
      return handle2(request, env, null, url);
    }
    if (path.startsWith("/star/")) {
      const starPath = path.slice(5);
      if (starPath === "/status") return status(request, env);
      if (starPath === "/gov") return gov(request, env);
      const { error, session: sess } = await requireSession(request, env);
      if (error) return error;
      if (starPath === "/timeline") return timeline(request, env, sess);
      if (starPath === "/services") return services(request, env, sess);
      if (starPath === "/intel") return intel(request, env, sess);
      if (starPath === "/econ") return econ(request, env, sess);
      if (starPath === "/identity") return identity(request, env, sess);
      if (starPath === "/media") return media(request, env, sess);
      return json({ error: "Unknown STAR route" }, 404);
    }
    if (path.startsWith("/runner/")) {
      if (await rateGuard(env, "runner", request, 60)) return json({ error: "Rate limited" }, 429);
      return handle3(path.slice(8), request, env);
    }
    if (path === "/ledger/digest" && method === "POST") return digestWrite(request, env);
    if (path === "/ledger/digest" && method === "GET") return digestRead(request, env);
    if (path === "/ledger/witness" && method === "POST") return witnessWrite(request, env);
    if (path === "/ledger/witness" && method === "GET") return witnessRead(request, env);
    if (path === "/ledger/verify" && method === "GET") return verify(request, env);
    console.log(JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), path, method, ip: _ip, status: 404, latency_ms: Date.now() - _t0 }));
    return json({ error: "Not found" }, 404);
  }
};

// ../../../../../opt/homebrew/Cellar/cloudflare-wrangler/4.60.0/libexec/lib/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../../../opt/homebrew/Cellar/cloudflare-wrangler/4.60.0/libexec/lib/node_modules/wrangler/templates/middleware/middleware-scheduled.ts
var scheduled = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  const url = new URL(request.url);
  if (url.pathname === "/__scheduled") {
    const cron = url.searchParams.get("cron") ?? "";
    await middlewareCtx.dispatch("scheduled", { cron });
    return new Response("Ran scheduled event");
  }
  const resp = await middlewareCtx.next(request, env);
  if (request.headers.get("referer")?.endsWith("/__scheduled") && url.pathname === "/favicon.ico" && resp.status === 500) {
    return new Response(null, { status: 404 });
  }
  return resp;
}, "scheduled");
var middleware_scheduled_default = scheduled;

// ../../../../../opt/homebrew/Cellar/cloudflare-wrangler/4.60.0/libexec/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-LFxSC2/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_scheduled_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// ../../../../../opt/homebrew/Cellar/cloudflare-wrangler/4.60.0/libexec/lib/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-LFxSC2/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
