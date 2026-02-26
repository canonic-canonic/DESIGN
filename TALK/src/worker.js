/**
 * canonic-services — Cloudflare Worker
 *
 * TALK backend + AUTH. MAGIC governed. Direct mapping. Zero hardcoding.
 * CANON.json → talk.js → Worker → LLM
 *
 * Provider, model, tokens — all from wrangler.toml [vars].
 * GitHub OAuth — client_id from vars, client_secret from secrets.
 *
 * GET  /health       — status
 * POST /chat         — conversation
 * GET  /auth/config  — GitHub OAuth config (client_id + scopes)
 * POST /auth/github  — exchange code for token, create server-side session
 * GET  /auth/session — validate session token, return user identity
 * POST /auth/logout  — delete session from KV
 * GET  /auth/grants?scope=X — check if session user can access scope X
 * POST /email/send   — send branded HTML email via Resend
 * POST /shop/checkout        — create Stripe Checkout session
 * POST /shop/webhook/stripe  — Stripe webhook verification endpoint
 * GET  /shop/wallet          — public-safe wallet summary from Stripe sessions
 * POST /talk/ledger          — log conversation turn to server-side ledger
 * GET  /talk/ledger?scope=X  — read session ledger for a scope
 * POST /talk/send            — cross-user message delivery
 * GET  /talk/inbox?scope=X   — read inbox for a user scope
 * POST /talk/ack             — acknowledge (mark read) inbox messages
 * POST /contribute            — submit governed contribution (COIN mint)
 * GET  /contribute?scope=X    — read contributions for a scope
 * GET  /omics/ncbi/*          — NCBI E-utilities proxy (GEO, ClinVar, PubMed)
 * GET  /omics/pharmgkb/*      — PharmGKB proxy (drug-gene interactions)
 *
 * MAGIC | CANONIC | 2026-02
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function addCors(headers) {
  const h = new Headers(headers || {});
  for (const [k, v] of Object.entries(CORS)) h.set(k, v);
  return h;
}

function coerceContentToText(content) {
  // KiloCode and some OpenAI-compatible clients send rich content parts:
  // - string
  // - { text: "..." }
  // - [{ type: "text", text: "..." }, ...]
  if (typeof content === 'string') return content;
  if (content && typeof content === 'object' && typeof content.text === 'string') return content.text;
  if (Array.isArray(content)) {
    const text = content
      .map(p => {
        if (!p) return '';
        if (typeof p === 'string') return p;
        if (typeof p.text === 'string') return p.text;
        if (p.type === 'text' && typeof p.text === 'string') return p.text;
        if (p.type === 'input_text' && typeof p.text === 'string') return p.text;
        return '';
      })
      .filter(Boolean)
      .join('');
    return text || '';
  }
  return '';
}

const PROVIDERS = {
  anthropic: {
    url: 'https://api.anthropic.com/v1/messages',
    build(env, system, messages) {
      return {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': env.ANTHROPIC_VERSION,
        },
        body: { model: env.MODEL, max_tokens: maxTokens(env), system, messages },
      };
    },
    parse(data) { return data.content?.[0]?.text; },
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
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
        },
        body: { model: env.OPENAI_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: 'system', content: system }, ...messages] },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
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
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}`,
        },
        body: { model: env.DEEPSEEK_MODEL || env.MODEL, max_tokens: maxTokens(env), messages: [{ role: 'system', content: system }, ...messages] },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
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
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + env.RUNPOD_API_KEY,
        },
        body: {
          model: env.RUNPOD_MODEL || env.MODEL,
          max_tokens: maxTokensFor('RUNPOD', env),
          messages: [{ role: 'system', content: system }, ...messages],
        },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
  },
  vastai: {
    // Vast.ai instances typically run an OpenAI-compatible server (vLLM) at
    //   http(s)://<ip>:<port>/v1
    // This adapter expects VASTAI_BASE_URL to point at that base, then appends
    // /chat/completions (same pattern as RUNPOD).
    url(env) {
      const raw = (env.VASTAI_BASE_URL || '').trim();
      if (!raw) return '';
      const base = raw.replace(/\/+$/, '');
      if (base.endsWith('/chat/completions')) return base;
      return base + '/chat/completions';
    },
    validate(env) {
      if (!env.VASTAI_BASE_URL) return 'VASTAI_BASE_URL not configured';
      // VASTAI_API_KEY is optional; only required if your upstream enforces it.
      return null;
    },
    build(env, system, messages) {
      const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim();
      const headers = { 'Content-Type': 'application/json' };
      if (key) headers.Authorization = 'Bearer ' + key;
      return {
        headers,
        body: {
          model: env.VASTAI_MODEL || env.MODEL,
          max_tokens: maxTokensFor('VASTAI', env),
          messages: [{ role: 'system', content: system }, ...messages],
        },
      };
    },
    parse(data) { return data.choices?.[0]?.message?.content; },
  },
};

function clampInt(n, lo, hi) {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}

function clampString(s, maxLen) {
  if (typeof s !== 'string') return '';
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + '…';
}

function parseIntEnv(env, key) {
  const v = env[key];
  if (v === undefined || v === null || v === '') return null;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}

function maxTokens(env) {
  // Governance: clamp requested max_tokens to an explicit min/max envelope.
  const lo = parseIntEnv(env, 'TOKENS_MIN') ?? 16;
  const hi = parseIntEnv(env, 'TOKENS_MAX') ?? 4096;
  const req = parseIntEnv(env, 'MAX_TOKENS') ?? hi;
  return clampInt(req, lo, hi);
}

function maxTokensFor(providerName, env) {
  // Provider-specific clamps override global min/max when set.
  const prefix = String(providerName || '').toUpperCase();
  const lo = parseIntEnv(env, `${prefix}_TOKENS_MIN`) ?? parseIntEnv(env, 'TOKENS_MIN') ?? 16;
  const hi = parseIntEnv(env, `${prefix}_TOKENS_MAX`) ?? parseIntEnv(env, 'TOKENS_MAX') ?? 4096;
  const req = parseIntEnv(env, 'MAX_TOKENS') ?? hi;
  return clampInt(req, lo, hi);
}

function timeoutMsFor(providerName, env) {
  // Defaults: Runpod cold starts can hang behind Cloudflare 504s; keep a short
  // timeout and fallback rather than taking down /chat.
  if (providerName === 'runpod') return parseIntEnv(env, 'RUNPOD_TIMEOUT_MS') ?? 12000;
  if (providerName === 'vastai') return parseIntEnv(env, 'VASTAI_TIMEOUT_MS') ?? (parseIntEnv(env, 'PROVIDER_TIMEOUT_MS') ?? 25000);
  return parseIntEnv(env, 'PROVIDER_TIMEOUT_MS') ?? 25000;
}

function redactSecrets(s) {
  if (typeof s !== 'string' || !s) return '';
  return s
    .replace(/Bearer\\s+[A-Za-z0-9._\\-]+/g, 'Bearer [REDACTED]')
    .replace(/sk-[A-Za-z0-9_\\-]+/g, 'sk-[REDACTED]')
    .replace(/re_[A-Za-z0-9_\\-]+/g, 're_[REDACTED]');
}

async function fetchWithTimeout(url, init, ms) {
  // AbortSignal.timeout exists in Workers; keep a fallback for safety.
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
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

function boolEnv(env, key, fallback = false) {
  const raw = String(env && env[key] !== undefined ? env[key] : '').trim().toLowerCase();
  if (!raw) return !!fallback;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function intEnv(env, key, fallback) {
  const n = parseIntEnv(env, key);
  return Number.isFinite(n) ? n : fallback;
}

function isoFromUnix(tsSec) {
  if (!Number.isFinite(tsSec)) return new Date().toISOString();
  return new Date(tsSec * 1000).toISOString();
}

function normalizeShopEvent(v) {
  const s = String(v || '').trim().toUpperCase();
  return (s === 'SALE' || s === 'DONATION' || s === 'INVEST' || s === 'BILL' || s === 'CLOSE') ? s : '';
}

function normalizeShopProduct(v) {
  const s = String(v || '').trim().toUpperCase();
  if (!s) return 'GENERAL';
  if (!/^[A-Z0-9][A-Z0-9-]{0,47}$/.test(s)) return 'GENERAL';
  return s;
}

function stripeApiBase(env) {
  return String(env.STRIPE_API_BASE || 'https://api.stripe.com').replace(/\/+$/, '');
}

async function stripeApiRequest(env, method, path, formFields) {
  if (!env.STRIPE_SECRET_KEY) {
    return { ok: false, status: 500, error: 'STRIPE_SECRET_KEY not configured' };
  }
  const headers = {
    'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
  };
  let body = null;
  if (formFields && typeof formFields === 'object') {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(formFields)) {
      if (v === undefined || v === null || v === '') continue;
      params.set(k, String(v));
    }
    body = params.toString();
  }
  try {
    const res = await fetch(stripeApiBase(env) + path, { method, headers, body });
    const raw = await res.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { raw }; }
    if (!res.ok) {
      const msg = (data && data.error && data.error.message) ? data.error.message : `Stripe ${res.status}`;
      return { ok: false, status: res.status, error: msg, data };
    }
    return { ok: true, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 502, error: `Stripe fetch error: ${String(e && e.message ? e.message : e)}` };
  }
}

function stripeSignatureParts(headerValue) {
  const out = { t: '', v1: [] };
  const h = String(headerValue || '').trim();
  if (!h) return out;
  for (const part of h.split(',')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === 't') out.t = val;
    if (key === 'v1' && val) out.v1.push(val);
  }
  return out;
}

function timingSafeEqHex(a, b) {
  const x = String(a || '');
  const y = String(b || '');
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

async function stripeVerifyWebhookSignature(rawBody, sigHeader, secret, toleranceSec) {
  if (!secret) return { ok: false, error: 'STRIPE_WEBHOOK_SECRET not configured' };
  const parts = stripeSignatureParts(sigHeader);
  if (!parts.t || !parts.v1.length) return { ok: false, error: 'Missing Stripe signature fields' };

  const ts = parseInt(parts.t, 10);
  if (!Number.isFinite(ts)) return { ok: false, error: 'Invalid Stripe signature timestamp' };
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > toleranceSec) return { ok: false, error: 'Stripe signature timestamp out of tolerance' };

  const payload = `${parts.t}.${rawBody}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  const sigHex = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

  const matched = parts.v1.some(v => timingSafeEqHex(v.toLowerCase(), sigHex.toLowerCase()));
  if (!matched) return { ok: false, error: 'Stripe signature mismatch' };
  return { ok: true };
}

function initWalletSummary() {
  return {
    canon: 'WALLET.v1',
    source: 'stripe',
    currency: 'COIN',
    work_equals_coin: true,
    events: 0,
    balance: 0,
    last_close: '',
    updated_at: new Date().toISOString(),
    totals: {
      SALE: 0,
      DONATION: 0,
      INVEST: 0,
      BILL: 0,
      CLOSE: 0,
      credit: 0,
      debit: 0,
      net: 0,
    },
    services: {},
    products: {},
    recent: [],
  };
}

function applyWalletDelta(bucket, key, delta) {
  const k = String(key || 'GENERAL').toUpperCase();
  if (!bucket[k]) bucket[k] = { credit: 0, debit: 0, net: 0 };
  if (delta >= 0) bucket[k].credit += delta;
  else bucket[k].debit += Math.abs(delta);
  bucket[k].net = bucket[k].credit - bucket[k].debit;
}

function sortedWalletBucket(bucket, topN) {
  const rows = Object.entries(bucket).map(([k, row]) => ({
    k,
    credit: row.credit || 0,
    debit: row.debit || 0,
    net: row.net || 0,
  }));
  rows.sort((a, b) => (b.net - a.net) || (b.credit - a.credit) || (a.debit - b.debit) || a.k.localeCompare(b.k));
  return topN > 0 ? rows.slice(0, topN) : rows;
}

function walletEventFromStripeSession(session, coinToCents) {
  if (!session || session.status !== 'complete' || session.payment_status !== 'paid') return null;
  const md = session.metadata || {};
  const eventType = normalizeShopEvent(md.event || md.type || 'SALE') || 'SALE';
  const amountCoinRaw = parseInt(md.amount_coin || '', 10);
  const amountCoin = Number.isFinite(amountCoinRaw) && amountCoinRaw > 0
    ? amountCoinRaw
    : Math.max(1, Math.round((Number(session.amount_total || 0) / Math.max(1, coinToCents))));
  const product = normalizeShopProduct(md.product || 'GENERAL');
  const service = normalizeShopProduct(md.service || 'BOOK');
  const delta = (eventType === 'BILL') ? -amountCoin : (eventType === 'CLOSE' ? 0 : amountCoin);
  return {
    id: String(session.id || ''),
    ts: isoFromUnix(Number(session.created || 0)),
    type: eventType,
    service,
    product,
    amount: amountCoin,
    delta,
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);
    // KiloCode (and some SDKs) may double-append /v1 when base URL already ends with /v1.
    // Normalize `/v1/v1/*` -> `/v1/*`.
    let path = url.pathname;
    if (path.startsWith('/v1/v1/')) path = path.slice(3);
    env = envForLane(url.hostname, env);

    if (path === '/health') {
      return json({ status: 'ok', provider: env.PROVIDER, model: env.MODEL, ts: Date.now() });
    }

    // OpenAI-compatible gateway for Kilo Code and other tooling.
    // - GET  /v1/models
    // - POST /v1/chat/completions
    // - POST /v1/responses (shim)
    if ((path === '/v1/models' || path === '/models') && request.method === 'GET') {
      return oaiModels(request, env);
    }
    if ((path === '/v1/chat/completions' || path === '/chat/completions') && request.method === 'POST') {
      return oaiChatCompletions(request, env);
    }
    if ((path === '/v1/responses' || path === '/responses') && request.method === 'POST') {
      return oaiResponses(request, env);
    }
    if (path === '/v1/bakeoff' && request.method === 'POST') {
      return oaiBakeoff(request, env);
    }

    if (path === '/auth/config') {
      return authConfig(env);
    }

    if (path === '/auth/github' && request.method === 'POST') {
      return authGitHub(request, env);
    }

    if (path === '/auth/session' && request.method === 'GET') {
      return authSession(request, env);
    }

    if (path === '/auth/logout' && request.method === 'POST') {
      return authLogout(request, env);
    }

    if (path === '/auth/grants' && request.method === 'GET') {
      return authGrants(request, env);
    }

    if (path === '/chat' && request.method === 'POST') {
      return chat(request, env);
    }

    if (path === '/email/send' && request.method === 'POST') {
      return emailSend(request, env);
    }

    if (path === '/shop/checkout' && request.method === 'POST') {
      return shopCheckout(request, env);
    }

    if (path === '/shop/webhook/stripe' && request.method === 'POST') {
      return shopStripeWebhook(request, env);
    }

    if (path === '/shop/wallet' && request.method === 'GET') {
      return shopWallet(request, env);
    }

    // TALK governed portal endpoints
    if (path === '/talk/ledger' && request.method === 'POST') {
      return talkLedgerWrite(request, env);
    }
    if (path === '/talk/ledger' && request.method === 'GET') {
      return talkLedgerRead(request, env);
    }
    if (path === '/talk/send' && request.method === 'POST') {
      return talkSend(request, env);
    }
    if (path === '/talk/inbox' && request.method === 'GET') {
      return talkInbox(request, env);
    }
    if (path === '/talk/ack' && request.method === 'POST') {
      return talkAck(request, env);
    }

    // CONTRIBUTE — governed contribution ledger (COIN mint)
    if (path === '/contribute' && request.method === 'POST') {
      return contribute(request, env);
    }
    if (path === '/contribute' && request.method === 'GET') {
      return contributeRead(request, env);
    }

    // OMICS — governed proxy for NCBI E-utilities + PharmGKB (browser CORS bypass)
    if (path.startsWith('/omics/')) {
      return omicsProxy(request, env);
    }

    return json({ error: 'Not found' }, 404);
  },
};

// OMICS proxy — transparent path-based forwarding for NCBI E-utilities + PharmGKB.
// Governed in TALK.md: GET /omics/ncbi/*, GET /omics/pharmgkb/*
const OMICS_UPSTREAMS = {
  '/omics/ncbi/':     'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/',
  '/omics/pharmgkb/': 'https://api.pharmgkb.org/v1/data/',
};

async function omicsProxy(request, env) {
  if (request.method !== 'GET') {
    return json({ error: 'Method not allowed' }, 405);
  }

  const url = new URL(request.url);
  const path = url.pathname;

  for (const [prefix, upstream] of Object.entries(OMICS_UPSTREAMS)) {
    if (path.startsWith(prefix)) {
      const rest = path.slice(prefix.length);
      const target = upstream + rest + url.search;
      const res = await fetch(target, { cf: { cacheTtl: 3600 } });
      const body = await res.arrayBuffer();
      const headers = addCors({
        'Content-Type': res.headers.get('Content-Type') || 'application/json',
        'Cache-Control': 'public, max-age=3600',
      });

      // LEDGER: record every proxy query (GOV: OMICS/CANON.md — every analysis ledgered)
      const source = prefix.includes('ncbi') ? 'ncbi' : 'pharmgkb';
      appendToLedger(env, 'OMICS', `OMICS:${source}`, {
        source,
        query_path: rest,
        query_params: url.search,
        upstream_status: res.status,
        ip: request.headers.get('CF-Connecting-IP') || 'unknown',
        work_ref: `omics:${source}:${Date.now()}`
      }).catch(function() {}); // fire-and-forget

      return new Response(body, { status: res.status, headers });
    }
  }

  return json({ error: 'Unknown omics upstream' }, 404);
}

function oaiError(status, message, type = 'invalid_request_error', code = null) {
  return json({ error: { message, type, param: null, code } }, status);
}

function normalizeResponseInputToMessages(input) {
  // OpenAI Responses API can pass input as a string or structured list.
  if (typeof input === 'string') return [{ role: 'user', content: input }];
  if (!Array.isArray(input)) return null;
  // Best-effort: allow [{role, content}] or content parts with {text}.
  const out = [];
  for (const item of input) {
    if (!item) continue;
    if (typeof item.role === 'string' && item.content !== undefined) {
      const text = coerceContentToText(item.content);
      if (text) out.push({ role: item.role, content: text });
      continue;
    }
    if (typeof item.text === 'string') {
      out.push({ role: 'user', content: item.text });
      continue;
    }
    const content = item.content;
    const text = coerceContentToText(content);
    if (text) out.push({ role: 'user', content: text });
  }
  return out.length ? out : null;
}

function requireGatewayKey(env) {
  return !!(env && env.CANONIC_API_KEY);
}

function checkGatewayKey(request, env) {
  if (!requireGatewayKey(env)) return null;
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const tok = m ? m[1].trim() : '';
  if (!tok || tok !== String(env.CANONIC_API_KEY)) return 'Unauthorized';
  return null;
}

function laneProviderFromHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return null;
  if (h === 'anthropic.canonic.org') return 'anthropic';
  if (h === 'runpod.canonic.org') return 'runpod';
  if (h === 'vast.canonic.org') return 'vastai';
  if (h === 'openai.canonic.org') return 'openai';
  if (h === 'deepseek.canonic.org') return 'deepseek';
  return null;
}

function envForLane(hostname, env) {
  const lane = laneProviderFromHostname(hostname);
  if (!lane) return env;

  const out = { ...env, LANE_PROVIDER: lane };
  out.PROVIDER = lane;
  out.FALLBACK_PROVIDER = lane;
  out.PROVIDER_CHAIN = lane;

  if (lane === 'runpod') out.MODEL = (env.RUNPOD_MODEL || env.MODEL);
  if (lane === 'vastai') out.MODEL = (env.VASTAI_MODEL || env.MODEL);
  if (lane === 'openai') out.MODEL = (env.OPENAI_MODEL || env.MODEL);
  if (lane === 'deepseek') out.MODEL = (env.DEEPSEEK_MODEL || env.MODEL);

  return out;
}

function completionsUrlFromBase(rawBase) {
  const raw = String(rawBase || '').trim();
  if (!raw) return '';
  const base = raw.replace(/\/+$/, '');
  if (base.endsWith('/chat/completions')) return base;
  if (base.endsWith('/v1')) return base + '/chat/completions';
  return base + '/v1/chat/completions';
}

function pushGatewayModel(out, seen, entry) {
  if (!entry || typeof entry !== 'object') return;
  const id = String(entry.id || '').trim();
  const provider = String(entry.provider || '').trim();
  if (!id || !provider) return;
  if (seen.has(id)) return;
  seen.add(id);
  out.push({ ...entry, id, provider });
}

function tokenBoundsForEntry(entry, env) {
  const provider = String((entry && entry.provider) || '').toUpperCase();
  const profile = String((entry && entry.profile) || 'talk').toLowerCase();
  const lo =
    parseIntEnv(env, `${provider}_TOKENS_MIN`) ??
    parseIntEnv(env, 'TOKENS_MIN') ??
    16;
  const hi =
    parseIntEnv(env, `${provider}_${profile === 'kilocode' ? 'KILOCODE_TOKENS_MAX' : 'TOKENS_MAX'}`) ??
    parseIntEnv(env, `${provider}_TOKENS_MAX`) ??
    (provider === 'RUNPOD' ? 512 : (parseIntEnv(env, 'TOKENS_MAX') ?? 4096));
  return { lo, hi };
}

function providerHasGatewayConfig(provider, env) {
  const p = String(provider || '').toLowerCase();
  if (p === 'anthropic') return !!(env.ANTHROPIC_API_KEY && (env.MODEL || '').trim());
  if (p === 'openai') return !!(env.OPENAI_API_KEY && ((env.OPENAI_MODEL || env.OPENAI_KILOCODE_MODEL || '').trim()));
  if (p === 'deepseek') return !!(env.DEEPSEEK_API_KEY && ((env.DEEPSEEK_MODEL || env.DEEPSEEK_KILOCODE_MODEL || '').trim()));
  if (p === 'runpod') {
    const hasBase = !!((env.RUNPOD_BASE_URL || env.RUNPOD_KILOCODE_BASE_URL || '').trim());
    const hasModel = !!((env.RUNPOD_MODEL || env.RUNPOD_KILOCODE_MODEL || '').trim());
    return !!(env.RUNPOD_API_KEY && hasBase && hasModel);
  }
  if (p === 'vastai') {
    const hasBase = !!((env.VASTAI_BASE_URL || env.VASTAI_KILOCODE_BASE_URL || '').trim());
    const hasModel = !!((env.VASTAI_MODEL || env.VASTAI_KILOCODE_MODEL || '').trim());
    return hasBase && hasModel;
  }
  return false;
}

function hasAliasConfig(env, prefix) {
  const keys = ['MODEL_ID', 'PROVIDER', 'UPSTREAM_MODEL', 'BASE_URL'];
  for (const k of keys) {
    if (String(env[`${prefix}_${k}`] || '').trim()) return true;
  }
  return false;
}

function resolveGatewayAliasEntry(env, spec) {
  const prefix = String(spec && spec.prefix ? spec.prefix : '').toUpperCase();
  const profile = spec && spec.profile === 'kilocode' ? 'kilocode' : 'chat';
  const required = !!(spec && spec.required);
  const defaultId = String((spec && spec.defaultId) || `canonic-${profile}`).trim();
  const defaultProviderOrder = Array.isArray(spec && spec.defaultProviderOrder)
    ? spec.defaultProviderOrder
    : (profile === 'kilocode'
      ? ['runpod', 'deepseek', 'openai', 'anthropic', 'vastai']
      : ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai']);
  if (!prefix) return null;
  if (!required && !hasAliasConfig(env, prefix)) return null;

  const requestedProvider = String(env[`${prefix}_PROVIDER`] || defaultProviderOrder[0]).toLowerCase().trim();
  const provider = providerHasGatewayConfig(requestedProvider, env)
    ? requestedProvider
    : (defaultProviderOrder.find(p => providerHasGatewayConfig(p, env)) || requestedProvider);

  const id = String(env[`${prefix}_MODEL_ID`] || defaultId).trim();
  let upstreamModel = String(env[`${prefix}_UPSTREAM_MODEL`] || '').trim();
  let baseUrl = String(env[`${prefix}_BASE_URL`] || '').trim();

  if (provider === 'anthropic') {
    if (!upstreamModel) upstreamModel = profile === 'kilocode'
      ? String(env.ANTHROPIC_KILOCODE_MODEL || env.MODEL || '').trim()
      : String(env.MODEL || '').trim();
    baseUrl = '';
  } else if (provider === 'openai') {
    if (!upstreamModel) upstreamModel = profile === 'kilocode'
      ? String(env.OPENAI_KILOCODE_MODEL || env.OPENAI_MODEL || '').trim()
      : String(env.OPENAI_MODEL || '').trim();
    if (!baseUrl) baseUrl = profile === 'kilocode'
      ? String(env.OPENAI_KILOCODE_BASE_URL || env.OPENAI_BASE_URL || '').trim()
      : String(env.OPENAI_BASE_URL || '').trim();
  } else if (provider === 'deepseek') {
    if (!upstreamModel) upstreamModel = profile === 'kilocode'
      ? String(env.DEEPSEEK_KILOCODE_MODEL || env.DEEPSEEK_MODEL || '').trim()
      : String(env.DEEPSEEK_MODEL || '').trim();
    if (!baseUrl) baseUrl = profile === 'kilocode'
      ? String(env.DEEPSEEK_KILOCODE_BASE_URL || env.DEEPSEEK_BASE_URL || '').trim()
      : String(env.DEEPSEEK_BASE_URL || '').trim();
  } else if (provider === 'runpod') {
    if (!upstreamModel) upstreamModel = profile === 'kilocode'
      ? String(env.RUNPOD_KILOCODE_MODEL || env.RUNPOD_MODEL || '').trim()
      : String(env.RUNPOD_MODEL || '').trim();
    if (!baseUrl) baseUrl = profile === 'kilocode'
      ? String(env.RUNPOD_KILOCODE_BASE_URL || env.RUNPOD_BASE_URL || '').trim()
      : String(env.RUNPOD_BASE_URL || '').trim();
  } else if (provider === 'vastai') {
    if (!upstreamModel) upstreamModel = profile === 'kilocode'
      ? String(env.VASTAI_KILOCODE_MODEL || env.VASTAI_MODEL || '').trim()
      : String(env.VASTAI_MODEL || '').trim();
    if (!baseUrl) baseUrl = profile === 'kilocode'
      ? String(env.VASTAI_KILOCODE_BASE_URL || env.VASTAI_BASE_URL || '').trim()
      : String(env.VASTAI_BASE_URL || '').trim();
  }

  if (!id || !upstreamModel) return null;
  const entry = { id, provider, profile, upstream_model: upstreamModel };
  if (baseUrl) entry.base_url = baseUrl;
  return entry;
}

function listGatewayModels(env) {
  const out = [];
  const seen = new Set();
  const specs = [
    {
      prefix: 'CHAT',
      profile: 'chat',
      defaultId: 'canonic-chat',
      required: true,
      defaultProviderOrder: ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai'],
    },
    {
      prefix: 'KILOCODE',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode',
      required: true,
      defaultProviderOrder: ['runpod', 'deepseek', 'openai', 'anthropic', 'vastai'],
    },
    {
      prefix: 'CHAT_COMMERCIAL',
      profile: 'chat',
      defaultId: 'canonic-chat-commercial',
      defaultProviderOrder: ['deepseek', 'anthropic', 'openai', 'runpod', 'vastai'],
    },
    {
      prefix: 'CHAT_COMMERCIAL_OPENAI',
      profile: 'chat',
      defaultId: 'canonic-chat-commercial-openai',
      defaultProviderOrder: ['openai', 'deepseek', 'anthropic', 'runpod', 'vastai'],
    },
    {
      prefix: 'CHAT_COMMERCIAL_ANTHROPIC',
      profile: 'chat',
      defaultId: 'canonic-chat-commercial-anthropic',
      defaultProviderOrder: ['anthropic', 'deepseek', 'openai', 'runpod', 'vastai'],
    },
    {
      prefix: 'CHAT_OPENSOURCE_RUNPOD',
      profile: 'chat',
      defaultId: 'canonic-chat-opensource-runpod',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_OPENSOURCE_VAST',
      profile: 'chat',
      defaultId: 'canonic-chat-opensource-vast',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_RUNPOD_DEEPSEEK',
      profile: 'chat',
      defaultId: 'canonic-chat-runpod-deepseek',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_RUNPOD_QWEN',
      profile: 'chat',
      defaultId: 'canonic-chat-runpod-qwen',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_RUNPOD_MISTRAL',
      profile: 'chat',
      defaultId: 'canonic-chat-runpod-mistral',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_RUNPOD_LLAMA',
      profile: 'chat',
      defaultId: 'canonic-chat-runpod-llama',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_RUNPOD_GLM',
      profile: 'chat',
      defaultId: 'canonic-chat-runpod-glm',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_VAST_DEEPSEEK',
      profile: 'chat',
      defaultId: 'canonic-chat-vast-deepseek',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_VAST_QWEN',
      profile: 'chat',
      defaultId: 'canonic-chat-vast-qwen',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_VAST_MISTRAL',
      profile: 'chat',
      defaultId: 'canonic-chat-vast-mistral',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_VAST_LLAMA',
      profile: 'chat',
      defaultId: 'canonic-chat-vast-llama',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'CHAT_VAST_GLM',
      profile: 'chat',
      defaultId: 'canonic-chat-vast-glm',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_COMMERCIAL',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-commercial',
      defaultProviderOrder: ['openai', 'deepseek', 'anthropic', 'runpod', 'vastai'],
    },
    {
      prefix: 'KILOCODE_OPENSOURCE_RUNPOD',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-opensource-runpod',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_OPENSOURCE_VAST',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-opensource-vast',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_RUNPOD_DEEPSEEK',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-runpod-deepseek',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_RUNPOD_QWEN',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-runpod-qwen',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_RUNPOD_GLM',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-runpod-glm',
      defaultProviderOrder: ['runpod', 'vastai', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_VAST_DEEPSEEK',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-vast-deepseek',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_VAST_QWEN',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-vast-qwen',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
    {
      prefix: 'KILOCODE_VAST_GLM',
      profile: 'kilocode',
      defaultId: 'canonic-kilocode-vast-glm',
      defaultProviderOrder: ['vastai', 'runpod', 'deepseek', 'openai', 'anthropic'],
    },
  ];

  for (const spec of specs) {
    const entry = resolveGatewayAliasEntry(env, spec);
    if (entry) pushGatewayModel(out, seen, entry);
  }

  const lane = (env.LANE_PROVIDER || '').trim();
  if (lane) return out.filter(m => m.provider === lane);
  return out;
}

function runpodEndpointIdFromBaseUrl(baseUrl) {
  if (!baseUrl) return null;
  const m = String(baseUrl).match(/\/v2\/([^/]+)\/openai\/v1\/?$/);
  return m ? m[1] : null;
}

function isRunpodProxyBaseUrl(baseUrl) {
  if (!baseUrl) return false;
  const b = String(baseUrl).replace(/\/+$/, '');
  return /\.proxy\.runpod\.net\/v1$/.test(b);
}

async function runpodProxyReady(baseUrl, env) {
  const b = String(baseUrl || '').replace(/\/+$/, '');
  if (!b) return null;
  try {
    const r = await fetchWithTimeout(b + '/models', {
      headers: { 'Accept': 'application/json' },
    }, parseIntEnv(env, 'RUNPOD_HEALTH_TIMEOUT_MS') ?? 2000);
    return { ok: r.ok, status: r.status };
  } catch {
    return null;
  }
}

async function runpodHealth(endpointId, env) {
  const id = String(endpointId || '').trim();
  if (!id) return null;
  // Use the EDGE /health as CANON. Keep this bounded and fail-soft.
  try {
    const r = await fetchWithTimeout(`https://api.runpod.ai/v2/${id}/health`, {
      headers: {
        'Accept': 'application/json',
        // Runpod health accepts raw key. (Bearer also often works, but keep canonical.)
        'Authorization': String(env.RUNPOD_API_KEY || ''),
      },
    }, parseIntEnv(env, 'RUNPOD_HEALTH_TIMEOUT_MS') ?? 2000);
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function oaiModels(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  const models = listGatewayModels(env).map(m => ({
    id: m.id,
    object: 'model',
    owned_by: 'canonic',
  }));
  return json({ object: 'list', data: models });
}

async function oaiResponses(request, env) {
  // Minimal OpenAI Responses API shim for clients that prefer /v1/responses.
  // We translate to chat.completions internally and then wrap the result.
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body;
  try { body = await request.json(); }
  catch { return oaiError(400, 'Invalid JSON'); }

  const model = (body && body.model ? String(body.model) : '').trim();
  const audience = String(
    (body && (body.audience || body.suite)) || '',
  ).toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  const autoAssignAudience = (audience === 'user' || audience === 'patient' || audience === 'dev' || audience === 'experiment');
  if (!model && !(randomize || autoAssignAudience)) return oaiError(400, 'Missing model');

  // Prefer explicit messages if provided; else derive from input.
  let messages = null;
  if (body && Array.isArray(body.messages) && body.messages.length) {
    messages = body.messages;
  } else if (body && body.input !== undefined) {
    messages = normalizeResponseInputToMessages(body.input);
  }
  if (!messages || !messages.length) return oaiError(400, 'Missing messages/input');

  // Map max_output_tokens -> max_tokens.
  const chatBody = {
    messages,
    max_tokens: body.max_output_tokens ?? body.max_tokens,
    temperature: body.temperature,
    top_p: body.top_p,
    presence_penalty: body.presence_penalty,
    frequency_penalty: body.frequency_penalty,
    stop: body.stop,
    seed: body.seed,
    stream: false,
    n: 1,
  };
  if (model) chatBody.model = model;
  if (audience) chatBody.audience = audience;
  if (randomize) chatBody.randomize_model = true;
  if (body && body.user_id !== undefined) chatBody.user_id = body.user_id;
  if (body && body.patient_id !== undefined) chatBody.patient_id = body.patient_id;
  if (body && body.session_id !== undefined) chatBody.session_id = body.session_id;

  // Reuse the chat.completions implementation (governance + routing).
  const r2 = new Request('https://api.canonic.org/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // Preserve any auth header for optional gateway key enforcement.
      'Authorization': request.headers.get('Authorization') || '',
    },
    body: JSON.stringify(chatBody),
  });
  const chatRes = await oaiChatCompletions(r2, env);
  const text = await chatRes.text();
  if (chatRes.status !== 200) {
    // Pass through OpenAI-style error payload for compatibility.
    return new Response(text, { status: chatRes.status, headers: addCors(chatRes.headers) });
  }

  let data;
  try { data = JSON.parse(text); } catch { return oaiError(502, 'Upstream returned invalid JSON', 'api_error'); }
  const content = data && data.choices && data.choices[0] && data.choices[0].message
    ? String(data.choices[0].message.content || '')
    : '';

  const usage = data && data.usage ? data.usage : null;
  const out = {
    id: 'resp-canonic-' + (data.id ? String(data.id).replace(/^chatcmpl-/, '') : String(Date.now())),
    object: 'response',
    created: Math.floor(Date.now() / 1000),
    model,
    output: [
      {
        type: 'message',
        role: 'assistant',
        content: [{ type: 'output_text', text: content }],
      },
    ],
    // Some clients look for a convenience string.
    output_text: content,
    usage,
  };

  const h = addCors({ 'Content-Type': 'application/json' });
  // Preserve CANONIC trace headers if present.
  const trace = chatRes.headers.get('x-canonic-trace-id');
  if (trace) h.set('x-canonic-trace-id', trace);
  const prof = chatRes.headers.get('x-canonic-model-profile');
  if (prof) h.set('x-canonic-model-profile', prof);
  const elapsed = chatRes.headers.get('x-canonic-upstream-elapsed-ms');
  if (elapsed) h.set('x-canonic-upstream-elapsed-ms', elapsed);
  return new Response(JSON.stringify(out), { status: 200, headers: h });
}

function stableIndexFromKey(key, len) {
  const n = Math.max(1, parseInt(len, 10) || 1);
  const s = String(key || '');
  if (!s) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
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

function resolveChatRequestedModel(body, env, registry) {
  const requested = (body && body.model ? String(body.model) : '').trim();
  if (requested) return { model: requested, assigned: false };

  const audience = String(
    (body && (body.audience || body.suite)) || '',
  ).toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  const autoAssignAudience = (audience === 'user' || audience === 'patient' || audience === 'dev' || audience === 'experiment');
  if (!(autoAssignAudience || randomize)) return { model: '', assigned: false };

  const configured =
    audience === 'dev' ? parseModelCsv(env.BAKEOFF_DEV_MODELS)
      : (audience === 'user' || audience === 'patient') ? parseModelCsv(env.BAKEOFF_USER_MODELS)
        : parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS);
  const fallback = registry.filter(m => m.profile === 'chat').map(m => m.id);
  const source = configured.length ? configured : fallback;
  const known = new Set(registry.map(m => m.id));
  const candidates = source.filter(id => known.has(id));
  if (!candidates.length) return { model: '', assigned: false, error: 'No randomized models configured' };

  const key = String(
    (body && (body.patient_id || body.user_id || body.session_id)) ||
    '',
  ).trim();
  const idx = stableIndexFromKey(key, candidates.length);
  return { model: candidates[idx], assigned: true };
}

async function oaiChatCompletions(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body;
  try { body = await request.json(); }
  catch { return oaiError(400, 'Invalid JSON'); }

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

  // Governance clamps.
  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);

  const stream = !!(body && body.stream);
  if (body && body.n && parseInt(body.n, 10) !== 1) return oaiError(400, 'Only n=1 is supported');

  // Trim to keep payload bounded.
  const messages = messagesIn.slice(-40).map(m => ({
    role: String(m.role || '').trim(),
    content: coerceContentToText(m.content),
  })).filter(m => m.role && m.content);
  if (!messages.length) return oaiError(400, 'No valid messages');

  const timeout_ms = parseIntEnv(env, 'OAI_GATEWAY_TIMEOUT_MS') ?? (stream ? 600000 : 120000);
  const trace_id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now());
  const started = Date.now();

  const allowed = ['temperature', 'top_p', 'presence_penalty', 'frequency_penalty', 'stop', 'seed'];
  const pass = {};
  for (const k of allowed) {
    if (body && body[k] !== undefined) pass[k] = body[k];
  }

  if (entry.provider === 'anthropic') {
    if (!env.ANTHROPIC_API_KEY) return oaiError(500, 'ANTHROPIC_API_KEY not configured');

    // OpenAI -> Anthropic translation:
    // - system: concatenate any system messages
    // - messages: keep user/assistant only
    const sys = messagesIn
      .filter(m => m && m.role === 'system')
      .map(m => coerceContentToText(m.content))
      .filter(Boolean)
      .join('\n\n');
    const anthMessages = messagesIn
      .filter(m => m && (m.role === 'user' || m.role === 'assistant'))
      .slice(-40)
      .map(m => ({ role: m.role, content: coerceContentToText(m.content) }))
      .filter(m => m.role && m.content);
    if (!anthMessages.length) return oaiError(400, 'No valid user/assistant messages');

    let res;
    try {
      res = await fetchWithTimeout(PROVIDERS.anthropic.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': env.ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: upstreamModel,
          max_tokens,
          system: sys || undefined,
          messages: anthMessages,
        }),
      }, parseIntEnv(env, 'OAI_GATEWAY_TIMEOUT_MS') ?? 25000);
    } catch (e) {
      return oaiError(502, `Upstream error: ${clampString(String(e && e.message ? e.message : e), 180)}`, 'api_error');
    }
    const text = await res.text();
    if (!res.ok) {
      const safe = clampString(redactSecrets(text), 900);
      return oaiError(502, `Anthropic ${res.status}: ${safe}`, 'api_error');
    }
    let data;
    try { data = JSON.parse(text); } catch { return oaiError(502, 'Anthropic returned invalid JSON', 'api_error'); }
    const content = data && data.content && data.content[0] && data.content[0].text ? String(data.content[0].text) : '';

    const h = addCors({ 'Content-Type': 'application/json' });
    h.set('x-canonic-trace-id', trace_id);
    h.set('x-canonic-model-profile', entry.profile || 'anthropic');
    h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
    if (selection.assigned) h.set('x-canonic-assigned-model', model);

    // Anthropic -> OpenAI chat.completions schema (minimal).
    const out = {
      id: 'chatcmpl-canonic-' + trace_id,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content },
          finish_reason: 'stop',
          logprobs: null,
        },
      ],
      usage: null,
    };

    // Some clients require streaming; provide a single-chunk SSE wrapper.
    if (stream) {
      const sh = addCors({
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
      });
      sh.set('x-canonic-trace-id', trace_id);
      sh.set('x-canonic-model-profile', entry.profile || 'anthropic');
      sh.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
      if (selection.assigned) sh.set('x-canonic-assigned-model', model);
      const chunk = {
        id: out.id,
        object: 'chat.completion.chunk',
        created: out.created,
        model: out.model,
        choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }],
      };
      const rs = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`));
          controller.enqueue(new TextEncoder().encode(`data: [DONE]\n\n`));
          controller.close();
        },
      });
      return new Response(rs, { status: 200, headers: sh });
    }

    return new Response(JSON.stringify(out), { status: 200, headers: h });
  }

  if (entry.provider === 'openai' || entry.provider === 'deepseek') {
    const p = PROVIDERS[entry.provider];
    if (!p) return oaiError(500, `Unsupported provider for this model: ${entry.provider}`);

    const providerError = p.validate?.(env);
    if (providerError) return oaiError(500, providerError, 'configuration_error');

    const providerUrl = entry.base_url
      ? completionsUrlFromBase(entry.base_url)
      : (typeof p.url === 'function' ? p.url(env) : p.url);
    if (!providerUrl) return oaiError(500, `Provider URL misconfigured: ${entry.provider}`, 'configuration_error');

    const payload = { model: upstreamModel, messages, max_tokens, stream, ...pass };
    const headers = { 'Content-Type': 'application/json' };
    if (entry.provider === 'openai') headers.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === 'deepseek') headers.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;

    let res;
    try {
      res = await fetchWithTimeout(providerUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      }, timeout_ms);
    } catch (e) {
      return oaiError(502, `Upstream error: ${clampString(String(e && e.message ? e.message : e), 180)}`, 'api_error');
    }

    const h = addCors(res.headers);
    h.set('x-canonic-trace-id', trace_id);
    h.set('x-canonic-model-profile', entry.profile || entry.provider);
    h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
    if (selection.assigned) h.set('x-canonic-assigned-model', model);

    if (stream) return new Response(res.body, { status: res.status, headers: h });

    const text = await res.text();
    if (!res.ok) {
      const safe = clampString(redactSecrets(text), 900);
      const up = entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek';
      return oaiError(502, `${up} ${res.status}: ${safe}`, 'api_error');
    }
    return new Response(text, { status: 200, headers: h });
  }

  // OpenAI-compatible upstream route (runpod or vastai).
  const baseUrl = (entry.base_url || '').replace(/\/+$/, '');
  if (!baseUrl) return oaiError(500, `Model misconfigured: ${entry.id}`);

  if (entry.provider === 'runpod') {
    if (!env.RUNPOD_API_KEY) return oaiError(500, 'RUNPOD_API_KEY not configured');

    // Preflight readiness to avoid long hangs when upstream isn't ready.
    if ((parseIntEnv(env, 'RUNPOD_PREFLIGHT_HEALTH') ?? 1) === 1) {
      const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
      if (endpointId) {
        // Runpod serverless.
        const h = await runpodHealth(endpointId, env);
        const w = h && h.workers ? h.workers : null;
        if (w) {
          const ready = w.ready || 0;
          const throttled = w.throttled || 0;
          if (ready < 1 || throttled > 0) {
            const resp = oaiError(503, `Model warming up (ready=${ready}, throttled=${throttled}). Try again shortly.`, 'api_error');
            const hh = addCors(resp.headers);
            hh.set('Retry-After', '10');
            return new Response(resp.body, { status: resp.status, headers: hh });
          }
        }
      } else if (isRunpodProxyBaseUrl(baseUrl)) {
        // Runpod pod proxy: treat /v1/models as readiness.
        const pr = await runpodProxyReady(baseUrl, env);
        if (!pr || !pr.ok) {
          const resp = oaiError(503, `Model warming up (proxy_ready=${pr ? pr.status : 'no_response'}). Try again shortly.`, 'api_error');
          const hh = addCors(resp.headers);
          hh.set('Retry-After', '10');
          return new Response(resp.body, { status: resp.status, headers: hh });
        }
      }
    }
  }

  const payload = { model: upstreamModel, messages, max_tokens, stream, ...pass };

  const headers = { 'Content-Type': 'application/json' };
  if (entry.provider === 'runpod') {
    headers.Authorization = 'Bearer ' + env.RUNPOD_API_KEY;
  } else if (entry.provider === 'vastai') {
    const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim();
    if (key) headers.Authorization = 'Bearer ' + key;
  } else {
    return oaiError(500, `Unsupported provider for this model: ${entry.provider}`);
  }

  let res;
  try {
    const upstreamUrl = baseUrl + '/chat/completions';
    res = await fetchWithTimeout(upstreamUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }, timeout_ms);
  } catch (e) {
    return oaiError(502, `Upstream error: ${clampString(String(e && e.message ? e.message : e), 180)}`, 'api_error');
  }

  const h = addCors(res.headers);
  h.set('x-canonic-trace-id', trace_id);
  h.set('x-canonic-model-profile', entry.profile);
  h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
  if (selection.assigned) h.set('x-canonic-assigned-model', model);

  // Streaming: pass-through SSE body from upstream (OpenAI-compatible).
  if (stream) {
    return new Response(res.body, { status: res.status, headers: h });
  }

  const text = await res.text();
  if (!res.ok) {
    const safe = clampString(redactSecrets(text), 900);
    const up = entry.provider === 'runpod' ? 'Runpod' : 'VastAI';
    return oaiError(502, `${up} ${res.status}: ${safe}`, 'api_error');
  }

  // Preserve OpenAI-compatible JSON schema from upstream.
  return new Response(text, { status: 200, headers: h });
}

async function callGatewayModel(entry, body, env, trace_id) {
  const started = Date.now();
  const model = entry.id;
  const upstreamModel = (entry.upstream_model || model || '').trim();
  if (!upstreamModel) {
    return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, elapsed_ms: Date.now() - started };
  }

  // Governance clamps.
  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);

  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) {
    return { model, ok: false, status: 400, error: 'Missing messages', elapsed_ms: Date.now() - started };
  }
  const messages = messagesIn.slice(-40).map(m => ({
    role: String(m.role || '').trim(),
    content: coerceContentToText(m.content),
  })).filter(m => m.role && m.content);
  if (!messages.length) {
    return { model, ok: false, status: 400, error: 'No valid messages', elapsed_ms: Date.now() - started };
  }

  const allowed = ['temperature', 'top_p', 'presence_penalty', 'frequency_penalty', 'stop', 'seed'];
  const pass = {};
  for (const k of allowed) {
    if (body && body[k] !== undefined) pass[k] = body[k];
  }

  const gov_pre = {
    provider: entry.provider,
    profile: entry.profile || null,
    model,
    upstream_model: upstreamModel,
    max_tokens,
    tokens_min: lo,
    tokens_max: hi,
  };

  if (entry.provider === 'anthropic') {
    if (!env.ANTHROPIC_API_KEY) {
      return { model, ok: false, status: 500, error: 'ANTHROPIC_API_KEY not configured', gov_pre, elapsed_ms: Date.now() - started };
    }

    const sys = messagesIn
      .filter(m => m && m.role === 'system')
      .map(m => coerceContentToText(m.content))
      .filter(Boolean)
      .join('\n\n');
    const anthMessages = messagesIn
      .filter(m => m && (m.role === 'user' || m.role === 'assistant'))
      .slice(-40)
      .map(m => ({ role: m.role, content: coerceContentToText(m.content) }))
      .filter(m => m.role && m.content);
    if (!anthMessages.length) {
      return { model, ok: false, status: 400, error: 'No valid user/assistant messages', gov_pre, elapsed_ms: Date.now() - started };
    }

    const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 60000;
    try {
      const res = await fetchWithTimeout(PROVIDERS.anthropic.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': env.ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: upstreamModel,
          max_tokens,
          system: sys || undefined,
          messages: anthMessages,
          // Best-effort mapping.
          temperature: pass.temperature,
          top_p: pass.top_p,
          stop_sequences: pass.stop ? (Array.isArray(pass.stop) ? pass.stop : [pass.stop]) : undefined,
        }),
      }, timeout_ms);

      const text = await res.text();
      if (!res.ok) {
        return { model, ok: false, status: 502, error: `Anthropic ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      }
      const data = JSON.parse(text);
      const content = data && data.content && data.content[0] && data.content[0].text ? String(data.content[0].text) : '';
      return {
        model,
        ok: true,
        status: 200,
        content,
        usage: data && data.usage ? data.usage : null,
        gov_pre,
        gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id },
        elapsed_ms: Date.now() - started,
      };
    } catch (e) {
      return { model, ok: false, status: 502, error: `Anthropic error: ${clampString(String(e && e.message ? e.message : e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
    }
  }

  if (entry.provider === 'openai' || entry.provider === 'deepseek') {
    const p = PROVIDERS[entry.provider];
    if (!p) return { model, ok: false, status: 500, error: `Unsupported provider: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };

    const providerError = p.validate?.(env);
    if (providerError) return { model, ok: false, status: 500, error: providerError, gov_pre, elapsed_ms: Date.now() - started };

    const providerUrl = entry.base_url
      ? completionsUrlFromBase(entry.base_url)
      : (typeof p.url === 'function' ? p.url(env) : p.url);
    if (!providerUrl) return { model, ok: false, status: 500, error: `Provider URL misconfigured: ${entry.provider}`, gov_pre, elapsed_ms: Date.now() - started };

    const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 120000;
    const payload = { model: upstreamModel, messages, max_tokens, stream: false, ...pass };

    const headers = { 'Content-Type': 'application/json' };
    if (entry.provider === 'openai') headers.Authorization = `Bearer ${env.OPENAI_API_KEY}`;
    if (entry.provider === 'deepseek') headers.Authorization = `Bearer ${env.DEEPSEEK_API_KEY}`;

    try {
      const res = await fetchWithTimeout(providerUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      }, timeout_ms);
      const text = await res.text();
      if (!res.ok) {
        const up = entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek';
        return { model, ok: false, status: 502, error: `${up} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
      }
      const data = JSON.parse(text);
      const content = data && data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : '';
      return {
        model,
        ok: true,
        status: 200,
        content: typeof content === 'string' ? content : '',
        usage: data && data.usage ? data.usage : null,
        gov_pre,
        gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id },
        elapsed_ms: Date.now() - started,
      };
    } catch (e) {
      const up = entry.provider === 'openai' ? 'OpenAI' : 'DeepSeek';
      return { model, ok: false, status: 502, error: `${up} error: ${clampString(String(e && e.message ? e.message : e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
    }
  }

  // OpenAI-compatible provider (runpod or vastai).
  const baseUrl = (entry.base_url || '').replace(/\/+$/, '');
  if (!baseUrl) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, gov_pre, elapsed_ms: Date.now() - started };

  const providerName = entry.provider;
  if (providerName === 'runpod' && !env.RUNPOD_API_KEY) {
    return { model, ok: false, status: 500, error: 'RUNPOD_API_KEY not configured', gov_pre, elapsed_ms: Date.now() - started };
  }

  // Preflight /health only for Runpod serverless.
  if (providerName === 'runpod') {
    const endpointId = runpodEndpointIdFromBaseUrl(baseUrl);
    if (endpointId) {
      const h = await runpodHealth(endpointId, env);
      const w = h && h.workers ? h.workers : null;
      if (w) {
        const ready = w.ready || 0;
        const throttled = w.throttled || 0;
        if (ready < 1 || throttled > 0) {
          return { model, ok: false, status: 503, error: `warming (ready=${ready}, throttled=${throttled})`, gov_pre, health: h, elapsed_ms: Date.now() - started };
        }
      }
    } else if (isRunpodProxyBaseUrl(baseUrl)) {
      const pr = await runpodProxyReady(baseUrl, env);
      if (!pr || !pr.ok) {
        return { model, ok: false, status: 503, error: `warming (proxy_ready=${pr ? pr.status : 'no_response'})`, gov_pre, elapsed_ms: Date.now() - started };
      }
    }
  }

  const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 120000;
  const payload = { model: upstreamModel, messages, max_tokens, stream: false, ...pass };

  const headers = { 'Content-Type': 'application/json' };
  if (providerName === 'runpod') {
    headers.Authorization = 'Bearer ' + env.RUNPOD_API_KEY;
  } else if (providerName === 'vastai') {
    const key = (env.VASTAI_API_KEY || env.VLLM_API_KEY || '').trim();
    if (key) headers.Authorization = 'Bearer ' + key;
  } else {
    return { model, ok: false, status: 500, error: `Unsupported provider: ${providerName}`, gov_pre, elapsed_ms: Date.now() - started };
  }

  try {
    const res = await fetchWithTimeout(baseUrl + '/chat/completions', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }, timeout_ms);
    const text = await res.text();
    if (!res.ok) {
      const up = providerName === 'runpod' ? 'Runpod' : 'VastAI';
      return { model, ok: false, status: 502, error: `${up} ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
    }
    const data = JSON.parse(text);
    const content = data && data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : '';
    return {
      model,
      ok: true,
      status: 200,
      content: typeof content === 'string' ? content : '',
      usage: data && data.usage ? data.usage : null,
      gov_pre,
      gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id },
      elapsed_ms: Date.now() - started,
    };
  } catch (e) {
    const up = providerName === 'runpod' ? 'Runpod' : 'VastAI';
    return { model, ok: false, status: 502, error: `${up} error: ${clampString(String(e && e.message ? e.message : e), 180)}`, gov_pre, elapsed_ms: Date.now() - started };
  }
}

function parseModelCsv(raw) {
  const s = String(raw || '').trim();
  if (!s) return [];
  return s.split(',').map(v => v.trim()).filter(Boolean);
}

async function oaiBakeoff(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body;
  try { body = await request.json(); }
  catch { return oaiError(400, 'Invalid JSON'); }

  const reg = listGatewayModels(env);
  const models = Array.isArray(body.models) ? body.models.map(String).map(s => s.trim()).filter(Boolean) : [];
  const audience = String(body.audience || body.suite || '').toLowerCase().trim();
  const presetModels =
    audience === 'dev' ? parseModelCsv(env.BAKEOFF_DEV_MODELS)
      : audience === 'user' ? parseModelCsv(env.BAKEOFF_USER_MODELS)
        : audience === 'experiment' ? parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS)
        : [];
  const defaults = (() => {
    const chat = reg.find(m => m.id === 'canonic-chat') || reg.find(m => m.profile === 'chat') || reg[0];
    const kilo = reg.find(m => m.id === 'canonic-kilocode') || reg.find(m => m.profile === 'kilocode');
    const list = [];
    if (chat && chat.id) list.push(chat.id);
    if (kilo && kilo.id) list.push(kilo.id);
    return list;
  })();
  const selected = models.length ? models : (presetModels.length ? presetModels : defaults);
  const want = selected.map(String).map(s => s.trim()).filter(Boolean);
  const entries = want.map(id => reg.find(m => m.id === id) || null).filter(Boolean);
  if (!entries.length) return oaiError(400, 'No valid models requested');

  const trace_id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now());

  // Execute in parallel by default to make comparisons fast.
  const parallel = body.parallel !== false;
  const calls = entries.map(e => callGatewayModel(e, body, env, trace_id));
  const results = parallel ? await Promise.all(calls) : (async () => { const out=[]; for (const c of calls) out.push(await c); return out; })();

  return json({
    object: 'bakeoff',
    trace_id,
    results,
  });
}

async function chat(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

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

  const trace_id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now());

  const primary = env.PROVIDER;
  const fallback = env.FALLBACK_PROVIDER || 'anthropic';
  const chain = env.PROVIDER_CHAIN
    ? String(env.PROVIDER_CHAIN).split(',').map(s => s.trim()).filter(Boolean)
    : (primary === 'runpod' ? [primary, fallback] : [primary]);

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
    const providerUrl = typeof provider.url === 'function' ? provider.url(env) : provider.url;
    const ms = timeoutMsFor(name, env);

    let res;
    const attemptStart = Date.now();
    const gov_pre = {
      provider: name,
      url: providerUrl,
      timeout_ms: ms,
      model: reqBody && reqBody.model ? reqBody.model : null,
      max_tokens: reqBody && reqBody.max_tokens ? reqBody.max_tokens : null,
      messages: Array.isArray(reqBody && reqBody.messages) ? reqBody.messages.length : null,
      tokens_min: parseIntEnv(env, 'TOKENS_MIN') ?? 16,
      tokens_max: parseIntEnv(env, 'TOKENS_MAX') ?? 4096,
      provider_tokens_max: parseIntEnv(env, `${String(name || '').toUpperCase()}_TOKENS_MAX`),
    };
    try {
      // Governed retry policy: allow a small number of tries for Runpod cold starts.
      const maxTries =
        (name === 'runpod') ? (parseIntEnv(env, 'RUNPOD_TRIES') ?? 2)
        : (name === 'vastai') ? (parseIntEnv(env, 'VASTAI_TRIES') ?? 1)
        : 1;
      const retryDelayMs =
        (name === 'runpod') ? (parseIntEnv(env, 'RUNPOD_RETRY_DELAY_MS') ?? 750)
        : (name === 'vastai') ? (parseIntEnv(env, 'VASTAI_RETRY_DELAY_MS') ?? 0)
        : 0;
      let lastErr = null;
      for (let t = 0; t < maxTries; t++) {
        try {
          res = await fetchWithTimeout(providerUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(reqBody),
          }, ms);
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e;
          if (t + 1 < maxTries && retryDelayMs > 0) await new Promise(r => setTimeout(r, retryDelayMs));
        }
      }
      if (lastErr) throw lastErr;
    } catch (e) {
      attempts.push({
        provider: name,
        ok: false,
        elapsed_ms: Date.now() - attemptStart,
        error: clampString(redactSecrets(String(e && e.message ? e.message : e)), 220),
        gov_pre,
      });
      continue;
    }

    if (!res || !res.ok) {
      const status = res ? res.status : 0;
      const errBody = res ? await res.text() : '';
      const safeErr = redactSecrets(errBody);
      attempts.push({
        provider: name,
        ok: false,
        elapsed_ms: Date.now() - attemptStart,
        status,
        detail: clampString(safeErr, 600),
        gov_pre,
        gov_post: {
          ok: false,
          status,
          elapsed_ms: Date.now() - attemptStart,
        },
      });

      // Fallback only on likely-provider/system issues.
      const shouldFallback = (status >= 500 || status === 429 || status === 0);
      if (shouldFallback) continue;
      return json(
        { error: `${name} ${status}`, detail: clampString(safeErr, 600), scope, trace_id },
        502,
      );
    }

    const data = await res.json();
    const parsed = provider.parse(data) || '';
    attempts.push({
      provider: name,
      ok: true,
      elapsed_ms: Date.now() - attemptStart,
      gov_pre,
      gov_post: {
        ok: true,
        status: res.status,
        elapsed_ms: Date.now() - attemptStart,
        usage: data && data.usage ? data.usage : null,
        parsed_chars: typeof parsed === 'string' ? parsed.length : 0,
        schema_ok: typeof parsed === 'string' && parsed.length > 0,
      },
    });
    return json({
      message: parsed || 'No response.',
      scope,
      provider_requested: primary,
      provider_used: name,
      provider_chain: chain,
      attempts,
      usage: data && data.usage ? data.usage : null,
      elapsed_ms: Date.now() - startedAt,
      trace_id,
    });
  }

  return json(
    {
      error: 'All providers failed',
      scope,
      provider_chain: chain,
      attempts,
      elapsed_ms: Date.now() - startedAt,
      trace_id,
    },
    502,
  );
}

// ── SHOP — Stripe checkout + wallet summary ────────────

async function shopCheckout(request, env) {
  if (!env.STRIPE_SECRET_KEY) return json({ error: 'STRIPE_SECRET_KEY not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const eventType = normalizeShopEvent(body && body.event) || '';
  if (!eventType || !['SALE', 'DONATION', 'INVEST'].includes(eventType)) {
    return json({ error: 'event must be SALE, DONATION, or INVEST' }, 400);
  }

  const amountCoin = parseInt(body && body.amount_coin, 10);
  if (!Number.isFinite(amountCoin) || amountCoin < 1 || amountCoin > 1000000) {
    return json({ error: 'amount_coin must be an integer between 1 and 1000000' }, 400);
  }

  const product = normalizeShopProduct(body && body.product);
  const service = normalizeShopProduct((body && body.service) || 'BOOK');
  const channel = normalizeShopProduct((body && body.channel) || 'SHOP');
  const note = clampString(String((body && body.note) || ''), 500);
  const name = clampString(String((body && body.name) || ''), 120);
  const email = clampString(String((body && body.email) || ''), 240);
  const coinToCents = Math.max(1, intEnv(env, 'SHOP_COIN_USD_CENTS', 100));
  const currency = String(env.SHOP_CURRENCY || 'usd').toLowerCase();
  const unitAmount = amountCoin * coinToCents;
  const origin = String(env.SHOP_ORIGIN || 'https://hadleylab-dexter.github.io').replace(/\/+$/, '');
  const successDefault = `${origin}/BOOKS/?checkout=success&session_id={CHECKOUT_SESSION_ID}`;
  const cancelDefault = `${origin}/BOOKS/?checkout=cancel`;
  const successUrl = String((body && body.success_url) || env.SHOP_SUCCESS_URL || successDefault).trim();
  const cancelUrl = String((body && body.cancel_url) || env.SHOP_CANCEL_URL || cancelDefault).trim();

  if (!/^https?:\/\//i.test(successUrl) || !/^https?:\/\//i.test(cancelUrl)) {
    return json({ error: 'success_url and cancel_url must be absolute HTTP URLs' }, 400);
  }

  const titleByType = {
    SALE: `${product} Reserve`,
    DONATION: `${product} Donation`,
    INVEST: `${product} Investor Commitment`,
  };

  const fields = {
    mode: 'payment',
    success_url: successUrl,
    cancel_url: cancelUrl,
    'line_items[0][quantity]': '1',
    'line_items[0][price_data][currency]': currency,
    'line_items[0][price_data][unit_amount]': String(unitAmount),
    'line_items[0][price_data][product_data][name]': titleByType[eventType] || `${product} ${eventType}`,
    'metadata[event]': eventType,
    'metadata[type]': eventType,
    'metadata[service]': service,
    'metadata[product]': product,
    'metadata[channel]': channel,
    'metadata[amount_coin]': String(amountCoin),
    'metadata[note]': note,
    'metadata[name]': name,
    'metadata[email]': email,
    'payment_intent_data[metadata][event]': eventType,
    'payment_intent_data[metadata][service]': service,
    'payment_intent_data[metadata][product]': product,
    'payment_intent_data[metadata][channel]': channel,
    'payment_intent_data[metadata][amount_coin]': String(amountCoin),
  };
  if (email) fields.customer_email = email;

  const created = await stripeApiRequest(env, 'POST', '/v1/checkout/sessions', fields);
  if (!created.ok) return json({ error: created.error || 'Stripe checkout create failed' }, created.status || 502);

  const session = created.data || {};
  return json({
    ok: true,
    session_id: session.id,
    url: session.url,
    event: eventType,
    product,
    amount_coin: amountCoin,
    amount_minor: unitAmount,
    currency,
  });
}

async function shopStripeWebhook(request, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: 'STRIPE_WEBHOOK_SECRET not configured' }, 500);
  const raw = await request.text();
  const sig = request.headers.get('stripe-signature') || '';
  const toleranceSec = Math.max(10, intEnv(env, 'SHOP_WEBHOOK_TOLERANCE_SEC', 300));
  const verified = await stripeVerifyWebhookSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET, toleranceSec);
  if (!verified.ok) return json({ error: verified.error || 'Invalid Stripe signature' }, 401);

  let evt;
  try { evt = JSON.parse(raw); }
  catch { return json({ error: 'Invalid Stripe event JSON' }, 400); }

  const typ = String(evt && evt.type || '');
  const obj = evt && evt.data && evt.data.object ? evt.data.object : {};
  const coinToCents = Math.max(1, intEnv(env, 'SHOP_COIN_USD_CENTS', 100));
  const mapped = walletEventFromStripeSession(obj, coinToCents);

  // Optional outbound fanout for filesystem VAULT ingest bridge.
  const relay = String(env.SHOP_STRIPE_EVENT_WEBHOOK_URL || '').trim();
  let relayed = false;
  if (relay && /^https?:\/\//i.test(relay)) {
    try {
      const relayPayload = {
        source: 'stripe',
        stripe_event_id: evt && evt.id ? evt.id : '',
        stripe_type: typ,
        wallet_event: mapped,
        raw: {
          id: obj && obj.id ? obj.id : '',
          status: obj && obj.status ? obj.status : '',
          payment_status: obj && obj.payment_status ? obj.payment_status : '',
        },
      };
      await fetch(relay, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(relayPayload),
      });
      relayed = true;
    } catch {
      relayed = false;
    }
  }

  // LEDGER: every Stripe event is INTEL (GOV: LEDGER/CANON.md)
  const ledgerResult = await appendToLedger(env, 'SHOP', 'SHOP', {
    stripe_event_id: evt && evt.id ? evt.id : '',
    stripe_type: typ,
    session_id: obj && obj.id ? obj.id : '',
    status: obj && obj.status ? obj.status : '',
    payment_status: obj && obj.payment_status ? obj.payment_status : '',
    wallet_event: mapped,
    work_ref: evt && evt.id ? evt.id : '',
  });

  return json({
    ok: true,
    stripe_event_id: evt && evt.id ? evt.id : '',
    stripe_type: typ,
    wallet_event: mapped,
    relayed,
    ledger: ledgerResult,
  });
}

async function shopWallet(request, env) {
  if (!env.STRIPE_SECRET_KEY) {
    if (boolEnv(env, 'SHOP_WALLET_STRIPE_REQUIRED', true)) {
      return json({ error: 'STRIPE_SECRET_KEY not configured' }, 500);
    }
    return json({ wallet: initWalletSummary(), source: 'empty' });
  }

  const url = new URL(request.url);
  const top = Math.max(1, Math.min(100, parseInt(url.searchParams.get('top') || '12', 10) || 12));
  const perPage = Math.max(1, Math.min(100, parseInt(url.searchParams.get('limit') || String(intEnv(env, 'SHOP_WALLET_PAGE_LIMIT', 100)), 10) || 100));
  const maxPages = Math.max(1, Math.min(20, parseInt(url.searchParams.get('pages') || String(intEnv(env, 'SHOP_WALLET_MAX_PAGES', 3)), 10) || 3));
  const coinToCents = Math.max(1, intEnv(env, 'SHOP_COIN_USD_CENTS', 100));

  const wallet = initWalletSummary();
  let startingAfter = '';
  let fetched = 0;

  for (let page = 0; page < maxPages; page++) {
    const qs = new URLSearchParams();
    qs.set('limit', String(perPage));
    if (startingAfter) qs.set('starting_after', startingAfter);
    const listed = await stripeApiRequest(env, 'GET', `/v1/checkout/sessions?${qs.toString()}`);
    if (!listed.ok) return json({ error: listed.error || 'Stripe list sessions failed' }, listed.status || 502);

    const data = listed.data || {};
    const rows = Array.isArray(data.data) ? data.data : [];
    fetched += rows.length;
    if (!rows.length) break;

    for (const session of rows) {
      const evt = walletEventFromStripeSession(session, coinToCents);
      if (!evt) continue;
      wallet.events += 1;
      wallet.balance += evt.delta;
      if (wallet.totals[evt.type] !== undefined) wallet.totals[evt.type] += evt.amount;
      if (evt.delta >= 0) wallet.totals.credit += evt.delta;
      else wallet.totals.debit += Math.abs(evt.delta);
      wallet.totals.net = wallet.totals.credit - wallet.totals.debit;
      applyWalletDelta(wallet.services, evt.service, evt.delta);
      applyWalletDelta(wallet.products, evt.product, evt.delta);
      wallet.recent.push({
        id: evt.id,
        ts: evt.ts,
        type: evt.type,
        service: evt.service,
        product: evt.product,
        amount: evt.amount,
        delta: evt.delta,
      });
    }

    if (!data.has_more) break;
    startingAfter = rows[rows.length - 1] && rows[rows.length - 1].id ? rows[rows.length - 1].id : '';
    if (!startingAfter) break;
  }

  wallet.services = sortedWalletBucket(wallet.services, top);
  wallet.products = sortedWalletBucket(wallet.products, top);
  wallet.recent = wallet.recent.sort((a, b) => String(b.ts).localeCompare(String(a.ts))).slice(0, top);
  wallet.updated_at = new Date().toISOString();

  return json({
    wallet,
    source: 'stripe',
    fetched_sessions: fetched,
    coin_to_cents: coinToCents,
  });
}

// ── AUTH — GitHub OAuth KYC ─────────────────────────────

function authConfig(env) {
  if (!env.GITHUB_CLIENT_ID) {
    return json({ error: 'GITHUB_CLIENT_ID not configured' }, 500);
  }
  return json({
    github_client_id: env.GITHUB_CLIENT_ID,
    scopes: 'read:user',
  });
}

async function authGitHub(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { code, redirect_uri } = body;
  if (!code) return json({ error: 'Missing code' }, 400);

  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return json({ error: 'GitHub OAuth not configured' }, 500);
  }

  // Exchange code for access token
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri,
    }),
  });

  const tokenData = await tokenRes.json();
  if (tokenData.error) {
    return json({ error: tokenData.error_description || tokenData.error }, 401);
  }

  // Fetch user profile
  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${tokenData.access_token}`,
      'User-Agent': 'CANONIC-KYC',
      'Accept': 'application/json',
    },
  });

  if (!userRes.ok) {
    return json({ error: 'Failed to fetch GitHub user' }, 502);
  }

  const user = await userRes.json();

  // Create server-side session in TALK_KV
  const sessionToken = crypto.randomUUID();
  const session = {
    user: user.login,
    github_uid: user.id,
    name: user.name,
    avatar_url: user.avatar_url,
    org: 'hadleylab',
    ts: new Date().toISOString(),
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
  };

  if (env.TALK_KV) {
    await env.TALK_KV.put(`session:${sessionToken}`, JSON.stringify(session), {
      expirationTtl: 7 * 24 * 60 * 60, // 7 days in seconds
    });

    // LEDGER: auth login is INTEL (GOV: LEDGER/CANON.md)
    await appendToLedger(env, 'AUTH', 'AUTH', {
      event: 'login',
      user: user.login,
      github_uid: user.id,
      provider: 'github',
      work_ref: `login:${user.login}`,
    });
  }

  return json({
    session_token: sessionToken,
    user: user.login,
    name: user.name,
    avatar_url: user.avatar_url,
    provenance: {
      provider: 'github',
      uid: user.id,
      verified_at: session.ts,
      gate: 'MAGIC-KYC',
    },
  });
}

async function authSession(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: 'Missing session token' }, 401);

  if (!env.TALK_KV) return json({ error: 'KV not configured' }, 500);

  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ error: 'Invalid or expired session' }, 401);

  const session = JSON.parse(raw);
  if (new Date(session.expires) < new Date()) {
    await env.TALK_KV.delete(`session:${token}`);
    return json({ error: 'Session expired' }, 401);
  }

  return json({
    user: session.user,
    github_uid: session.github_uid,
    name: session.name,
    avatar_url: session.avatar_url,
    org: session.org,
    ts: session.ts,
    expires: session.expires,
  });
}

async function authLogout(request, env) {
  const token = extractSessionToken(request);
  if (!token) return json({ error: 'Missing session token' }, 401);

  if (env.TALK_KV) {
    const raw = await env.TALK_KV.get(`session:${token}`);
    if (raw) {
      const session = JSON.parse(raw);
      await env.TALK_KV.delete(`session:${token}`);
      // LEDGER: auth logout is INTEL (GOV: LEDGER/CANON.md)
      await appendToLedger(env, 'AUTH', 'AUTH', {
        event: 'logout',
        user: session.user,
        work_ref: `logout:${session.user}`,
      });
    }
  }

  return json({ ok: true });
}

async function authGrants(request, env) {
  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope parameter' }, 400);

  const token = extractSessionToken(request);
  if (!token) return json({ granted: false, reason: 'no_session' });

  if (!env.TALK_KV) return json({ error: 'KV not configured' }, 500);

  const raw = await env.TALK_KV.get(`session:${token}`);
  if (!raw) return json({ granted: false, reason: 'invalid_session' });

  const session = JSON.parse(raw);
  if (new Date(session.expires) < new Date()) {
    return json({ granted: false, reason: 'expired_session' });
  }

  // Fetch scope's CANON.json to check privacy/readers
  // Convention: CANON.json is stored at canon:{scope} in KV or fetched from origin
  const canonKey = `canon:${scope}`;
  const canonRaw = await env.TALK_KV.get(canonKey);

  if (!canonRaw) {
    // No CANON.json cached — default: grant if authenticated (ORG member)
    return json({ granted: true, user: session.user, reason: 'org_member_default' });
  }

  const canon = JSON.parse(canonRaw);
  if (!canon.privacy || canon.privacy === 'PUBLIC') {
    return json({ granted: true, user: session.user, reason: 'public_scope' });
  }

  // PRIVATE scope — check readers
  const readers = canon.readers || [];
  if (readers.length === 0) {
    // No readers declared — ORG members only (fail-closed to public, open to org)
    return json({ granted: true, user: session.user, reason: 'org_member' });
  }

  if (readers.includes('*') || readers.includes(session.user)) {
    return json({ granted: true, user: session.user, reason: 'reader' });
  }

  // Ledger deny
  if (env.TALK_KV) {
    await env.TALK_KV.put(
      `auth:deny:${session.user}:${scope}:${Date.now()}`,
      JSON.stringify({ user: session.user, scope, ts: new Date().toISOString() }),
      { expirationTtl: 30 * 24 * 60 * 60 }
    );
  }

  return json({ granted: false, user: session.user, reason: 'not_reader' });
}

function extractSessionToken(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  // Also check query param for GET requests
  const url = new URL(request.url);
  return url.searchParams.get('token') || null;
}

// ── EMAIL — Branded HTML via Resend ─────────────────────

async function emailSend(request, env) {
  if (!env.RESEND_API_KEY) {
    return json({ error: 'RESEND_API_KEY not configured' }, 500);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { to, subject, html, from, cc, bcc, reply_to } = body;
  if (!to || !subject || !html) {
    return json({ error: 'Missing to, subject, or html' }, 400);
  }

  const sender = from || env.EMAIL_FROM || 'founder@canonic.org';
  const recipient = Array.isArray(to) ? to[0] : to;

  const payload = { from: sender, to: [recipient], subject, html };
  if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];
  if (bcc) payload.bcc = Array.isArray(bcc) ? bcc : [bcc];
  if (reply_to) payload.reply_to = reply_to;
  if (body.attachments) payload.attachments = body.attachments;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errBody = await res.text();
    return json({ error: `Resend ${res.status}`, detail: errBody }, 502);
  }

  const data = await res.json();

  // LEDGER: every email send is INTEL (GOV: LEDGER/CANON.md)
  const ledgerResult = await appendToLedger(env, 'EMAIL', body.scope || 'EMAIL', {
    to: recipient,
    cc: payload.cc || null,
    bcc: payload.bcc || null,
    subject,
    from: sender,
    work_ref: data.id, // resend_id
  });

  return json({ sent: true, id: data.id, to: recipient, subject, ledger: ledgerResult });
}

// ── HASH — Content addressing for ledger chain integrity ───────────

async function sha256(message) {
  const data = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── SANITIZE — Strip HTML tags from user input ───────────

function sanitize(str) {
  if (!str || typeof str !== 'string') return str;
  return str.replace(/<[^>]*>/g, '').trim();
}

// ── RATE LIMIT — KV-backed per-key rate limiting ───────────

async function checkRate(env, prefix, key, maxPerHour) {
  if (!env.TALK_KV) return false;
  const rateKey = `rate:${prefix}:${key}`;
  const count = parseInt(await env.TALK_KV.get(rateKey) || '0', 10);
  if (count >= maxPerHour) return true; // rate limited
  await env.TALK_KV.put(rateKey, String(count + 1), { expirationTtl: 3600 });
  return false;
}

// ── LEDGER APPEND — Unified hash-chained append for all stream types ───────────
// GOV: LEDGER/CANON.md — every record gets id + prev + type + scope
// Types: GRADIENT | TALK | CONTRIBUTE | EMAIL | PROVISION | AUTH | SHOP

async function appendToLedger(env, type, scope, fields) {
  if (!env.TALK_KV) return null;
  const key = `ledger:${type}:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch {}

  const ts = new Date().toISOString();
  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${type}:${scope}:${prev}:${JSON.stringify(fields)}`);

  const entry = { id, prev, ts, type, scope, ...fields };
  ledger.push(entry);

  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    const overflow = ledger.slice(0, ledger.length - 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(overflow));
    ledger = ledger.slice(-1000);
  }

  await env.TALK_KV.put(key, JSON.stringify(ledger));
  return { id, ts, entries: ledger.length };
}

// ── TALK LEDGER — Server-side session logging ───────────

async function talkLedgerWrite(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  // Rate limit: 100 ledger writes per scope per hour
  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, trace_id, provider_used, elapsed_ms } = body;
  const user_message = sanitize(body.user_message);
  const assistant_message = sanitize(body.assistant_message);
  if (!scope || !user_message) return json({ error: 'Missing scope or user_message' }, 400);

  if (await checkRate(env, 'ledger', scope, 100)) {
    return json({ error: 'Rate limited', scope }, 429);
  }

  const ts = new Date().toISOString();

  // Append to scope's ledger (list stored as JSON array in KV)
  const key = `ledger:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch {}

  // Hash chain: id = content hash, prev = last entry's id
  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${scope}:${user_message}:${prev}`);

  const entry = {
    id,
    prev,
    ts,
    type: 'TALK',
    scope,
    trace_id: trace_id || null,
    user: user_message,
    assistant: assistant_message || null,
    provider: provider_used || null,
    elapsed_ms: elapsed_ms || null,
  };

  ledger.push(entry);
  // Cap at 1000 entries per scope — archive overflow before pruning
  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    const overflow = ledger.slice(0, ledger.length - 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(overflow));
    ledger = ledger.slice(-1000);
  }

  await env.TALK_KV.put(key, JSON.stringify(ledger));
  return json({ ok: true, id, scope, entries: ledger.length, ts });
}

async function talkLedgerRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const key = `ledger:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch {}

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const slice = ledger.slice(-(offset + limit), offset ? -offset : undefined);

  return json({ scope, total: ledger.length, entries: slice });
}

// ── TALK MESSAGING — Cross-user communication ───────────

async function talkSend(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { from, to, message, context } = body;
  if (!from || !to || !message) return json({ error: 'Missing from, to, or message' }, 400);

  const ts = new Date().toISOString();
  const id = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now());
  const entry = { id, ts, from, to, message, context: context || null, read: false };

  // Append to recipient's inbox
  const key = `inbox:${to}`;
  let inbox = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) inbox = JSON.parse(raw);
  } catch {}

  inbox.push(entry);
  if (inbox.length > 500) inbox = inbox.slice(-500);

  await env.TALK_KV.put(key, JSON.stringify(inbox));

  // Also log to sender's outbox for audit
  const outKey = `outbox:${from}`;
  let outbox = [];
  try {
    const raw = await env.TALK_KV.get(outKey);
    if (raw) outbox = JSON.parse(raw);
  } catch {}
  outbox.push(entry);
  if (outbox.length > 500) outbox = outbox.slice(-500);
  await env.TALK_KV.put(outKey, JSON.stringify(outbox));

  // LEDGER: every cross-user message is INTEL (GOV: LEDGER/CANON.md)
  await appendToLedger(env, 'TALK', `MSG:${from}:${to}`, {
    from,
    to,
    message_id: id,
    work_ref: id,
  });

  return json({ ok: true, id, from, to, ts });
}

async function talkInbox(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const key = `inbox:${scope}`;
  let inbox = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) inbox = JSON.parse(raw);
  } catch {}

  const unreadOnly = url.searchParams.get('unread') === 'true';
  const messages = unreadOnly ? inbox.filter(m => !m.read) : inbox;

  return json({ scope, total: inbox.length, unread: inbox.filter(m => !m.read).length, messages });
}

async function talkAck(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, message_ids } = body;
  if (!scope || !Array.isArray(message_ids)) return json({ error: 'Missing scope or message_ids' }, 400);

  const key = `inbox:${scope}`;
  let inbox = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) inbox = JSON.parse(raw);
  } catch {}

  const idSet = new Set(message_ids);
  let acked = 0;
  for (const msg of inbox) {
    if (idSet.has(msg.id) && !msg.read) {
      msg.read = true;
      acked++;
    }
  }

  await env.TALK_KV.put(key, JSON.stringify(inbox));
  return json({ ok: true, scope, acked });
}

// ── CONTRIBUTE — Governed contribution ledger (COIN mint) ───────────

async function contribute(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, contributor, email, affiliation, chapter, source } = body;
  const story = sanitize(body.story);
  if (!scope || !story) return json({ error: 'Missing scope or story' }, 400);

  // Rate limit: 10 contributions per IP per hour
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await checkRate(env, 'contribute', ip, 10)) {
    return json({ error: 'Rate limited' }, 429);
  }

  const ts = new Date().toISOString();

  const key = `contributions:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch {}

  // Hash chain: id = content hash, prev = last entry's id
  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${scope}:${story}:${prev}`);

  const entry = {
    id,
    prev,
    ts,
    type: 'CONTRIBUTE',
    scope,
    contributor: contributor || 'Anonymous',
    email: email || null,
    affiliation: affiliation || null,
    chapter: chapter || null,
    story,
    source: source || null,
    coin_event: 'MINT:CONTRIBUTE',
  };

  ledger.push(entry);
  // Cap at 1000 entries per scope — archive overflow before pruning
  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    const overflow = ledger.slice(0, ledger.length - 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(overflow));
    ledger = ledger.slice(-1000);
  }

  await env.TALK_KV.put(key, JSON.stringify(ledger));

  // Fire confirmation email (non-blocking — don't fail the contribution if email fails)
  if (email && env.RESEND_API_KEY) {
    try {
      const name = contributor || 'Friend';
      const receiptShort = id.slice(0, 8);
      const storyPreview = story.length > 200 ? story.slice(0, 200) + '...' : story;
      const emailHtml = `
<div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#e5e5e5;padding:40px;border:1px solid #222;">
  <div style="text-align:center;margin-bottom:32px;">
    <div style="font-size:28px;font-weight:800;letter-spacing:2px;color:#d4a855;">COIN MINTED</div>
    <div style="font-size:13px;color:#888;margin-top:4px;">${scope}</div>
  </div>
  <div style="margin-bottom:24px;">
    <span style="color:#d4a855;">Dear ${name},</span>
  </div>
  <div style="margin-bottom:24px;line-height:1.6;">
    Your contribution has been recorded on the governed ledger. Every contribution is WORK. Every WORK mints COIN.
  </div>
  <div style="background:#111;border:1px solid #333;padding:20px;margin-bottom:24px;font-family:monospace;font-size:13px;">
    <div><span style="color:#888;">Receipt:</span> <span style="color:#d4a855;">${receiptShort}</span></div>
    <div><span style="color:#888;">Event:</span> MINT:CONTRIBUTE</div>
    <div><span style="color:#888;">Scope:</span> ${scope}</div>
    <div><span style="color:#888;">Time:</span> ${ts}</div>
    ${chapter ? '<div><span style="color:#888;">Chapter:</span> ' + chapter + '</div>' : ''}
    ${source ? '<div><span style="color:#888;">Source:</span> ' + source + '</div>' : ''}
  </div>
  <div style="margin-bottom:24px;line-height:1.6;">
    <span style="color:#888;">Your words:</span><br>
    <em>&ldquo;${storyPreview}&rdquo;</em>
  </div>
  <div style="text-align:center;margin:32px 0;">
    <a href="https://hadleylab-canonic.github.io/SHOP/" style="background:#d4a855;color:#000;padding:12px 32px;text-decoration:none;font-weight:700;font-size:14px;letter-spacing:1px;">CLAIM YOUR COIN</a>
  </div>
  <div style="margin-bottom:24px;line-height:1.6;font-size:14px;">
    Your COIN is waiting. Every contribution is work. Every work has value. Claim yours.
  </div>
  <div style="border-top:1px solid #222;padding-top:20px;font-size:12px;color:#666;text-align:center;">
    Every contribution governed. Every provenance traced.<br><br>
    <a href="https://canonic.org" style="color:#d4a855;text-decoration:none;">CANONIC</a>
  </div>
</div>`;

      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from: 'CANONIC <canonic@canonic.org>',
          to: [email],
          subject: `COIN MINTED — Your ${scope} contribution (${receiptShort})`,
          html: emailHtml,
        }),
      });
    } catch (emailErr) {
      // Email failure must not block the contribution response
    }
  }

  return json({ ok: true, id, scope, ts, coin_event: 'MINT:CONTRIBUTE', entries: ledger.length });
}

async function contributeRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const key = `contributions:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch {}

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const slice = ledger.slice(-(offset + limit), offset ? -offset : undefined);

  return json({ scope, total: ledger.length, entries: slice });
}
