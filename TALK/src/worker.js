/**
 * canonic-services — Cloudflare Worker (thin router)
 *
 * TALK backend + AUTH. MAGIC governed. Direct mapping. Zero hardcoding.
 * CANON.json → talk.js → Worker → LLM
 *
 * All domain logic lives in src/domains/*, shared utilities in src/kernel/*.
 * This file is the route table only.
 *
 * MAGIC | CANONIC | 2026-03
 */

import { json } from './kernel/http.js';
import { corsOrigin, CORS_DEFAULTS, setReqOrigin } from './kernel/cors.js';
import { checkRate } from './kernel/rate.js';
import { extractSessionToken } from './kernel/util.js';

// ── Domain imports ──
import { envForLane, oaiModels, oaiChatCompletions, oaiResponses, oaiBakeoff } from './domains/gateway.js';
import { chat } from './domains/chat.js';
import { deepHealth } from './domains/health.js';
import { authConfig, authGitHub, authSession, authLogout, authGrants, galaxyAuth } from './domains/auth.js';
import { handle as emailSend } from './domains/email.js';
import { shopCheckout, shopStripeWebhook, shopWallet } from './domains/shop.js';
import { ledgerWrite, ledgerRead, send as talkSend, inbox as talkInbox, ack as talkAck } from './domains/talk.js';
import { contribute, contributeRead } from './domains/contribute.js';
import { handle as omicsProxy } from './domains/omics.js';
import * as star from './domains/star.js';
import { handle as runnerRoute } from './domains/runner.js';
import { digestWrite, digestRead, witnessWrite, witnessRead, verify as federationVerify } from './domains/federation.js';

// ── Helpers ──

function rateGuard(env, bucket, request, limit) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  return checkRate(env, bucket, ip, limit);
}

// ── Router ──

export default {
  async fetch(request, env) {
    const _t0 = Date.now();
    setReqOrigin(corsOrigin(request, env));

    // Preflight
    if (request.method === 'OPTIONS') {
      const h = { ...CORS_DEFAULTS };
      const origin = corsOrigin(request, env);
      if (origin) h['Access-Control-Allow-Origin'] = origin;
      return new Response(null, { status: 204, headers: h });
    }

    const url = new URL(request.url);
    let path = url.pathname;
    if (path.startsWith('/v1/v1/')) path = path.slice(3);
    const method = request.method;
    const _ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    env = envForLane(url.hostname, env);

    // ── Health ──
    if (path === '/health') {
      if (url.searchParams.get('deep') === 'true') return deepHealth(env);
      return json({ status: 'ok', provider: env.PROVIDER, model: env.MODEL, ts: Date.now() });
    }

    // ── OpenAI-compatible gateway ──
    if ((path === '/v1/models' || path === '/models') && method === 'GET')
      return oaiModels(request, env);
    if ((path === '/v1/chat/completions' || path === '/chat/completions') && method === 'POST') {
      if (await rateGuard(env, 'oai', request, 120)) return json({ error: 'Rate limited' }, 429);
      return oaiChatCompletions(request, env);
    }
    if ((path === '/v1/responses' || path === '/responses') && method === 'POST')
      return oaiResponses(request, env);
    if (path === '/v1/bakeoff' && method === 'POST')
      return oaiBakeoff(request, env);

    // ── Auth ──
    if (path === '/auth/config')
      return authConfig(env);
    if (path === '/api/v1/auth/github/callback' && method === 'GET') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) return json({ error: 'Missing code or state' }, 400);
      try {
        const returnUrl = new URL(state);
        returnUrl.searchParams.set('code', code);
        return new Response(null, { status: 302, headers: { 'Location': returnUrl.toString() } });
      } catch (_) { return json({ error: 'Invalid state URL' }, 400); }
    }
    if (path === '/auth/github' && method === 'POST') {
      if (await rateGuard(env, 'auth', request, 20)) return json({ error: 'Rate limited' }, 429);
      return authGitHub(request, env);
    }
    if (path === '/auth/session' && method === 'GET')
      return authSession(request, env);
    if (path === '/auth/logout' && method === 'POST')
      return authLogout(request, env);
    if (path === '/auth/grants' && method === 'GET')
      return authGrants(request, env);
    if (path === '/galaxy/auth' && method === 'GET')
      return galaxyAuth(request, env);

    // ── Chat ──
    if (path === '/chat' && method === 'POST') {
      if (await rateGuard(env, 'chat', request, 60)) return json({ error: 'Rate limited' }, 429);
      return chat(request, env);
    }

    // ── Email ──
    if (path === '/email/send' && method === 'POST') {
      if (await rateGuard(env, 'email', request, 10)) return json({ error: 'Rate limited' }, 429);
      return emailSend(request, env);
    }

    // ── Shop ──
    if (path === '/shop/checkout' && method === 'POST') {
      if (await rateGuard(env, 'checkout', request, 20)) return json({ error: 'Rate limited' }, 429);
      return shopCheckout(request, env);
    }
    if (path === '/shop/webhook/stripe' && method === 'POST')
      return shopStripeWebhook(request, env);
    if (path === '/shop/wallet' && method === 'GET')
      return shopWallet(request, env);

    // ── Talk ──
    if (path === '/talk/ledger' && method === 'POST') return ledgerWrite(request, env);
    if (path === '/talk/ledger' && method === 'GET') return ledgerRead(request, env);
    if (path === '/talk/send' && method === 'POST') return talkSend(request, env);
    if (path === '/talk/inbox' && method === 'GET') return talkInbox(request, env);
    if (path === '/talk/ack' && method === 'POST') return talkAck(request, env);

    // ── Contribute ──
    if (path === '/contribute' && method === 'POST') return contribute(request, env);
    if (path === '/contribute' && method === 'GET') return contributeRead(request, env);

    // ── Omics ──
    if (path.startsWith('/omics/')) {
      if (await rateGuard(env, 'omics', request, 200)) return json({ error: 'Rate limited' }, 429);
      return omicsProxy(request, env, null, url);
    }

    // ── Star (personal portal) ──
    if (path.startsWith('/star/')) {
      const starPath = path.slice(5);
      if (starPath === '/status') return star.status(request, env);
      if (starPath === '/gov') return star.gov(request, env);
      // Authenticated star routes
      const token = extractSessionToken(request);
      if (!token) return json({ error: 'Missing session token' }, 401);
      const sessRaw = await env.TALK_KV.get(`session:${token}`);
      if (!sessRaw) return json({ error: 'Invalid or expired session' }, 401);
      const sess = JSON.parse(sessRaw);
      if (new Date(sess.expires) < new Date()) return json({ error: 'Session expired' }, 401);
      if (starPath === '/timeline') return star.timeline(request, env, sess);
      if (starPath === '/services') return star.services(request, env, sess);
      if (starPath === '/intel') return star.intel(request, env, sess);
      if (starPath === '/econ') return star.econ(request, env, sess);
      if (starPath === '/identity') return star.identity(request, env, sess);
      if (starPath === '/media') return star.media(request, env, sess);
      return json({ error: 'Unknown STAR route' }, 404);
    }

    // ── Runner ──
    if (path.startsWith('/runner/')) {
      if (await rateGuard(env, 'runner', request, 60)) return json({ error: 'Rate limited' }, 429);
      return runnerRoute(path.slice(8), request, env);
    }

    // ── Federation ──
    if (path === '/ledger/digest' && method === 'POST') return digestWrite(request, env);
    if (path === '/ledger/digest' && method === 'GET') return digestRead(request, env);
    if (path === '/ledger/witness' && method === 'POST') return witnessWrite(request, env);
    if (path === '/ledger/witness' && method === 'GET') return witnessRead(request, env);
    if (path === '/ledger/verify' && method === 'GET') return federationVerify(request, env);

    // ── 404 ──
    console.log(JSON.stringify({ ts: new Date().toISOString(), path, method, ip: _ip, status: 404, latency_ms: Date.now() - _t0 }));
    return json({ error: 'Not found' }, 404);
  },
};
