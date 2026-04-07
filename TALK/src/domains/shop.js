/**
 * SHOP — Stripe checkout + wallet summary.
 * GOV: SHOP/CANON.md, LEDGER/CANON.md
 */

import { json } from '../kernel/http.js';
import { fetchWithRetry } from '../kernel/http.js';
import { requireEnv } from '../kernel/env.js';
import { intEnv, boolEnv } from '../kernel/env.js';
import { clampString } from '../kernel/util.js';
import { appendToLedger } from '../kernel/ledger.js';

// ── Stripe utilities ──

function stripeApiBase(env) {
  return String(env.STRIPE_API_BASE || 'https://api.stripe.com').replace(/\/+$/, '');
}

async function stripeApiRequest(env, method, path, formFields) {
  if (!env.STRIPE_SECRET_KEY) return { ok: false, status: 500, error: 'STRIPE_SECRET_KEY not configured' };
  const headers = { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` };
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
    const res = await fetchWithRetry(stripeApiBase(env) + path, { method, headers, body }, { maxRetries: 2, timeoutMs: 15000 });
    const raw = await res.text();
    let data;
    try { data = JSON.parse(raw); } catch (e) { console.error('[TALK]', e.message || e); data = { raw }; }
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
  const x = String(a || ''); const y = String(b || '');
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
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSec) return { ok: false, error: 'Stripe signature timestamp out of tolerance' };
  const payload = `${parts.t}.${rawBody}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  const sigHex = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const matched = parts.v1.some(v => timingSafeEqHex(v.toLowerCase(), sigHex.toLowerCase()));
  if (!matched) return { ok: false, error: 'Stripe signature mismatch' };
  return { ok: true };
}

// ── Wallet helpers ──

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

function isoFromUnix(tsSec) {
  if (!Number.isFinite(tsSec)) return new Date().toISOString();
  return new Date(tsSec * 1000).toISOString();
}

function initWalletSummary() {
  return {
    canon: 'WALLET.v1', source: 'stripe', currency: 'COIN', work_equals_coin: true,
    events: 0, balance: 0, last_close: '', updated_at: new Date().toISOString(),
    totals: { SALE: 0, DONATION: 0, INVEST: 0, BILL: 0, CLOSE: 0, credit: 0, debit: 0, net: 0 },
    services: {}, products: {}, recent: [],
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
    k, credit: row.credit || 0, debit: row.debit || 0, net: row.net || 0,
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
  return { id: String(session.id || ''), ts: isoFromUnix(Number(session.created || 0)), type: eventType, service, product, amount: amountCoin, delta };
}

// ── Exported: these are also needed by runner for Stripe checkout
export { stripeApiRequest, normalizeShopEvent, normalizeShopProduct };

// ── Route handlers ──

export async function shopCheckout(request, env) {
  if (!env.STRIPE_SECRET_KEY) return json({ error: 'STRIPE_SECRET_KEY not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const eventType = normalizeShopEvent(body && body.event) || '';
  if (!eventType || !['SALE', 'DONATION', 'INVEST'].includes(eventType)) return json({ error: 'event must be SALE, DONATION, or INVEST' }, 400);

  const amountCoin = parseInt(body && body.amount_coin, 10);
  if (!Number.isFinite(amountCoin) || amountCoin < 1 || amountCoin > 1000000) return json({ error: 'amount_coin must be an integer between 1 and 1000000' }, 400);

  const product = normalizeShopProduct(body && body.product);
  const service = normalizeShopProduct((body && body.service) || 'BOOK');
  const channel = normalizeShopProduct((body && body.channel) || 'SHOP');
  const note = clampString(String((body && body.note) || ''), 500);
  const name = clampString(String((body && body.name) || ''), 120);
  const email = clampString(String((body && body.email) || ''), 240);
  const coinToCents = Math.max(1, intEnv(env, 'SHOP_COIN_USD_CENTS', 100));
  const currency = requireEnv(env, 'SHOP_CURRENCY', 'shop').toLowerCase();
  const unitAmount = amountCoin * coinToCents;
  const origin = requireEnv(env, 'SHOP_ORIGIN', 'shop').replace(/\/+$/, '');
  const successPath = requireEnv(env, 'SHOP_SUCCESS_PATH', 'shop');
  const cancelPath = requireEnv(env, 'SHOP_CANCEL_PATH', 'shop');
  const successUrl = String((body && body.success_url) || env.SHOP_SUCCESS_URL || `${origin}${successPath}`).trim();
  const cancelUrl = String((body && body.cancel_url) || env.SHOP_CANCEL_URL || `${origin}${cancelPath}`).trim();

  if (!/^https?:\/\//i.test(successUrl) || !/^https?:\/\//i.test(cancelUrl)) return json({ error: 'success_url and cancel_url must be absolute HTTP URLs' }, 400);

  const titleByType = { SALE: `${product} Reserve`, DONATION: `${product} Donation`, INVEST: `${product} Investor Commitment` };

  const fields = {
    mode: 'payment', success_url: successUrl, cancel_url: cancelUrl,
    'line_items[0][quantity]': '1',
    'line_items[0][price_data][currency]': currency,
    'line_items[0][price_data][unit_amount]': String(unitAmount),
    'line_items[0][price_data][product_data][name]': titleByType[eventType] || `${product} ${eventType}`,
    'metadata[event]': eventType, 'metadata[type]': eventType, 'metadata[service]': service,
    'metadata[product]': product, 'metadata[channel]': channel, 'metadata[amount_coin]': String(amountCoin),
    'metadata[note]': note, 'metadata[name]': name, 'metadata[email]': email,
    'payment_intent_data[metadata][event]': eventType, 'payment_intent_data[metadata][service]': service,
    'payment_intent_data[metadata][product]': product, 'payment_intent_data[metadata][channel]': channel,
    'payment_intent_data[metadata][amount_coin]': String(amountCoin),
  };
  if (email) fields.customer_email = email;

  const created = await stripeApiRequest(env, 'POST', '/v1/checkout/sessions', fields);
  if (!created.ok) return json({ error: created.error || 'Stripe checkout create failed' }, created.status || 502);

  const session = created.data || {};
  return json({ ok: true, session_id: session.id, url: session.url, event: eventType, product, amount_coin: amountCoin, amount_minor: unitAmount, currency });
}

export async function shopStripeWebhook(request, env) {
  if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: 'STRIPE_WEBHOOK_SECRET not configured' }, 500);
  const raw = await request.text();
  const sig = request.headers.get('stripe-signature') || '';
  const toleranceSec = Math.max(10, intEnv(env, 'SHOP_WEBHOOK_TOLERANCE_SEC', 300));
  const verified = await stripeVerifyWebhookSignature(raw, sig, env.STRIPE_WEBHOOK_SECRET, toleranceSec);
  if (!verified.ok) return json({ error: verified.error || 'Invalid Stripe signature' }, 401);

  let evt;
  try { evt = JSON.parse(raw); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid Stripe event JSON' }, 400); }

  const typ = String(evt && evt.type || '');
  const obj = evt && evt.data && evt.data.object ? evt.data.object : {};
  const coinToCents = Math.max(1, intEnv(env, 'SHOP_COIN_USD_CENTS', 100));
  const mapped = walletEventFromStripeSession(obj, coinToCents);

  const relay = String(env.SHOP_STRIPE_EVENT_WEBHOOK_URL || '').trim();
  let relayed = false;
  if (relay && /^https?:\/\//i.test(relay)) {
    try {
      await fetch(relay, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: 'stripe', stripe_event_id: evt && evt.id ? evt.id : '', stripe_type: typ, wallet_event: mapped,
          raw: { id: obj.id || '', status: obj.status || '', payment_status: obj.payment_status || '' },
        }),
      });
      relayed = true;
    } catch (e) { console.error('[TALK]', e.message || e); }
  }

  // RUNNER fiat lane: credit buyer's COIN balance on successful checkout
  let runnerMinted = false;
  if (mapped && typ === 'checkout.session.completed') {
    const md = obj.metadata || {};
    if (md.service === 'RUNNER' && md.user_id && md.amount_coin) {
      const userId = md.user_id;
      const coinAmount = parseInt(md.amount_coin, 10);
      if (coinAmount > 0) {
        const balKey = `runner:balance:${userId}`;
        const currentBal = parseInt(await env.TALK_KV.get(balKey) || '0', 10);
        await env.TALK_KV.put(balKey, String(currentBal + coinAmount));
        await appendToLedger(env, 'RUNNER', 'RUNNER', {
          event: 'FIAT_MINT', user_id: userId, amount_coin: coinAmount,
          stripe_session_id: obj.id || '', stripe_event_id: evt.id || '',
          usd_cents: obj.amount_total || 0,
        });
        runnerMinted = true;
      }
    }
  }

  // RUNNER Connect: handle transfer failures — credit COIN back (GOV: COIN/CANON.md Cashout)
  if (typ === 'transfer.failed') {
    const md = obj.metadata || {};
    if (md.service === 'RUNNER' && md.event === 'SETTLE' && md.user_id && md.amount_coin) {
      const userId = md.user_id;
      const coinAmount = parseInt(md.amount_coin, 10);
      const feeCoin = parseInt(md.fee_coin || '0', 10);
      if (coinAmount > 0) {
        const balKey = `runner:balance:${userId}`;
        const currentBal = parseInt(await env.TALK_KV.get(balKey) || '0', 10);
        await env.TALK_KV.put(balKey, String(currentBal + coinAmount + feeCoin));
        // Debit treasury fee back
        const treasuryBal = parseInt(await env.TALK_KV.get('runner:balance:TREASURY') || '0', 10);
        await env.TALK_KV.put('runner:balance:TREASURY', String(Math.max(0, treasuryBal - feeCoin)));
        await appendToLedger(env, 'RUNNER', 'RUNNER', {
          event: 'SETTLE_FAILED', user_id: userId, amount_coin: coinAmount, fee_reversed: feeCoin,
          stripe_transfer_id: obj.id || '', stripe_event_id: evt.id || '',
        });
      }
    }
  }

  // RUNNER Connect: track account verification status
  if (typ === 'account.updated' && obj.metadata && obj.metadata.user_id && obj.metadata.service === 'RUNNER') {
    const userId = obj.metadata.user_id;
    const acctRaw = await env.TALK_KV.get(`runner:stripe_account:${userId}`);
    if (acctRaw) {
      const acctData = JSON.parse(acctRaw);
      acctData.payouts_enabled = obj.payouts_enabled || false;
      acctData.charges_enabled = obj.charges_enabled || false;
      acctData.details_submitted = obj.details_submitted || false;
      acctData.updated_at = new Date().toISOString();
      await env.TALK_KV.put(`runner:stripe_account:${userId}`, JSON.stringify(acctData));
    }
  }

  const ledgerResult = await appendToLedger(env, 'SHOP', 'SHOP', {
    stripe_event_id: evt && evt.id ? evt.id : '', stripe_type: typ,
    session_id: obj.id || '', status: obj.status || '', payment_status: obj.payment_status || '',
    wallet_event: mapped, work_ref: evt && evt.id ? evt.id : '',
  });

  return json({ ok: true, stripe_event_id: evt && evt.id ? evt.id : '', stripe_type: typ, wallet_event: mapped, relayed, runner_minted: runnerMinted, ledger: ledgerResult });
}

export async function shopWallet(request, env) {
  if (!env.STRIPE_SECRET_KEY) {
    if (boolEnv(env, 'SHOP_WALLET_STRIPE_REQUIRED', true)) return json({ error: 'STRIPE_SECRET_KEY not configured' }, 500);
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
      wallet.recent.push({ id: evt.id, ts: evt.ts, type: evt.type, service: evt.service, product: evt.product, amount: evt.amount, delta: evt.delta });
    }

    if (!data.has_more) break;
    startingAfter = rows[rows.length - 1] && rows[rows.length - 1].id ? rows[rows.length - 1].id : '';
    if (!startingAfter) break;
  }

  wallet.services = sortedWalletBucket(wallet.services, top);
  wallet.products = sortedWalletBucket(wallet.products, top);
  wallet.recent = wallet.recent.sort((a, b) => String(b.ts).localeCompare(String(a.ts))).slice(0, top);
  wallet.updated_at = new Date().toISOString();

  return json({ wallet, source: 'stripe', fetched_sessions: fetched, coin_to_cents: coinToCents });
}
