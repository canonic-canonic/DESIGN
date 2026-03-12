/**
 * HEALTH — Deep governance tree scan with KV-cached rotation.
 * GOV: MONITORING/CANON.md
 */

import { json } from '../kernel/http.js';
import { requireEnv, requireIntEnv, boolEnv } from '../kernel/env.js';
import { PROVIDERS, preflightAllProviders } from './providers.js';
import { chat } from './chat.js';

export async function deepHealth(env) {
  const privateSet = new Set((env.GOV_PRIVATE_SCOPES || '').split(',').filter(Boolean));
  const vanity = (env.GOV_VANITY_DOMAINS || '').split(',').filter(Boolean);
  const CACHE_TTL = requireIntEnv(env, 'HEALTH_CACHE_TTL_S', 'health') * 1000;
  const BUDGET = requireIntEnv(env, 'HEALTH_BUDGET', 'health');
  const CACHE_KEY = 'health:deep:cache';

  const fleetRoots = requireEnv(env, 'GOV_FLEET_ROOTS', 'health').split(',').filter(Boolean);
  const sitemap = []; const allChecks = []; const seen = new Set();

  for (const base of fleetRoots) {
    const fleet = new URL(base).hostname.split('.')[0];
    let discovered = false;
    try {
      const resp = await fetch(`${base}/surfaces.json`, { headers: { 'User-Agent': 'canonic-health/1.0' } });
      if (resp.ok) {
        const raw = await resp.json();
        const list = Array.isArray(raw) ? raw : (raw.surfaces || []);
        for (const s of list) {
          const url = base + s.path;
          if (seen.has(url)) continue; seen.add(url);
          const entry = { scope: s.scope, fleet, urls: [url] };
          if (s.surface_type) entry.surface_type = s.surface_type;
          if (privateSet.has(s.scope)) { entry.private = true; sitemap.push(entry); continue; }
          sitemap.push(entry); allChecks.push({ url, scope: s.scope });
        }
        discovered = true;
      }
    } catch (e) { console.error('[TALK]', e.message || e); }

    if (!discovered) {
      const envKey = fleet === 'hadleylab' ? 'GOV_HADLEYLAB_SCOPES' : 'GOV_CANONIC_SCOPES';
      const scopes = (env[envKey] || '').split(',').filter(Boolean);
      const prefix = fleet === 'hadleylab' ? `${base}/SERVICES/` : `${base}/`;
      for (const scope of scopes) {
        const url = `${prefix}${scope}/`;
        if (seen.has(url)) continue; seen.add(url);
        const entry = { scope, fleet, urls: [url] };
        if (privateSet.has(scope)) { entry.private = true; sitemap.push(entry); continue; }
        sitemap.push(entry); allChecks.push({ url, scope });
      }
      if (fleet === 'hadleylab') {
        for (const rawUrl of (env.GOV_EXTRA_SURFACES || '').split(',').filter(Boolean)) {
          const u = rawUrl.endsWith('/') ? rawUrl : rawUrl + '/';
          if (seen.has(u)) continue; seen.add(u);
          const scope = u.replace(/\/$/, '').split('/').pop();
          allChecks.push({ url: u, scope }); sitemap.push({ scope, fleet, urls: [u] });
        }
      }
    }
  }

  for (const v of vanity) {
    const u = v.endsWith('/') ? v : v + '/';
    if (!seen.has(u)) { allChecks.push({ url: u, scope: '_vanity' }); seen.add(u); }
  }

  // Load cached results
  let cached = {};
  try { const raw = env.TALK_KV ? await env.TALK_KV.get(CACHE_KEY) : null; if (raw) cached = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }
  const now = Date.now();

  const stale = []; const fresh = [];
  for (const c of allChecks) {
    const entry = cached[c.url];
    if (entry && (now - entry.ts) < CACHE_TTL) fresh.push(entry); else stale.push(c);
  }

  const toCheck = stale.slice(0, BUDGET);
  const freshResults = []; let aborted = false;
  for (let i = 0; i < toCheck.length; i += 3) {
    if (aborted) break;
    const results = await Promise.allSettled(toCheck.slice(i, i + 3).map(async ({ url, scope }) => {
      try {
        const resp = await fetch(url, { method: 'HEAD', headers: { 'User-Agent': 'canonic-health/1.0' }, redirect: 'follow' });
        const code = resp.status;
        return { url, scope, status: code < 400 ? 'ok' : 'error', detail: code < 400 ? null : `HTTP ${code}`, ts: now };
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('Too many subrequests')) aborted = true;
        return { url, scope, status: 'unreachable', detail: msg, ts: now };
      }
    }));
    for (const r of results) { if (r.status === 'fulfilled') freshResults.push(r.value); }
  }

  for (const r of freshResults) cached[r.url] = r;
  for (const key of Object.keys(cached)) { if ((now - cached[key].ts) > CACHE_TTL * 2) delete cached[key]; }
  try { if (env.TALK_KV) await env.TALK_KV.put(CACHE_KEY, JSON.stringify(cached), { expirationTtl: Math.ceil(CACHE_TTL * 2 / 1000) }); } catch (e) { console.error('[TALK_KV]', e.message || e); }

  // Assemble surfaces
  const surfaces = [];
  const checkedUrls = new Set(freshResults.map(r => r.url));
  for (const r of freshResults) surfaces.push({ url: r.url, scope: r.scope, status: r.status, detail: r.detail || undefined });
  for (const f of fresh) { if (!checkedUrls.has(f.url)) surfaces.push({ url: f.url, scope: f.scope, status: f.status, detail: f.detail || undefined, cached: `${Math.round((now - f.ts) / 1000)}s ago` }); }
  for (const sm of sitemap) { if (sm.private) surfaces.push({ url: sm.urls[0], scope: sm.scope, status: 'private', detail: 'no public surface (by design)' }); }
  const allCovered = new Set(surfaces.map(s => s.url));
  for (const c of allChecks) { if (!allCovered.has(c.url)) surfaces.push({ url: c.url, scope: c.scope, status: 'pending', detail: 'queued for next rotation' }); }

  // Service checks
  const services = []; const svcViolations = [];
  const primary = env.PROVIDER; const primaryProvider = PROVIDERS[primary];
  if (!primaryProvider) { services.push({ service: 'TALK', status: 'error', detail: `Unknown provider: ${primary}` }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'TALK', detail: `Unknown provider: ${primary}` }); }
  else { const valErr = primaryProvider.validate?.(env); if (valErr) { services.push({ service: 'TALK', status: 'error', detail: valErr }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'TALK', detail: valErr }); } else services.push({ service: 'TALK', status: 'ok', provider: primary, model: env.MODEL }); }

  const chain = env.PROVIDER_CHAIN ? String(env.PROVIDER_CHAIN).split(',').map(s => s.trim()).filter(Boolean) : [primary];
  const chainStatus = chain.map(name => { const p = PROVIDERS[name]; if (!p) return { provider: name, status: 'error', detail: 'unknown provider' }; const err = p.validate?.(env); return err ? { provider: name, status: 'error', detail: err } : { provider: name, status: 'ok' }; });
  services.push({ service: 'TALK_CHAIN', status: chainStatus.every(c => c.status === 'ok') ? 'ok' : chainStatus.some(c => c.status === 'ok') ? 'degraded' : 'error', chain: chainStatus });
  for (const c of chainStatus) { if (c.status === 'error') svcViolations.push({ type: 'SERVICE_ERROR', service: `TALK_CHAIN/${c.provider}`, detail: c.detail }); }

  if (boolEnv(env, 'PREFLIGHT_HEALTH', false)) {
    const PREFLIGHT_CACHE_KEY = 'health:preflight:cache';
    const PREFLIGHT_TTL = requireIntEnv(env, 'PREFLIGHT_CACHE_TTL_S', 'preflight') * 1000;
    let preflightResult = null;
    try { const raw = env.TALK_KV ? await env.TALK_KV.get(PREFLIGHT_CACHE_KEY) : null; if (raw) { const c = JSON.parse(raw); if (c?.ts && (now - c.ts) < PREFLIGHT_TTL) { preflightResult = c; preflightResult._cached = true; preflightResult._cached_age_s = Math.round((now - c.ts) / 1000); } } } catch (e) { console.error('[TALK_KV]', e.message || e); }
    if (!preflightResult) { try { preflightResult = await preflightAllProviders(env); preflightResult.ts = now; if (env.TALK_KV) try { await env.TALK_KV.put(PREFLIGHT_CACHE_KEY, JSON.stringify(preflightResult), { expirationTtl: Math.ceil(PREFLIGHT_TTL * 2 / 1000) }); } catch (e) { console.error('[TALK_KV]', e.message || e); } } catch (e) { preflightResult = { service: 'TALK_PREFLIGHT', status: 'error', error: String(e.message || e) }; } }
    services.push(preflightResult);
    if (preflightResult.providers) { for (const [pName, pResult] of Object.entries(preflightResult.providers)) { if (pResult.status === 'error') svcViolations.push({ type: 'PREFLIGHT_ERROR', service: `TALK_PREFLIGHT/${pName}`, detail: pResult.error || `${pName} preflight failed` }); } }
  }

  // KV, AUTH, EMAIL, SHOP checks
  try { if (env.TALK_KV) { const tk = 'health:kv:probe'; await env.TALK_KV.put(tk, '1', { expirationTtl: 60 }); const v = await env.TALK_KV.get(tk); services.push({ service: 'KV', status: v === '1' ? 'ok' : 'error', detail: v === '1' ? null : 'read-back mismatch' }); } else { services.push({ service: 'KV', status: 'error', detail: 'TALK_KV binding missing' }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'KV', detail: 'TALK_KV binding missing' }); } } catch (e) { services.push({ service: 'KV', status: 'error', detail: String(e.message || e) }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'KV', detail: String(e.message || e) }); }
  if (env.GITHUB_CLIENT_ID) services.push({ service: 'AUTH', status: 'ok' }); else { services.push({ service: 'AUTH', status: 'error', detail: 'GITHUB_CLIENT_ID missing' }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'AUTH', detail: 'GITHUB_CLIENT_ID missing' }); }
  if (env.RESEND_API_KEY) services.push({ service: 'EMAIL', status: 'ok' }); else { services.push({ service: 'EMAIL', status: 'error', detail: 'RESEND_API_KEY missing' }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'EMAIL', detail: 'RESEND_API_KEY missing' }); }
  if (env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET) services.push({ service: 'SHOP', status: 'ok' }); else { const missing = [!env.STRIPE_SECRET_KEY && 'STRIPE_SECRET_KEY', !env.STRIPE_WEBHOOK_SECRET && 'STRIPE_WEBHOOK_SECRET'].filter(Boolean); services.push({ service: 'SHOP', status: 'error', detail: `Missing: ${missing.join(', ')}` }); svcViolations.push({ type: 'SERVICE_ERROR', service: 'SHOP', detail: `Missing: ${missing.join(', ')}` }); }

  const allPublicScopes = allChecks.map(c => c.scope).filter(s => s !== '_vanity');
  services.push({ service: 'TALK_SCOPES', status: 'ok', count: allPublicScopes.length, scopes: allPublicScopes.map(s => ({ scope: s, status: 'ok' })) });

  // INTEL testing
  const INTEL_TTL = requireIntEnv(env, 'HEALTH_INTEL_TTL_S', 'intel') * 1000;
  const INTEL_CACHE_KEY = 'health:intel:cache';
  let intelCached = {};
  try { const raw = env.TALK_KV ? await env.TALK_KV.get(INTEL_CACHE_KEY) : null; if (raw) intelCached = JSON.parse(raw); } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const accessibleUrls = surfaces.filter(s => s.status === 'ok' || (s.cached && s.status === 'ok')).map(s => s.url);
  const intelStale = [];
  for (const url of accessibleUrls) { const entry = intelCached[url]; if (entry && (now - entry.ts) < INTEL_TTL) continue; intelStale.push(url); }

  const intelFresh = [];
  for (const surfaceUrl of intelStale) {
    const canonUrl = surfaceUrl + 'CANON.json';
    const scope = surfaceUrl.replace(/\/$/, '').split('/').pop();
    try {
      const resp = await fetch(canonUrl, { headers: { 'User-Agent': 'canonic-health/1.0' } });
      if (!resp.ok) { intelFresh.push({ url: surfaceUrl, scope, status: 'skip', detail: `CANON.json HTTP ${resp.status}`, ts: now }); continue; }
      const canon = await resp.json();
      const controls = canon.controls || {};
      const render = { surface_type: canon.surface_type || 'unknown', view: controls.view || 'web', talk: controls.talk || 'side', gate: controls.gate || undefined, downloads: [] };
      for (const dl of controls.downloads || []) {
        try { const dlResp = await fetch(new URL(dl.href, surfaceUrl).href, { method: 'HEAD', headers: { 'User-Agent': 'canonic-health/1.0' } }); render.downloads.push({ label: dl.label, href: dl.href, status: dlResp.ok ? 'ok' : 'error', detail: dlResp.ok ? undefined : `HTTP ${dlResp.status}` }); }
        catch (e) { render.downloads.push({ label: dl.label, href: dl.href, status: 'error', detail: String(e.message || e) }); }
      }
      if (!canon.systemPrompt || !canon.scope) { intelFresh.push({ url: surfaceUrl, scope, status: 'invalid', detail: 'missing systemPrompt or scope', render, ts: now }); continue; }
      const welcome = canon.welcome || '';
      const genericWelcome = `Welcome to **${canon.scope}**`;
      const welcomeInContext = welcome.length > 0 && (welcome.length > genericWelcome.length + 80 || /\[.*\]\(|evidence|govern|sourced|clinical|trial|NCT|BI-RADS|mCODE/i.test(welcome));
      if (!canon.test || !canon.test.prompts || !canon.test.prompts.length) { intelFresh.push({ url: surfaceUrl, scope, status: 'no_test', render, ts: now }); continue; }

      const prompts = canon.test.prompts; const promptResults = []; let scopeElapsed = 0; let subrequestExhausted = false;
      for (const fixture of prompts) {
        try {
          const chatReq = new Request('https://internal/chat', { method: 'POST', body: JSON.stringify({ message: fixture.prompt, scope: canon.scope, system: canon.systemPrompt }), headers: { 'Content-Type': 'application/json' } });
          const chatStart = Date.now(); const chatResp = await chat(chatReq, env); const elapsed_ms = Date.now() - chatStart; scopeElapsed += elapsed_ms;
          if (!chatResp.ok) { promptResults.push({ prompt: fixture.prompt, status: 'chat_error', elapsed_ms }); continue; }
          const chatData = await chatResp.json(); const responseText = (chatData.message || '').toLowerCase();
          const expectHit = fixture.expect.filter(e => responseText.includes(e.toLowerCase())).length;
          const crossArr = fixture.cross || []; const crossHit = crossArr.filter(c => responseText.includes(c.toLowerCase())).length;
          const threshold = Math.ceil(fixture.expect.length * 0.5);
          const pStatus = expectHit >= threshold ? (crossArr.length === 0 || crossHit >= 1 ? 'ok' : 'weak') : 'fail';
          promptResults.push({ prompt: fixture.prompt, status: pStatus, expect_hit: expectHit, expect_total: fixture.expect.length, cross_hit: crossHit, cross_total: crossArr.length, missing: fixture.expect.filter(e => !responseText.includes(e.toLowerCase())).length ? fixture.expect.filter(e => !responseText.includes(e.toLowerCase())) : undefined, missing_cross: crossArr.filter(c => !responseText.includes(c.toLowerCase())).length ? crossArr.filter(c => !responseText.includes(c.toLowerCase())) : undefined, elapsed_ms });
        } catch (promptErr) {
          const pmsg = String(promptErr.message || promptErr);
          if (pmsg.includes('Too many subrequests')) { subrequestExhausted = true; break; }
          promptResults.push({ prompt: fixture.prompt, status: 'chat_error', detail: pmsg });
        }
      }

      const hasFail = promptResults.some(p => p.status === 'fail'); const hasWeak = promptResults.some(p => p.status === 'weak'); const hasError = promptResults.some(p => p.status === 'chat_error');
      let intelStatus = hasFail ? 'fail' : hasWeak ? 'weak' : hasError ? 'chat_error' : 'ok';
      if (intelStatus === 'ok' && !welcomeInContext) intelStatus = 'weak';

      const detailParts = [];
      if (intelStatus !== 'ok') { for (const p of promptResults) { if (p.missing) detailParts.push(...p.missing); if (p.missing_cross) detailParts.push(...p.missing_cross.map(c => `cross:${c}`)); } }
      if (!welcomeInContext) detailParts.push('welcome:generic');

      intelFresh.push({
        url: surfaceUrl, scope, status: promptResults.length ? intelStatus : 'error', render,
        prompts_tested: promptResults.length, prompts_total: prompts.length,
        prompts_passed: promptResults.filter(p => p.status === 'ok').length,
        expect_hit: promptResults.reduce((s, p) => s + (p.expect_hit || 0), 0), expect_total: promptResults.reduce((s, p) => s + (p.expect_total || 0), 0),
        cross_hit: promptResults.reduce((s, p) => s + (p.cross_hit || 0), 0), cross_total: promptResults.reduce((s, p) => s + (p.cross_total || 0), 0),
        welcome_in_context: welcomeInContext,
        detail: detailParts.length ? `missing: ${[...new Set(detailParts)].join(', ')}` : undefined,
        prompt_details: promptResults, elapsed_ms: scopeElapsed, ts: now,
      });
      if (subrequestExhausted) break;
    } catch (e) {
      if (String(e.message || e).includes('Too many subrequests')) break;
      intelFresh.push({ url: surfaceUrl, scope, status: 'error', detail: String(e.message || e), ts: now });
    }
  }

  for (const r of intelFresh) { if (r.prompts_total && r.prompts_tested < r.prompts_total) continue; intelCached[r.url] = r; }
  for (const key of Object.keys(intelCached)) { if ((now - intelCached[key].ts) > INTEL_TTL * 2) delete intelCached[key]; }
  try { if (env.TALK_KV) await env.TALK_KV.put(INTEL_CACHE_KEY, JSON.stringify(intelCached), { expirationTtl: Math.ceil(INTEL_TTL * 2 / 1000) }); } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const intelChecks = []; const intelDiscovered = new Set();
  for (const r of intelFresh) { if (r.status === 'no_test' || r.status === 'skip') continue; intelChecks.push({ scope: r.scope, status: r.status, prompts_tested: r.prompts_tested, prompts_total: r.prompts_total, prompts_passed: r.prompts_passed, expect_hit: r.expect_hit, expect_total: r.expect_total, cross_hit: r.cross_hit, cross_total: r.cross_total, welcome_in_context: r.welcome_in_context, detail: r.detail, prompt_details: r.prompt_details, elapsed_ms: r.elapsed_ms }); intelDiscovered.add(r.url); }
  for (const [url, entry] of Object.entries(intelCached)) { if (intelFresh.some(r => r.url === url)) continue; if (entry.status === 'no_test' || entry.status === 'skip') continue; if ((now - entry.ts) < INTEL_TTL) { intelChecks.push({ scope: entry.scope, status: entry.status, prompts_tested: entry.prompts_tested, prompts_total: entry.prompts_total, prompts_passed: entry.prompts_passed, expect_hit: entry.expect_hit, expect_total: entry.expect_total, cross_hit: entry.cross_hit, cross_total: entry.cross_total, welcome_in_context: entry.welcome_in_context, detail: entry.detail, prompt_details: entry.prompt_details, cached: `${Math.round((now - entry.ts) / 1000)}s ago`, elapsed_ms: entry.elapsed_ms }); intelDiscovered.add(url); } }

  const renderChecks = [];
  for (const [, entry] of Object.entries(intelCached)) { if (!entry.render) continue; const r = entry.render; const dlBroken = (r.downloads || []).filter(d => d.status !== 'ok'); renderChecks.push({ scope: entry.scope, surface_type: r.surface_type, view: r.view, talk: r.talk, gate: r.gate || undefined, downloads: r.downloads.length, downloads_ok: r.downloads.filter(d => d.status === 'ok').length, downloads_broken: dlBroken.length ? dlBroken : undefined }); }

  const probed = surfaces.filter(s => s.status !== 'private' && s.status !== 'pending');
  const okCount = probed.filter(s => s.status === 'ok').length; const pending = surfaces.filter(s => s.status === 'pending').length; const privateCount = surfaces.filter(s => s.status === 'private').length;
  const noTestCount = Object.values(intelCached).filter(e => e.status === 'no_test' && (now - e.ts) < INTEL_TTL).length;

  const violations = [
    ...probed.filter(s => s.status === 'error' || s.status === 'unreachable').map(s => ({ type: 'SURFACE_ERROR', scope: s.scope, url: s.url, detail: s.detail })),
    ...svcViolations,
    ...intelChecks.filter(c => c.status === 'fail').map(c => ({ type: 'INTEL_FAIL', scope: c.scope, detail: c.detail })),
    ...renderChecks.filter(r => r.downloads_broken?.length).map(r => ({ type: 'DOWNLOAD_BROKEN', scope: r.scope, detail: r.downloads_broken.map(d => `${d.label}: ${d.detail}`).join(', ') })),
  ];

  const overall = violations.length > 0 ? 'degraded' : pending > 0 ? 'warming' : 'ok';
  return json({
    status: overall, provider: env.PROVIDER, model: env.MODEL, ts: now,
    total: allChecks.length + privateCount, checked: probed.length, ok: okCount,
    private: privateCount || undefined, pending: pending || undefined,
    services: { total: services.length, ok: services.filter(s => s.status === 'ok').length, checks: services },
    intel: { total: accessibleUrls.length, tested: intelChecks.filter(c => ['ok', 'weak', 'fail'].includes(c.status)).length, passed: intelChecks.filter(c => c.status === 'ok').length, weak: intelChecks.filter(c => c.status === 'weak').length || undefined, failed: intelChecks.filter(c => c.status === 'fail').length || undefined, pending: (accessibleUrls.length - intelDiscovered.size - noTestCount) > 0 ? (accessibleUrls.length - intelDiscovered.size - noTestCount) : undefined, checks: intelChecks.length ? intelChecks : undefined },
    render: { total: renderChecks.length, checks: renderChecks.length ? renderChecks : undefined },
    sitemap, surfaces, violations: violations.length ? violations : undefined,
  });
}
