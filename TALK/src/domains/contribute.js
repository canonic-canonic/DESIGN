/**
 * CONTRIBUTE — Governed contribution ledger (COIN mint).
 * GOV: CONTRIBUTE/CANON.md, LEDGER/CANON.md
 */

import { json } from '../kernel/http.js';
import { sha256 } from '../kernel/crypto.js';
import { sanitize } from '../kernel/crypto.js';
import { checkRate } from '../kernel/rate.js';

export async function contribute(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { scope, contributor, email, affiliation, chapter, source } = body;
  const story = sanitize(body.story);
  if (!scope || !story) return json({ error: 'Missing scope or story' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await checkRate(env, 'contribute', ip, 10)) return json({ error: 'Rate limited' }, 429);

  const ts = new Date().toISOString();
  const key = `contributions:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const prev = ledger.length ? ledger[ledger.length - 1].id : '000000000000';
  const id = await sha256(`${ts}:${scope}:${story}:${prev}`);

  const entry = {
    id, prev, ts, type: 'CONTRIBUTE', scope,
    contributor: contributor || 'Anonymous', email: email || null,
    affiliation: affiliation || null, chapter: chapter || null,
    story, source: source || null, coin_event: 'MINT:CONTRIBUTE',
  };

  ledger.push(entry);
  if (ledger.length > 1000) {
    const epoch = Math.floor(Date.now() / 1000);
    await env.TALK_KV.put(`${key}:archive:${epoch}`, JSON.stringify(ledger.slice(0, ledger.length - 1000)));
    ledger = ledger.slice(-1000);
  }
  await env.TALK_KV.put(key, JSON.stringify(ledger));

  // Confirmation email (non-blocking)
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
  <div style="margin-bottom:24px;"><span style="color:#d4a855;">Dear ${name},</span></div>
  <div style="margin-bottom:24px;line-height:1.6;">Your contribution has been recorded on the governed ledger. Every contribution is WORK. Every WORK mints COIN.</div>
  <div style="background:#111;border:1px solid #333;padding:20px;margin-bottom:24px;font-family:monospace;font-size:13px;">
    <div><span style="color:#888;">Receipt:</span> <span style="color:#d4a855;">${receiptShort}</span></div>
    <div><span style="color:#888;">Event:</span> MINT:CONTRIBUTE</div>
    <div><span style="color:#888;">Scope:</span> ${scope}</div>
    <div><span style="color:#888;">Time:</span> ${ts}</div>
    ${chapter ? '<div><span style="color:#888;">Chapter:</span> ' + chapter + '</div>' : ''}
    ${source ? '<div><span style="color:#888;">Source:</span> ' + source + '</div>' : ''}
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
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.RESEND_API_KEY}` },
        body: JSON.stringify({
          from: 'CANONIC <canonic@canonic.org>', to: [email],
          subject: `COIN MINTED — Your ${scope} contribution (${receiptShort})`, html: emailHtml,
        }),
      });
    } catch (e) { console.error('[TALK]', e.message || e); }
  }

  return json({ ok: true, id, scope, ts, coin_event: 'MINT:CONTRIBUTE', entries: ledger.length });
}

export async function contributeRead(request, env) {
  if (!env.TALK_KV) return json({ error: 'TALK_KV not configured' }, 500);

  const url = new URL(request.url);
  const scope = url.searchParams.get('scope');
  if (!scope) return json({ error: 'Missing scope param' }, 400);

  const key = `contributions:${scope}`;
  let ledger = [];
  try {
    const raw = await env.TALK_KV.get(key);
    if (raw) ledger = JSON.parse(raw);
  } catch (e) { console.error('[TALK_KV]', e.message || e); }

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const slice = ledger.slice(-(offset + limit), offset ? -offset : undefined);

  return json({ scope, total: ledger.length, entries: slice });
}
