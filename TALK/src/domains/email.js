/**
 * EMAIL — Branded HTML via Resend.
 * GOV: EMAIL/CANON.md — MUST BCC sender on every outbound.
 */

import { json } from '../kernel/http.js';
import { fetchWithRetry } from '../kernel/http.js';
import { requireEnv } from '../kernel/env.js';
import { appendToLedger } from '../kernel/ledger.js';

export async function handle(request, env) {
  if (!env.RESEND_API_KEY) return json({ error: 'RESEND_API_KEY not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { to, subject, html, from, cc, bcc, reply_to } = body;
  if (!to || !subject || !html) return json({ error: 'Missing to, subject, or html' }, 400);

  const sender = from || requireEnv(env, 'EMAIL_FROM', 'email');
  const recipient = Array.isArray(to) ? to[0] : to;

  const payload = { from: sender, to: [recipient], subject, html };
  if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];

  // GOV: EMAIL/CANON.md — MUST BCC sender on every outbound
  const senderAddr = sender.includes('<') ? sender.match(/<([^>]+)>/)?.[1] || sender : sender;
  if (bcc) {
    const bccList = Array.isArray(bcc) ? bcc : [bcc];
    if (!bccList.includes(senderAddr)) bccList.push(senderAddr);
    payload.bcc = bccList;
  } else {
    payload.bcc = [senderAddr];
  }

  if (reply_to) payload.reply_to = reply_to;
  if (body.attachments) payload.attachments = body.attachments;

  const res = await fetchWithRetry('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify(payload),
  }, { maxRetries: 2, timeoutMs: 10000 });

  if (!res.ok) {
    const errBody = await res.text();
    return json({ error: `Resend ${res.status}`, detail: errBody }, 502);
  }

  const data = await res.json();

  const ledgerResult = await appendToLedger(env, 'EMAIL', body.scope || 'EMAIL', {
    to: recipient, cc: payload.cc || null, bcc: payload.bcc || null,
    subject, from: sender, work_ref: data.id,
  });

  return json({ sent: true, id: data.id, to: recipient, subject, ledger: ledgerResult });
}
