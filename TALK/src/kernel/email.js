/**
 * EMAIL — Resend API wrapper with retry + BCC governance.
 * GOV: EMAIL/CANON.md — MUST BCC sender, MUST retry.
 */

import { fetchWithRetry } from './http.js';

export async function sendEmail(env, { from, to, subject, html, cc, bcc, reply_to, attachments }) {
  if (!env.RESEND_API_KEY) return { ok: false, error: 'RESEND_API_KEY not configured' };
  const sender = from || env.EMAIL_FROM || 'founder@canonic.org';
  const recipient = Array.isArray(to) ? to : [to];
  const payload = { from: sender, to: recipient, subject, html };
  if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];

  // GOV: EMAIL/CANON.md — MUST BCC sender on every outbound
  const senderAddr = sender.includes('<') ? (sender.match(/<([^>]+)>/)?.[1] || sender) : sender;
  const bccList = bcc ? (Array.isArray(bcc) ? [...bcc] : [bcc]) : [];
  if (!bccList.includes(senderAddr)) bccList.push(senderAddr);
  payload.bcc = bccList;

  if (reply_to) payload.reply_to = reply_to;
  if (attachments) payload.attachments = attachments;

  try {
    const res = await fetchWithRetry('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.RESEND_API_KEY}` },
      body: JSON.stringify(payload),
    }, { maxRetries: 2, timeoutMs: 10000 });

    if (!res.ok) return { ok: false, status: res.status, error: await res.text() };
    const data = await res.json();
    return { ok: true, id: data.id };
  } catch (e) {
    console.error('[EMAIL]', e.message || e);
    return { ok: false, error: String(e.message || e) };
  }
}
