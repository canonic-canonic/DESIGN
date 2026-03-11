/**
 * EMAIL — Branded HTML via Resend.
 * GOV: EMAIL/CANON.md — MUST BCC sender on every outbound.
 */

import { json } from '../kernel/http.js';
import { appendToLedger } from '../kernel/ledger.js';
import { sendEmail } from '../kernel/email.js';

export async function handle(request, env) {
  if (!env.RESEND_API_KEY) return json({ error: 'RESEND_API_KEY not configured' }, 500);

  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { to, subject, html, from, cc, bcc, reply_to } = body;
  if (!to || !subject || !html) return json({ error: 'Missing to, subject, or html' }, 400);

  const result = await sendEmail(env, { from, to, subject, html, cc, bcc, reply_to, attachments: body.attachments });
  if (!result.ok) return json({ error: `Resend ${result.status || 'error'}`, detail: result.error }, 502);

  const recipient = Array.isArray(to) ? to[0] : to;
  const sender = from || env.EMAIL_FROM || 'founder@canonic.org';
  const ledgerResult = await appendToLedger(env, 'EMAIL', body.scope || 'EMAIL', {
    to: recipient, subject, from: sender, work_ref: result.id,
  });

  return json({ sent: true, id: result.id, to: recipient, subject, ledger: ledgerResult });
}
