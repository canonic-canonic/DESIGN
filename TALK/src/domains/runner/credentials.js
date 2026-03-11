/**
 * RUNNER/CREDENTIALS — Vendor credential submission + verification.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';
import { appendToLedger } from '../../kernel/ledger.js';
import { sendEmail } from '../../kernel/email.js';

export async function handleCredentialSubmit(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || '').trim();
  const credType = (body.type || '').trim();
  const licenseNumber = (body.license_number || '').trim();
  if (!userId || !credType || !licenseNumber) return json({ error: 'user_id, type, and license_number required' }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: 'user not found' }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  creds[credType] = { license_number: licenseNumber, issuing_authority: body.issuing_authority || '', expiry: body.expiry || '', status: 'pending', submitted_at: new Date().toISOString() };
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'CREDENTIAL_SUBMITTED', user_id: userId, credential_type: credType, license_number: licenseNumber });
  return json({ success: true, user_id: userId, credential: creds[credType] });
}

export async function handleCredentialVerify(request, kv, env) {
  const body = await request.json().catch(() => ({}));
  const userId = (body.user_id || '').trim();
  const credType = (body.type || '').trim();
  const verdict = body.verified === true ? 'verified' : 'rejected';
  if (!userId || !credType) return json({ error: 'user_id and type required' }, 400);
  const raw = await kv.get(`runner:user:${userId}`);
  if (!raw) return json({ error: 'user not found' }, 404);
  const user = JSON.parse(raw);
  const creds = user.credentials || {};
  if (!creds[credType]) return json({ error: 'credential not found' }, 404);
  creds[credType].status = verdict; creds[credType].verified_at = new Date().toISOString(); creds[credType].verified_by = body.verified_by || 'ops';
  user.credentials = creds;
  await kv.put(`runner:user:${userId}`, JSON.stringify(user));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'CREDENTIAL_VERIFIED', user_id: userId, credential_type: credType, verdict, verified_by: body.verified_by || 'ops' });
  if (user.email && env.RESEND_API_KEY) {
    const statusText = verdict === 'verified' ? 'approved' : 'rejected';
    sendEmail(env, {
      to: user.email,
      subject: `RUNNER: Your ${credType} credential has been ${statusText}`,
      html: `<p>Your <strong>${credType}</strong> credential (${creds[credType].license_number}) has been <strong>${statusText}</strong> on RUNNER.</p>
${verdict === 'verified' ? '<p>You can now claim tasks that require this credential.</p>' : '<p>Please resubmit with a valid license number.</p>'}
<p><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Go to RUNNER</a></p>`,
    }).catch(() => {});
  }
  return json({ success: true, user_id: userId, credential: creds[credType] });
}
