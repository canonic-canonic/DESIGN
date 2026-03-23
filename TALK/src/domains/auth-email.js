/**
 * EMAIL AUTH — Magic link authentication.
 * Send a magic link to email → user clicks → session token issued.
 * GOV: AUTH/CANON.md — EVERY SESSION GOVERNED.
 */

import { json } from '../kernel/http.js';
import { sendEmail } from '../kernel/email.js';

// Generate a random token
function generateToken(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * POST /auth/email/send
 * Body: { email, redirect_url? }
 * Sends a magic link to the email address. Stores token in KV with 15min TTL.
 */
export async function emailSend(request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: 'KV not configured' }, 500);

  const body = await request.json().catch(() => ({}));
  const email = (body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return json({ error: 'valid email required' }, 400);

  // Rate limit: 3 magic links per email per 15 minutes
  const rateKey = `auth:rate:${email}`;
  const rateCount = parseInt(await kv.get(rateKey) || '0', 10);
  if (rateCount >= 3) return json({ error: 'too many attempts, try again in 15 minutes' }, 429);
  await kv.put(rateKey, String(rateCount + 1), { expirationTtl: 900 });

  // Generate magic token
  const token = generateToken();
  const magicKey = `auth:magic:${token}`;
  await kv.put(magicKey, JSON.stringify({ email, created: Date.now() }), { expirationTtl: 900 }); // 15 min TTL

  // Build magic link
  const baseUrl = body.redirect_url || 'https://gorunner.pro';
  const magicUrl = `${baseUrl}?auth_token=${token}`;

  // Send email
  const result = await sendEmail(env, {
    from: 'GoRunner <runner@canonic.org>',
    to: email,
    subject: 'Sign in to GoRunner',
    html: `
      <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
        <h2 style="color: #EF4444; margin-bottom: 8px;">GoRunner</h2>
        <p style="color: #666; margin-bottom: 32px;">Real Estate Task Marketplace</p>
        <p>Click below to sign in:</p>
        <a href="${magicUrl}" style="display: inline-block; background: linear-gradient(to right, #EF4444, #F97316); color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: bold; margin: 16px 0;">Sign In to GoRunner</a>
        <p style="color: #999; font-size: 13px; margin-top: 32px;">This link expires in 15 minutes. If you didn't request this, ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 32px 0;" />
        <p style="color: #ccc; font-size: 11px;">Powered by CANONIC INTL — every session governed, every grant audited.</p>
      </div>
    `,
  });

  if (!result.ok) return json({ error: 'failed to send email', detail: result.error }, 500);
  return json({ ok: true, email });
}

/**
 * POST /auth/email/verify
 * Body: { token }
 * Verifies magic link token, creates session, returns session_token + user.
 */
export async function emailVerify(request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: 'KV not configured' }, 500);

  const body = await request.json().catch(() => ({}));
  const token = (body.token || '').trim();
  if (!token) return json({ error: 'token required' }, 400);

  // Look up magic token
  const magicKey = `auth:magic:${token}`;
  const raw = await kv.get(magicKey);
  if (!raw) return json({ error: 'invalid or expired token' }, 401);

  const { email } = JSON.parse(raw);

  // Consume token (one-time use)
  await kv.delete(magicKey);

  // Create session token
  const sessionToken = generateToken(48);
  const sessionKey = `auth:session:${sessionToken}`;
  await kv.put(sessionKey, JSON.stringify({ email, created: Date.now() }), { expirationTtl: 604800 }); // 7 day session

  // Resolve or create runner user
  let user = null;
  const existingRaw = await kv.get(`runner:email:${email}`);
  if (existingRaw) {
    user = JSON.parse(existingRaw);
  } else {
    // New user — create with signup bonus
    const id = 'U' + Array.from(crypto.getRandomValues(new Uint8Array(6))).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const startupCoin = 50;
    user = { id, name: email.split('@')[0], email, role: 'Requester', created_at: new Date().toISOString(), status: 'active' };
    await kv.put(`runner:user:${id}`, JSON.stringify(user));
    await kv.put(`runner:email:${email}`, JSON.stringify(user));
    await kv.put(`runner:balance:${id}`, String(startupCoin));
  }

  // Get balance
  const bal = parseInt(await kv.get(`runner:balance:${user.id}`) || '0', 10);

  return json({ ok: true, session_token: sessionToken, user, balance: bal });
}

/**
 * Validate session middleware — checks Bearer token against KV.
 */
export async function emailSession(request, env) {
  const kv = env.TALK_KV;
  if (!kv) return json({ error: 'KV not configured' }, 500);

  const auth = request.headers.get('authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return json({ error: 'no session' }, 401);

  const sessionKey = `auth:session:${token}`;
  const raw = await kv.get(sessionKey);
  if (!raw) return json({ error: 'invalid session' }, 401);

  const { email } = JSON.parse(raw);
  const userRaw = await kv.get(`runner:email:${email}`);
  if (!userRaw) return json({ error: 'user not found' }, 404);

  const user = JSON.parse(userRaw);
  return json({ ok: true, user, email });
}
