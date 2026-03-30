/**
 * REDDIT — Governed community posting lane.
 *
 * Every submission ledgered. Every subreddit declared. Every emission traced to CAMPAIGN.
 * Governed by: hadleylab-canonic/SERVICES/REDDIT/CANON.md
 *
 * REDDIT | CANONIC | 2026
 */

import { json } from '../kernel/http.js';
import { extractSessionToken } from '../kernel/util.js';

// ── Declared subreddits (from SERVICES/REDDIT/INTEL.md) ──
const DECLARED_SUBREDDITS = new Set([
  'MachineLearning', 'healthIT', 'bioinformatics', 'artificial', 'LegalTech',
]);

// ── Reddit OAuth (script-type app, server-to-server) ──

async function getRedditToken(env) {
  const auth = btoa(`${env.REDDIT_CLIENT_ID}:${env.REDDIT_CLIENT_SECRET}`);
  const res = await fetch('https://www.reddit.com/api/v1/access_token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'canonic-reddit/1.0 (by /u/idrdex)',
    },
    body: `grant_type=password&username=${encodeURIComponent(env.REDDIT_USERNAME)}&password=${encodeURIComponent(env.REDDIT_PASSWORD)}`,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Reddit OAuth failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  if (!data.access_token) throw new Error('No access_token in Reddit response');
  return data.access_token;
}

// ── Submit post ──

export async function submit(request, env, session) {
  // Principal gate: DEXTER only
  const user = (session.user || '').toLowerCase();
  if (user !== 'idrdex') {
    return json({ error: `Access denied for ${session.user}. DEXTER only.` }, 403);
  }

  let body;
  try {
    body = await request.json();
  } catch (_) {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const { campaign, subreddit, kind, title, text, flair_id } = body;

  // Validate required fields
  if (!subreddit) return json({ error: 'Missing subreddit' }, 400);
  if (!title) return json({ error: 'Missing title' }, 400);
  if (!kind || !['self', 'link'].includes(kind)) return json({ error: 'kind must be "self" or "link"' }, 400);

  // Subreddit registry check (CANON: MUST NOT post to undeclared subreddits)
  if (!DECLARED_SUBREDDITS.has(subreddit)) {
    return json({ error: `Subreddit r/${subreddit} not declared in REDDIT/INTEL.md. Declared: ${[...DECLARED_SUBREDDITS].join(', ')}` }, 403);
  }

  // Preflight: title length (Reddit max 300 chars)
  if (title.length > 300) {
    return json({ error: `Title too long: ${title.length}/300 chars` }, 400);
  }

  // Get Reddit access token
  let redditToken;
  try {
    redditToken = await getRedditToken(env);
  } catch (e) {
    return json({ error: `Reddit auth failed: ${e.message}` }, 502);
  }

  // Submit to Reddit
  const submitBody = new URLSearchParams({
    sr: subreddit,
    kind: kind,
    title: title,
    resubmit: 'true',
    api_type: 'json',
  });
  if (kind === 'self' && text) submitBody.set('text', text);
  if (kind === 'link' && body.url) submitBody.set('url', body.url);
  if (flair_id) submitBody.set('flair_id', flair_id);

  const submitRes = await fetch('https://oauth.reddit.com/api/submit', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${redditToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'canonic-reddit/1.0 (by /u/idrdex)',
    },
    body: submitBody.toString(),
  });

  const submitData = await submitRes.json();

  // Check for Reddit errors
  if (submitData.json?.errors?.length > 0) {
    return json({
      error: 'Reddit submission failed',
      reddit_errors: submitData.json.errors,
    }, 422);
  }

  const postUrl = submitData.json?.data?.url || '';
  const redditId = submitData.json?.data?.id || '';
  const redditName = submitData.json?.data?.name || '';
  const postedAt = new Date().toISOString();

  // Ledger the submission (CANON: MUST ledger every submission)
  if (env.TALK_KV) {
    const ledgerKey = `reddit:post:${redditName || Date.now()}`;
    await env.TALK_KV.put(ledgerKey, JSON.stringify({
      event: 'REDDIT:POST',
      campaign: campaign || '',
      subreddit,
      kind,
      title,
      url: postUrl,
      reddit_id: redditId,
      reddit_name: redditName,
      user: session.user,
      posted_at: postedAt,
    }), { expirationTtl: 365 * 24 * 60 * 60 }); // 1 year retention
  }

  return json({
    success: true,
    url: postUrl,
    reddit_id: redditId,
    reddit_name: redditName,
    subreddit,
    campaign: campaign || '',
    posted_at: postedAt,
  });
}

// ── Status check ──

export async function status(request, env, session) {
  let redditToken;
  try {
    redditToken = await getRedditToken(env);
  } catch (e) {
    return json({ authenticated: false, error: e.message });
  }

  const meRes = await fetch('https://oauth.reddit.com/api/v1/me', {
    headers: {
      'Authorization': `Bearer ${redditToken}`,
      'User-Agent': 'canonic-reddit/1.0 (by /u/idrdex)',
    },
  });

  if (!meRes.ok) {
    return json({ authenticated: false, error: `Reddit API: ${meRes.status}` });
  }

  const me = await meRes.json();
  return json({
    authenticated: true,
    username: me.name,
    karma: { link: me.link_karma, comment: me.comment_karma },
    declared_subreddits: [...DECLARED_SUBREDDITS],
  });
}
