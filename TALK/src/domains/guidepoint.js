/**
 * GUIDEPOINT — Classify inbound consultation requests, action via browser URL.
 * GOV: DEXTER/SERVICES/GUIDEPOINT/CANON.md
 *
 * INTEL + COIN + EMAIL composed.
 * Fiat earned becomes COIN. Every decision ledgered.
 */

import { json } from '../kernel/http.js';
import { appendToLedger } from '../kernel/ledger.js';
import { fetchWithRetry } from '../kernel/http.js';

// ── INTEL: keyword lists (from GUIDEPOINT/INTEL.md) ──

const ACCEPT_KW = [
  'ai', 'artificial intelligence', 'machine learning', 'deep learning',
  'llm', 'large language model', 'foundation model', 'continual learning',
  'transfer learning', 'ai agent', 'authentication', 'ai model',
  'ai utilization', 'ai research', 'natural language processing', 'nlp',
  'computer vision', 'neural network', 'transformer', 'gpt', 'claude',
  'generative ai', 'oncology', 'breast cancer', 'mammography', 'mammogram',
  'medical imaging', 'radiology ai', 'pathology', 'bioinformatics',
  'genomics', 'clinical informatics', 'health it', 'digital health',
  'computational biology', 'ehr', 'electronic health record',
];

const DECLINE_KW = [
  'survey', 'recruit only', 'marketing', 'demand generation',
  'benchmarking', 'payer', 'interventional radiology perspectives',
  'laboratory specimen', 'outpatient provider space',
];

const DECLINE_SENDERS = ['surveys@guidepoint.com'];
const ALLOWED_DOMAINS = ['guidepointglobal.com', 'guidepoint.com'];

// ── Classify ──

function classify(subject, fromAddr) {
  const lower = (subject || '').toLowerCase();
  const sender = (fromAddr || '').toLowerCase();

  // Sender-level decline
  if (DECLINE_SENDERS.some(s => sender.includes(s))) return 'DECLINE';

  // Keyword match — decline first (more specific)
  const declineHit = DECLINE_KW.some(kw => lower.includes(kw));
  const acceptHit = ACCEPT_KW.some(kw => lower.includes(kw));

  // GOV: decline wins on conflict — off-topic is off-topic even if "AI" appears in subject
  if (declineHit) return 'DECLINE';
  if (acceptHit) return 'ACCEPT';
  return 'HOLD'; // no match — manual review
}

// ── Parse subject ──

function parseSubject(subject) {
  const idMatch = (subject || '').match(/#(\d+)/);
  const topicMatch = (subject || '').match(/(?:Consultation Request|Request)\s*-\s*(.+?)(?:\s*\(#|\s*$)/i);
  return {
    project_id: idMatch ? idMatch[1] : null,
    topic: topicMatch ? topicMatch[1].trim() : subject,
  };
}

// ── Extract action URLs from HTML ──

function extractUrls(html) {
  const acceptMatch = (html || '').match(/id=3D"button-review-project"[^>]*href=3D"([^"]+)"/);
  const declineMatch = (html || '').match(/id=3D"button-decline-now"[^>]*href=3D"([^"]+)"/);
  // Also try unencoded HTML (post-parsing)
  const acceptPlain = (html || '').match(/id="button-review-project"[^>]*href="([^"]+)"/);
  const declinePlain = (html || '').match(/id="button-decline-now"[^>]*href="([^"]+)"/);
  return {
    accept: decodeQP(acceptMatch?.[1]) || acceptPlain?.[1] || null,
    decline: decodeQP(declineMatch?.[1]) || declinePlain?.[1] || null,
  };
}

function decodeQP(s) {
  if (!s) return null;
  return s.replace(/=3D/g, '=').replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// ── Validate sender domain ──

function validSender(fromAddr) {
  const addr = (fromAddr || '').toLowerCase();
  return ALLOWED_DOMAINS.some(d => addr.endsWith('@' + d) || addr.includes('@' + d));
}

// ── Inbound handler ──

export async function inbound(request, env) {
  // Validate webhook secret
  const secret = request.headers.get('X-Webhook-Secret');
  if (!env.GUIDEPOINT_WEBHOOK_SECRET || secret !== env.GUIDEPOINT_WEBHOOK_SECRET) {
    return json({ error: 'Unauthorized' }, 401);
  }

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { from, subject, html } = body;
  if (!from || !subject) return json({ error: 'Missing from or subject' }, 400);

  // Validate sender
  if (!validSender(from)) return json({ error: 'Sender not in allowlist' }, 403);

  // Parse + classify
  const { project_id, topic } = parseSubject(subject);
  const decision = classify(subject, from);

  // Extract URLs
  const urls = extractUrls(html);

  // Action
  let actioned = false;
  if (decision === 'ACCEPT' && urls.accept) {
    try { await fetchWithRetry(urls.accept, { method: 'GET' }, { maxRetries: 1, timeoutMs: 10000 }); actioned = true; }
    catch (e) { console.error('[GUIDEPOINT] accept click failed:', e.message); }
  } else if (decision === 'DECLINE' && urls.decline) {
    try { await fetchWithRetry(urls.decline, { method: 'GET' }, { maxRetries: 1, timeoutMs: 10000 }); actioned = true; }
    catch (e) { console.error('[GUIDEPOINT] decline click failed:', e.message); }
  }

  // Ledger
  await appendToLedger(env, 'GUIDEPOINT', 'GUIDEPOINT', {
    project_id, topic, decision, actioned, from, subject,
    work_ref: project_id ? `guidepoint:${project_id}` : `guidepoint:${Date.now()}`,
  });

  return json({ ok: true, project_id, topic, decision, actioned });
}

// ── Complete handler (manual — record fiat as COIN) ──

export async function complete(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { project_id, fiat_usd, notes } = body;
  if (!project_id || !fiat_usd) return json({ error: 'Missing project_id or fiat_usd' }, 400);

  const coin = { key: `DEXTER:GUIDEPOINT:${project_id}`, fiat_usd, notes };

  await appendToLedger(env, 'COIN', 'GUIDEPOINT', {
    ...coin,
    inventor: 'DEXTER',
    work_ref: `guidepoint:${project_id}`,
  });

  return json({ ok: true, coin, ledger: true });
}

// ── Ledger read ──

export async function ledger(request, env) {
  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit') || '50');
  const key = 'ledger:GUIDEPOINT:GUIDEPOINT';
  const raw = await env.TALK_KV.get(key);
  if (!raw) return json({ scope: 'GUIDEPOINT', total: 0, entries: [] });
  const entries = JSON.parse(raw).slice(-limit);
  return json({ scope: 'GUIDEPOINT', total: entries.length, entries });
}
