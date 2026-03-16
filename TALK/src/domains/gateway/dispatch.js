/**
 * GATEWAY/DISPATCH — oaiChatCompletions, oaiResponses, callGatewayModel.
 * GOV: TALK/CANON.md
 */

import { json, oaiError, fetchWithTimeout, addCors } from '../../kernel/http.js';
import { parseIntEnv } from '../../kernel/env.js';
import { clampInt, clampString, redactSecrets, coerceContentToText } from '../../kernel/util.js';
import { PROVIDERS } from '../providers.js';
import {
  checkGatewayKey, listGatewayModels, tokenBoundsForEntry,
  resolveChatRequestedModel, normalizeResponseInputToMessages,
} from './registry.js';

// ── Exported route handlers ──

export async function oaiModels(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');
  const models = listGatewayModels(env).map(m => ({ id: m.id, object: 'model', owned_by: 'canonic' }));
  return json({ object: 'list', data: models });
}

export async function oaiChatCompletions(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body;
  try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }

  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return oaiError(400, 'Missing messages');

  const reg = listGatewayModels(env);
  const selection = resolveChatRequestedModel(body, env, reg);
  if (selection.error) return oaiError(400, selection.error);
  const model = selection.model;
  if (!model) return oaiError(400, 'Missing model');
  const entry = reg.find(m => m.id === model) || null;
  if (!entry) return oaiError(400, `Unknown model: ${model || '(empty)'}`, 'invalid_request_error', 'model_not_found');
  const upstreamModel = (entry.upstream_model || entry.id || '').trim();
  if (!upstreamModel) return oaiError(500, `Model misconfigured: ${entry.id}`);

  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);
  const stream = !!(body && body.stream);
  if (body && body.n && parseInt(body.n, 10) !== 1) return oaiError(400, 'Only n=1 is supported');

  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const started = Date.now();

  // Anthropic
  if (!env.ANTHROPIC_API_KEY) return oaiError(500, 'ANTHROPIC_API_KEY not configured');
  const sys = messagesIn.filter(m => m && m.role === 'system').map(m => coerceContentToText(m.content)).filter(Boolean).join('\n\n');
  const anthMessages = messagesIn.filter(m => m && (m.role === 'user' || m.role === 'assistant')).slice(-40).map(m => ({ role: m.role, content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
  if (!anthMessages.length) return oaiError(400, 'No valid user/assistant messages');

  let res;
  try {
    res = await fetchWithTimeout(PROVIDERS.anthropic.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION },
      body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || undefined, messages: anthMessages }),
    }, parseIntEnv(env, 'OAI_GATEWAY_TIMEOUT_MS') ?? 25000);
  } catch (e) { return oaiError(502, `Upstream error: ${clampString(String(e?.message || e), 180)}`, 'api_error'); }

  const text = await res.text();
  if (!res.ok) return oaiError(502, `Anthropic ${res.status}: ${clampString(redactSecrets(text), 900)}`, 'api_error');
  let data; try { data = JSON.parse(text); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(502, 'Anthropic returned invalid JSON', 'api_error'); }
  const content = data?.content?.[0]?.text ? String(data.content[0].text) : '';

  const h = addCors({ 'Content-Type': 'application/json' });
  h.set('x-canonic-trace-id', trace_id); h.set('x-canonic-model-profile', entry.profile || 'anthropic');
  h.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
  if (selection.assigned) h.set('x-canonic-assigned-model', model);

  const out = { id: 'chatcmpl-canonic-' + trace_id, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop', logprobs: null }], usage: null };

  if (stream) {
    const sh = addCors({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' });
    sh.set('x-canonic-trace-id', trace_id); sh.set('x-canonic-model-profile', entry.profile || 'anthropic');
    sh.set('x-canonic-upstream-elapsed-ms', String(Date.now() - started));
    if (selection.assigned) sh.set('x-canonic-assigned-model', model);
    const chunk = { id: out.id, object: 'chat.completion.chunk', created: out.created, model: out.model, choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] };
    const rs = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`)); controller.enqueue(new TextEncoder().encode(`data: [DONE]\n\n`)); controller.close(); } });
    return new Response(rs, { status: 200, headers: sh });
  }
  return new Response(JSON.stringify(out), { status: 200, headers: h });
}

export async function oaiResponses(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');

  let body; try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }
  const model = (body?.model ? String(body.model) : '').trim();
  const audience = String((body && (body.audience || body.suite)) || '').toLowerCase().trim();
  const randomize = !!(body && body.randomize_model);
  if (!model && !(randomize || ['user', 'patient', 'dev', 'experiment'].includes(audience))) return oaiError(400, 'Missing model');

  let messages = null;
  if (body && Array.isArray(body.messages) && body.messages.length) messages = body.messages;
  else if (body && body.input !== undefined) messages = normalizeResponseInputToMessages(body.input);
  if (!messages || !messages.length) return oaiError(400, 'Missing messages/input');

  const chatBody = { messages, max_tokens: body.max_output_tokens ?? body.max_tokens, temperature: body.temperature, top_p: body.top_p, presence_penalty: body.presence_penalty, frequency_penalty: body.frequency_penalty, stop: body.stop, seed: body.seed, stream: false, n: 1 };
  if (model) chatBody.model = model;
  if (audience) chatBody.audience = audience;
  if (randomize) chatBody.randomize_model = true;
  if (body?.user_id !== undefined) chatBody.user_id = body.user_id;
  if (body?.patient_id !== undefined) chatBody.patient_id = body.patient_id;
  if (body?.session_id !== undefined) chatBody.session_id = body.session_id;

  const r2 = new Request('https://api.canonic.org/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': request.headers.get('Authorization') || '' }, body: JSON.stringify(chatBody) });
  const chatRes = await oaiChatCompletions(r2, env);
  const text = await chatRes.text();
  if (chatRes.status !== 200) return new Response(text, { status: chatRes.status, headers: addCors(chatRes.headers) });

  let data; try { data = JSON.parse(text); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(502, 'Upstream returned invalid JSON', 'api_error'); }
  const content = data?.choices?.[0]?.message ? String(data.choices[0].message.content || '') : '';

  const out = {
    id: 'resp-canonic-' + (data.id ? String(data.id).replace(/^chatcmpl-/, '') : String(Date.now())),
    object: 'response', created: Math.floor(Date.now() / 1000), model,
    output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: content }] }],
    output_text: content, usage: data?.usage || null,
  };
  const h = addCors({ 'Content-Type': 'application/json' });
  const trace = chatRes.headers.get('x-canonic-trace-id'); if (trace) h.set('x-canonic-trace-id', trace);
  const prof = chatRes.headers.get('x-canonic-model-profile'); if (prof) h.set('x-canonic-model-profile', prof);
  const elapsed = chatRes.headers.get('x-canonic-upstream-elapsed-ms'); if (elapsed) h.set('x-canonic-upstream-elapsed-ms', elapsed);
  return new Response(JSON.stringify(out), { status: 200, headers: h });
}

// callGatewayModel for bakeoff
export async function callGatewayModel(entry, body, env, trace_id) {
  const started = Date.now();
  const model = entry.id;
  const upstreamModel = (entry.upstream_model || model || '').trim();
  if (!upstreamModel) return { model, ok: false, status: 500, error: `Model misconfigured: ${model}`, elapsed_ms: Date.now() - started };

  const wantMax = Number.isFinite(body.max_tokens) ? parseInt(body.max_tokens, 10) : null;
  const { lo, hi } = tokenBoundsForEntry(entry, env);
  const max_tokens = clampInt(wantMax ?? hi, lo, hi);

  const messagesIn = body && Array.isArray(body.messages) ? body.messages : null;
  if (!messagesIn || !messagesIn.length) return { model, ok: false, status: 400, error: 'Missing messages', elapsed_ms: Date.now() - started };
  const messages = messagesIn.slice(-40).map(m => ({ role: String(m.role || '').trim(), content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
  if (!messages.length) return { model, ok: false, status: 400, error: 'No valid messages', elapsed_ms: Date.now() - started };

  const allowed = ['temperature', 'top_p', 'presence_penalty', 'frequency_penalty', 'stop', 'seed'];
  const pass = {};
  for (const k of allowed) { if (body && body[k] !== undefined) pass[k] = body[k]; }
  const gov_pre = { provider: entry.provider, profile: entry.profile || null, model, upstream_model: upstreamModel, max_tokens, tokens_min: lo, tokens_max: hi };

  // Anthropic
  if (!env.ANTHROPIC_API_KEY) return { model, ok: false, status: 500, error: 'ANTHROPIC_API_KEY not configured', gov_pre, elapsed_ms: Date.now() - started };
  const sys = messagesIn.filter(m => m?.role === 'system').map(m => coerceContentToText(m.content)).filter(Boolean).join('\n\n');
  const anthMessages = messagesIn.filter(m => m && (m.role === 'user' || m.role === 'assistant')).slice(-40).map(m => ({ role: m.role, content: coerceContentToText(m.content) })).filter(m => m.role && m.content);
  if (!anthMessages.length) return { model, ok: false, status: 400, error: 'No valid user/assistant messages', gov_pre, elapsed_ms: Date.now() - started };
  const timeout_ms = parseIntEnv(env, 'BAKEOFF_TIMEOUT_MS') ?? 60000;
  try {
    const res = await fetchWithTimeout(PROVIDERS.anthropic.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': env.ANTHROPIC_VERSION }, body: JSON.stringify({ model: upstreamModel, max_tokens, system: sys || undefined, messages: anthMessages, temperature: pass.temperature, top_p: pass.top_p, stop_sequences: pass.stop ? (Array.isArray(pass.stop) ? pass.stop : [pass.stop]) : undefined }) }, timeout_ms);
    const text = await res.text();
    if (!res.ok) return { model, ok: false, status: 502, error: `Anthropic ${res.status}: ${clampString(redactSecrets(text), 600)}`, gov_pre, elapsed_ms: Date.now() - started };
    const data = JSON.parse(text);
    const content = data?.content?.[0]?.text ? String(data.content[0].text) : '';
    return { model, ok: true, status: 200, content, usage: data?.usage || null, gov_pre, gov_post: { ok: true, elapsed_ms: Date.now() - started, trace_id }, elapsed_ms: Date.now() - started };
  } catch (e) { return { model, ok: false, status: 502, error: `Anthropic error: ${clampString(String(e?.message || e), 180)}`, gov_pre, elapsed_ms: Date.now() - started }; }
}
