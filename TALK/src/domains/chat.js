/**
 * CHAT — Governed conversation endpoint. Anthropic only. No fallbacks. No chain.
 * GOV: TALK/CANON.md
 */

import { json, fetchWithTimeout } from '../kernel/http.js';
import { requireIntEnv } from '../kernel/env.js';
import { clampString, redactSecrets } from '../kernel/util.js';
import { PROVIDERS, timeoutMsFor } from './providers.js';

export async function chat(request, env) {
  let body;
  try { body = await request.json(); }
  catch (e) { console.error('[TALK]', e.message || e); return json({ error: 'Invalid JSON' }, 400); }

  const { message, history = [], system, scope } = body;
  if (!message) return json({ error: 'Missing message' }, 400);

  const wantsStream = (request.headers.get('Accept') || '').includes('text/event-stream')
    || body.stream === true;

  const messages = [];
  for (const msg of history.slice(-10)) {
    if (msg.role && msg.content) messages.push({ role: msg.role, content: msg.content });
  }
  if (!messages.length || messages[messages.length - 1].content !== message) {
    messages.push({ role: 'user', content: message });
  }

  const systemPrompt = system || `TALK. Scope: ${scope || 'UNGOVERNED'}.`;
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());

  // ── Tier-based model selection: FREE → Haiku, FREEMIUM → Sonnet ──
  const tier = body.tier || (body.config && body.config.tier) || '';
  const model = (tier === 'FREE' && env.HAIKU_MODEL) ? env.HAIKU_MODEL : env.MODEL;

  // ── Single provider: Anthropic. No chain. No fallback. ──
  const provider = PROVIDERS.anthropic;
  const providerError = provider.validate?.(env);
  if (providerError) return json({ error: providerError, scope, trace_id }, 500);

  const { headers: provHeaders, body: reqBody } = provider.build(env, systemPrompt, messages);
  // Override model with tier-selected model
  reqBody.model = model;
  const providerUrl = provider.url;
  const ms = timeoutMsFor('anthropic', env);

  if (wantsStream) reqBody.stream = true;

  const startedAt = Date.now();
  const gov_pre = {
    provider: 'anthropic', url: providerUrl, timeout_ms: ms,
    model: reqBody.model, max_tokens: reqBody.max_tokens,
    messages: reqBody.messages.length,
    tokens_min: requireIntEnv(env, 'TOKENS_MIN', 'tokens'),
    tokens_max: requireIntEnv(env, 'TOKENS_MAX', 'tokens'),
    tier: tier || 'UNSET',
  };

  let res;
  try {
    res = await fetchWithTimeout(providerUrl, { method: 'POST', headers: provHeaders, body: JSON.stringify(reqBody) }, ms);
  } catch (e) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: 'anthropic', status: 0, error: String(e?.message || e).slice(0, 200), scope, trace_id }));
    return json({ error: clampString(redactSecrets(String(e?.message || e)), 220), scope, trace_id }, 502);
  }

  if (!res || !res.ok) {
    const status = res ? res.status : 0;
    const errBody = res ? await res.text() : '';
    const safeErr = redactSecrets(errBody);
    console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: 'anthropic', status, scope, trace_id }));
    return json({ error: `anthropic ${status}`, detail: clampString(safeErr, 600), scope, trace_id }, status >= 500 ? 502 : status);
  }

  // ── SSE streaming path ──
  if (wantsStream && res.body) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: 'anthropic', status: 200, mode: 'stream', scope, trace_id, model }));
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    (async () => {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const payload = line.slice(6).trim();
            if (payload === '[DONE]') {
              await writer.write(encoder.encode(`data: ${JSON.stringify({ done: true, trace_id, provider_used: 'anthropic', model, elapsed_ms: Date.now() - startedAt })}\n\n`));
              continue;
            }
            try {
              const chunk = JSON.parse(payload);
              // Anthropic stream format only — strict, no fallback
              const text = chunk?.delta?.text || '';
              if (text) {
                await writer.write(encoder.encode(`data: ${JSON.stringify({ token: text, done: false })}\n\n`));
              }
            } catch {}
          }
        }
        await writer.write(encoder.encode(`data: ${JSON.stringify({ done: true, trace_id, provider_used: 'anthropic', model, elapsed_ms: Date.now() - startedAt })}\n\n`));
      } catch (e) {
        await writer.write(encoder.encode(`data: ${JSON.stringify({ error: String(e?.message || e), done: true })}\n\n`));
      } finally {
        await writer.close();
      }
    })();

    return new Response(readable, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Trace-Id': trace_id,
      },
    });
  }

  // ── Non-streaming path ──
  const data = await res.json();
  const parsed = provider.parse(data) || '';
  const gov_post = {
    ok: true, status: res.status, elapsed_ms: Date.now() - startedAt,
    usage: data?.usage || null, parsed_chars: parsed.length, schema_ok: parsed.length > 0,
  };
  console.log(JSON.stringify({ ts: new Date().toISOString(), path: '/chat', provider: 'anthropic', status: 200, latency_ms: Date.now() - startedAt, scope, trace_id, model }));
  return json({
    message: parsed || 'No response.', scope, provider_used: 'anthropic', model,
    usage: data?.usage || null, elapsed_ms: Date.now() - startedAt, trace_id, gov_pre, gov_post,
  });
}
