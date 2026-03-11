/**
 * GATEWAY/BAKEOFF — Multi-model comparison endpoint.
 * GOV: TALK/CANON.md
 */

import { json, oaiError } from '../../kernel/http.js';
import { checkGatewayKey, listGatewayModels, parseModelCsv } from './registry.js';
import { callGatewayModel } from './dispatch.js';

export async function oaiBakeoff(request, env) {
  const gateErr = checkGatewayKey(request, env);
  if (gateErr) return oaiError(401, gateErr, 'authentication_error');
  let body; try { body = await request.json(); } catch (e) { console.error('[TALK]', e.message || e); return oaiError(400, 'Invalid JSON'); }
  const reg = listGatewayModels(env);
  const models = Array.isArray(body.models) ? body.models.map(String).map(s => s.trim()).filter(Boolean) : [];
  const audience = String(body.audience || body.suite || '').toLowerCase().trim();
  const presetModels = audience === 'dev' ? parseModelCsv(env.BAKEOFF_DEV_MODELS) : audience === 'user' ? parseModelCsv(env.BAKEOFF_USER_MODELS) : audience === 'experiment' ? parseModelCsv(env.BAKEOFF_EXPERIMENT_MODELS) : [];
  const defaults = (() => { const chat = reg.find(m => m.id === 'canonic-chat') || reg.find(m => m.profile === 'chat') || reg[0]; const kilo = reg.find(m => m.id === 'canonic-kilocode') || reg.find(m => m.profile === 'kilocode'); const list = []; if (chat?.id) list.push(chat.id); if (kilo?.id) list.push(kilo.id); return list; })();
  const selected = models.length ? models : (presetModels.length ? presetModels : defaults);
  const entries = selected.map(String).map(s => s.trim()).filter(Boolean).map(id => reg.find(m => m.id === id) || null).filter(Boolean);
  if (!entries.length) return oaiError(400, 'No valid models requested');
  const trace_id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const parallel = body.parallel !== false;
  const calls = entries.map(e => callGatewayModel(e, body, env, trace_id));
  const results = parallel ? await Promise.all(calls) : (async () => { const out = []; for (const c of calls) out.push(await c); return out; })();
  return json({ object: 'bakeoff', trace_id, results });
}
