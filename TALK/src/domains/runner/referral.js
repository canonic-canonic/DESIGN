/**
 * RUNNER/REFERRAL — NONA → RUNNER auto-stage tasks for a deal.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';
import { appendToLedger } from '../../kernel/ledger.js';
import { TASK_PRICES, uid } from './index.js';
import { STAGE_TASKS } from './constants.generated.js';

export async function handleReferral(request, env, kv) {
  const body = await request.json().catch(() => ({}));
  const { requester_id, address, stage, deal_id, source } = body;
  if (!requester_id || !address) return json({ error: 'requester_id and address required' }, 400);

  const dealStage = (stage || 'inquiry').toLowerCase();
  const taskTypes = STAGE_TASKS[dealStage] || STAGE_TASKS.inquiry;
  const totalCoin = taskTypes.reduce((s, t) => s + (TASK_PRICES[t] || 5), 0);
  let bal = parseInt(await kv.get(`runner:balance:${requester_id}`) || '0', 10);
  if (bal < totalCoin) return json({ error: 'Insufficient COIN for referral batch', balance: bal, required: totalCoin }, 402);

  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const created = [];
  for (const taskType of taskTypes) {
    const feeCoin = TASK_PRICES[taskType] || 5;
    const tid = 'T' + uid();
    const task = {
      id: tid, requester_id, runner_id: null, type: taskType,
      title: taskType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      status: 'posted', location: { address }, scheduled_time: '', fee_coin: feeCoin, offered_fee_usd: 50,
      notes: `Auto-staged from ${source || 'NONA'} ${dealStage} (deal: ${deal_id || 'n/a'})`,
      proof_url: null, proof_note: null, rating: null, tip_coin: 0,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    };
    bal -= feeCoin; allTasks.push(task); created.push(task);
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_POSTED', task_id: tid, task_type: taskType, requester_id, fee_coin: feeCoin, address, referral_source: source || 'NONA', referral_stage: dealStage, deal_id: deal_id || null });
  }
  await kv.put(`runner:balance:${requester_id}`, String(bal));
  await kv.put('runner:tasks:all', JSON.stringify(allTasks));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'REFERRAL_STAGED', source: source || 'NONA', stage: dealStage, deal_id: deal_id || null, requester_id, address, tasks_created: created.length, total_coin: totalCoin });
  return json({ success: true, stage: dealStage, tasks: created, balance: bal, deal_id });
}
