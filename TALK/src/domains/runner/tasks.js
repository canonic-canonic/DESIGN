/**
 * RUNNER/TASKS — Task CRUD and lifecycle actions.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';
import { kvGet } from '../../kernel/kv.js';
import { appendToLedger } from '../../kernel/ledger.js';
import { sendEmail } from '../../kernel/email.js';
import { TASK_PRICES, KYC_REQUIRED, uid } from './index.js';
import { notifyVendors, notifyAgent } from './notify.js';

export async function createTask(body, env, kv) {
  if (!body.requester_id) return json({ error: 'requester_id is required' }, 400);
  const taskType = body.type || 'lockbox_install';
  const feeCoin = TASK_PRICES[taskType] || Math.max(1, parseInt(body.offered_fee_usd) || 50);

  // GOV: COIN/CANON.md — resolve balance from VAULT wallet first, fall back to KV counter
  const principal = await kv.get(`runner:principal:${body.requester_id}`);
  let bal = 0, useVault = false, wallet = null;
  if (principal) {
    const walletRaw = await kv.get(`vault:wallet:${principal}`);
    if (walletRaw) {
      try { wallet = JSON.parse(walletRaw); bal = wallet.balance || 0; useVault = true; } catch {}
    }
  }
  if (!useVault) bal = parseInt(await kv.get(`runner:balance:${body.requester_id}`) || '0', 10);
  if (bal < feeCoin) return json({ error: 'Insufficient COIN', balance: bal, required: feeCoin }, 402);

  const tid = 'T' + uid();
  const task = {
    id: tid, requester_id: body.requester_id, runner_id: null, type: taskType,
    title: body.title || taskType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    status: 'posted', location: { address: (body.location || {}).address || body.address || '' },
    scheduled_time: body.scheduled_time || '', fee_coin: feeCoin,
    offered_fee_usd: parseInt(body.offered_fee_usd) || 50, notes: body.notes || '',
    proof_url: null, proof_note: null, rating: null, tip_coin: 0,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  };
  if (useVault) {
    wallet.balance = bal - feeCoin;
    await kv.put(`vault:wallet:${principal}`, JSON.stringify(wallet));
  } else {
    await kv.put(`runner:balance:${body.requester_id}`, String(bal - feeCoin));
  }
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  allTasks.push(task);
  await kv.put('runner:tasks:all', JSON.stringify(allTasks));
  await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_POSTED', task_id: tid, task_type: taskType, requester_id: body.requester_id, fee_coin: feeCoin, address: task.location.address });
  if (env.RESEND_API_KEY) notifyVendors(env, kv, task).catch(e => console.error('[RUNNER:NOTIFY]', e.message || e));
  return json({ success: true, task, balance: bal - feeCoin });
}

export async function listTasks(url, kv) {
  const role = url.searchParams.get('role') || '';
  const userId = url.searchParams.get('user_id') || '';
  let tasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  if (role === 'Requester' && userId) tasks = tasks.filter(t => t.requester_id === userId);
  else if (role === 'Runner' && userId) tasks = tasks.filter(t => t.status === 'posted' || t.runner_id === userId);
  tasks.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  return json({ tasks });
}

export async function handleTaskAction(taskId, action, request, env, kv) {
  const method = request.method;
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const task = allTasks.find(t => t.id === taskId);
  if (!task) return json({ error: 'task not found' }, 404);

  if (action === 'accept' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: 'runner_id required' }, 400);
    if (!['posted', 'assigned'].includes(task.status)) return json({ error: `cannot accept in status: ${task.status}` }, 400);
    const kycReq = KYC_REQUIRED[task.type];
    if (kycReq) {
      const vendor = await kvGet(kv, `runner:user:${body.runner_id}`, {});
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== 'verified') return json({ error: 'Credential verification required', task_type: task.type, required_credential: kycReq, vendor_id: body.runner_id }, 403);
    }
    task.runner_id = body.runner_id; task.status = 'accepted'; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'VENDOR_CLAIMED', task_id: taskId, task_type: task.type, runner_id: body.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin });
    if (env.RESEND_API_KEY) notifyAgent(env, kv, task).catch(e => console.error('[RUNNER:NOTIFY]', e.message || e));
    return json({ success: true, task });
  }

  if (action === 'assign' && method === 'PATCH') {
    const body = await request.json().catch(() => ({}));
    if (!body.runner_id) return json({ error: 'runner_id required' }, 400);
    if (task.status !== 'posted') return json({ error: `cannot assign in status: ${task.status}` }, 400);
    task.runner_id = body.runner_id; task.status = 'assigned'; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    return json({ success: true, task });
  }

  if (action === 'proof' && method === 'POST') {
    if (!['accepted', 'in_progress'].includes(task.status)) return json({ error: `cannot upload proof in status: ${task.status}` }, 400);
    let body, fileHash = null, fileKey = null;
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('multipart/form-data')) {
      const formData = await request.formData();
      const file = formData.get('file');
      const note = formData.get('note') || 'Task completed as requested';
      if (file && file.size > 0) {
        const buf = await file.arrayBuffer();
        const hashBuf = await crypto.subtle.digest('SHA-256', buf);
        fileHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        fileKey = `runner:evidence:${taskId}:${fileHash.slice(0, 12)}`;
        await kv.put(fileKey, buf, { metadata: { task_id: taskId, filename: file.name || 'evidence', content_type: file.type || 'application/octet-stream', hash: fileHash, uploaded_at: new Date().toISOString() }});
      }
      body = { note };
    } else {
      body = await request.json().catch(() => ({}));
      fileHash = body.proof_hash || null;
    }
    task.status = 'in_progress'; task.proof_note = body.note || 'Task completed as requested';
    task.proof_hash = fileHash; task.proof_key = fileKey; task.updated_at = new Date().toISOString();
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'EVIDENCE_UPLOADED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, proof_hash: fileHash, proof_note: task.proof_note });
    return json({ success: true, task, proof_hash: fileHash });
  }

  if (action === 'complete' && method === 'POST') {
    if (!['in_progress', 'accepted'].includes(task.status)) return json({ error: `cannot complete in status: ${task.status}` }, 400);
    task.status = 'completed'; task.completed_at = new Date().toISOString(); task.updated_at = new Date().toISOString();
    if (task.runner_id && task.fee_coin) {
      const vendorBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(vendorBal + task.fee_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_COMPLETED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, fee_coin: task.fee_coin, coin_credited_to: task.runner_id });
    return json({ success: true, task });
  }

  if (action === 'rate' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (task.status !== 'completed') return json({ error: `cannot rate in status: ${task.status}` }, 400);
    task.rating = Math.max(1, Math.min(5, parseInt(body.rating) || 5));
    task.tip_coin = Math.max(0, parseInt(body.tip_usd || body.tip_coin) || 0);
    task.status = 'rated'; task.updated_at = new Date().toISOString();
    if (task.tip_coin > 0 && task.runner_id) {
      const tipBal = parseInt(await kv.get(`runner:balance:${task.runner_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.runner_id}`, String(tipBal + task.tip_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'DEAL_CLOSED', task_id: taskId, task_type: task.type, runner_id: task.runner_id, requester_id: task.requester_id, rating: task.rating, tip_coin: task.tip_coin, fee_coin: task.fee_coin });
    return json({ success: true, task });
  }

  if (action === 'cancel' && method === 'POST') {
    if (['completed', 'rated'].includes(task.status)) return json({ error: `cannot cancel in status: ${task.status}` }, 400);
    const prevStatus = task.status;
    task.status = 'cancelled'; task.updated_at = new Date().toISOString();
    if (task.fee_coin && task.requester_id) {
      const refBal = parseInt(await kv.get(`runner:balance:${task.requester_id}`) || '0', 10);
      await kv.put(`runner:balance:${task.requester_id}`, String(refBal + task.fee_coin));
    }
    await kv.put('runner:tasks:all', JSON.stringify(allTasks));
    await appendToLedger(env, 'RUNNER', 'RUNNER', { event: 'TASK_CANCELLED', task_id: taskId, task_type: task.type, requester_id: task.requester_id, fee_coin: task.fee_coin, prev_status: prevStatus });
    return json({ success: true, task });
  }

  return json({ error: 'unknown action' }, 404);
}
