/**
 * RUNNER/NOTIFY — Email notifications for task events.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { sendEmail } from '../../kernel/email.js';
import { kvGet } from '../../kernel/kv.js';
import { KYC_REQUIRED } from './index.js';

export async function notifyVendors(env, kv, task) {
  const runnerIds = await kvGet(kv, 'runner:role:runner', []);
  const kycReq = KYC_REQUIRED[task.type];
  for (const id of runnerIds) {
    const vendor = await kvGet(kv, `runner:user:${id}`);
    if (!vendor || !vendor.email) continue;
    if (kycReq) {
      const creds = vendor.credentials || {};
      if (!creds[kycReq] || creds[kycReq].status !== 'verified') continue;
    }
    await sendEmail(env, {
      to: vendor.email,
      subject: `RUNNER: New ${task.title} task — ${task.fee_coin} COIN`,
      html: `<p>A new task has been posted on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || 'TBD'}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">ID</td><td style="padding:4px 12px;font-family:monospace;">${task.id}</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">Claim on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC · Every task ledgered.</p>`,
    });
  }
}

export async function notifyAgent(env, kv, task) {
  if (!task.requester_id) return;
  const agent = await kvGet(kv, `runner:user:${task.requester_id}`);
  if (!agent || !agent.email) return;
  let vendorName = 'A vendor';
  if (task.runner_id) {
    const vendor = await kvGet(kv, `runner:user:${task.runner_id}`);
    if (vendor) vendorName = vendor.name || vendorName;
  }
  await sendEmail(env, {
    to: agent.email,
    subject: `RUNNER: ${vendorName} claimed your ${task.title} task`,
    html: `<p><strong>${vendorName}</strong> has claimed your task on <strong>RUNNER</strong>.</p>
<table style="border-collapse:collapse;font-family:sans-serif;">
<tr><td style="padding:4px 12px;font-weight:600;">Task</td><td style="padding:4px 12px;">${task.title}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Location</td><td style="padding:4px 12px;">${task.location.address || 'TBD'}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Vendor</td><td style="padding:4px 12px;">${vendorName}</td></tr>
<tr><td style="padding:4px 12px;font-weight:600;">Fee</td><td style="padding:4px 12px;">${task.fee_coin} COIN</td></tr>
</table>
<p style="margin-top:16px;"><a href="https://gorunner.pro" style="background:#f97316;color:#fff;padding:8px 20px;border-radius:6px;text-decoration:none;font-weight:600;">View on RUNNER</a></p>
<p style="font-size:11px;color:#888;margin-top:16px;">CANONIC · Every task ledgered.</p>`,
  });
}
