/**
 * RUNNER/CALENDAR — Calendar and availability queries.
 * GOV: SERVICES/TALK/RUNNER/CANON.md
 */

import { json } from '../../kernel/http.js';

export async function handleCalendar(url, kv) {
  const userId = url.searchParams.get('user_id') || '';
  const dateStr = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const range = url.searchParams.get('range') || 'week';
  const allTasks = JSON.parse(await kv.get('runner:tasks:all') || '[]');
  const base = new Date(dateStr + 'T00:00:00Z');
  let rangeStart, rangeEnd;
  if (range === 'day') { rangeStart = rangeEnd = dateStr; }
  else if (range === 'month') {
    rangeStart = dateStr.slice(0, 8) + '01';
    rangeEnd = dateStr.slice(0, 8) + String(new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() + 1, 0)).getUTCDate()).padStart(2, '0');
  } else {
    const dow = base.getUTCDay() || 7;
    const mon = new Date(base.getTime() - (dow - 1) * 86400000);
    rangeStart = mon.toISOString().slice(0, 10);
    rangeEnd = new Date(mon.getTime() + 6 * 86400000).toISOString().slice(0, 10);
  }
  const events = allTasks.filter(t => {
    if (userId && t.requester_id !== userId && t.runner_id !== userId) return false;
    const d = (t.scheduled_time || t.created_at || '').slice(0, 10);
    return d >= rangeStart && d <= rangeEnd;
  }).map(t => ({
    id: t.id, type: t.type, title: t.title, status: t.status,
    date: (t.scheduled_time || t.created_at || '').slice(0, 10),
    time: (t.scheduled_time || '').slice(11, 16) || null,
    address: (t.location && t.location.address) || '', fee_coin: t.fee_coin,
  })).sort((a, b) => (a.date + (a.time || '')).localeCompare(b.date + (b.time || '')));
  let availability = null;
  if (userId) { const avRaw = await kv.get(`runner:availability:${userId}`); if (avRaw) availability = JSON.parse(avRaw); }
  return json({ range: { start: rangeStart, end: rangeEnd, type: range }, events, availability });
}
