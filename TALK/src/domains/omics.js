/**
 * OMICS — Governed proxy for NCBI E-utilities + PharmGKB.
 * GOV: OMICS/CANON.md — every analysis ledgered.
 */

import { json } from '../kernel/http.js';
import { addCors } from '../kernel/cors.js';
import { _reqOrigin } from '../kernel/cors.js';
import { appendToLedger } from '../kernel/ledger.js';

const OMICS_UPSTREAMS = {
  '/omics/ncbi/':     'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/',
  '/omics/pharmgkb/': 'https://api.pharmgkb.org/v1/data/',
};

export async function handle(request, env, ctx, url) {
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);

  const path = url.pathname;
  for (const [prefix, upstream] of Object.entries(OMICS_UPSTREAMS)) {
    if (path.startsWith(prefix)) {
      const rest = path.slice(prefix.length);
      const target = upstream + rest + url.search;
      const res = await fetch(target, { cf: { cacheTtl: 3600 } });
      const body = await res.arrayBuffer();
      const headers = addCors({
        'Content-Type': res.headers.get('Content-Type') || 'application/json',
        'Cache-Control': 'public, max-age=3600',
      }, _reqOrigin);

      const source = prefix.includes('ncbi') ? 'ncbi' : 'pharmgkb';
      appendToLedger(env, 'OMICS', `OMICS:${source}`, {
        source, query_path: rest, query_params: url.search,
        upstream_status: res.status,
        ip: request.headers.get('CF-Connecting-IP') || 'unknown',
        work_ref: `omics:${source}:${Date.now()}`,
      }).catch(e => console.error('[TALK]', e.message || e));

      return new Response(body, { status: res.status, headers });
    }
  }

  return json({ error: 'Unknown omics upstream' }, 404);
}
