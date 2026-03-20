/**
 * ADMIN — Governed administrative operations via GALAXY operating surface.
 * Scope creation, INTEL editing, build triggering.
 * All operations require authenticated session + write permission.
 * All operations log to COIN ledger (CONTRIBUTE event).
 *
 * GOV: GALAXY/PRIMITIVES/CANON.md
 * MAGIC | CANONIC | 2026-03
 */

import { json } from '../kernel/http.js';
import { appendToLedger } from '../kernel/ledger.js';
import { kvGet } from '../kernel/kv.js';
import { requireSession } from './auth.js';

// ── Role guard ──────────────────────────────────────────
const ADMIN_ROLES = new Set(['ADMIN', 'GOV_GENERAL', 'SUPERUSER']);

async function requireAdmin(request, env) {
  const { session, error } = await requireSession(request, env);
  if (error) return { error };
  const grants = await kvGet(env.TALK_KV, `grants:${session.user}`, {});
  const role = grants.role || session.role || 'USER';
  if (!ADMIN_ROLES.has(role.toUpperCase())) {
    return { error: json({ error: 'Forbidden: admin role required' }, 403) };
  }
  return { session, role };
}

/**
 * POST /admin/scope/create
 * Creates a new governed scope by writing CANON.md + structural files.
 * Stages the change for the next build cycle.
 *
 * Body: { parent, name, axiom, privacy?, inherits? }
 */
export async function scopeCreate(request, env) {
  const { session, error } = await requireAdmin(request, env);
  if (error) return error;

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { parent, name, axiom, privacy, inherits } = body;
  if (!parent || !name || !axiom) {
    return json({ error: 'Missing required fields: parent, name, axiom' }, 400);
  }

  // Validate name (alphanumeric + hyphens, uppercase)
  const safeName = name.toUpperCase().replace(/[^A-Z0-9-]/g, '');
  if (!safeName || safeName.length < 2) {
    return json({ error: 'Invalid scope name' }, 400);
  }

  // Build CANON.md content
  const inheritLine = inherits ? `\ninherits: ${inherits}` : '';
  const canonContent = `# ${safeName} — CANON${inheritLine}
version: 2026-03

---

## Axiom

**${axiom}**

## Constraints

\`\`\`
MUST:     ${axiom.split('.')[0]}
\`\`\`

---

*${safeName} | CANON*
`;

  const readmeContent = `# ${safeName}\n\n${axiom}\n`;
  const vocabContent = `# ${safeName} — VOCAB\n\n| Term | Definition |\n|------|------------|\n\n---\n\n*${safeName} | VOCAB*\n`;

  // Store pending scope creation in KV (picked up by build pipeline)
  const pendingKey = `admin:pending:scope:${parent}/${safeName}`;
  const pending = {
    parent,
    name: safeName,
    axiom,
    privacy: privacy || 'PUBLIC',
    inherits: inherits || null,
    files: {
      'CANON.md': canonContent,
      'README.md': readmeContent,
      'VOCAB.md': vocabContent,
    },
    created_by: session.user,
    created_at: new Date().toISOString(),
  };

  await env.TALK_KV.put(pendingKey, JSON.stringify(pending));

  // Log to COIN ledger
  await appendToLedger(env, 'CONTRIBUTE', parent, {
    contributor: session.user,
    action: 'SCOPE_CREATE',
    scope_name: safeName,
    axiom,
    coin_event: 'MINT:CONTRIBUTE',
  }, { key: `contributions:${parent}` });

  return json({
    ok: true,
    scope: `${parent}/${safeName}`,
    message: `Scope ${safeName} staged under ${parent}. Will be live after next build.`,
    pending_key: pendingKey,
  });
}

/**
 * POST /admin/intel/update
 * Updates INTEL for a scope. Stages the change for the next build cycle.
 *
 * Body: { scope, intel }
 */
export async function intelUpdate(request, env) {
  const { session, error } = await requireAdmin(request, env);
  if (error) return error;

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, intel } = body;
  if (!scope || !intel) {
    return json({ error: 'Missing required fields: scope, intel' }, 400);
  }

  // Store pending intel update in KV
  const pendingKey = `admin:pending:intel:${scope}`;
  const pending = {
    scope,
    intel,
    updated_by: session.user,
    updated_at: new Date().toISOString(),
  };

  await env.TALK_KV.put(pendingKey, JSON.stringify(pending));

  // Log to COIN ledger
  await appendToLedger(env, 'CONTRIBUTE', scope, {
    contributor: session.user,
    action: 'INTEL_UPDATE',
    intel_preview: intel.slice(0, 100),
    coin_event: 'MINT:CONTRIBUTE',
  }, { key: `contributions:${scope}` });

  return json({
    ok: true,
    scope,
    message: `INTEL updated for ${scope}. Will be live after next build.`,
  });
}

/**
 * POST /admin/learning/add
 * Adds a LEARNING pattern to a scope.
 *
 * Body: { scope, signal, pattern }
 */
export async function learningAdd(request, env) {
  const { session, error } = await requireAdmin(request, env);
  if (error) return error;

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON' }, 400); }

  const { scope, signal, pattern } = body;
  if (!scope || !pattern) {
    return json({ error: 'Missing required fields: scope, pattern' }, 400);
  }

  const date = new Date().toISOString().split('T')[0];
  const pendingKey = `admin:pending:learning:${scope}:${Date.now()}`;
  const pending = {
    scope,
    signal: signal || 'USER_LEARNING',
    pattern,
    date,
    added_by: session.user,
  };

  await env.TALK_KV.put(pendingKey, JSON.stringify(pending));

  await appendToLedger(env, 'CONTRIBUTE', scope, {
    contributor: session.user,
    action: 'LEARNING_ADD',
    signal: signal || 'USER_LEARNING',
    pattern_preview: pattern.slice(0, 100),
    coin_event: 'MINT:CONTRIBUTE',
  }, { key: `contributions:${scope}` });

  return json({
    ok: true,
    scope,
    message: `Learning pattern added for ${scope}.`,
  });
}

/**
 * POST /admin/rebuild
 * Triggers a build pipeline rebuild (GitHub Actions dispatch).
 */
export async function triggerRebuild(request, env) {
  const { session, error } = await requireAdmin(request, env);
  if (error) return error;

  // Rate limit: 1 rebuild per hour
  const lastRebuild = await kvGet(env.TALK_KV, 'admin:last_rebuild', null);
  if (lastRebuild) {
    const elapsed = Date.now() - new Date(lastRebuild).getTime();
    if (elapsed < 3600000) {
      const remaining = Math.ceil((3600000 - elapsed) / 60000);
      return json({ error: `Rebuild rate limited. Try again in ${remaining} minutes.` }, 429);
    }
  }

  await env.TALK_KV.put('admin:last_rebuild', JSON.stringify(new Date().toISOString()));

  await appendToLedger(env, 'CONTRIBUTE', 'GALAXY', {
    contributor: session.user,
    action: 'BUILD_TRIGGER',
    coin_event: 'MINT:CONTRIBUTE',
  }, { key: 'contributions:GALAXY' });

  // Dispatch GitHub Actions workflow if configured
  if (env.GITHUB_TOKEN && env.GITHUB_REPO) {
    try {
      const res = await fetch(
        `https://api.github.com/repos/${env.GITHUB_REPO}/dispatches`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            event_type: 'galaxy_rebuild',
            client_payload: { user: session.user, trigger: 'admin_api' },
          }),
        }
      );
      if (!res.ok) {
        return json({ ok: true, rebuild: 'queued', dispatch: 'failed', status: res.status });
      }
    } catch (e) {
      return json({ ok: true, rebuild: 'queued', dispatch: 'error', message: e.message });
    }
  }

  return json({
    ok: true,
    message: 'Build triggered. Galaxy will regenerate in 8-12 minutes.',
  });
}

/**
 * GET /admin/mutations
 * Lists pending mutations for build reconciliation.
 */
export async function mutationsList(request, env) {
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  const mutations = await kvGet(env.TALK_KV, 'admin:mutations', []);

  // Also list pending scope/intel/learning keys
  const pendingList = await env.TALK_KV.list({ prefix: 'admin:pending:' });
  const pending = pendingList.keys.map(k => ({ key: k.name, expiration: k.expiration }));

  return json({ mutations, pending, count: mutations.length + pending.length });
}
