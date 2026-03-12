// CANON.json fetcher — runtime config from governance
// Source: runner-canonic/SERVICES/TALK/RUNNER/CANON.json
// Published at: hadleylab.org/talks/runner/CANON.json

import type { Canon } from "./types";

// In production, set NEXT_PUBLIC_CANON_URL to the published governance endpoint.
// Locally, served from /public/CANON.json (copied from runner-canonic/SERVICES/TALK/RUNNER/CANON.json).
const CANON_URL =
  process.env.NEXT_PUBLIC_CANON_URL ||
  "/CANON.json";

let _cache: Canon | null = null;
let _fetchPromise: Promise<Canon> | null = null;

export async function fetchCanon(): Promise<Canon> {
  if (_cache) return _cache;
  if (_fetchPromise) return _fetchPromise;

  _fetchPromise = fetch(CANON_URL)
    .then((res) => {
      if (!res.ok) throw new Error(`CANON.json fetch failed: ${res.status}`);
      return res.json() as Promise<Canon>;
    })
    .then((canon) => {
      _cache = canon;
      _fetchPromise = null;
      return canon;
    })
    .catch((err) => {
      _fetchPromise = null;
      throw err;
    });

  return _fetchPromise;
}

export function getCanonSync(): Canon | null {
  return _cache;
}

export function invalidateCanon() {
  _cache = null;
  _fetchPromise = null;
}
