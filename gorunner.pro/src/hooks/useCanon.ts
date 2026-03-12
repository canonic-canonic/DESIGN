"use client";

import useSWR from "swr";
import type { Canon } from "@/lib/types";

const CANON_URL =
  process.env.NEXT_PUBLIC_CANON_URL ||
  "/CANON.json";

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error(`CANON.json: ${r.status}`);
    return r.json() as Promise<Canon>;
  });

export function useCanon() {
  const { data, error, isLoading } = useSWR<Canon>(CANON_URL, fetcher, {
    revalidateOnFocus: false,
    dedupingInterval: 60_000,
  });
  return { canon: data ?? null, error, loading: isLoading };
}
