"use client";

import useSWR, { mutate as globalMutate } from "swr";
import { getBalance } from "@/lib/api";

function balanceKey(userId: string | undefined) {
  return userId ? `balance:${userId}` : null;
}

export function useBalance(userId: string | undefined) {
  const { data, error, isLoading, mutate } = useSWR(
    balanceKey(userId),
    () => getBalance(userId!),
    {
      revalidateOnFocus: true,
      dedupingInterval: 5_000,
      refreshInterval: 15_000,
    }
  );

  return {
    balance: data?.balance ?? null,
    error,
    loading: isLoading,
    refresh: mutate,
  };
}

// Call this after any COIN mutation (complete, rate+tip, checkout return)
// to invalidate balance across all mounted components
export function refreshBalance(userId: string) {
  globalMutate(balanceKey(userId));
}
