"use client";

import useSWR from "swr";
import type { Task } from "@/lib/types";

const API = process.env.NEXT_PUBLIC_API_URL || "https://api.canonic.org";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem("canonic_session_token");
  } catch {
    return null;
  }
}

const fetcher = async (url: string) => {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`Tasks: ${res.status}`);
  return res.json();
};

export function useTasks(userId?: string, role?: string) {
  const params = new URLSearchParams();
  if (userId) params.set("user_id", userId);
  if (role) params.set("role", role);
  const query = params.toString();
  // Allow fetching without userId when role is provided (e.g. "available" tasks)
  const url = (userId || role)
    ? `${API}/runner/tasks${query ? `?${query}` : ""}`
    : null;

  const { data, error, isLoading, mutate } = useSWR<{ tasks: Task[] }>(
    url,
    fetcher,
    { refreshInterval: 30_000 }
  );

  return {
    tasks: data?.tasks ?? [],
    error,
    loading: isLoading,
    refresh: mutate,
  };
}

export function useTask(taskId?: string) {
  const url = taskId ? `${API}/runner/tasks/${taskId}` : null;

  const { data, error, isLoading, mutate } = useSWR<{ task: Task }>(
    url,
    fetcher,
    { refreshInterval: 10_000 }
  );

  return {
    task: data?.task ?? null,
    error,
    loading: isLoading,
    refresh: mutate,
  };
}
