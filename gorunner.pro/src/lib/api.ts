// API client for api.canonic.org/runner/*
// Port of RUNNER_PLUGIN.API pattern from runner.js

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://api.canonic.org";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem("canonic_session_token");
  } catch {
    return null;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Don't set Content-Type for FormData (let browser set multipart boundary)
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(
      (err as Record<string, string>).error || `HTTP ${res.status}`
    );
  }

  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────
export async function authLogin(data: {
  name: string;
  github: string;
  role: string;
}) {
  return request<{
    user: { id: string; role: string };
    principal?: string;
  }>("/runner/auth", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function authGitHub(code: string, redirectUri?: string) {
  return request<{
    session_token?: string;
    access_token?: string;
    user?: string;
    name?: string;
    avatar_url?: string;
  }>("/auth/github", {
    method: "POST",
    body: JSON.stringify({ code, redirect_uri: redirectUri }),
  });
}

export async function validateSession() {
  return request<{
    user?: string;
    name?: string;
    avatar_url?: string;
  }>("/auth/session");
}

// ── Tasks ─────────────────────────────────────────────────────────
export async function getTasks(params?: {
  user_id?: string;
  role?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.user_id) qs.set("user_id", params.user_id);
  if (params?.role) qs.set("role", params.role);
  const query = qs.toString();
  return request<{ tasks: import("./types").Task[] }>(
    `/runner/tasks${query ? `?${query}` : ""}`
  );
}

export async function createTask(data: {
  requester_id: string;
  type: string;
  title: string;
  address: string;
  scheduled_time?: string;
  fee_usd: number;
  notes?: string;
}) {
  return request<{ task: import("./types").Task }>("/runner/tasks", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function taskAction(
  taskId: string,
  action: string,
  body?: Record<string, unknown>
) {
  return request<{ task: import("./types").Task }>(
    `/runner/tasks/${taskId}/${action}`,
    {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    }
  );
}

export async function assignTask(
  taskId: string,
  runnerId: string
) {
  return request<{ task: import("./types").Task }>(
    `/runner/tasks/${taskId}/assign`,
    {
      method: "PATCH",
      body: JSON.stringify({ runner_id: runnerId }),
    }
  );
}

export async function uploadProof(taskId: string, file: File, note?: string) {
  const formData = new FormData();
  formData.append("file", file);
  if (note) formData.append("note", note);
  return request<{ hash: string }>(`/runner/tasks/${taskId}/proof`, {
    method: "POST",
    body: formData,
  });
}

// ── Profile & Stats ───────────────────────────────────────────────
export async function getProfile(userId: string) {
  return request<import("./types").User & { balance?: number }>(
    `/runner/profile?user_id=${userId}`
  );
}

export async function getBalance(userId: string) {
  return request<{ balance: number }>(
    `/runner/balance?user_id=${userId}`
  );
}

export async function getStats() {
  return request<import("./types").PlatformStats>("/runner/stats");
}

export async function getRunners() {
  return request<{ runners: import("./types").RunnerProfile[] }>(
    "/runner/list"
  );
}

// ── Location ──────────────────────────────────────────────────────
export async function updateLocation(
  userId: string,
  lat: number,
  lng: number
) {
  return request("/runner/location", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, lat, lng }),
  });
}

export async function getRunnerLocation(taskId: string) {
  return request<{
    lat: number;
    lng: number;
    eta_minutes?: number;
    distance_miles?: number;
  }>(`/runner/location?task_id=${taskId}`);
}

// ── Task Simulation ──────────────────────────────────────────────
export async function simulateMovement(
  taskId: string,
  progress: number,
  runnerId?: string
) {
  return request<{
    lat: number;
    lng: number;
    distance_remaining: number;
    eta_minutes: number;
    arrived: boolean;
    progress: number;
  }>(`/runner/tasks/${taskId}/simulate`, {
    method: "POST",
    body: JSON.stringify({ progress, runner_id: runnerId }),
  });
}

// ── Runner Availability ──────────────────────────────────────────
export async function setAvailability(userId: string, available: boolean) {
  return request<{ success: boolean; available: boolean }>(
    "/runner/available",
    {
      method: "POST",
      body: JSON.stringify({ user_id: userId, available }),
    }
  );
}

// ── Onboarding ────────────────────────────────────────────────────
export async function onboardProfile(data: {
  user_id: string;
  first_name: string;
  last_name: string;
  phone: string;
  vehicle_type?: string;
  service_area?: string;
}) {
  return request("/runner/onboard/profile", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function onboardVerify(data: {
  user_id: string;
  credential_type: string;
  license_number: string;
}) {
  return request("/runner/onboard/verify", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function onboardComplete(userId: string) {
  return request("/runner/onboard/complete", {
    method: "POST",
    body: JSON.stringify({ user_id: userId }),
  });
}

// ── Credentials ───────────────────────────────────────────────────
export async function submitCredential(data: {
  user_id: string;
  type: string;
  license_number: string;
}) {
  return request("/runner/credentials", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

// ── Payout (Stripe Connect) ──────────────────────────────────────
export async function payoutSetup(userId: string) {
  return request<{ ok: boolean; url: string; acct_id: string }>(
    "/runner/payout/setup",
    {
      method: "POST",
      body: JSON.stringify({ user_id: userId }),
    }
  );
}

export async function payoutStatus(userId: string) {
  return request<{
    connected: boolean;
    acct_id?: string;
    payouts_enabled?: boolean;
    charges_enabled?: boolean;
    details_submitted?: boolean;
  }>("/runner/payout/status", {
    method: "POST",
    body: JSON.stringify({ user_id: userId }),
  });
}

export async function payoutCashout(
  userId: string,
  amountCoin: number
) {
  return request<{
    ok: boolean;
    amount_coin: number;
    fee_coin: number;
    net_usd_cents: number;
    transfer_id: string;
    balance: number;
  }>("/runner/payout/cashout", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, amount_coin: amountCoin }),
  });
}

// ── Checkout ──────────────────────────────────────────────────────
export async function checkout(userId: string, amountCoin: number) {
  return request<{ session_id: string; url: string }>(
    "/runner/checkout",
    {
      method: "POST",
      body: JSON.stringify({
        user_id: userId,
        amount_coin: amountCoin,
      }),
    }
  );
}

// ── Chat ──────────────────────────────────────────────────────────
export async function sendChat(message: string, config?: Record<string, unknown>) {
  return request<{ reply: string }>("/chat", {
    method: "POST",
    body: JSON.stringify({ message, ...config }),
  });
}

// ── Ledger ────────────────────────────────────────────────────────
export async function getLedger(limit?: number) {
  const qs = limit ? `?limit=${limit}` : "";
  return request<{ entries: unknown[] }>(`/runner/ledger${qs}`);
}

// ── INTEL Board ──────────────────────────────────────────────────
export async function getBoard() {
  return request<{ tasks: import("./types").Task[] }>("/runner/board");
}

export async function getCalendar() {
  return request<{ events: unknown[] }>("/runner/calendar");
}

export async function getEvidence(taskId: string) {
  return request<{ evidence: unknown[] }>(`/runner/evidence/${taskId}`);
}
