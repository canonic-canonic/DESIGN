// Types derived from runner-canonic/SERVICES/TALK/RUNNER/CANON.json
// Zero hardcoding — all values come from CANON.json at runtime

export type Role = "Pro" | "Runner" | "Ops";
export type AuthRole = "Requester" | "Runner" | "Ops";

export type TaskStatus =
  | "posted"
  | "assigned"
  | "accepted"
  | "in_progress"
  | "completed"
  | "rated"
  | "cancelled";

export interface TaskType {
  key: string;
  label: string;
  coin: number;
  vendor_gate: string | null;
  credential_key: string | null;
  evidence: string;
  category: "physical" | "admin";
}

export interface TaskInstruction {
  title: string;
  overview: string;
  requirements: string[];
  steps: { step: number; title: string; description: string }[];
  tips: string[];
}

export interface QuickAction {
  key: string;
  message: string;
  label: string;
}

export interface CoinPhase {
  name: string;
  tasks: string;
  coin: number;
}

export interface CoinEconomics {
  per_listing: number;
  nona_referral: number;
  full_transaction: number;
  phases: CoinPhase[];
}

export interface FiduciaryDuty {
  duty: string;
  enforcement: string;
}

export interface Canon {
  service: string;
  version: string;
  runner: boolean;
  axiom: string;
  roles: { key: string; view: string; does: string }[];
  task_types: TaskType[];
  task_lifecycle: TaskStatus[];
  transitions: Record<string, TaskStatus[]>;
  auth_roles: AuthRole[];
  referral_stages: Record<string, string[]>;
  task_instructions: Record<string, TaskInstruction>;
  quick_actions: QuickAction[];
  coin_economics: CoinEconomics;
  persona: {
    tone: string;
    audience: string;
    voice: string;
    warmth: string;
  };
  fiduciary: {
    statute: string;
    duties: FiduciaryDuty[];
  };
}

export interface User {
  id: string;
  name: string;
  email?: string;
  github?: string;
  role: AuthRole;
  avatar_color?: string;
  created_at?: string;
}

export interface RunnerProfile {
  id: string;
  user_id: string;
  onboarding_completed: boolean;
  onboarding_step: number;
  profile?: {
    first_name: string;
    last_name: string;
    phone: string;
  };
  vehicle?: {
    type: string;
    make: string;
    model: string;
    year: string;
    color: string;
    license_plate: string;
  };
  rating_avg: number;
  total_ratings: number;
  completed_tasks: number;
  available: boolean;
  current_location?: { lat: number; lng: number };
}

export interface Task {
  id: string;
  requester_id: string;
  assigned_runner_id?: string;
  type: string;
  title: string;
  location?: {
    lat: number;
    lng: number;
    address: string;
  };
  scheduled_time?: string;
  offered_fee_usd: number;
  notes?: string;
  status: TaskStatus;
  runner_progress?: number;
  runner_location?: { lat: number; lng: number };
  proof_photos?: string[];
  rating?: number;
  tip_usd?: number;
  tip_coin?: number;
  current_eta_minutes?: number;
  current_distance_miles?: number;
  created_at: string;
  completed_at?: string;
}

export interface PlatformStats {
  total_tasks: number;
  active_tasks: number;
  completed_tasks: number;
  total_runners: number;
  coin_minted: number;
}

// Icon map — driven by CANON.json task_type keys
export const TASK_ICONS: Record<string, string> = {
  lockbox_install: "🔐",
  lockbox_remove: "🔐",
  yard_sign_install: "🪧",
  yard_sign_remove: "🪧",
  photo_shoot: "📸",
  staging: "🛋️",
  inspection: "🔍",
  appraisal: "📊",
  title: "📜",
  open_house: "🏠",
  showing: "👁️",
  cma: "📈",
  contract: "📝",
  closing: "🎯",
  flyer_delivery: "📄",
  vendor_meetup: "🤝",
  key_run: "🔑",
};

export const STATUS_COLORS: Record<TaskStatus, string> = {
  posted: "#3b82f6",
  assigned: "#8b5cf6",
  accepted: "#6366f1",
  in_progress: "#f59e0b",
  completed: "#22c55e",
  rated: "#10b981",
  cancelled: "#ef4444",
};
