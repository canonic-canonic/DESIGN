// Chat message types — discriminated union for React rendering
// Ported from runner.js hook architecture

import type { Task, RunnerProfile, PlatformStats } from "./types";

export type ChatMessageType =
  | "text"
  | "task-cards"
  | "stats"
  | "runner-list"
  | "coin-event"
  | "fee-confirm"
  | "tip-prompt"
  | "task-created";

export interface TextMessage {
  type: "text";
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: Date;
}

export interface TaskCardsMessage {
  type: "task-cards";
  role: "assistant";
  tasks: Task[];
  timestamp: Date;
}

export interface StatsMessage {
  type: "stats";
  role: "assistant";
  stats: PlatformStats;
  timestamp: Date;
}

export interface RunnerListMessage {
  type: "runner-list";
  role: "assistant";
  runners: RunnerProfile[];
  timestamp: Date;
}

export interface CoinEventMessage {
  type: "coin-event";
  role: "system";
  event: "earned" | "spent" | "tip" | "purchased";
  amount: number;
  label: string;
  taskId?: string;
  timestamp: Date;
}

export interface FeeConfirmMessage {
  type: "fee-confirm";
  role: "assistant";
  taskType: string;
  coin: number;
  usd: number;
  address: string;
  onConfirm: () => void;
  onCancel: () => void;
  timestamp: Date;
}

export interface TipPromptMessage {
  type: "tip-prompt";
  role: "assistant";
  taskId: string;
  timestamp: Date;
}

export interface TaskCreatedMessage {
  type: "task-created";
  role: "system";
  task: Task;
  timestamp: Date;
}

export type ChatMessage =
  | TextMessage
  | TaskCardsMessage
  | StatsMessage
  | RunnerListMessage
  | CoinEventMessage
  | FeeConfirmMessage
  | TipPromptMessage
  | TaskCreatedMessage;
