// Chat engine — pure functions ported from runner.js beforeSend/afterReceive hooks
// Detects local commands, injects runner context, scans for task IDs

import type { Task, PlatformStats, RunnerProfile } from "./types";
import type { ChatMessage } from "./chatTypes";
import { getTasks, getStats, getRunners, getLedger } from "./api";

export interface UserContext {
  userId?: string;
  role?: string;
  principal?: string;
}

export interface BeforeSendResult {
  handled: boolean;
  localMessages?: ChatMessage[];
  enrichedText?: string;
}

// ── beforeSend ────────────────────────────────────────────────────
// Detect client-side commands and inject context
export async function beforeSend(
  text: string,
  userContext: UserContext
): Promise<BeforeSendResult> {
  const lower = text.toLowerCase().trim();

  // "show my tasks" / "my tasks"
  if (/^(show\s+)?(my\s+)?tasks$/i.test(lower)) {
    try {
      const { tasks } = await getTasks({
        user_id: userContext.userId,
        role: userContext.role,
      });
      return {
        handled: true,
        localMessages: [
          {
            type: "task-cards",
            role: "assistant",
            tasks,
            timestamp: new Date(),
          },
        ],
      };
    } catch {
      return { handled: false, enrichedText: text };
    }
  }

  // "show stats" / "stats"
  if (/^(show\s+)?stats$/i.test(lower)) {
    try {
      const stats = (await getStats()) as PlatformStats;
      return {
        handled: true,
        localMessages: [
          {
            type: "stats",
            role: "assistant",
            stats,
            timestamp: new Date(),
          },
        ],
      };
    } catch {
      return { handled: false, enrichedText: text };
    }
  }

  // "show runners" / "top runners" / "leaderboard" / "who are the top runners"
  if (
    /^(show\s+)?(runners|top\s+runners|leaderboard|who\s+are\s+the\s+top\s+runners\??)$/i.test(
      lower
    )
  ) {
    try {
      const { runners } = (await getRunners()) as {
        runners: RunnerProfile[];
      };
      return {
        handled: true,
        localMessages: [
          {
            type: "runner-list",
            role: "assistant",
            runners: runners.sort(
              (a, b) => b.completed_tasks - a.completed_tasks
            ),
            timestamp: new Date(),
          },
        ],
      };
    } catch {
      return { handled: false, enrichedText: text };
    }
  }

  // "show earnings" / "my earnings" / "show ledger"
  if (/^(show\s+)?(my\s+)?(earnings|ledger)$/i.test(lower)) {
    try {
      const { entries } = await getLedger(20);
      const events: ChatMessage[] = (
        entries as Array<{
          type?: string;
          amount?: number;
          label?: string;
          task_id?: string;
          created_at?: string;
        }>
      ).map((e) => ({
        type: "coin-event" as const,
        role: "system" as const,
        event: (e.type === "PURCHASE"
          ? "purchased"
          : e.type?.startsWith("MINT:TIP")
            ? "tip"
            : "earned") as "earned" | "spent" | "tip" | "purchased",
        amount: e.amount || 0,
        label: e.label || e.type || "COIN event",
        taskId: e.task_id,
        timestamp: new Date(e.created_at || Date.now()),
      }));
      return { handled: true, localMessages: events };
    } catch {
      return { handled: false, enrichedText: text };
    }
  }

  // Not a command — pass through with enriched context
  return { handled: false, enrichedText: text };
}

// ── afterReceive ──────────────────────────────────────────────────
// Scan LLM reply for task IDs (T + 12+ hex chars)
const TASK_ID_PATTERN = /\b(T[A-F0-9]{12,})\b/g;

export function extractTaskIds(reply: string): string[] {
  const matches = reply.match(TASK_ID_PATTERN);
  if (!matches) return [];
  return Array.from(new Set(matches));
}

// Fetch tasks by IDs and return as TaskCardsMessage
export async function afterReceive(
  reply: string,
  userContext: UserContext
): Promise<ChatMessage[]> {
  const ids = extractTaskIds(reply);
  if (ids.length === 0) return [];

  try {
    const { tasks } = await getTasks({
      user_id: userContext.userId,
      role: userContext.role,
    });
    const matched = tasks.filter((t: Task) =>
      ids.some((id) => t.id.toUpperCase().includes(id))
    );
    if (matched.length === 0) return [];
    return [
      {
        type: "task-cards",
        role: "assistant",
        tasks: matched,
        timestamp: new Date(),
      },
    ];
  } catch {
    return [];
  }
}
