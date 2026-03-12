"use client";

import { useRouter } from "next/navigation";
import type { ChatMessage } from "@/lib/chatTypes";
import type { Canon } from "@/lib/types";
import { TaskCard } from "@/components/TaskCard";
import { CoinEventCard } from "./CoinEventCard";
import { StatusBadge } from "@/components/StatusBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { Star, Trophy, Shield } from "lucide-react";

interface MessageRendererProps {
  message: ChatMessage;
  canon: Canon | null;
}

export function ChatMessageRenderer({ message, canon }: MessageRendererProps) {
  const router = useRouter();

  switch (message.type) {
    case "text":
      return (
        <div
          className={`flex ${
            message.role === "user" ? "justify-end" : "justify-start"
          }`}
        >
          <div
            className={`max-w-[85%] rounded-2xl px-4 py-2.5 text-sm ${
              message.role === "user"
                ? "bg-purple-500 text-white"
                : message.role === "system"
                  ? "bg-gray-50 dark:bg-gray-800/50 text-gray-500 text-xs italic"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            }`}
          >
            {message.content}
          </div>
        </div>
      );

    case "task-cards":
      return (
        <div className="space-y-2">
          {message.tasks.length === 0 ? (
            <div className="text-center text-xs text-gray-400 py-2">
              No tasks found
            </div>
          ) : (
            message.tasks.map((task) => (
              <TaskCard
                key={task.id}
                task={task}
                canon={canon}
                onClick={() => router.push(`/tasks?id=${task.id}`)}
                className="shadow-none border-gray-100 dark:border-gray-800"
              />
            ))
          )}
        </div>
      );

    case "stats":
      return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
          <div className="text-xs font-semibold text-gray-500 uppercase">
            Platform Stats
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[
              {
                label: "Tasks",
                value: message.stats.total_tasks,
              },
              {
                label: "Active",
                value: message.stats.active_tasks,
              },
              {
                label: "Done",
                value: message.stats.completed_tasks,
              },
            ].map((s) => (
              <div
                key={s.label}
                className="text-center rounded-lg bg-gray-50 dark:bg-gray-800 p-2"
              >
                <div className="text-lg font-bold">{s.value}</div>
                <div className="text-[10px] text-gray-500">{s.label}</div>
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>{message.stats.total_runners} runners</span>
            <span>∩{message.stats.coin_minted} minted</span>
          </div>
        </div>
      );

    case "runner-list":
      return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
          <div className="bg-gradient-pro px-4 py-2 text-white text-xs font-semibold flex items-center gap-1.5">
            <Trophy className="h-3.5 w-3.5" />
            Leaderboard
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {message.runners.slice(0, 10).map((runner, i) => (
              <div
                key={runner.id}
                className="flex items-center gap-3 px-4 py-2.5"
              >
                <span className="text-sm font-bold text-gray-400 w-5 text-center">
                  {i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : `${i + 1}`}
                </span>
                <div className="h-8 w-8 rounded-full bg-gradient-runner flex items-center justify-center text-white text-xs font-bold">
                  {runner.profile
                    ? `${runner.profile.first_name[0]}${runner.profile.last_name[0]}`
                    : "R"}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium truncate">
                    {runner.profile
                      ? `${runner.profile.first_name} ${runner.profile.last_name}`
                      : `Runner ${runner.id.slice(0, 6)}`}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <span className="text-amber-500">
                      {"★".repeat(Math.round(runner.rating_avg))}
                    </span>
                    <span>{runner.completed_tasks} tasks</span>
                  </div>
                </div>
                {runner.available && (
                  <span className="h-2 w-2 rounded-full bg-green-400" />
                )}
              </div>
            ))}
          </div>
        </div>
      );

    case "coin-event":
      return <CoinEventCard msg={message} />;

    case "fee-confirm":
      return (
        <div className="rounded-xl border-2 border-purple-200 dark:border-purple-800 p-4 space-y-3">
          <div className="text-sm font-medium">Confirm Task Fee</div>
          <div className="flex items-center justify-between">
            <StatusBadge status="posted" />
            <CoinBadge coin={message.coin} usd={message.usd} size="sm" />
          </div>
          <div className="text-xs text-gray-500">{message.address}</div>
          <div className="flex gap-2">
            <button
              onClick={message.onConfirm}
              className="flex-1 rounded-lg bg-purple-500 text-white text-sm font-medium py-2"
            >
              Confirm
            </button>
            <button
              onClick={message.onCancel}
              className="flex-1 rounded-lg border border-gray-300 dark:border-gray-700 text-sm py-2"
            >
              Cancel
            </button>
          </div>
        </div>
      );

    case "tip-prompt":
      return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 text-center space-y-2">
          <Star className="h-6 w-6 text-amber-400 mx-auto" />
          <div className="text-sm font-medium">Task completed!</div>
          <div className="text-xs text-gray-500">
            Rate and tip your runner
          </div>
          <button
            onClick={() => router.push(`/tasks?id=${message.taskId}`)}
            className="rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 text-white text-sm font-medium px-4 py-2"
          >
            Rate & Tip
          </button>
        </div>
      );

    case "task-created":
      return (
        <div className="rounded-xl bg-green-50 dark:bg-green-900/10 p-3 flex items-center gap-3">
          <Shield className="h-5 w-5 text-green-500" />
          <div>
            <div className="text-sm font-medium text-green-700 dark:text-green-300">
              Task posted
            </div>
            <div className="text-xs text-green-600 dark:text-green-400">
              {message.task.title || message.task.type}
            </div>
          </div>
        </div>
      );

    default:
      return null;
  }
}
