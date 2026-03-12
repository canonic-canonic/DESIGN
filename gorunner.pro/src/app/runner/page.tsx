"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { TaskCard } from "@/components/TaskCard";
import { CoinBalance, CoinBadge } from "@/components/CoinBadge";
import { useBalance } from "@/hooks/useBalance";
import { taskAction } from "@/lib/api";
import { toast } from "sonner";

type Tab = "available" | "active" | "earnings";

export default function RunnerDashboard() {
  const router = useRouter();
  const { identity, user } = useAuth();
  const { canon } = useCanon();
  const [tab, setTab] = useState<Tab>("available");

  // All tasks — runner sees available + their assigned
  const { tasks: allTasks, refresh } = useTasks(identity?.userId, "Runner");
  const { tasks: availableTasks } = useTasks(undefined, "available");
  const { balance: balanceValue } = useBalance(identity?.userId);

  const available = availableTasks.filter((t) => t.status === "posted");
  const active = allTasks.filter(
    (t) =>
      t.assigned_runner_id === identity?.userId &&
      !["completed", "rated", "cancelled"].includes(t.status)
  );
  const completed = allTasks.filter(
    (t) =>
      t.assigned_runner_id === identity?.userId &&
      ["completed", "rated"].includes(t.status)
  );

  const totalEarned = completed.reduce((sum, t) => {
    const tt = canon?.task_types?.find((x) => x.key === t.type);
    return sum + (tt?.coin || 0);
  }, 0);

  async function handleAccept(taskId: string) {
    if (!identity) return;
    try {
      await taskAction(taskId, "accept", {
        runner_id: identity.userId,
      });
      toast.success("Task accepted!");
      refresh();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to accept"
      );
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="bg-gradient-runner px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm text-white/70">Runner</p>
              <h1 className="text-xl font-bold">
                {user?.name || user?.user || "Runner"}
              </h1>
            </div>
            <CoinBalance
              balance={balanceValue ?? 0}
              className="bg-white/10 text-amber-300"
            />
          </div>

          {/* Balance + Earnings */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-white/10 p-4 text-center">
              <div className="text-3xl font-bold">{balanceValue ?? 0}</div>
              <div className="text-sm text-white/70">∩ Credit Balance</div>
            </div>
            <div className="rounded-lg bg-white/10 p-4 text-center">
              <div className="text-3xl font-bold">{totalEarned}</div>
              <div className="text-sm text-white/70">Credits Earned</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-lg mx-auto px-4 pt-4">
        <div className="flex gap-1 rounded-lg bg-gray-100 dark:bg-gray-800 p-1">
          {(["available", "active", "earnings"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
                tab === t
                  ? "bg-white dark:bg-gray-900 shadow-sm"
                  : "text-gray-500 hover:text-gray-700"
              }`}
            >
              {t === "available"
                ? `Available (${available.length})`
                : t === "active"
                  ? `Active (${active.length})`
                  : "Earnings"}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-4 space-y-3">
        {tab === "available" &&
          available.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              canon={canon}
              actions={
                <button
                  onClick={() => handleAccept(task.id)}
                  className="w-full rounded-lg bg-runner-orange text-white font-semibold py-2 text-sm hover:opacity-90"
                >
                  Accept Task
                </button>
              }
            />
          ))}

        {tab === "active" &&
          active.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              canon={canon}
              onClick={() =>
                router.push(`/runner/active?task=${task.id}`)
              }
              actions={
                <span className="text-xs text-purple-500 font-medium">
                  Tap to continue →
                </span>
              }
            />
          ))}

        {tab === "earnings" && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-gray-200 dark:border-gray-800 p-3 text-center">
                <div className="text-2xl font-bold">{totalEarned}</div>
                <div className="text-xs text-gray-500">Credits Earned</div>
              </div>
              <div className="rounded-lg border border-gray-200 dark:border-gray-800 p-3 text-center">
                <div className="text-2xl font-bold">
                  {completed.length}
                </div>
                <div className="text-xs text-gray-500">Tasks Done</div>
              </div>
            </div>
            {completed.map((task) => {
              const tt = canon?.task_types?.find(
                (x) => x.key === task.type
              );
              return (
                <div
                  key={task.id}
                  className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-800 p-3"
                >
                  <div>
                    <div className="text-sm font-medium">
                      {tt?.label || task.type}
                    </div>
                    <div className="text-xs text-gray-500">
                      {task.completed_at
                        ? new Date(task.completed_at).toLocaleDateString()
                        : ""}
                    </div>
                  </div>
                  <div className="text-right">
                    <CoinBadge
                      coin={tt?.coin || 0}
                      usd={task.offered_fee_usd}
                      size="sm"
                    />
                    {task.rating && (
                      <div className="text-xs text-amber-500 mt-0.5">
                        {"★".repeat(task.rating)}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {tab === "available" && available.length === 0 && (
          <p className="text-center text-sm text-gray-400 py-8">
            No available tasks right now
          </p>
        )}
        {tab === "active" && active.length === 0 && (
          <p className="text-center text-sm text-gray-400 py-8">
            No active tasks
          </p>
        )}
      </div>
    </div>
  );
}
