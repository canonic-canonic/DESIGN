"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { TaskCard } from "@/components/TaskCard";
import { QuickActions } from "@/components/QuickActions";
import { CoinBalance } from "@/components/CoinBadge";
import { useBalance } from "@/hooks/useBalance";
import { Plus, CheckCircle, Clock, List } from "lucide-react";

export default function ProDashboard() {
  const router = useRouter();
  const { identity, user } = useAuth();
  const { canon } = useCanon();
  const { tasks, loading } = useTasks(identity?.userId, "Requester");
  const { balance } = useBalance(identity?.userId);

  const activeTasks = tasks.filter(
    (t) => !["completed", "rated", "cancelled"].includes(t.status)
  );
  const completedTasks = tasks.filter((t) =>
    ["completed", "rated"].includes(t.status)
  );

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="bg-gradient-pro px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm text-white/70">Welcome back</p>
              <h1 className="text-xl font-bold">
                {user?.name || user?.user || "Pro"}
              </h1>
            </div>
            <CoinBalance
              balance={balance ?? 0}
              className="bg-white/10 text-amber-300"
            />
          </div>

          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-2">
            {[
              { icon: List, value: tasks.length, label: "Total" },
              { icon: Clock, value: activeTasks.length, label: "Active" },
              {
                icon: CheckCircle,
                value: completedTasks.length,
                label: "Done",
              },
            ].map(({ icon: Icon, value, label }) => (
              <div
                key={label}
                className="rounded-lg bg-white/10 p-3 text-center"
              >
                <Icon className="h-4 w-4 mx-auto mb-1 text-white/70" />
                <div className="text-lg font-bold">{value}</div>
                <div className="text-[10px] text-white/60">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-6 space-y-6">
        {/* Post task CTA */}
        <button
          onClick={() => router.push("/pro/create")}
          className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-runner text-white font-semibold py-3 hover:opacity-90 transition-opacity"
        >
          <Plus className="h-5 w-5" />
          Post a Task
        </button>

        {/* Quick actions from CANON.json */}
        {canon?.quick_actions && (
          <div>
            <h2 className="text-sm font-semibold text-gray-500 mb-2">
              Quick Actions
            </h2>
            <QuickActions
              actions={canon.quick_actions}
              onSelect={(a) =>
                router.push(`/pro/create?type=${a.key}`)
              }
            />
          </div>
        )}

        {/* Active tasks */}
        {activeTasks.length > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-gray-500 mb-2">
              Active Tasks
            </h2>
            <div className="space-y-3">
              {activeTasks.map((task) => (
                <TaskCard
                  key={task.id}
                  task={task}
                  canon={canon}
                  onClick={() => router.push(`/tasks/${task.id}`)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Completed */}
        {completedTasks.length > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-gray-500 mb-2">
              Completed
            </h2>
            <div className="space-y-3">
              {completedTasks.slice(0, 5).map((task) => (
                <TaskCard
                  key={task.id}
                  task={task}
                  canon={canon}
                  onClick={() => router.push(`/tasks/${task.id}`)}
                />
              ))}
            </div>
          </div>
        )}

        {!loading && tasks.length === 0 && (
          <div className="text-center py-12 text-gray-400">
            <p className="text-sm">No tasks yet. Post your first one!</p>
          </div>
        )}
      </div>
    </div>
  );
}
