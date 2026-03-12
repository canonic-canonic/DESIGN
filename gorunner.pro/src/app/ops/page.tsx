"use client";

import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { TaskCard } from "@/components/TaskCard";
import { assignTask, getStats, getRunners } from "@/lib/api";
import { toast } from "sonner";
import useSWR from "swr";
import {
  BarChart3,
  Users,
  CheckCircle,
  Clock,
  Coins,
} from "lucide-react";

export default function OpsDashboard() {
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { tasks, refresh } = useTasks(identity?.userId, "Ops");

  const { data: stats } = useSWR("stats", getStats);
  const { data: runnersData } = useSWR("runners", getRunners);

  const runners = runnersData?.runners || [];

  async function handleAssign(taskId: string, runnerId: string) {
    try {
      await assignTask(taskId, runnerId);
      toast.success("Runner assigned!");
      refresh();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Assignment failed"
      );
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="bg-gradient-ops px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <h1 className="text-xl font-bold">Ops Dashboard</h1>
          <p className="text-sm text-white/70">Platform management</p>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-6 space-y-6">
        {/* Stats grid */}
        <div className="grid grid-cols-3 gap-2">
          {[
            {
              icon: BarChart3,
              value: stats?.total_tasks ?? 0,
              label: "Tasks",
            },
            {
              icon: Clock,
              value: stats?.active_tasks ?? 0,
              label: "Active",
            },
            {
              icon: CheckCircle,
              value: stats?.completed_tasks ?? 0,
              label: "Done",
            },
            {
              icon: Coins,
              value: stats?.coin_minted ?? 0,
              label: "Credits Minted",
            },
            {
              icon: Users,
              value: stats?.total_runners ?? 0,
              label: "Runners",
            },
            {
              icon: Users,
              value: runners.filter((r) => r.available).length,
              label: "Available",
            },
          ].map(({ icon: Icon, value, label }) => (
            <div
              key={label}
              className="rounded-lg border border-gray-200 dark:border-gray-800 p-3 text-center"
            >
              <Icon className="h-4 w-4 mx-auto mb-1 text-gray-400" />
              <div className="text-lg font-bold">{value}</div>
              <div className="text-[10px] text-gray-500">{label}</div>
            </div>
          ))}
        </div>

        {/* Runner list */}
        <div>
          <h2 className="text-sm font-semibold text-gray-500 mb-2">
            Runners
          </h2>
          <div className="space-y-2">
            {runners.map((r) => (
              <div
                key={r.id}
                className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-800 p-3"
              >
                <div>
                  <div className="text-sm font-medium">
                    {r.profile?.first_name || "Runner"}{" "}
                    {r.profile?.last_name || r.id.slice(0, 8)}
                  </div>
                  <div className="text-xs text-gray-500">
                    {r.completed_tasks ?? 0} tasks · ★{" "}
                    {(r.rating_avg ?? 0).toFixed(1)}
                  </div>
                </div>
                <span
                  className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    r.available
                      ? "bg-green-100 text-green-700"
                      : "bg-gray-100 text-gray-500"
                  }`}
                >
                  {r.available ? "Available" : "Busy"}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent tasks */}
        <div>
          <h2 className="text-sm font-semibold text-gray-500 mb-2">
            Recent Tasks
          </h2>
          <div className="space-y-3">
            {tasks.slice(0, 10).map((task) => (
              <TaskCard key={task.id} task={task} canon={canon} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
