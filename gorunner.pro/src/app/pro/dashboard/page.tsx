"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { useBalance } from "@/hooks/useBalance";
import { formatCompact, formatNumber } from "@/lib/utils";
import useSWR from "swr";
import { getStats, getRunners } from "@/lib/api";
import { TaskCard } from "@/components/TaskCard";
import { CoinBadge } from "@/components/CoinBadge";
import type { PlatformStats, RunnerProfile } from "@/lib/types";
import {
  ArrowLeft,
  TrendingUp,
  Users,
  Zap,
  Shield,
  Clock,
  CheckCircle,
  AlertCircle,
  ArrowUpRight,
} from "lucide-react";

export default function ProDashboardPage() {
  const router = useRouter();
  const { identity, user } = useAuth();
  const { canon } = useCanon();
  const { tasks } = useTasks(identity?.userId, "Requester");
  const { balance } = useBalance(identity?.userId);

  const { data: statsData } = useSWR("dash:stats", () => getStats(), {
    revalidateOnFocus: false,
    dedupingInterval: 30_000,
  });
  const { data: runnersData } = useSWR("dash:runners", () => getRunners(), {
    revalidateOnFocus: false,
    dedupingInterval: 30_000,
  });

  const stats = statsData as PlatformStats | undefined;
  const runners = (runnersData?.runners || []) as RunnerProfile[];

  const activeTasks = tasks.filter(
    (t) => !["completed", "rated", "cancelled"].includes(t.status)
  );
  const completedTasks = tasks.filter((t) =>
    ["completed", "rated"].includes(t.status)
  );
  const postedTasks = tasks.filter((t) => t.status === "posted");

  const bal = balance ?? 0;

  return (
    <div className="min-h-screen pb-20">
      {/* Hero header with big bold balance */}
      <div className="bg-gradient-pro px-4 pt-12 pb-8 text-white">
        <div className="max-w-lg mx-auto">
          <button
            type="button"
            onClick={() => router.push("/pro")}
            className="flex items-center gap-1 text-xs text-white/60 mb-4"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Chat
          </button>

          <p className="text-xs text-white/60 uppercase tracking-wider mb-1">
            ∩ Credit Balance
          </p>
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-5xl font-black tracking-tight">
              {formatCompact(bal)}
            </span>
            <span className="text-lg text-amber-300 font-semibold">∩</span>
          </div>
          <p className="text-xs text-white/50">
            {formatNumber(bal)} credits · {user?.name || "Pro"}
          </p>

          {/* My task metrics */}
          <div className="grid grid-cols-4 gap-2 mt-6">
            {[
              { icon: Zap, value: tasks.length, label: "Total", color: "text-blue-300" },
              { icon: AlertCircle, value: postedTasks.length, label: "Posted", color: "text-yellow-300" },
              { icon: Clock, value: activeTasks.length, label: "Active", color: "text-orange-300" },
              { icon: CheckCircle, value: completedTasks.length, label: "Done", color: "text-green-300" },
            ].map(({ icon: Icon, value, label, color }) => (
              <div
                key={label}
                onClick={() => router.push("/pro")}
                className="rounded-xl bg-white/10 p-3 text-center cursor-pointer hover:bg-white/20 transition-colors"
              >
                <Icon className={`h-4 w-4 mx-auto mb-1 ${color}`} />
                <div className="text-xl font-bold">{value}</div>
                <div className="text-[9px] text-white/50 uppercase">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-6 space-y-6">
        {/* Platform overview */}
        {stats && (
          <div>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5" />
              Platform Overview
            </h2>
            <div className="grid grid-cols-3 gap-3">
              {[
                { value: stats.total_tasks, label: "Total Tasks", sub: `${stats.active_tasks} active` },
                { value: stats.total_runners, label: "Runners", sub: `${stats.completed_tasks} completed` },
                { value: stats.coin_minted, label: "∩ Minted", sub: "platform total" },
              ].map((s) => (
                <div
                  key={s.label}
                  onClick={() => router.push("/board")}
                  className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 text-center cursor-pointer hover:border-purple-300 hover:shadow-md transition-all"
                >
                  <div className="text-2xl font-bold">{formatCompact(s.value)}</div>
                  <div className="text-[10px] text-gray-500 font-medium">{s.label}</div>
                  <div className="text-[9px] text-gray-400 mt-0.5">{s.sub}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Active runners */}
        {runners.length > 0 && (
          <div>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Users className="h-3.5 w-3.5" />
              Active Runners ({runners.length})
              <button
                type="button"
                onClick={() => router.push("/board")}
                className="ml-auto text-purple-500 flex items-center gap-0.5"
              >
                View all <ArrowUpRight className="h-3 w-3" />
              </button>
            </h2>
            <div className="flex gap-3 overflow-x-auto pb-1 scrollbar-hide">
              {runners.slice(0, 6).map((r, i) => {
                const name = r.profile
                  ? `${r.profile.first_name} ${r.profile.last_name[0]}.`
                  : `Runner ${i + 1}`;
                const initials = r.profile
                  ? `${r.profile.first_name[0]}${r.profile.last_name[0]}`
                  : "R";
                return (
                  <div
                    key={r.id}
                    onClick={() => router.push("/board")}
                    className="flex-shrink-0 w-20 text-center cursor-pointer group"
                  >
                    <div className="relative mx-auto mb-1">
                      <div className="h-14 w-14 rounded-full bg-gradient-runner flex items-center justify-center text-white font-bold text-sm group-hover:scale-110 transition-transform">
                        {initials}
                      </div>
                      {r.available && (
                        <span className="absolute bottom-0 right-0 h-3.5 w-3.5 rounded-full bg-green-400 border-2 border-white dark:border-gray-950" />
                      )}
                    </div>
                    <div className="text-[11px] font-medium truncate">{name}</div>
                    <div className="text-[10px] text-amber-500">
                      {"★".repeat(Math.round(r.rating_avg))}
                    </div>
                    <div className="text-[9px] text-gray-400">{r.completed_tasks} tasks</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ∩ Credit Economics */}
        {canon?.coin_economics && (
          <div>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              ∩ Credit Economics
            </h2>
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
              {canon.coin_economics.phases.map((p, i) => (
                <div
                  key={p.name}
                  className={`flex items-center justify-between px-4 py-3 ${
                    i < canon.coin_economics.phases.length - 1
                      ? "border-b border-gray-100 dark:border-gray-800"
                      : ""
                  }`}
                >
                  <div>
                    <div className="text-sm font-medium">{p.name}</div>
                    <div className="text-xs text-gray-400">{p.tasks}</div>
                  </div>
                  <CoinBadge coin={p.coin} size="sm" />
                </div>
              ))}
              <div className="bg-gradient-pro px-4 py-3 flex items-center justify-between text-white">
                <span className="font-bold text-sm">Full Listing</span>
                <span className="text-lg font-black">∩{canon.coin_economics.per_listing}</span>
              </div>
            </div>
          </div>
        )}

        {/* Recent tasks */}
        {tasks.length > 0 && (
          <div>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
              Recent Tasks
            </h2>
            <div className="space-y-3">
              {tasks.slice(0, 5).map((task) => (
                <TaskCard
                  key={task.id}
                  task={task}
                  canon={canon}
                  onClick={() => router.push(`/tasks?id=${task.id}`)}
                />
              ))}
            </div>
          </div>
        )}

        {tasks.length === 0 && (
          <div className="text-center py-12 space-y-3">
            <div className="text-4xl">📋</div>
            <p className="text-sm text-gray-500">No tasks yet</p>
            <p className="text-xs text-gray-400">
              Tap &quot;Post a Task&quot; or use a quick action pill in chat to get started
            </p>
            <button
              type="button"
              onClick={() => router.push("/pro/create")}
              className="inline-flex items-center gap-2 rounded-full bg-gradient-runner text-white font-semibold px-6 py-2.5 text-sm"
            >
              <Zap className="h-4 w-4" />
              Post Your First Task
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
