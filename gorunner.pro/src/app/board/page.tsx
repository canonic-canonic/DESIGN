"use client";

import { useState } from "react";
import { useCanon } from "@/hooks/useCanon";
import { formatCompact, formatNumber } from "@/lib/utils";
import useSWR from "swr";
import { getRunners, getStats } from "@/lib/api";
import { RunnerProfileCard } from "@/components/RunnerProfileCard";
import { CredentialBadge } from "@/components/CredentialBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { Trophy, Shield, BarChart3, TrendingUp } from "lucide-react";
import type { RunnerProfile, PlatformStats } from "@/lib/types";

type Tab = "leaderboard" | "governance" | "stats";

export default function CommunityBoard() {
  const [tab, setTab] = useState<Tab>("leaderboard");
  const [expandedRunner, setExpandedRunner] = useState<string | null>(null);
  const { canon } = useCanon();

  const { data: runnersData } = useSWR("board:runners", () => getRunners(), {
    revalidateOnFocus: false,
    dedupingInterval: 30_000,
  });
  const { data: statsData } = useSWR("board:stats", () => getStats(), {
    revalidateOnFocus: false,
    dedupingInterval: 30_000,
  });

  const runners = (runnersData?.runners || []).sort(
    (a: RunnerProfile, b: RunnerProfile) =>
      b.completed_tasks - a.completed_tasks
  );
  const stats = statsData as PlatformStats | undefined;

  return (
    <div className="min-h-screen pb-20">
      {/* Header */}
      <div className="bg-gradient-to-br from-purple-600 via-indigo-600 to-blue-600 px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <div className="flex items-center gap-2 mb-1">
            <Trophy className="h-5 w-5 text-yellow-300" />
            <h1 className="text-xl font-bold">Community Board</h1>
          </div>
          <p className="text-xs text-white/60">
            INTEL — leaderboard, credentials, governance transparency
          </p>

          {/* Hero stats — big and bold */}
          {stats && (
            <div className="grid grid-cols-3 gap-2 mt-4">
              {[
                { value: stats.total_runners, label: "Runners" },
                { value: stats.completed_tasks, label: "Completed" },
                { value: stats.coin_minted, label: "∩ Minted", prefix: "∩" },
              ].map((s) => (
                <div key={s.label} className="rounded-xl bg-white/10 p-3 text-center">
                  <div className="text-2xl font-black">
                    {s.prefix || ""}{formatCompact(s.value)}
                  </div>
                  <div className="text-[9px] text-white/50 uppercase">{s.label}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-lg mx-auto px-4 pt-4">
        <div className="flex gap-1 rounded-xl bg-gray-100 dark:bg-gray-800 p-1">
          {(
            [
              { key: "leaderboard", icon: Trophy, label: "Leaderboard" },
              { key: "governance", icon: Shield, label: "Governance" },
              { key: "stats", icon: BarChart3, label: "Stats" },
            ] as const
          ).map((t) => (
            <button
              key={t.key}
              type="button"
              onClick={() => setTab(t.key)}
              className={`flex-1 flex items-center justify-center gap-1 rounded-lg py-2.5 text-xs font-medium transition-all ${
                tab === t.key
                  ? "bg-white dark:bg-gray-900 shadow-sm scale-[1.02]"
                  : "text-gray-500 hover:text-gray-700"
              }`}
            >
              <t.icon className="h-3.5 w-3.5" />
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-4 space-y-3">
        {/* Leaderboard — interactive runner cards */}
        {tab === "leaderboard" && (
          <>
            {runners.length === 0 ? (
              <div className="text-center py-12 space-y-3">
                <div className="text-4xl">🏆</div>
                <p className="text-sm text-gray-500">No runners yet</p>
                <p className="text-xs text-gray-400">
                  Runners will appear here once they complete onboarding
                </p>
              </div>
            ) : (
              runners.map((runner: RunnerProfile, i: number) => (
                <div
                  key={runner.id}
                  onClick={() =>
                    setExpandedRunner(
                      expandedRunner === runner.id ? null : runner.id
                    )
                  }
                  className="cursor-pointer transition-all hover:scale-[1.01]"
                >
                  <RunnerProfileCard
                    runner={runner}
                    rank={i + 1}
                  />
                </div>
              ))
            )}
          </>
        )}

        {/* Governance transparency */}
        {tab === "governance" && canon && (
          <div className="space-y-4">
            {/* Task types */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
              <div className="bg-purple-50 dark:bg-purple-900/10 px-4 py-3 flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-purple-500" />
                <h3 className="text-sm font-semibold">17 Governed Task Types</h3>
              </div>
              <div className="divide-y divide-gray-100 dark:divide-gray-800">
                {canon.task_types.map((tt) => (
                  <div
                    key={tt.key}
                    className="flex items-center justify-between px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm">{tt.label}</span>
                      {tt.credential_key && (
                        <CredentialBadge credentialKey={tt.credential_key} />
                      )}
                    </div>
                    <CoinBadge coin={tt.coin} size="sm" />
                  </div>
                ))}
              </div>
            </div>

            {/* Fiduciary duties */}
            {canon.fiduciary && (
              <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
                <div className="bg-green-50 dark:bg-green-900/10 px-4 py-3 flex items-center gap-1.5">
                  <Shield className="h-4 w-4 text-green-500" />
                  <h3 className="text-sm font-semibold">Fiduciary Compliance — {canon.fiduciary.statute}</h3>
                </div>
                <div className="p-4 space-y-2">
                  {canon.fiduciary.duties.map((d) => (
                    <div
                      key={d.duty}
                      className="flex items-start gap-2 text-xs"
                    >
                      <span className="text-green-500 mt-0.5">✓</span>
                      <div>
                        <span className="font-medium">{d.duty}</span>
                        <span className="text-gray-500"> — {d.enforcement}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Credential types */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
              <div className="bg-amber-50 dark:bg-amber-900/10 px-4 py-3 flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-amber-500" />
                <h3 className="text-sm font-semibold">Credential Requirements</h3>
              </div>
              <div className="p-4 flex flex-wrap gap-2">
                {[
                  "business_license",
                  "FL_468",
                  "FL_FREAB_USPAP",
                  "FL_626",
                  "FL_626_NMLS",
                  "real_estate_license",
                ].map((key) => (
                  <CredentialBadge key={key} credentialKey={key} size="md" />
                ))}
              </div>
            </div>

            {/* COIN economics */}
            {canon.coin_economics && (
              <div className="rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
                <div className="bg-gray-50 dark:bg-gray-800 px-4 py-3">
                  <h3 className="text-sm font-semibold">∩ Credit Economics</h3>
                </div>
                <div className="p-4 space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded-xl bg-gradient-pro p-4 text-center text-white">
                      <div className="text-2xl font-black">∩{canon.coin_economics.per_listing}</div>
                      <div className="text-[10px] text-white/70">Per Listing</div>
                    </div>
                    <div className="rounded-xl bg-gradient-runner p-4 text-center text-white">
                      <div className="text-2xl font-black">∩{canon.coin_economics.full_transaction}</div>
                      <div className="text-[10px] text-white/70">Full Transaction</div>
                    </div>
                  </div>
                  <div className="space-y-1">
                    {canon.coin_economics.phases.map((p) => (
                      <div
                        key={p.name}
                        className="flex items-center justify-between text-xs py-1"
                      >
                        <span className="text-gray-600 dark:text-gray-400">{p.name}</span>
                        <span className="font-bold">∩{p.coin}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Platform stats — big bold numbers */}
        {tab === "stats" && stats && (
          <div className="space-y-4">
            {/* Hero minted */}
            <div className="rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 p-6 text-center text-white">
              <TrendingUp className="h-6 w-6 mx-auto mb-2 text-white/70" />
              <div className="text-4xl font-black">∩{formatCompact(stats.coin_minted)}</div>
              <div className="text-xs text-white/60 mt-1">Total ∩ Credits Minted</div>
              <div className="text-[10px] text-white/40 mt-0.5">{formatNumber(stats.coin_minted)} credits</div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Total Tasks", value: stats.total_tasks, color: "border-blue-200" },
                { label: "Active Now", value: stats.active_tasks, color: "border-orange-200" },
                { label: "Completed", value: stats.completed_tasks, color: "border-green-200" },
                { label: "Runners", value: stats.total_runners, color: "border-purple-200" },
              ].map((s) => (
                <div
                  key={s.label}
                  className={`rounded-xl border-2 ${s.color} dark:border-gray-800 p-4 text-center hover:shadow-md transition-shadow cursor-default`}
                >
                  <div className="text-3xl font-black">{formatCompact(s.value)}</div>
                  <div className="text-[10px] text-gray-500 font-medium uppercase">{s.label}</div>
                  <div className="text-[9px] text-gray-400">{formatNumber(s.value)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
