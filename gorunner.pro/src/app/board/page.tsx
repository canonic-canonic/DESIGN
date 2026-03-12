"use client";

import { useState } from "react";
import { useCanon } from "@/hooks/useCanon";
import useSWR from "swr";
import { getRunners, getStats } from "@/lib/api";
import { RunnerProfileCard } from "@/components/RunnerProfileCard";
import { CredentialBadge } from "@/components/CredentialBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { Trophy, Users, Shield, BarChart3 } from "lucide-react";
import type { RunnerProfile, PlatformStats } from "@/lib/types";

type Tab = "leaderboard" | "governance" | "stats";

export default function CommunityBoard() {
  const [tab, setTab] = useState<Tab>("leaderboard");
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
          <p className="text-sm text-white/70">
            INTEL — leaderboard, credentials, governance transparency
          </p>

          {/* Quick stats */}
          {stats && (
            <div className="grid grid-cols-3 gap-2 mt-4">
              <div className="rounded-lg bg-white/10 p-2 text-center">
                <div className="text-lg font-bold">{stats.total_runners}</div>
                <div className="text-[9px] text-white/60">Runners</div>
              </div>
              <div className="rounded-lg bg-white/10 p-2 text-center">
                <div className="text-lg font-bold">{stats.completed_tasks}</div>
                <div className="text-[9px] text-white/60">Completed</div>
              </div>
              <div className="rounded-lg bg-white/10 p-2 text-center">
                <div className="text-lg font-bold">∩{stats.coin_minted}</div>
                <div className="text-[9px] text-white/60">Minted</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-lg mx-auto px-4 pt-4">
        <div className="flex gap-1 rounded-lg bg-gray-100 dark:bg-gray-800 p-1">
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
              className={`flex-1 flex items-center justify-center gap-1 rounded-md py-2 text-xs font-medium transition-colors ${
                tab === t.key
                  ? "bg-white dark:bg-gray-900 shadow-sm"
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
        {/* Leaderboard */}
        {tab === "leaderboard" && (
          <>
            {runners.length === 0 ? (
              <p className="text-center text-sm text-gray-400 py-8">
                No runners yet
              </p>
            ) : (
              runners.map((runner: RunnerProfile, i: number) => (
                <RunnerProfileCard
                  key={runner.id}
                  runner={runner}
                  rank={i + 1}
                />
              ))
            )}
          </>
        )}

        {/* Governance transparency */}
        {tab === "governance" && canon && (
          <div className="space-y-4">
            {/* Task types */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
              <h3 className="text-sm font-semibold flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-purple-500" />
                17 Governed Task Types
              </h3>
              <div className="space-y-2">
                {canon.task_types.map((tt) => (
                  <div
                    key={tt.key}
                    className="flex items-center justify-between py-1.5 border-b border-gray-50 dark:border-gray-800 last:border-0"
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
              <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
                <h3 className="text-sm font-semibold flex items-center gap-1.5">
                  <Shield className="h-4 w-4 text-green-500" />
                  Fiduciary Compliance — {canon.fiduciary.statute}
                </h3>
                <div className="space-y-2">
                  {canon.fiduciary.duties.map((d) => (
                    <div
                      key={d.duty}
                      className="flex items-start gap-2 text-xs"
                    >
                      <span className="text-green-500 mt-0.5">✓</span>
                      <div>
                        <span className="font-medium">{d.duty}</span>
                        <span className="text-gray-500">
                          {" "}
                          — {d.enforcement}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Credential types */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
              <h3 className="text-sm font-semibold flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-amber-500" />
                Credential Requirements
              </h3>
              <div className="flex flex-wrap gap-2">
                {[
                  "business_license",
                  "FL_468",
                  "FL_FREAB_USPAP",
                  "FL_626",
                  "FL_626_NMLS",
                  "real_estate_license",
                ].map((key) => (
                  <CredentialBadge
                    key={key}
                    credentialKey={key}
                    size="md"
                  />
                ))}
              </div>
            </div>

            {/* COIN economics */}
            {canon.coin_economics && (
              <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
                <h3 className="text-sm font-semibold">∩ Credit Economics</h3>
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-800 p-3 text-center">
                    <div className="text-xl font-bold">
                      ∩{canon.coin_economics.per_listing}
                    </div>
                    <div className="text-[10px] text-gray-500">Per Listing</div>
                  </div>
                  <div className="rounded-lg bg-gray-50 dark:bg-gray-800 p-3 text-center">
                    <div className="text-xl font-bold">
                      ∩{canon.coin_economics.full_transaction}
                    </div>
                    <div className="text-[10px] text-gray-500">
                      Full Transaction
                    </div>
                  </div>
                </div>
                <div className="space-y-1">
                  {canon.coin_economics.phases.map((p) => (
                    <div
                      key={p.name}
                      className="flex items-center justify-between text-xs"
                    >
                      <span className="text-gray-600 dark:text-gray-400">
                        {p.name}
                      </span>
                      <span className="font-medium">∩{p.coin}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Platform stats */}
        {tab === "stats" && stats && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Total Tasks", value: stats.total_tasks },
                { label: "Active", value: stats.active_tasks },
                { label: "Completed", value: stats.completed_tasks },
                { label: "Runners", value: stats.total_runners },
              ].map((s) => (
                <div
                  key={s.label}
                  className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 text-center"
                >
                  <div className="text-2xl font-bold">{s.value}</div>
                  <div className="text-xs text-gray-500">{s.label}</div>
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 text-center">
              <div className="text-3xl font-bold">∩{stats.coin_minted}</div>
              <div className="text-xs text-gray-500">
                Total ∩ Credits Minted
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
