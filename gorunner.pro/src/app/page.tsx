"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { TASK_ICONS } from "@/lib/types";
import { CoinBadge } from "@/components/CoinBadge";
import { Zap, Shield, BarChart3, Users, ArrowRight } from "lucide-react";

export default function ShopLanding() {
  const { user, identity, loading, login } = useAuth();
  const { canon } = useCanon();
  const router = useRouter();

  // Redirect authenticated users to their dashboard
  useEffect(() => {
    if (!loading && identity) {
      const role = identity.role;
      if (role === "Runner") router.replace("/runner");
      else if (role === "Ops") router.replace("/ops");
      else router.replace("/pro");
    }
  }, [loading, identity, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="bg-gradient-hero text-white px-4 py-16 text-center">
        <div className="max-w-lg mx-auto space-y-6">
          <h1 className="text-3xl font-bold leading-tight">
            Post a task.
            <br />
            A pro handles it.
            <br />
            <span className="text-amber-400">You earn ∩ Credits.</span>
          </h1>
          <p className="text-gray-300 text-sm">
            {canon?.axiom ||
              "The operations partner every Lake Nona realtor wishes they had."}
          </p>
          <button
            onClick={login}
            className="inline-flex items-center gap-2 bg-white text-gray-900 font-semibold rounded-full px-6 py-3 hover:bg-gray-100 transition-colors"
          >
            Get Started with GitHub
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </section>

      {/* Stats */}
      <section className="px-4 py-8 -mt-6">
        <div className="max-w-lg mx-auto grid grid-cols-3 gap-3">
          {[
            {
              value: canon?.task_types?.length || 17,
              label: "Task Types",
              icon: Zap,
            },
            {
              value: canon?.coin_economics?.per_listing || 161,
              label: "Credits / Listing",
              icon: BarChart3,
            },
            {
              value: canon?.fiduciary?.duties?.length || 6,
              label: "Fiduciary Duties",
              icon: Shield,
            },
          ].map(({ value, label, icon: Icon }) => (
            <div
              key={label}
              className="rounded-xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 p-3 text-center shadow-sm"
            >
              <Icon className="h-5 w-5 mx-auto text-purple-500 mb-1" />
              <div className="text-xl font-bold">{value}</div>
              <div className="text-[10px] text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Task Types */}
      <section className="px-4 py-6">
        <div className="max-w-lg mx-auto">
          <h2 className="text-lg font-bold mb-4">Task Types</h2>
          <div className="grid grid-cols-2 gap-2">
            {(canon?.task_types || []).map((t) => (
              <div
                key={t.key}
                className="flex items-center gap-2 rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-3"
              >
                <span className="text-lg">{TASK_ICONS[t.key] || "📋"}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">
                    {t.label}
                  </div>
                  <CoinBadge coin={t.coin} size="sm" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* COIN Economics */}
      <section className="px-4 py-6 bg-gray-100 dark:bg-gray-900">
        <div className="max-w-lg mx-auto">
          <h2 className="text-lg font-bold mb-4">Credit Economics</h2>
          <div className="space-y-2">
            {(canon?.coin_economics?.phases || []).map((phase) => (
              <div
                key={phase.name}
                className="flex items-center justify-between rounded-lg bg-white dark:bg-gray-800 p-3"
              >
                <div>
                  <div className="text-sm font-semibold">{phase.name}</div>
                  <div className="text-xs text-gray-500">{phase.tasks}</div>
                </div>
                <CoinBadge coin={phase.coin} size="sm" />
              </div>
            ))}
            <div className="flex items-center justify-between rounded-lg bg-gradient-pro p-3 text-white">
              <span className="font-bold">Total per listing</span>
              <span className="font-bold text-lg">
                ∩{canon?.coin_economics?.per_listing || 161} Credits
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Fiduciary Compliance */}
      <section className="px-4 py-6">
        <div className="max-w-lg mx-auto">
          <h2 className="text-lg font-bold mb-1">Fiduciary Compliance</h2>
          <p className="text-xs text-gray-500 mb-4">
            FL 475.278 — Every duty enforced by governance
          </p>
          <div className="space-y-2">
            {(canon?.fiduciary?.duties || []).map((d) => (
              <div
                key={d.duty}
                className="rounded-lg border border-gray-200 dark:border-gray-800 p-3"
              >
                <div className="text-sm font-semibold text-purple-600">
                  {d.duty}
                </div>
                <div className="text-xs text-gray-500">{d.enforcement}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-4 py-12 text-center">
        <button
          onClick={login}
          className="inline-flex items-center gap-2 bg-gradient-pro text-white font-semibold rounded-full px-8 py-3 hover:opacity-90 transition-opacity"
        >
          Start Posting Tasks
          <ArrowRight className="h-4 w-4" />
        </button>
        <p className="text-xs text-gray-500 mt-3">
          Powered by CANONIC — Governance Intelligence
        </p>
      </section>
    </div>
  );
}
