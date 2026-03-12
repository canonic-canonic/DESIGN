"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { CoinBadge, CoinBalance } from "@/components/CoinBadge";
import { useBalance, refreshBalance } from "@/hooks/useBalance";
import { checkout } from "@/lib/api";
import { toast } from "sonner";
import { ArrowLeft, TrendingUp, ShoppingCart } from "lucide-react";

export default function EarningsPage() {
  const router = useRouter();
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { tasks } = useTasks(identity?.userId, "Runner");
  const { balance: balanceValue } = useBalance(identity?.userId);

  const completed = tasks.filter(
    (t) =>
      t.assigned_runner_id === identity?.userId &&
      ["completed", "rated"].includes(t.status)
  );

  const totalEarned = completed.reduce((sum, t) => {
    const tt = canon?.task_types?.find((x) => x.key === t.type);
    return sum + (tt?.coin || 0);
  }, 0);

  async function handleCheckout() {
    if (!identity) return;
    try {
      const { url } = await checkout(identity.userId, 100);
      window.location.href = url;
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Checkout failed"
      );
    }
  }

  return (
    <div className="min-h-screen pb-20">
      <div className="bg-gradient-runner px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <button
            onClick={() => router.push("/runner")}
            className="flex items-center gap-1 text-sm text-white/70 mb-2"
          >
            <ArrowLeft className="h-4 w-4" /> Dashboard
          </button>
          <h1 className="text-xl font-bold">Earnings</h1>

          <div className="grid grid-cols-2 gap-3 mt-4">
            <div className="rounded-lg bg-white/10 p-4 text-center">
              <div className="text-3xl font-bold">
                {balanceValue ?? 0}
              </div>
              <div className="text-xs text-white/70">∩ Credit Balance</div>
            </div>
            <div className="rounded-lg bg-white/10 p-4 text-center">
              <div className="text-3xl font-bold">{totalEarned}</div>
              <div className="text-xs text-white/70">Credits Earned</div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-6 space-y-6">
        {/* COIN Economics phases from CANON.json */}
        <div>
          <h2 className="text-sm font-semibold text-gray-500 mb-3 flex items-center gap-1">
            <TrendingUp className="h-4 w-4" /> Credits per Listing Phase
          </h2>
          <div className="space-y-2">
            {(canon?.coin_economics?.phases || []).map((phase) => (
              <div
                key={phase.name}
                className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-800 p-3"
              >
                <div>
                  <div className="text-sm font-medium">{phase.name}</div>
                  <div className="text-xs text-gray-500">{phase.tasks}</div>
                </div>
                <CoinBadge coin={phase.coin} size="sm" />
              </div>
            ))}
          </div>
        </div>

        {/* Task history */}
        <div>
          <h2 className="text-sm font-semibold text-gray-500 mb-3">
            Completed Tasks ({completed.length})
          </h2>
          <div className="space-y-2">
            {completed.map((task) => {
              const tt = canon?.task_types?.find((x) => x.key === task.type);
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
                      {task.rating && ` · ${"★".repeat(task.rating)}`}
                    </div>
                  </div>
                  <CoinBadge
                    coin={tt?.coin || 0}
                    usd={task.offered_fee_usd}
                    size="sm"
                  />
                </div>
              );
            })}
          </div>
        </div>

        {/* Buy COIN */}
        <button
          onClick={handleCheckout}
          className="w-full flex items-center justify-center gap-2 rounded-xl border-2 border-amber-400 text-amber-600 font-semibold py-3"
        >
          <ShoppingCart className="h-5 w-5" />
          Purchase Credits via Stripe
        </button>
      </div>
    </div>
  );
}
