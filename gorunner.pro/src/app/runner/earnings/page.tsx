"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { CoinBadge, CoinBalance } from "@/components/CoinBadge";
import { useBalance, refreshBalance } from "@/hooks/useBalance";
import { checkout, payoutSetup, payoutStatus, payoutCashout } from "@/lib/api";
import { toast } from "sonner";
import { useState, useEffect } from "react";
import { ArrowLeft, TrendingUp, ShoppingCart, Banknote } from "lucide-react";

export default function EarningsPage() {
  const router = useRouter();
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { tasks } = useTasks(identity?.userId, "Runner");
  const { balance: balanceValue } = useBalance(identity?.userId);

  const [connectStatus, setConnectStatus] = useState<{
    connected: boolean;
    payouts_enabled?: boolean;
    details_submitted?: boolean;
  }>({ connected: false });
  const [cashoutAmount, setCashoutAmount] = useState("");
  const [cashoutLoading, setCashoutLoading] = useState(false);

  useEffect(() => {
    if (identity?.userId) {
      payoutStatus(identity.userId).then(setConnectStatus).catch(() => {});
    }
  }, [identity?.userId]);

  async function handlePayoutSetup() {
    if (!identity) return;
    try {
      const { url } = await payoutSetup(identity.userId);
      window.location.href = url;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Payout setup failed");
    }
  }

  async function handleCashout() {
    if (!identity) return;
    const amount = parseInt(cashoutAmount, 10);
    if (!amount || amount < 10) {
      toast.error("Minimum cashout is 10 credits");
      return;
    }
    setCashoutLoading(true);
    try {
      const result = await payoutCashout(identity.userId, amount);
      toast.success(`Cashed out ∩${result.amount_coin} (fee ∩${result.fee_coin})`);
      setCashoutAmount("");
      refreshBalance(identity.userId);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Cashout failed");
    } finally {
      setCashoutLoading(false);
    }
  }

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

        {/* Cashout — GOV: COIN/CANON.md Cashout, WALLET/WALLET.md SETTLE Constraints */}
        <div className="rounded-xl border-2 border-green-400 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-green-700 flex items-center gap-1">
            <Banknote className="h-4 w-4" /> Cash Out to Bank
          </h2>
          {!connectStatus.connected ? (
            <button
              onClick={handlePayoutSetup}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-green-600 text-white font-semibold py-3"
            >
              Set Up Cashout via Stripe
            </button>
          ) : !connectStatus.payouts_enabled ? (
            <div className="text-center py-3">
              <p className="text-sm text-gray-500">
                {connectStatus.details_submitted
                  ? "Stripe is verifying your account. Check back soon."
                  : "Stripe onboarding incomplete."}
              </p>
              <button
                onClick={handlePayoutSetup}
                className="mt-2 text-sm text-green-600 underline"
              >
                {connectStatus.details_submitted ? "Check Status" : "Continue Setup"}
              </button>
            </div>
          ) : (
            <>
              <div className="flex gap-2">
                <input
                  type="number"
                  min={10}
                  placeholder="Amount (min 10)"
                  value={cashoutAmount}
                  onChange={(e) => setCashoutAmount(e.target.value)}
                  className="flex-1 rounded-lg border border-gray-300 dark:border-gray-700 px-3 py-2 text-sm"
                />
                <button
                  onClick={handleCashout}
                  disabled={cashoutLoading}
                  className="rounded-lg bg-green-600 text-white font-semibold px-4 py-2 text-sm disabled:opacity-50"
                >
                  {cashoutLoading ? "..." : "Cash Out"}
                </button>
              </div>
              {cashoutAmount && parseInt(cashoutAmount, 10) >= 10 && (
                <p className="text-xs text-gray-500">
                  ∩{parseInt(cashoutAmount, 10)} − 5% fee (∩
                  {Math.ceil(parseInt(cashoutAmount, 10) * 0.05)}) = $
                  {((parseInt(cashoutAmount, 10)) / 100).toFixed(2)} to your bank
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
