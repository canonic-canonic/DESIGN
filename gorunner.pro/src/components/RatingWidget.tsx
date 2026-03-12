"use client";

import { useState } from "react";
import { taskAction } from "@/lib/api";
import { refreshBalance } from "@/hooks/useBalance";
import { toast } from "sonner";
import { Star, X } from "lucide-react";

interface RatingWidgetProps {
  taskId: string;
  userId?: string;
  balance?: number | null;
  onDone: () => void;
}

export function RatingWidget({ taskId, userId, balance, onDone }: RatingWidgetProps) {
  const [rating, setRating] = useState(5);
  const [tipCoin, setTipCoin] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    setSubmitting(true);
    try {
      await taskAction(taskId, "rate", {
        rating,
        tip_coin: tipCoin,
      });
      if (userId) refreshBalance(userId);
      toast.success(
        tipCoin > 0
          ? `Rated! ∩${tipCoin} Credits tip sent`
          : "Thanks for rating!"
      );
      onDone();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Rating failed"
      );
    } finally {
      setSubmitting(false);
    }
  }

  // Disable tip options that exceed balance
  function canAffordTip(amount: number): boolean {
    if (amount === 0) return true;
    if (balance === null || balance === undefined) return true; // unknown balance — let server validate
    return balance >= amount;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/50">
      <div className="animate-slide-up w-full max-w-lg rounded-t-2xl bg-white dark:bg-gray-900 p-6 space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold">Rate This Task</h3>
          <button onClick={onDone} className="text-gray-400">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Stars */}
        <div className="flex justify-center gap-2">
          {[1, 2, 3, 4, 5].map((n) => (
            <button key={n} onClick={() => setRating(n)}>
              <Star
                className={`h-10 w-10 transition-colors ${
                  n <= rating
                    ? "fill-amber-400 text-amber-400"
                    : "text-gray-300"
                }`}
              />
            </button>
          ))}
        </div>

        {/* Tip */}
        <div>
          <label className="text-sm font-semibold text-gray-500 mb-2 block">
            Add a Credit tip (optional)
          </label>
          <div className="flex gap-2">
            {[0, 1, 3, 5].map((t) => (
              <button
                key={t}
                onClick={() => canAffordTip(t) && setTipCoin(t)}
                disabled={!canAffordTip(t)}
                className={`flex-1 rounded-lg border py-2 text-sm font-medium transition-colors ${
                  tipCoin === t
                    ? "border-amber-500 bg-amber-50 dark:bg-amber-900/20 text-amber-700"
                    : !canAffordTip(t)
                      ? "border-gray-100 text-gray-300 cursor-not-allowed"
                      : "border-gray-200 dark:border-gray-800"
                }`}
              >
                {t === 0 ? "None" : `∩${t}`}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={handleSubmit}
          disabled={submitting}
          className="w-full rounded-xl bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold py-3 disabled:opacity-50"
        >
          {submitting ? "Submitting..." : "Submit Rating"}
        </button>
      </div>
    </div>
  );
}
