"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { createTask } from "@/lib/api";
import { TASK_ICONS } from "@/lib/types";
import { CoinBadge } from "@/components/CoinBadge";
import { toast } from "sonner";
import { ArrowLeft, MapPin, Clock, DollarSign, FileText } from "lucide-react";

export default function CreateTaskPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center"><div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" /></div>}>
      <CreateTask />
    </Suspense>
  );
}

function CreateTask() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { identity } = useAuth();
  const { canon } = useCanon();

  const preselectedType = searchParams.get("type") || "";
  const [type, setType] = useState(preselectedType);
  const [title, setTitle] = useState("");
  const [address, setAddress] = useState("");
  const [scheduledTime, setScheduledTime] = useState("");
  const [feeUsd, setFeeUsd] = useState(50);
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const taskType = canon?.task_types?.find((t) => t.key === type);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!identity || !type) return;

    setSubmitting(true);
    try {
      await createTask({
        requester_id: identity.userId,
        type,
        title: title || `${taskType?.label || type} Task`,
        address,
        scheduled_time: scheduledTime || undefined,
        fee_usd: feeUsd,
        notes: notes || undefined,
      });
      toast.success("Task posted!");
      router.push("/pro");
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to create task"
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="bg-gradient-pro px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1 text-sm text-white/70 mb-2"
          >
            <ArrowLeft className="h-4 w-4" /> Back
          </button>
          <h1 className="text-xl font-bold">Post a Task</h1>
          <p className="text-sm text-white/70">
            Select type, set location, name your fee
          </p>
        </div>
      </div>

      <form
        onSubmit={handleSubmit}
        className="max-w-lg mx-auto px-4 py-6 space-y-6"
      >
        {/* Task type selector — 17 types from CANON.json */}
        <div>
          <label className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2 block">
            Task Type
          </label>
          <div className="grid grid-cols-3 gap-2">
            {(canon?.task_types || []).map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => setType(t.key)}
                className={`flex flex-col items-center gap-1 rounded-lg border p-3 text-center transition-colors ${
                  type === t.key
                    ? "border-purple-500 bg-purple-50 dark:bg-purple-900/20"
                    : "border-gray-200 dark:border-gray-800 hover:border-gray-300"
                }`}
              >
                <span className="text-lg">
                  {TASK_ICONS[t.key] || "📋"}
                </span>
                <span className="text-[10px] font-medium leading-tight">
                  {t.label}
                </span>
                <CoinBadge coin={t.coin} size="sm" />
              </button>
            ))}
          </div>
          {taskType?.vendor_gate && (
            <p className="text-xs text-amber-600 mt-2">
              Vendor gate: {taskType.vendor_gate}
            </p>
          )}
        </div>

        {/* Title */}
        <div>
          <label className="flex items-center gap-1 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">
            <FileText className="h-4 w-4" /> Title
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={
              taskType
                ? `${taskType.label} at...`
                : "Describe your task"
            }
            className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
          />
        </div>

        {/* Address */}
        <div>
          <label className="flex items-center gap-1 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">
            <MapPin className="h-4 w-4" /> Property Address
          </label>
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="123 Main St, Lake Nona, FL"
            required
            className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
          />
        </div>

        {/* Schedule */}
        <div>
          <label className="flex items-center gap-1 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">
            <Clock className="h-4 w-4" /> Schedule (optional)
          </label>
          <input
            type="datetime-local"
            value={scheduledTime}
            onChange={(e) => setScheduledTime(e.target.value)}
            className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
          />
        </div>

        {/* Fee */}
        <div>
          <label className="flex items-center gap-1 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">
            <DollarSign className="h-4 w-4" /> Fee (USD)
          </label>
          <div className="flex gap-2">
            {[35, 50, 60, 85].map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFeeUsd(f)}
                className={`flex-1 rounded-lg border py-2 text-sm font-medium transition-colors ${
                  feeUsd === f
                    ? "border-green-500 bg-green-50 dark:bg-green-900/20 text-green-700"
                    : "border-gray-200 dark:border-gray-800"
                }`}
              >
                ${f}
              </button>
            ))}
          </div>
          <input
            type="number"
            value={feeUsd}
            onChange={(e) => setFeeUsd(Number(e.target.value))}
            min={0}
            className="w-full mt-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
          />
        </div>

        {/* Notes */}
        <div>
          <label className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1 block">
            Instructions / Notes
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            placeholder="Access code, special instructions..."
            className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm resize-none"
          />
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={!type || !address || submitting}
          className="w-full rounded-xl bg-gradient-runner text-white font-semibold py-3 disabled:opacity-50 hover:opacity-90 transition-opacity"
        >
          {submitting ? "Posting..." : "Post Task"}
        </button>
      </form>
    </div>
  );
}
