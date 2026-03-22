"use client";

import { Suspense, useState, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTask } from "@/hooks/useTasks";
import { useLocation } from "@/hooks/useLocation";
import { taskAction, uploadProof } from "@/lib/api";
import { refreshBalance } from "@/hooks/useBalance";
import { StatusBadge } from "@/components/StatusBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { TaskProgressBar } from "@/components/ProgressBar";
import { TASK_ICONS } from "@/lib/types";
import { toast } from "sonner";
import {
  ArrowLeft,
  Navigation,
  MapPinned,
  Camera,
  CheckCircle,
  MapPin,
  FileText,
  XCircle,
  Clock,
  Coins,
} from "lucide-react";
import dynamic from "next/dynamic";

const TrackingMap = dynamic(() => import("@/components/TrackingMap"), {
  ssr: false,
  loading: () => (
    <div className="h-48 bg-gray-200 dark:bg-gray-800 rounded-xl animate-pulse" />
  ),
});

export default function RunnerActivePage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center">
          <div className="h-8 w-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <RunnerActiveView />
    </Suspense>
  );
}

function RunnerActiveView() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const taskId = searchParams.get("task") || "";
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { task, refresh } = useTask(taskId);
  const isTracking =
    !!task &&
    ["assigned", "accepted", "in_progress"].includes(task?.status || "");
  const { position } = useLocation(identity?.userId, isTracking);

  const fileRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [completing, setCompleting] = useState(false);
  const [proofUploaded, setProofUploaded] = useState(false);
  const [checkedSteps, setCheckedSteps] = useState<number[]>([]);

  if (!taskId) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="text-center space-y-3">
          <div className="text-4xl">{"\u{1F4CB}"}</div>
          <p className="text-sm text-gray-500 font-medium">
            No active task selected
          </p>
          <button
            type="button"
            onClick={() => router.push("/runner")}
            className="text-sm text-purple-600 underline"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const taskType = canon?.task_types?.find((t) => t.key === task.type);
  const instructions = canon?.task_instructions?.[task.type];
  const icon = TASK_ICONS[task.type] || "\u{1F4CB}";
  const hasArrived = !!task.arrived_at;
  const hasProof = !!task.proof_hash || proofUploaded;

  // Determine which phase the runner is in
  const phase =
    task.status === "assigned" || task.status === "accepted"
      ? "ready" // Ready to start driving
      : task.status === "in_progress" && !hasArrived
        ? "driving" // En route
        : task.status === "in_progress" && hasArrived && !hasProof
          ? "onsite" // At location, needs proof
          : task.status === "in_progress" && hasProof
            ? "finishing" // Proof uploaded, ready to complete
            : task.status === "completed" || task.status === "rated"
              ? "done"
              : "ready";

  async function handleStartDriving() {
    try {
      await taskAction(task!.id, "en_route", {
        runner_id: identity?.userId,
      });
      toast.success("On your way!");
      refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    }
  }

  async function handleArrived() {
    try {
      await taskAction(task!.id, "arrived", {
        runner_id: identity?.userId,
      });
      toast.success("Arrived at location!");
      refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    }
  }

  async function handleUploadProof() {
    fileRef.current?.click();
  }

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      await uploadProof(task!.id, file, "Evidence photo");
      setProofUploaded(true);
      toast.success("Photo uploaded!");
      refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function handleComplete() {
    setCompleting(true);
    try {
      await taskAction(task!.id, "complete");
      if (identity?.userId) refreshBalance(identity.userId);
      toast.success(
        `Task complete! ∩${taskType?.coin || 0} Credits earned`
      );
      router.push("/runner");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    } finally {
      setCompleting(false);
    }
  }

  async function handleCancel() {
    try {
      await taskAction(task!.id, "cancel");
      toast.success("Task cancelled");
      router.push("/runner");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Cancel failed");
    }
  }

  function toggleStep(step: number) {
    setCheckedSteps((prev) =>
      prev.includes(step) ? prev.filter((s) => s !== step) : [...prev, step]
    );
  }

  return (
    <div className="min-h-screen pb-20">
      {/* Header */}
      <div className="bg-gradient-runner px-4 pt-12 pb-4 text-white">
        <div className="max-w-lg mx-auto">
          <button
            type="button"
            onClick={() => router.push("/runner")}
            className="flex items-center gap-1 text-sm text-white/70 mb-2"
          >
            <ArrowLeft className="h-4 w-4" /> Dashboard
          </button>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-2xl">{icon}</span>
              <div>
                <h1 className="text-lg font-bold">
                  {task.title || taskType?.label}
                </h1>
                <StatusBadge status={task.status} />
              </div>
            </div>
            <CoinBadge
              coin={taskType?.coin ?? 0}
              usd={task.offered_fee_usd}
            />
          </div>
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 py-4 space-y-4">
        {/* Progress bar */}
        <TaskProgressBar status={task.status} />

        {/* Map */}
        {task.location && (
          <TrackingMap destination={task.location} runnerPosition={position} />
        )}

        {/* Location card */}
        {task.location?.address && (
          <div className="flex items-center gap-2 rounded-lg bg-gray-50 dark:bg-gray-800 p-3 text-sm">
            <MapPin className="h-4 w-4 text-red-500 flex-shrink-0" />
            <span className="flex-1">{task.location.address}</span>
            {phase === "driving" && (
              <span className="text-xs text-blue-500 font-medium flex items-center gap-1">
                <Clock className="h-3 w-3" />
                En route
              </span>
            )}
          </div>
        )}

        {/* Pro's notes */}
        {task.notes && (
          <div className="rounded-lg bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800 p-3 text-sm">
            <strong className="text-yellow-700 dark:text-yellow-300 flex items-center gap-1">
              <FileText className="h-3.5 w-3.5" />
              Pro&apos;s Instructions:
            </strong>
            <p className="text-yellow-800 dark:text-yellow-200 mt-1">
              {task.notes}
            </p>
          </div>
        )}

        {/* ── Phase: READY — Start Driving ──────────────────────────── */}
        {phase === "ready" && (
          <button
            type="button"
            onClick={handleStartDriving}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-semibold py-4 text-lg shadow-lg shadow-blue-500/20 active:scale-[0.98] transition-transform"
          >
            <Navigation className="h-6 w-6" />
            Start Driving
          </button>
        )}

        {/* ── Phase: DRIVING — I've Arrived ─────────────────────────── */}
        {phase === "driving" && (
          <div className="space-y-3">
            <div className="rounded-xl bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 p-4 text-center">
              <Navigation className="h-8 w-8 text-blue-500 mx-auto mb-2 animate-pulse" />
              <p className="font-semibold text-blue-800 dark:text-blue-200">
                Driving to task location
              </p>
              <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
                Tap the button below when you arrive
              </p>
            </div>
            <button
              type="button"
              onClick={handleArrived}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 text-white font-semibold py-4 text-lg shadow-lg shadow-amber-500/20 active:scale-[0.98] transition-transform"
            >
              <MapPinned className="h-6 w-6" />
              I&apos;ve Arrived
            </button>
          </div>
        )}

        {/* ── Phase: ONSITE — Instructions + Upload Proof ───────────── */}
        {(phase === "onsite" || phase === "finishing") && (
          <div className="space-y-4">
            {/* Task instructions with checkboxes */}
            {instructions && (
              <div className="rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10 p-4 space-y-3">
                <h3 className="font-semibold text-sm text-amber-800 dark:text-amber-200">
                  {instructions.title}
                </h3>
                {instructions.overview && (
                  <p className="text-xs text-amber-700 dark:text-amber-300">
                    {instructions.overview}
                  </p>
                )}

                {/* Requirements */}
                {instructions.requirements?.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-[10px] font-bold uppercase text-amber-600 dark:text-amber-400 tracking-wider">
                      Requirements
                    </p>
                    <ul className="text-xs text-amber-700 dark:text-amber-300 space-y-0.5">
                      {instructions.requirements.map((r, i) => (
                        <li key={i} className="flex items-start gap-1.5">
                          <span className="text-amber-500 mt-0.5">
                            {"\u2022"}
                          </span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Steps with checkboxes */}
                <div className="space-y-2">
                  <p className="text-[10px] font-bold uppercase text-amber-600 dark:text-amber-400 tracking-wider">
                    Steps
                  </p>
                  {instructions.steps.map((s) => (
                    <button
                      type="button"
                      key={s.step}
                      onClick={() => toggleStep(s.step)}
                      className="flex gap-3 w-full text-left"
                    >
                      <span
                        className={`flex-shrink-0 h-6 w-6 rounded-full text-xs font-bold flex items-center justify-center transition-colors ${
                          checkedSteps.includes(s.step)
                            ? "bg-green-500 text-white"
                            : "bg-amber-200 dark:bg-amber-800 text-amber-800 dark:text-amber-200"
                        }`}
                      >
                        {checkedSteps.includes(s.step) ? "\u2713" : s.step}
                      </span>
                      <div>
                        <div
                          className={`text-xs font-semibold ${checkedSteps.includes(s.step) ? "line-through text-gray-400" : ""}`}
                        >
                          {s.title}
                        </div>
                        <div className="text-xs text-gray-600 dark:text-gray-400">
                          {s.description}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>

                {/* Tips */}
                {instructions.tips?.length > 0 && (
                  <div className="space-y-1 pt-2 border-t border-amber-200 dark:border-amber-700">
                    <p className="text-[10px] font-bold uppercase text-amber-600 dark:text-amber-400 tracking-wider">
                      Tips
                    </p>
                    <ul className="text-xs text-amber-700 dark:text-amber-300 space-y-0.5">
                      {instructions.tips.map((t, i) => (
                        <li key={i} className="flex items-start gap-1.5">
                          <span className="text-amber-500 mt-0.5">
                            {"\u{1F4A1}"}
                          </span>
                          {t}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Upload proof */}
            <input
              ref={fileRef}
              type="file"
              accept="image/*"
              capture="environment"
              className="hidden"
              onChange={handleFileChange}
            />
            <button
              type="button"
              onClick={handleUploadProof}
              disabled={uploading}
              className={`w-full flex items-center justify-center gap-2 rounded-xl font-semibold py-3 transition-colors ${
                hasProof
                  ? "border-2 border-green-300 dark:border-green-700 text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/10"
                  : "border-2 border-dashed border-blue-300 dark:border-blue-700 text-blue-600 dark:text-blue-400"
              }`}
            >
              <Camera className="h-5 w-5" />
              {uploading
                ? "Uploading..."
                : hasProof
                  ? "Evidence Uploaded \u2713 (tap to add more)"
                  : "Upload Evidence Photo"}
            </button>

            {/* Complete button */}
            <button
              type="button"
              onClick={handleComplete}
              disabled={completing || !hasProof}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-green-500 to-emerald-500 text-white font-semibold py-4 text-lg disabled:opacity-50 shadow-lg shadow-green-500/20 active:scale-[0.98] transition-transform"
            >
              {completing ? (
                <>
                  <div className="h-5 w-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Completing...
                </>
              ) : !hasProof ? (
                <>
                  <Camera className="h-5 w-5" />
                  Upload Evidence First
                </>
              ) : (
                <>
                  <Coins className="h-5 w-5" />
                  Complete &amp; Earn ∩{taskType?.coin || 0} Credits
                </>
              )}
            </button>
          </div>
        )}

        {/* Done state */}
        {phase === "done" && (
          <div className="rounded-xl bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-800 p-6 text-center space-y-2">
            <CheckCircle className="h-12 w-12 text-green-500 mx-auto" />
            <h3 className="text-lg font-bold text-green-800 dark:text-green-200">
              Task Complete!
            </h3>
            <p className="text-sm text-green-600 dark:text-green-400">
              ∩{taskType?.coin || 0} Credits earned
            </p>
          </div>
        )}

        {/* Cancel button (not for completed/rated) */}
        {!["completed", "rated", "cancelled"].includes(task.status) && (
          <button
            type="button"
            onClick={handleCancel}
            className="w-full flex items-center justify-center gap-2 rounded-xl border border-red-200 dark:border-red-800 text-red-500 font-medium py-2.5 text-sm hover:bg-red-50 dark:hover:bg-red-900/10 transition-colors"
          >
            <XCircle className="h-4 w-4" />
            Cancel Task
          </button>
        )}
      </div>
    </div>
  );
}
