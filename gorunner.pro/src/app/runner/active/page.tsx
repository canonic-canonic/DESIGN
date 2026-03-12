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
import { TASK_ICONS } from "@/lib/types";
import { toast } from "sonner";
import {
  ArrowLeft,
  Navigation,
  Camera,
  CheckCircle,
  MapPin,
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
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center"><div className="h-8 w-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" /></div>}>
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
  const { position } = useLocation(
    identity?.userId,
    !!task && ["assigned", "accepted", "in_progress"].includes(task?.status || "")
  );

  const fileRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [completing, setCompleting] = useState(false);
  const [proofUploaded, setProofUploaded] = useState(false);

  if (!task) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const taskType = canon?.task_types?.find((t) => t.key === task.type);
  const instructions = canon?.task_instructions?.[task.type];
  const icon = TASK_ICONS[task.type] || "📋";

  async function handleMarkEnRoute() {
    try {
      await taskAction(task!.id, "mark_en_route", {
        runner_id: identity?.userId,
      });
      toast.success("On your way!");
      refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    }
  }

  async function handleMarkArrived() {
    try {
      await taskAction(task!.id, "mark_arrived", {
        runner_id: identity?.userId,
      });
      toast.success("Arrived!");
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
      toast.success(`Task complete! ∩${taskType?.coin || 0} Credits earned`);
      router.push("/runner");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    } finally {
      setCompleting(false);
    }
  }

  return (
    <div className="min-h-screen pb-20">
      {/* Header */}
      <div className="bg-gradient-runner px-4 pt-12 pb-4 text-white">
        <div className="max-w-lg mx-auto">
          <button
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
        {/* Map */}
        {task.location && (
          <TrackingMap
            destination={task.location}
            runnerPosition={position}
          />
        )}

        {/* Location */}
        {task.location?.address && (
          <div className="flex items-center gap-2 rounded-lg bg-gray-50 dark:bg-gray-800 p-3 text-sm">
            <MapPin className="h-4 w-4 text-red-500 flex-shrink-0" />
            {task.location.address}
          </div>
        )}

        {/* Action buttons based on status */}
        {(task.status === "assigned" || task.status === "accepted") && (
          <button
            onClick={handleMarkEnRoute}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-semibold py-3"
          >
            <Navigation className="h-5 w-5" />
            Start Driving
          </button>
        )}

        {task.status === "in_progress" && (
          <div className="space-y-3">
            {/* Instructions */}
            {instructions && (
              <div className="rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10 p-4 space-y-3">
                <h3 className="font-semibold text-sm text-amber-800 dark:text-amber-200">
                  {instructions.title}
                </h3>
                <div className="space-y-2">
                  {instructions.steps.map((s) => (
                    <div key={s.step} className="flex gap-3">
                      <span className="flex-shrink-0 h-6 w-6 rounded-full bg-amber-200 dark:bg-amber-800 text-amber-800 dark:text-amber-200 text-xs font-bold flex items-center justify-center">
                        {s.step}
                      </span>
                      <div>
                        <div className="text-xs font-semibold">
                          {s.title}
                        </div>
                        <div className="text-xs text-gray-600 dark:text-gray-400">
                          {s.description}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
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
              onClick={handleUploadProof}
              disabled={uploading}
              className="w-full flex items-center justify-center gap-2 rounded-xl border-2 border-dashed border-blue-300 dark:border-blue-700 text-blue-600 dark:text-blue-400 font-semibold py-3"
            >
              <Camera className="h-5 w-5" />
              {uploading ? "Uploading..." : "Upload Evidence Photo"}
            </button>

            {/* Complete — evidence required (RUNNER/CANON.md MUST NOT allow without proof) */}
            <button
              onClick={handleComplete}
              disabled={completing || !proofUploaded}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-green-500 to-emerald-500 text-white font-semibold py-3 disabled:opacity-50"
            >
              <CheckCircle className="h-5 w-5" />
              {completing
                ? "Completing..."
                : !proofUploaded
                  ? "Upload Evidence First"
                  : `Complete & Earn ∩${taskType?.coin || 0} Credits`}
            </button>
          </div>
        )}

        {/* Notes */}
        {task.notes && (
          <div className="rounded-lg bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800 p-3 text-sm">
            <strong className="text-yellow-700 dark:text-yellow-300">
              Pro's Instructions:
            </strong>
            <p className="text-yellow-800 dark:text-yellow-200 mt-1">
              {task.notes}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
