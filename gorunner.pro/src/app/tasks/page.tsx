"use client";

import { Suspense, useState, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTask } from "@/hooks/useTasks";
import { getRunnerLocation } from "@/lib/api";
import { useBalance } from "@/hooks/useBalance";
import { StatusBadge } from "@/components/StatusBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { TaskProgressBar } from "@/components/ProgressBar";
import { RatingWidget } from "@/components/RatingWidget";
import { ChatOverlay } from "@/components/ChatOverlay";
import { TASK_ICONS } from "@/lib/types";
import { haversineDistance, estimateEta } from "@/lib/utils";
import {
  ArrowLeft,
  MapPin,
  Clock,
  Navigation,
  MessageCircle,
  Star,
  User,
} from "lucide-react";
import dynamic from "next/dynamic";

const TrackingMap = dynamic(() => import("@/components/TrackingMap"), {
  ssr: false,
  loading: () => (
    <div className="h-64 bg-gray-200 dark:bg-gray-800 rounded-xl animate-pulse" />
  ),
});

export default function TaskDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <TaskDetail />
    </Suspense>
  );
}

function TaskDetail() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const router = useRouter();
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { task, refresh } = useTask(id);
  const { balance } = useBalance(identity?.userId);

  const [runnerPos, setRunnerPos] = useState<{
    lat: number;
    lng: number;
  } | null>(null);
  const [showChat, setShowChat] = useState(false);
  const [showRating, setShowRating] = useState(false);

  useEffect(() => {
    if (!task || !["assigned", "accepted", "in_progress"].includes(task.status))
      return;
    const poll = setInterval(async () => {
      try {
        const loc = await getRunnerLocation(task.id);
        if (loc.lat && loc.lng) setRunnerPos(loc);
      } catch {}
    }, 3000);
    return () => clearInterval(poll);
  }, [task]);

  if (!id) {
    return (
      <div className="flex min-h-screen items-center justify-center text-gray-400">
        No task ID provided
      </div>
    );
  }

  if (!task) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const taskType = canon?.task_types?.find((t) => t.key === task.type);
  const icon = TASK_ICONS[task.type] || "📋";
  const instructions = canon?.task_instructions?.[task.type];

  const distance =
    runnerPos && task.location
      ? haversineDistance(
          runnerPos.lat,
          runnerPos.lng,
          task.location.lat,
          task.location.lng
        )
      : null;
  const eta = distance !== null ? estimateEta(distance) : null;

  const canRate =
    task.status === "completed" &&
    !task.rating &&
    task.requester_id === identity?.userId;

  return (
    <div className="min-h-screen pb-20">
      <div className="bg-gradient-pro px-4 pt-12 pb-4 text-white">
        <div className="max-w-lg mx-auto">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1 text-sm text-white/70 mb-2"
          >
            <ArrowLeft className="h-4 w-4" /> Back
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
        <TaskProgressBar status={task.status} />

        {task.location?.lat && task.location?.lng && (
          <TrackingMap
            destination={task.location}
            runnerPosition={runnerPos}
          />
        )}

        {task.assigned_runner_id && (
          <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-full bg-gradient-runner flex items-center justify-center text-white">
                  <User className="h-5 w-5" />
                </div>
                <div>
                  <div className="text-sm font-semibold">Runner assigned</div>
                  {eta !== null && (
                    <div className="flex items-center gap-2 text-xs text-gray-500">
                      <Navigation className="h-3 w-3" />
                      {distance!.toFixed(1)} mi · ~{eta} min
                    </div>
                  )}
                </div>
              </div>
              <button
                onClick={() => setShowChat(true)}
                className="rounded-full bg-purple-100 dark:bg-purple-900/20 p-2 text-purple-600"
              >
                <MessageCircle className="h-5 w-5" />
              </button>
            </div>
          </div>
        )}

        <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
          {task.location?.address && (
            <div className="flex items-center gap-2 text-sm">
              <MapPin className="h-4 w-4 text-gray-400 flex-shrink-0" />
              {task.location.address}
            </div>
          )}
          {task.scheduled_time && (
            <div className="flex items-center gap-2 text-sm">
              <Clock className="h-4 w-4 text-gray-400 flex-shrink-0" />
              {new Date(task.scheduled_time).toLocaleString()}
            </div>
          )}
          {task.notes && (
            <div className="rounded-lg bg-amber-50 dark:bg-amber-900/10 p-3 text-sm text-amber-800 dark:text-amber-200">
              <strong>Notes:</strong> {task.notes}
            </div>
          )}
        </div>

        {instructions && (
          <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-4 space-y-3">
            <h3 className="font-semibold text-sm">{instructions.title}</h3>
            <p className="text-xs text-gray-500">{instructions.overview}</p>
            <div className="space-y-1">
              <h4 className="text-xs font-semibold text-gray-400 uppercase">Requirements</h4>
              {instructions.requirements.map((r: string, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="text-green-500">✓</span> {r}
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-gray-400 uppercase">Steps</h4>
              {instructions.steps.map((s: { step: number; title: string; description: string }) => (
                <div key={s.step} className="flex gap-3">
                  <span className="flex-shrink-0 h-6 w-6 rounded-full bg-purple-100 dark:bg-purple-900/20 text-purple-600 text-xs font-bold flex items-center justify-center">
                    {s.step}
                  </span>
                  <div>
                    <div className="text-xs font-semibold">{s.title}</div>
                    <div className="text-xs text-gray-500">{s.description}</div>
                  </div>
                </div>
              ))}
            </div>
            {instructions.tips.length > 0 && (
              <div className="rounded-lg bg-blue-50 dark:bg-blue-900/10 p-3 space-y-1">
                <h4 className="text-xs font-semibold text-blue-600">Pro Tips</h4>
                {instructions.tips.map((t: string, i: number) => (
                  <div key={i} className="text-xs text-blue-800 dark:text-blue-200">
                    • {t}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {canRate && (
          <button
            onClick={() => setShowRating(true)}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold py-3"
          >
            <Star className="h-5 w-5" />
            Rate This Task
          </button>
        )}
      </div>

      {showChat && (
        <ChatOverlay taskId={task.id} onClose={() => setShowChat(false)} />
      )}
      {showRating && (
        <RatingWidget
          taskId={task.id}
          userId={identity?.userId}
          balance={balance}
          onDone={() => { setShowRating(false); refresh(); }}
        />
      )}
    </div>
  );
}
