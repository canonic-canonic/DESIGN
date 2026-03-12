"use client";

import { Suspense, useRef, useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTask } from "@/hooks/useTasks";
import { useBalance } from "@/hooks/useBalance";
import { useChat } from "@/hooks/useChat";
import { getRunnerLocation } from "@/lib/api";
import { StatusBadge } from "@/components/StatusBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { TaskProgressBar } from "@/components/ProgressBar";
import { RatingWidget } from "@/components/RatingWidget";
import { ChatInput } from "@/components/chat/ChatInput";
import { ChatMessageRenderer } from "@/components/chat/ChatMessageRenderer";
import { TASK_ICONS } from "@/lib/types";
import { haversineDistance, estimateEta } from "@/lib/utils";
import {
  ArrowLeft,
  MapPin,
  Clock,
  Navigation,
  Star,
  User,
} from "lucide-react";
import dynamic from "next/dynamic";

const TrackingMap = dynamic(() => import("@/components/TrackingMap"), {
  ssr: false,
  loading: () => (
    <div className="h-48 bg-gray-200 dark:bg-gray-800 rounded-xl animate-pulse" />
  ),
});

export default function TaskDetailPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center">
          <div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <TaskChatThread />
    </Suspense>
  );
}

function TaskChatThread() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const router = useRouter();
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { task, refresh } = useTask(id);
  const { balance } = useBalance(identity?.userId);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showRating, setShowRating] = useState(false);

  const [runnerPos, setRunnerPos] = useState<{
    lat: number;
    lng: number;
  } | null>(null);

  // Chat thread for this specific task
  const { messages, sendMessage, sending } = useChat({
    userContext: {
      userId: identity?.userId,
      role: identity?.role,
      principal: identity?.principal,
    },
    taskId: id,
  });

  // Auto-scroll on new messages
  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages]);

  // Poll runner location for active tasks
  useEffect(() => {
    if (
      !task ||
      !["assigned", "accepted", "in_progress"].includes(task.status)
    )
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

  // Task-specific quick actions
  const taskQuickActions = [
    { key: "_status", label: "Status", message: "What's the status of this task?" },
    { key: "_eta", label: "ETA", message: "What's the runner's ETA?" },
    { key: "_help", label: "Help", message: "I need help with this task" },
  ];

  return (
    <div className="flex flex-col h-screen">
      {/* Sticky task header */}
      <div className="bg-gradient-pro px-4 pt-10 pb-3 text-white flex-shrink-0">
        <div className="max-w-lg mx-auto">
          <button
            type="button"
            onClick={() => router.back()}
            className="flex items-center gap-1 text-xs text-white/70 mb-2"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </button>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xl">{icon}</span>
              <div>
                <h1 className="text-sm font-bold">
                  {task.title || taskType?.label}
                </h1>
                <StatusBadge status={task.status} />
              </div>
            </div>
            <CoinBadge
              coin={taskType?.coin ?? 0}
              usd={task.offered_fee_usd}
              size="sm"
            />
          </div>
          <div className="mt-2">
            <TaskProgressBar status={task.status} />
          </div>
        </div>
      </div>

      {/* Scrollable chat body */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 py-3 space-y-3 max-w-lg mx-auto w-full"
      >
        {/* Task context card — first "message" in the thread */}
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 p-3 space-y-2 bg-gray-50 dark:bg-gray-800/50">
          {task.location?.address && (
            <div className="flex items-center gap-1.5 text-xs text-gray-500">
              <MapPin className="h-3 w-3 flex-shrink-0" />
              {task.location.address}
            </div>
          )}
          {task.scheduled_time && (
            <div className="flex items-center gap-1.5 text-xs text-gray-500">
              <Clock className="h-3 w-3 flex-shrink-0" />
              {new Date(task.scheduled_time).toLocaleString()}
            </div>
          )}
          {task.assigned_runner_id && (
            <div className="flex items-center gap-1.5 text-xs text-gray-500">
              <User className="h-3 w-3 flex-shrink-0" />
              Runner assigned
              {eta !== null && (
                <span className="flex items-center gap-1 ml-2">
                  <Navigation className="h-2.5 w-2.5" />
                  {distance!.toFixed(1)} mi · ~{eta} min
                </span>
              )}
            </div>
          )}
          {task.notes && (
            <div className="text-xs text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/10 rounded-lg p-2">
              {task.notes}
            </div>
          )}
        </div>

        {/* Map for active tasks */}
        {task.location?.lat &&
          task.location?.lng &&
          ["assigned", "accepted", "in_progress"].includes(task.status) && (
            <TrackingMap
              destination={task.location}
              runnerPosition={runnerPos}
            />
          )}

        {/* Instructions as system message */}
        {instructions && (
          <div className="rounded-xl bg-blue-50 dark:bg-blue-900/10 p-3 space-y-2">
            <div className="text-xs font-semibold text-blue-600">
              {instructions.title}
            </div>
            <div className="text-xs text-blue-800 dark:text-blue-200">
              {instructions.overview}
            </div>
            <div className="space-y-1">
              {instructions.steps.slice(0, 3).map((s) => (
                <div key={s.step} className="flex gap-2 text-xs">
                  <span className="flex-shrink-0 h-4 w-4 rounded-full bg-blue-200 dark:bg-blue-800 text-blue-700 dark:text-blue-300 text-[10px] font-bold flex items-center justify-center">
                    {s.step}
                  </span>
                  <span className="text-blue-700 dark:text-blue-300">
                    {s.title}
                  </span>
                </div>
              ))}
              {instructions.steps.length > 3 && (
                <div className="text-[10px] text-blue-500">
                  +{instructions.steps.length - 3} more steps
                </div>
              )}
            </div>
          </div>
        )}

        {/* Chat messages */}
        {messages.map((msg, i) => (
          <ChatMessageRenderer key={i} message={msg} canon={canon} />
        ))}

        {sending && (
          <div className="flex justify-start">
            <div className="bg-gray-100 dark:bg-gray-800 rounded-2xl px-3 py-2">
              <div className="flex gap-1">
                <span className="h-2 w-2 rounded-full bg-gray-400 animate-bounce" />
                <span className="h-2 w-2 rounded-full bg-gray-400 animate-bounce [animation-delay:0.1s]" />
                <span className="h-2 w-2 rounded-full bg-gray-400 animate-bounce [animation-delay:0.2s]" />
              </div>
            </div>
          </div>
        )}

        {/* Rating prompt inline */}
        {canRate && (
          <div className="rounded-xl border-2 border-purple-200 dark:border-purple-800 p-4 text-center space-y-2">
            <Star className="h-6 w-6 text-amber-400 mx-auto" />
            <div className="text-sm font-medium">Task completed!</div>
            <button
              type="button"
              onClick={() => setShowRating(true)}
              className="rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 text-white text-sm font-medium px-6 py-2"
            >
              Rate & Tip
            </button>
          </div>
        )}
      </div>

      {/* Chat input */}
      <div className="flex-shrink-0 max-w-lg mx-auto w-full safe-area-pb pb-16">
        <ChatInput
          onSend={sendMessage}
          sending={sending}
          quickActions={taskQuickActions}
          placeholder="Chat about this task..."
        />
      </div>

      {/* Rating overlay */}
      {showRating && (
        <RatingWidget
          taskId={task.id}
          userId={identity?.userId}
          balance={balance}
          onDone={() => {
            setShowRating(false);
            refresh();
          }}
        />
      )}
    </div>
  );
}
