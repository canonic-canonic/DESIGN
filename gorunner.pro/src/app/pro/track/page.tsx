"use client";

import { Suspense, useState, useEffect, useRef, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTask } from "@/hooks/useTasks";
import { getRunnerLocation, taskAction, simulateMovement } from "@/lib/api";
import { TASK_ICONS, type Task } from "@/lib/types";
import { StatusBadge } from "@/components/StatusBadge";
import { CoinBadge } from "@/components/CoinBadge";
import { RatingWidget } from "@/components/RatingWidget";
import { toast } from "sonner";
import dynamic from "next/dynamic";
import {
  X,
  RefreshCw,
  MapPin,
  Star,
  Phone,
  MessageCircle,
  Car,
  Target,
  Send,
  XCircle,
} from "lucide-react";

const TrackingMap = dynamic(() => import("@/components/TrackingMap"), {
  ssr: false,
  loading: () => (
    <div className="h-full w-full bg-gray-800 animate-pulse" />
  ),
});

export default function ProTrackPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-gray-900">
          <div className="h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <ProTrackView />
    </Suspense>
  );
}

function ProTrackView() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const taskId = searchParams.get("task") || "";
  const { identity } = useAuth();
  const { canon } = useCanon();
  const { task, refresh } = useTask(taskId);

  // Runner location polling
  const [runnerPos, setRunnerPos] = useState<{
    lat: number;
    lng: number;
  } | null>(null);
  const [eta, setEta] = useState<number | null>(null);
  const [distance, setDistance] = useState<number | null>(null);

  // Chat state
  const [showChat, setShowChat] = useState(false);
  const [chatMessages, setChatMessages] = useState<
    { role: string; content: string; ts: Date }[]
  >([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Demo simulation state
  const [simStatus, setSimStatus] = useState<string | null>(null);
  const simRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Poll runner location every 3s when task is active
  useEffect(() => {
    if (!taskId || !task) return;
    const active = ["accepted", "assigned", "in_progress"].includes(
      task.status
    );
    if (!active) return;

    const poll = async () => {
      try {
        const loc = await getRunnerLocation(taskId);
        if (loc.lat != null) {
          setRunnerPos({ lat: loc.lat, lng: loc.lng });
          if (loc.eta_minutes != null) setEta(loc.eta_minutes);
          if (loc.distance_miles != null) setDistance(loc.distance_miles);
        }
      } catch {}
    };
    poll();
    const interval = setInterval(poll, 3000);
    return () => clearInterval(interval);
  }, [taskId, task?.status]);

  // Use task-stored runner location as fallback
  useEffect(() => {
    if (task?.runner_location && !runnerPos) {
      setRunnerPos(task.runner_location);
    }
    if (task?.current_eta_minutes != null) setEta(task.current_eta_minutes);
    if (task?.current_distance_miles != null)
      setDistance(task.current_distance_miles);
  }, [task]);

  // Scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (simRef.current) clearTimeout(simRef.current);
    };
  }, []);

  const handleCancel = async () => {
    if (!task) return;
    try {
      await taskAction(task.id, "cancel");
      toast.success("Task cancelled. Credits refunded.");
      router.push("/pro");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Cancel failed");
    }
  };

  const sendChatMessage = useCallback(async () => {
    if (!chatInput.trim() || !task) return;
    const msg = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [
      ...prev,
      { role: "user", content: msg, ts: new Date() },
    ]);
    setChatLoading(true);
    // Simulate runner response (LLM-powered in production)
    await new Promise((r) => setTimeout(r, 800 + Math.random() * 1200));
    const replies: Record<string, string[]> = {
      posted: [
        "I'm being matched with a runner. Should be just a moment!",
        "Looking for the best runner near your property.",
      ],
      accepted: [
        "Your runner is getting ready to head out!",
        "I've accepted the task and will start driving shortly.",
      ],
      in_progress: [
        `I'm on my way! About ${eta ?? "a few"} minutes out.`,
        "Making good progress. I'll let you know when I arrive!",
        `Currently ${distance ? distance.toFixed(1) + " miles" : "heading"} to the property.`,
      ],
      completed: [
        "All done! The task is complete. Check the evidence photos.",
        "Task finished! Happy to help.",
      ],
    };
    const statusReplies =
      replies[task.status] || replies["in_progress"];
    const reply =
      statusReplies[Math.floor(Math.random() * statusReplies.length)];
    setChatMessages((prev) => [
      ...prev,
      { role: "runner", content: reply, ts: new Date() },
    ]);
    setChatLoading(false);
  }, [chatInput, task, eta, distance]);

  if (!taskId) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-900 text-white">
        <div className="text-center space-y-3">
          <p className="text-gray-400">No task selected</p>
          <button
            onClick={() => router.push("/pro")}
            className="text-blue-400 underline text-sm"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-900">
        <div className="h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const taskType = canon?.task_types?.find((t) => t.key === task.type);
  const icon = TASK_ICONS[task.type] || "\u{1F4CB}";
  const isActive = ["accepted", "assigned", "in_progress"].includes(
    task.status
  );

  // Progress percentage for bar
  const progressMap: Record<string, number> = {
    posted: 0,
    assigned: 15,
    accepted: 25,
    in_progress: 50,
    completed: 100,
    rated: 100,
    cancelled: 0,
  };
  // Refine in_progress with runner_progress
  let progress = progressMap[task.status] ?? 0;
  if (task.status === "in_progress" && task.runner_progress != null) {
    progress = 25 + task.runner_progress * 50;
    if (task.arrived_at) progress = Math.max(progress, 75);
  }
  if (task.proof_hash) progress = Math.max(progress, 90);

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Map Area — takes top 45% */}
      <div className="relative h-[45vh] bg-gray-800 overflow-hidden">
        {task.location?.lat != null ? (
          <div className="h-full w-full [&_.leaflet-container]:h-full [&_.leaflet-container]:w-full [&_.leaflet-container]:rounded-none [&>div]:h-full [&>div]:rounded-none">
            <TrackingMap
              destination={task.location}
              runnerPosition={runnerPos}
            />
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500">
            <MapPin className="h-8 w-8" />
          </div>
        )}

        {/* Back button */}
        <div className="absolute top-4 left-4 z-[1000]">
          <button
            onClick={() => router.push("/pro")}
            className="h-10 w-10 rounded-full bg-gray-800/80 backdrop-blur flex items-center justify-center hover:bg-gray-700 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Refresh */}
        <div className="absolute top-4 right-4 z-[1000]">
          <button
            onClick={() => refresh()}
            className="h-10 w-10 rounded-full bg-gray-800/80 backdrop-blur flex items-center justify-center hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className="h-5 w-5" />
          </button>
        </div>

        {/* ETA Badge */}
        {eta != null && isActive && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 z-[1000]">
            <div className="bg-gray-800/90 backdrop-blur rounded-xl px-6 py-3 text-center">
              <p className="text-3xl font-bold">{eta}</p>
              <p className="text-xs text-gray-400">min away</p>
            </div>
          </div>
        )}

        {/* Simulation status badge */}
        {simStatus && (
          <div className="absolute top-16 left-1/2 -translate-x-1/2 z-[1000]">
            <div className="bg-blue-600/90 backdrop-blur rounded-full px-4 py-2 flex items-center gap-2">
              <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
              <span className="text-sm font-medium">{simStatus}</span>
            </div>
          </div>
        )}
      </div>

      {/* Chat Overlay */}
      {showChat && (
        <div className="fixed inset-0 bg-black/50 z-[2000] flex items-end justify-center">
          <div className="bg-white w-full max-w-lg rounded-t-3xl h-[70vh] flex flex-col">
            {/* Chat header */}
            <div className="p-4 border-b flex items-center justify-between bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-t-3xl">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-blue-700 flex items-center justify-center font-bold">
                  R
                </div>
                <div>
                  <h3 className="font-semibold">Your Runner</h3>
                  <p className="text-xs text-white/80">Active</p>
                </div>
              </div>
              <button
                onClick={() => setShowChat(false)}
                className="h-8 w-8 rounded-full hover:bg-white/20 flex items-center justify-center"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-50">
              {chatMessages.length === 0 && (
                <div className="text-center text-gray-500 py-8">
                  <MessageCircle className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                  <p className="text-gray-600">
                    Start a conversation with your runner
                  </p>
                  <p className="text-sm text-gray-400 mt-1">
                    They&apos;ll respond based on their current status
                  </p>
                </div>
              )}
              {chatMessages.map((msg, i) => (
                <div
                  key={i}
                  className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[80%] rounded-2xl px-4 py-2 ${
                      msg.role === "user"
                        ? "bg-blue-500 text-white rounded-br-sm"
                        : "bg-white text-gray-800 shadow-sm rounded-bl-sm"
                    }`}
                  >
                    <p>{msg.content}</p>
                    <p
                      className={`text-xs mt-1 ${msg.role === "user" ? "text-blue-200" : "text-gray-400"}`}
                    >
                      {msg.ts.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </p>
                  </div>
                </div>
              ))}
              {chatLoading && (
                <div className="flex justify-start">
                  <div className="bg-white rounded-2xl px-4 py-3 shadow-sm">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:150ms]" />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:300ms]" />
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t bg-white">
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-xl border border-gray-300 px-4 py-2 text-sm text-gray-900 focus:outline-none focus:border-blue-400"
                  placeholder="Type a message..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) =>
                    e.key === "Enter" && sendChatMessage()
                  }
                />
                <button
                  onClick={sendChatMessage}
                  disabled={!chatInput.trim() || chatLoading}
                  className="h-10 w-10 rounded-xl bg-blue-500 text-white flex items-center justify-center disabled:opacity-50"
                >
                  <Send className="h-4 w-4" />
                </button>
              </div>
              {/* Quick messages */}
              <div className="flex gap-2 mt-2 overflow-x-auto pb-1">
                {[
                  "Where are you?",
                  "How long until you arrive?",
                  "Any issues?",
                  "Thanks!",
                ].map((msg) => (
                  <button
                    key={msg}
                    onClick={() => setChatInput(msg)}
                    className="whitespace-nowrap text-xs px-3 py-1.5 rounded-full border border-gray-200 text-gray-600 hover:border-blue-300 hover:text-blue-600 transition-colors"
                  >
                    {msg}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Bottom Panel */}
      <div className="bg-white text-gray-900 rounded-t-3xl -mt-6 relative z-10 min-h-[55vh]">
        <div className="p-6 space-y-5 max-w-lg mx-auto">
          {/* Status header */}
          <div className="text-center">
            <StatusBadge status={task.status} />
            <h2 className="text-xl font-bold mt-3">
              {icon} {task.title || taskType?.label}
            </h2>
            {task.location?.address && (
              <p className="text-gray-500 text-sm flex items-center justify-center gap-1 mt-1">
                <MapPin className="w-4 h-4" />
                {task.location.address}
              </p>
            )}
          </div>

          {/* Progress bar */}
          <div>
            <div className="flex justify-between text-[10px] text-gray-400 mb-2">
              <span>Posted</span>
              <span>Assigned</span>
              <span>En Route</span>
              <span>Arrived</span>
              <span>Done</span>
            </div>
            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-green-500 rounded-full transition-all duration-700"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          {/* Runner card (when assigned) */}
          {task.runner_id ? (
            <div className="rounded-2xl border border-gray-200 bg-gray-50 p-4">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-xl font-bold">
                  <Car className="w-6 h-6" />
                </div>
                <div className="flex-1">
                  <h3 className="font-bold text-lg">Runner</h3>
                  <div className="flex items-center gap-1 text-sm text-gray-500">
                    <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                    Active
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() =>
                      toast.info("Calling runner... (demo mode)")
                    }
                    className="h-10 w-10 rounded-full border border-gray-300 flex items-center justify-center hover:bg-gray-100"
                  >
                    <Phone className="w-4 h-4 text-gray-600" />
                  </button>
                  <button
                    onClick={() => setShowChat(true)}
                    className="h-10 w-10 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center hover:bg-blue-100"
                  >
                    <MessageCircle className="w-4 h-4 text-blue-600" />
                  </button>
                </div>
              </div>

              {/* ETA info when en route */}
              {isActive && (distance != null || eta != null) && (
                <div className="mt-4 flex items-center justify-around bg-white rounded-lg p-3">
                  <div className="text-center">
                    <p className="text-2xl font-bold text-blue-600">
                      {distance?.toFixed(1) ?? "--"}
                    </p>
                    <p className="text-xs text-gray-500">miles away</p>
                  </div>
                  <div className="w-px h-10 bg-gray-200" />
                  <div className="text-center">
                    <p className="text-2xl font-bold text-green-600">
                      {eta ?? "--"}
                    </p>
                    <p className="text-xs text-gray-500">min ETA</p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-2xl border border-gray-200 bg-gray-50 p-6 text-center">
              <div className="h-10 w-10 border-2 border-gray-300 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <h3 className="font-semibold text-gray-700">
                Finding a Runner...
              </h3>
              <p className="text-sm text-gray-500">
                Matching your task with nearby runners
              </p>
            </div>
          )}

          {/* Task details */}
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <span className="text-gray-500">Task Type</span>
              <span className="font-medium">{taskType?.label || task.type}</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <span className="text-gray-500">Fee</span>
              <CoinBadge coin={taskType?.coin ?? task.fee_coin ?? 0} usd={task.offered_fee_usd} size="sm" />
            </div>
            {task.notes && (
              <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                <span className="text-xs font-semibold text-yellow-700 block mb-1">
                  Notes
                </span>
                <p className="text-yellow-800">{task.notes}</p>
              </div>
            )}
          </div>

          {/* Rating (when completed) */}
          {task.status === "completed" && (
            <RatingWidget
              taskId={task.id}
              userId={identity?.userId}
              onDone={() => {
                refresh();
              }}
            />
          )}

          {/* Cancel button */}
          {!["completed", "rated", "cancelled"].includes(task.status) && (
            <button
              onClick={handleCancel}
              className="w-full flex items-center justify-center gap-2 rounded-xl border-2 border-red-200 text-red-600 font-semibold py-3 hover:bg-red-50 transition-colors"
            >
              <XCircle className="h-5 w-5" />
              Cancel Task
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
