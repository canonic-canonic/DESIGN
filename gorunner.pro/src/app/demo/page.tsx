"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import {
  createTask,
  taskAction,
  simulateMovement,
  uploadProof,
  authLogin,
} from "@/lib/api";
import { toast } from "sonner";
import dynamic from "next/dynamic";
import {
  Play,
  Pause,
  RotateCcw,
  Car,
  Target,
  MapPin,
  CheckCircle,
  Camera,
  Star,
  Zap,
} from "lucide-react";

const TrackingMap = dynamic(() => import("@/components/TrackingMap"), {
  ssr: false,
  loading: () => (
    <div className="h-full w-full bg-gray-800 animate-pulse" />
  ),
});

type SimPhase =
  | "idle"
  | "posting"
  | "finding"
  | "matched"
  | "driving"
  | "arrived"
  | "completing"
  | "completed"
  | "rated";

const PHASE_LABELS: Record<SimPhase, string> = {
  idle: "Ready to Demo",
  posting: "Posting Task...",
  finding: "Finding Runner...",
  matched: "Runner Matched!",
  driving: "Runner Driving...",
  arrived: "Runner Arrived!",
  completing: "Completing Task...",
  completed: "Task Complete!",
  rated: "Rated! Demo Done.",
};

export default function DemoPage() {
  const router = useRouter();
  const { identity } = useAuth();
  const [phase, setPhase] = useState<SimPhase>("idle");
  const [progress, setProgress] = useState(0);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [runnerId, setRunnerId] = useState<string | null>(null);
  const [runnerPos, setRunnerPos] = useState<{
    lat: number;
    lng: number;
  } | null>(null);
  const [eta, setEta] = useState<number | null>(null);
  const [distance, setDistance] = useState<number | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const abortRef = useRef(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const destination = { lat: 28.3675, lng: -81.2089, address: "123 Lake Nona Blvd, Orlando FL 32827" };

  function addLog(msg: string) {
    setLog((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  }

  async function sleep(ms: number) {
    return new Promise<void>((resolve) => {
      timerRef.current = setTimeout(resolve, ms);
    });
  }

  const runDemo = useCallback(async () => {
    if (!identity?.userId) {
      toast.error("Sign in first");
      return;
    }
    abortRef.current = false;
    setPhase("idle");
    setProgress(0);
    setLog([]);
    setRunnerPos(null);
    setEta(null);
    setDistance(null);

    try {
      // 1. Post task
      setPhase("posting");
      addLog("Posting lockbox install task...");
      const taskRes = await createTask({
        requester_id: identity.userId,
        type: "lockbox_install",
        title: "Lockbox Install — 123 Lake Nona Blvd",
        address: destination.address,
        fee_usd: 50,
      });
      const tid = taskRes.task?.id || (taskRes as Record<string, unknown>).task_id as string;
      if (!tid) throw new Error("Task creation failed");
      setTaskId(tid);
      addLog(`Task posted: ${tid}`);
      await sleep(1500);
      if (abortRef.current) return;

      // 2. Create demo runner
      setPhase("finding");
      addLog("Finding a runner...");
      await sleep(2000);
      if (abortRef.current) return;

      const runnerNames = ["Alex Martinez", "Jordan Smith", "Casey Johnson", "Taylor Williams"];
      const name = runnerNames[Math.floor(Math.random() * runnerNames.length)];
      const loginRes = await authLogin({ name, github: "", role: "Runner" });
      const rid = loginRes.user?.id;
      if (!rid) throw new Error("Runner creation failed");
      setRunnerId(rid);
      addLog(`Runner created: ${name} (${rid})`);

      // 3. Runner accepts
      setPhase("matched");
      await taskAction(tid, "accept", { runner_id: rid });
      addLog(`${name} accepted the task`);
      toast.success(`Runner matched: ${name}`);
      await sleep(2000);
      if (abortRef.current) return;

      // 4. En route
      setPhase("driving");
      await taskAction(tid, "en_route", { runner_id: rid });
      addLog("Runner started driving");

      // 5. Simulate driving (10 steps over ~15s)
      for (let i = 1; i <= 10; i++) {
        if (abortRef.current) return;
        const p = i / 10;
        setProgress(p);
        try {
          const simRes = await simulateMovement(tid, Math.min(p, 0.95), rid);
          setRunnerPos({ lat: simRes.lat, lng: simRes.lng });
          setEta(simRes.eta_minutes);
          setDistance(simRes.distance_remaining);
          if (i % 3 === 0) addLog(`Progress: ${Math.round(p * 100)}% — ${simRes.distance_remaining.toFixed(1)}mi, ${simRes.eta_minutes}min`);
        } catch {}
        await sleep(1500);
      }
      if (abortRef.current) return;

      // 6. Arrived
      setPhase("arrived");
      await taskAction(tid, "arrived", { runner_id: rid });
      addLog("Runner arrived at location");
      toast.success("Runner arrived!");
      await sleep(2000);
      if (abortRef.current) return;

      // 7. Upload proof (mock blob)
      setPhase("completing");
      addLog("Uploading evidence photo...");
      const blob = new Blob(["demo-evidence"], { type: "image/jpeg" });
      const file = new File([blob], "lockbox-proof.jpg", { type: "image/jpeg" });
      await uploadProof(tid, file, "Lockbox installed successfully");
      addLog("Evidence uploaded");
      await sleep(2000);
      if (abortRef.current) return;

      // 8. Complete
      setPhase("completed");
      await taskAction(tid, "complete");
      addLog("Task completed! Runner earned credits.");
      toast.success("Task complete!");
      await sleep(2000);
      if (abortRef.current) return;

      // 9. Rate
      setPhase("rated");
      await taskAction(tid, "rate", { rating: 5, tip_coin: 2 });
      addLog("Rated 5 stars with 2 credit tip. Demo done.");
      toast.success("Demo complete!");
    } catch (err) {
      addLog(`Error: ${err instanceof Error ? err.message : "Unknown"}`);
      toast.error(err instanceof Error ? err.message : "Demo failed");
    }
  }, [identity?.userId]);

  const stopDemo = useCallback(() => {
    abortRef.current = true;
    if (timerRef.current) clearTimeout(timerRef.current);
    addLog("Demo stopped");
    setPhase("idle");
  }, []);

  useEffect(() => {
    return () => {
      abortRef.current = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const isRunning = phase !== "idle" && phase !== "rated";

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Map */}
      <div className="relative h-[40vh] overflow-hidden">
        <div className="h-full w-full [&_.leaflet-container]:h-full [&_.leaflet-container]:w-full [&_.leaflet-container]:rounded-none [&>div]:h-full [&>div]:rounded-none">
          <TrackingMap destination={destination} runnerPosition={runnerPos} />
        </div>

        {/* Phase badge */}
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-[1000]">
          <div
            className={`backdrop-blur rounded-full px-5 py-2 flex items-center gap-2 ${
              phase === "completed" || phase === "rated"
                ? "bg-green-600/90"
                : isRunning
                  ? "bg-blue-600/90"
                  : "bg-gray-700/90"
            }`}
          >
            {isRunning && phase !== "completed" && (
              <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
            )}
            {(phase === "completed" || phase === "rated") && (
              <CheckCircle className="w-4 h-4" />
            )}
            <span className="text-sm font-semibold">
              {PHASE_LABELS[phase]}
            </span>
          </div>
        </div>

        {/* ETA during driving */}
        {phase === "driving" && eta != null && (
          <div className="absolute top-14 left-1/2 -translate-x-1/2 z-[1000]">
            <div className="bg-gray-800/90 backdrop-blur rounded-xl px-5 py-2 text-center">
              <span className="text-2xl font-bold">{eta}</span>
              <span className="text-xs text-gray-400 ml-1">min</span>
              <span className="mx-2 text-gray-600">|</span>
              <span className="text-2xl font-bold">
                {distance?.toFixed(1) ?? "--"}
              </span>
              <span className="text-xs text-gray-400 ml-1">mi</span>
            </div>
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="bg-gray-900 rounded-t-3xl -mt-6 relative z-10 min-h-[60vh]">
        <div className="max-w-lg mx-auto p-6 space-y-5">
          <div className="text-center">
            <h1 className="text-xl font-bold">Lockbox Demo Simulation</h1>
            <p className="text-sm text-gray-400 mt-1">
              End-to-end task lifecycle in ~30 seconds
            </p>
          </div>

          {/* Progress bar */}
          <div>
            <div className="flex justify-between text-[9px] text-gray-500 mb-1">
              <span>Post</span>
              <span>Match</span>
              <span>Drive</span>
              <span>Arrive</span>
              <span>Proof</span>
              <span>Done</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 via-cyan-500 to-green-500 rounded-full transition-all duration-700"
                style={{
                  width: `${
                    phase === "idle"
                      ? 0
                      : phase === "posting"
                        ? 5
                        : phase === "finding"
                          ? 15
                          : phase === "matched"
                            ? 25
                            : phase === "driving"
                              ? 25 + progress * 40
                              : phase === "arrived"
                                ? 70
                                : phase === "completing"
                                  ? 85
                                  : 100
                  }%`,
                }}
              />
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-3">
            {!isRunning ? (
              <button
                type="button"
                onClick={runDemo}
                className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-semibold py-4 text-lg active:scale-[0.98] transition-transform"
              >
                <Play className="h-5 w-5" />
                {phase === "rated" ? "Run Again" : "Start Demo"}
              </button>
            ) : (
              <button
                type="button"
                onClick={stopDemo}
                className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-red-500/80 text-white font-semibold py-4 text-lg"
              >
                <Pause className="h-5 w-5" />
                Stop
              </button>
            )}
            <button
              type="button"
              onClick={() => router.push("/pro")}
              className="rounded-xl border border-gray-700 px-4 flex items-center justify-center hover:bg-gray-800 transition-colors"
            >
              <RotateCcw className="h-5 w-5 text-gray-400" />
            </button>
          </div>

          {/* Event log */}
          <div className="rounded-xl bg-gray-800/50 border border-gray-700 p-4 max-h-48 overflow-y-auto font-mono text-xs text-gray-400 space-y-1">
            {log.length === 0 ? (
              <p className="text-gray-600">
                Tap &quot;Start Demo&quot; to begin the simulation...
              </p>
            ) : (
              log.map((entry, i) => (
                <div key={i} className="leading-tight">
                  {entry}
                </div>
              ))
            )}
          </div>

          {/* Task ID link */}
          {taskId && (
            <button
              type="button"
              onClick={() =>
                router.push(`/pro/track?task=${taskId}`)
              }
              className="w-full text-center text-sm text-blue-400 hover:text-blue-300 underline"
            >
              Open in Pro Tracking View
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
