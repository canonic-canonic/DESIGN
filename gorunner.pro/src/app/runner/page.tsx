"use client";

import { useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { useBalance } from "@/hooks/useBalance";
import { useChat } from "@/hooks/useChat";
import { formatCompact, formatNumber } from "@/lib/utils";
import { ChatInput } from "@/components/chat/ChatInput";
import { ChatMessageRenderer } from "@/components/chat/ChatMessageRenderer";
import { ArrowUpRight } from "lucide-react";

export default function RunnerDashboard() {
  const router = useRouter();
  const { identity, user } = useAuth();
  const { canon } = useCanon();
  const { tasks: allTasks } = useTasks(identity?.userId, "Runner");
  const { tasks: availableTasks } = useTasks(undefined, "available");
  const { balance: balanceValue } = useBalance(identity?.userId);
  const scrollRef = useRef<HTMLDivElement>(null);

  const { messages, sendMessage, sending } = useChat({
    userContext: {
      userId: identity?.userId,
      role: identity?.role,
      principal: identity?.principal,
    },
  });

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages]);

  const active = allTasks.filter(
    (t) =>
      t.assigned_runner_id === identity?.userId &&
      !["completed", "rated", "cancelled"].includes(t.status)
  );
  const completed = allTasks.filter(
    (t) =>
      t.assigned_runner_id === identity?.userId &&
      ["completed", "rated"].includes(t.status)
  );
  const totalEarned = completed.reduce((sum, t) => {
    const tt = canon?.task_types?.find((x) => x.key === t.type);
    return sum + (tt?.coin || 0);
  }, 0);

  const bal = balanceValue ?? 0;

  const runnerQuickActions = [
    { key: "_tasks", label: "My Tasks", message: "show my tasks" },
    { key: "_available", label: "Available", message: "show tasks" },
    { key: "_earnings", label: "Earnings", message: "show earnings" },
    { key: "_leaderboard", label: "Leaderboard", message: "show leaderboard" },
  ];

  return (
    <div className="flex flex-col h-screen">
      {/* Polished header — big bold balance */}
      <div className="bg-gradient-runner px-4 pt-10 pb-4 text-white flex-shrink-0">
        <div className="max-w-lg mx-auto">
          <div className="flex items-start justify-between mb-3">
            <div>
              <p className="text-[10px] text-white/50 uppercase tracking-wider">Runner</p>
              <h1 className="text-lg font-bold leading-tight">
                {user?.name || user?.user || "Runner"}
              </h1>
            </div>
            {/* Hero balance */}
            <div
              onClick={() => router.push("/runner/earnings")}
              className="text-right cursor-pointer group"
            >
              <div className="flex items-baseline gap-1 justify-end">
                <span className="text-3xl font-black tracking-tight text-amber-300 group-hover:scale-105 transition-transform inline-block">
                  {formatCompact(bal)}
                </span>
                <span className="text-sm text-amber-300/70">∩</span>
              </div>
              <p className="text-[9px] text-white/40 flex items-center gap-0.5 justify-end">
                {formatNumber(bal)} credits
                <ArrowUpRight className="h-2.5 w-2.5" />
              </p>
            </div>
          </div>

          {/* Stat pills */}
          <div className="flex gap-2">
            <div
              onClick={() => sendMessage("show tasks")}
              className="flex-1 rounded-xl bg-white/10 px-3 py-2 text-center cursor-pointer hover:bg-white/20 transition-colors"
            >
              <div className="text-lg font-bold">{availableTasks.filter(t => t.status === "posted").length}</div>
              <div className="text-[9px] text-white/60 uppercase">Available</div>
            </div>
            <div
              onClick={() => router.push("/runner/active")}
              className="flex-1 rounded-xl bg-orange-500/20 px-3 py-2 text-center cursor-pointer hover:bg-white/20 transition-colors"
            >
              <div className="text-lg font-bold">{active.length}</div>
              <div className="text-[9px] text-white/60 uppercase">Active</div>
            </div>
            <div
              onClick={() => router.push("/runner/earnings")}
              className="flex-1 rounded-xl bg-green-500/20 px-3 py-2 text-center cursor-pointer hover:bg-white/20 transition-colors"
            >
              <div className="text-lg font-bold">∩{formatCompact(totalEarned)}</div>
              <div className="text-[9px] text-white/60 uppercase">Earned</div>
            </div>
          </div>
        </div>
      </div>

      {/* Chat messages */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 py-2 space-y-3 max-w-lg mx-auto w-full"
      >
        {messages.length === 0 && (
          <div className="text-center py-10 space-y-3">
            <div className="text-4xl">🏃</div>
            <p className="text-sm text-gray-500 font-medium">
              Your AI assistant for GoRunner
            </p>
            <div className="space-y-1">
              <p className="text-xs text-gray-400">Try saying:</p>
              <div className="flex flex-wrap justify-center gap-1.5">
                {[
                  "show my tasks",
                  "show leaderboard",
                  "show earnings",
                  "show stats",
                ].map((tip) => (
                  <button
                    key={tip}
                    type="button"
                    onClick={() => sendMessage(tip)}
                    className="rounded-full border border-gray-200 dark:border-gray-700 px-3 py-1 text-xs text-gray-500 hover:border-purple-300 hover:text-purple-600 transition-colors"
                  >
                    &quot;{tip}&quot;
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
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
      </div>

      {/* Chat input */}
      <div className="flex-shrink-0 max-w-lg mx-auto w-full safe-area-pb pb-16">
        <ChatInput
          onSend={sendMessage}
          sending={sending}
          quickActions={runnerQuickActions}
          placeholder="Ask about tasks, earnings, or runners..."
        />
      </div>
    </div>
  );
}
