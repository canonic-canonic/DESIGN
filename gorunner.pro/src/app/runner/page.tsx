"use client";

import { useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useCanon } from "@/hooks/useCanon";
import { useTasks } from "@/hooks/useTasks";
import { useBalance } from "@/hooks/useBalance";
import { useChat } from "@/hooks/useChat";
import { CoinBalance } from "@/components/CoinBadge";
import { ChatInput } from "@/components/chat/ChatInput";
import { ChatMessageRenderer } from "@/components/chat/ChatMessageRenderer";

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

  // Runner-specific quick messages
  const runnerQuickActions = [
    { key: "_tasks", label: "My Tasks", message: "show my tasks" },
    { key: "_available", label: "Available", message: "show tasks" },
    { key: "_earnings", label: "Earnings", message: "show earnings" },
    { key: "_leaderboard", label: "Leaderboard", message: "show leaderboard" },
  ];

  return (
    <div className="flex flex-col h-screen">
      {/* Compact header */}
      <div className="bg-gradient-runner px-4 pt-10 pb-4 text-white flex-shrink-0">
        <div className="max-w-lg mx-auto">
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-xs text-white/70">Runner</p>
              <h1 className="text-lg font-bold">
                {user?.name || user?.user || "Runner"}
              </h1>
            </div>
            <CoinBalance
              balance={balanceValue ?? 0}
              className="bg-white/10 text-amber-300"
            />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div className="rounded-lg bg-white/10 p-2 text-center">
              <div className="text-sm font-bold">{availableTasks.filter(t => t.status === "posted").length}</div>
              <div className="text-[9px] text-white/60">Available</div>
            </div>
            <div className="rounded-lg bg-white/10 p-2 text-center">
              <div className="text-sm font-bold">{active.length}</div>
              <div className="text-[9px] text-white/60">Active</div>
            </div>
            <div className="rounded-lg bg-white/10 p-2 text-center">
              <div className="text-sm font-bold">∩{totalEarned}</div>
              <div className="text-[9px] text-white/60">Earned</div>
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
          <div className="text-center py-8 space-y-2">
            <p className="text-sm text-gray-400">
              Chat with your assistant or tap a quick action
            </p>
            <p className="text-xs text-gray-300">
              Try &quot;show my tasks&quot; or &quot;show leaderboard&quot;
            </p>
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

      {/* Chat input with runner pills */}
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
