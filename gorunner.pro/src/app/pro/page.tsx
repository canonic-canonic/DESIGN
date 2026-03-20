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
import { Plus, CheckCircle, Clock, ArrowUpRight } from "lucide-react";

export default function ProDashboard() {
  const router = useRouter();
  const { identity, user } = useAuth();
  const { canon } = useCanon();
  const { tasks } = useTasks(identity?.userId, "Requester");
  const { balance } = useBalance(identity?.userId);
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

  const activeTasks = tasks.filter(
    (t) => !["completed", "rated", "cancelled"].includes(t.status)
  );
  const completedTasks = tasks.filter((t) =>
    ["completed", "rated"].includes(t.status)
  );

  const bal = balance ?? 0;

  return (
    <div className="flex flex-col h-[calc(100dvh-3.5rem)]">
      {/* Polished header — big bold balance */}
      <div className="bg-gradient-pro px-4 pt-10 pb-4 text-white flex-shrink-0">
        <div className="max-w-lg mx-auto">
          <div className="flex items-start justify-between mb-3">
            <div>
              <p className="text-[10px] text-white/50 uppercase tracking-wider">Pro</p>
              <h1 className="text-lg font-bold leading-tight">
                {user?.name || user?.user || "Pro"}
              </h1>
            </div>
            {/* Hero balance — big and bold */}
            <div
              onClick={() => router.push("/pro/dashboard")}
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

          {/* Stat pills — interactive */}
          <div className="flex gap-2">
            {[
              { value: tasks.length, label: "Total", color: "bg-white/10" },
              { value: activeTasks.length, label: "Active", icon: Clock, color: "bg-orange-500/20" },
              { value: completedTasks.length, label: "Done", icon: CheckCircle, color: "bg-green-500/20" },
            ].map(({ value, label, color }) => (
              <div
                key={label}
                onClick={() => router.push("/pro/dashboard")}
                className={`flex-1 rounded-xl ${color} px-3 py-2 text-center cursor-pointer hover:bg-white/20 transition-colors`}
              >
                <div className="text-lg font-bold">{value}</div>
                <div className="text-[9px] text-white/60 uppercase">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Post task CTA */}
      <div className="max-w-lg mx-auto w-full px-4 py-2 flex-shrink-0">
        <button
          type="button"
          onClick={() => router.push("/pro/create")}
          className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-runner text-white font-semibold py-2.5 text-sm hover:opacity-90 transition-opacity active:scale-[0.98]"
        >
          <Plus className="h-4 w-4" />
          Post a Task
        </button>
      </div>

      {/* Chat messages */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 pb-2 space-y-3 max-w-lg mx-auto w-full"
      >
        {messages.length === 0 && (
          <div className="text-center py-10 space-y-3">
            <div className="text-4xl">💬</div>
            <p className="text-sm text-gray-500 font-medium">
              Your AI assistant for GoRunner
            </p>
            <div className="space-y-1">
              <p className="text-xs text-gray-400">Try saying:</p>
              <div className="flex flex-wrap justify-center gap-1.5">
                {[
                  "show my tasks",
                  "show stats",
                  "show leaderboard",
                  "show earnings",
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

      {/* Chat input with quick action pills */}
      <div className="flex-shrink-0 max-w-lg mx-auto w-full">
        <ChatInput
          onSend={sendMessage}
          sending={sending}
          quickActions={canon?.quick_actions}
        />
      </div>
    </div>
  );
}
