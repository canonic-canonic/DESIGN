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
import { Plus, CheckCircle, Clock, List } from "lucide-react";

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

  return (
    <div className="flex flex-col h-screen">
      {/* Compact header */}
      <div className="bg-gradient-pro px-4 pt-10 pb-4 text-white flex-shrink-0">
        <div className="max-w-lg mx-auto">
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-xs text-white/70">Pro</p>
              <h1 className="text-lg font-bold">
                {user?.name || user?.user || "Pro"}
              </h1>
            </div>
            <CoinBalance
              balance={balance ?? 0}
              className="bg-white/10 text-amber-300"
            />
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[
              { icon: List, value: tasks.length, label: "Total" },
              { icon: Clock, value: activeTasks.length, label: "Active" },
              { icon: CheckCircle, value: completedTasks.length, label: "Done" },
            ].map(({ icon: Icon, value, label }) => (
              <div key={label} className="rounded-lg bg-white/10 p-2 text-center">
                <Icon className="h-3.5 w-3.5 mx-auto mb-0.5 text-white/70" />
                <div className="text-sm font-bold">{value}</div>
                <div className="text-[9px] text-white/60">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Post task CTA */}
      <div className="max-w-lg mx-auto w-full px-4 py-2 flex-shrink-0">
        <button
          onClick={() => router.push("/pro/create")}
          className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-runner text-white font-semibold py-2.5 text-sm hover:opacity-90 transition-opacity"
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
          <div className="text-center py-8 space-y-2">
            <p className="text-sm text-gray-400">
              Chat with your assistant or tap a quick action
            </p>
            <p className="text-xs text-gray-300">
              Try &quot;show my tasks&quot; or &quot;show stats&quot;
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

      {/* Chat input with quick action pills */}
      <div className="flex-shrink-0 max-w-lg mx-auto w-full safe-area-pb pb-16">
        <ChatInput
          onSend={sendMessage}
          sending={sending}
          quickActions={canon?.quick_actions}
        />
      </div>
    </div>
  );
}
