"use client";

import type { CoinEventMessage } from "@/lib/chatTypes";
import { cn } from "@/lib/utils";

const EVENT_STYLES: Record<
  CoinEventMessage["event"],
  { bg: string; text: string; icon: string; sign: string }
> = {
  earned: {
    bg: "bg-green-50 dark:bg-green-900/10",
    text: "text-green-700 dark:text-green-300",
    icon: "🟢",
    sign: "+",
  },
  spent: {
    bg: "bg-amber-50 dark:bg-amber-900/10",
    text: "text-amber-700 dark:text-amber-300",
    icon: "🟡",
    sign: "-",
  },
  tip: {
    bg: "bg-purple-50 dark:bg-purple-900/10",
    text: "text-purple-700 dark:text-purple-300",
    icon: "💜",
    sign: "+",
  },
  purchased: {
    bg: "bg-blue-50 dark:bg-blue-900/10",
    text: "text-blue-700 dark:text-blue-300",
    icon: "💰",
    sign: "+",
  },
};

export function CoinEventCard({ msg }: { msg: CoinEventMessage }) {
  const style = EVENT_STYLES[msg.event];

  return (
    <div
      className={cn(
        "rounded-xl px-4 py-3 flex items-center gap-3",
        style.bg
      )}
    >
      <span className="text-lg">{style.icon}</span>
      <div className="flex-1 min-w-0">
        <div className={cn("text-sm font-medium", style.text)}>
          {msg.label}
        </div>
        <div className="text-xs text-gray-500">
          {msg.timestamp.toLocaleTimeString(undefined, {
            hour: "numeric",
            minute: "2-digit",
          })}
        </div>
      </div>
      <div className={cn("text-sm font-bold", style.text)}>
        {style.sign}∩{msg.amount}
      </div>
    </div>
  );
}
