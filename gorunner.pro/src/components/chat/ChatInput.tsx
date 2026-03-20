"use client";

import { useState } from "react";
import { Send } from "lucide-react";
import type { QuickAction } from "@/lib/types";
import { TASK_ICONS } from "@/lib/types";

interface ChatInputProps {
  onSend: (text: string) => void;
  sending: boolean;
  quickActions?: QuickAction[];
  placeholder?: string;
}

export function ChatInput({
  onSend,
  sending,
  quickActions,
  placeholder = "Ask about tasks, runners, or credits...",
}: ChatInputProps) {
  const [input, setInput] = useState("");

  function handleSend() {
    if (!input.trim() || sending) return;
    onSend(input.trim());
    setInput("");
  }

  return (
    <div className="border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
      {/* Quick action pills */}
      {quickActions && quickActions.length > 0 && (
        <div className="px-3 pt-2 pb-1 flex gap-1.5 overflow-x-auto scrollbar-hide">
          {quickActions.map((a) => (
            <button
              key={a.key}
              onClick={() => onSend(a.message)}
              disabled={sending}
              className="flex-shrink-0 inline-flex items-center gap-1 rounded-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-gray-300 hover:border-purple-300 hover:text-purple-600 transition-colors disabled:opacity-50"
            >
              <span>{a.icon || TASK_ICONS[a.key] || "📋"}</span>
              {a.label}
            </button>
          ))}
        </div>
      )}

      {/* Text input */}
      <div className="px-3 py-2 flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          placeholder={placeholder}
          className="flex-1 rounded-full border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 px-4 py-2 text-sm outline-none focus:border-purple-400 transition-colors"
        />
        <button
          onClick={handleSend}
          disabled={!input.trim() || sending}
          className="rounded-full bg-purple-500 p-2.5 text-white disabled:opacity-50 transition-opacity"
        >
          <Send className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
