"use client";

import { useState, useRef, useEffect } from "react";
import { sendChat } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { X, Send } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ChatOverlayProps {
  taskId: string;
  onClose: () => void;
}

export function ChatOverlay({ taskId, onClose }: ChatOverlayProps) {
  const { identity } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages]);

  async function handleSend() {
    if (!input.trim() || sending) return;
    const text = input.trim();
    setInput("");

    const userMsg: Message = {
      role: "user",
      content: text,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setSending(true);

    try {
      const res = await sendChat(text, {
        runner_user: {
          id: identity?.userId,
          role: identity?.role,
          principal: identity?.principal,
        },
        task_id: taskId,
      });
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: res.reply || "I'm here to help with your task.",
          timestamp: new Date(),
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Connection issue. Please try again.",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setSending(false);
    }
  }

  const quickMessages = [
    "Where are you?",
    "How long?",
    "Any issues?",
    "Thanks!",
  ];

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-black/50">
      <div className="flex-1" onClick={onClose} />
      <div className="animate-slide-up max-h-[70vh] w-full max-w-lg mx-auto flex flex-col rounded-t-2xl bg-white dark:bg-gray-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-800">
          <h3 className="font-semibold text-sm">Task Chat</h3>
          <button onClick={onClose} className="text-gray-400">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Messages */}
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto p-4 space-y-3"
        >
          {messages.length === 0 && (
            <p className="text-center text-xs text-gray-400 py-8">
              Ask about this task or coordinate with your runner
            </p>
          )}
          {messages.map((msg, i) => (
            <div
              key={i}
              className={`flex ${
                msg.role === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`max-w-[80%] rounded-2xl px-3 py-2 text-sm ${
                  msg.role === "user"
                    ? "bg-purple-500 text-white"
                    : "bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                }`}
              >
                {msg.content}
              </div>
            </div>
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

        {/* Quick messages */}
        <div className="px-4 py-2 flex gap-1 overflow-x-auto">
          {quickMessages.map((qm) => (
            <button
              key={qm}
              onClick={() => {
                setInput(qm);
              }}
              className="flex-shrink-0 rounded-full border border-gray-200 dark:border-gray-700 px-3 py-1 text-xs text-gray-600 dark:text-gray-400 hover:border-purple-300"
            >
              {qm}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800 flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Type a message..."
            className="flex-1 rounded-full border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 px-4 py-2 text-sm outline-none focus:border-purple-400"
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || sending}
            className="rounded-full bg-purple-500 p-2 text-white disabled:opacity-50"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
