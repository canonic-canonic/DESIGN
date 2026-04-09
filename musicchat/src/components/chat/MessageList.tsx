"use client";

import { useEffect, useRef } from "react";
import { MessageBubble } from "./MessageBubble";
import type { Message, Track } from "@/lib/types";

interface Props {
  messages: Message[];
  onReact: (messageId: string, emoji: string) => void;
  onFlag?: (track: Track) => void;
}

export function MessageList({ messages, onReact, onFlag }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const wasAtBottom = useRef(true);

  // Track if user is at bottom
  const handleScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    wasAtBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
  };

  // Auto-scroll on new messages (only if already at bottom)
  useEffect(() => {
    if (wasAtBottom.current) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages.length]);

  if (!messages.length) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <div className="text-3xl mb-3">💬</div>
          <div className="text-gray-400 font-medium">No messages yet</div>
          <div className="text-sm text-gray-600 mt-1">Be the first to say something</div>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} onScroll={handleScroll} className="flex-1 overflow-y-auto">
      <div className="py-4">
        {messages.map((msg) => (
          <MessageBubble key={msg.id} message={msg} onReact={onReact} onFlag={onFlag} />
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
