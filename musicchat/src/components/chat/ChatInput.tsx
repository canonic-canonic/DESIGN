"use client";

import { useState, useRef, type KeyboardEvent } from "react";
import { useAuth } from "@/lib/auth";
import { usePlayer } from "@/lib/player";
import { initials } from "@/lib/utils";
import { Send, Music, LogIn } from "lucide-react";
import type { Track } from "@/lib/types";

interface Props {
  onSend: (body: string, trackEmbed?: Track) => Promise<void>;
  channelName: string;
}

export function ChatInput({ onSend, channelName }: Props) {
  const { user, login } = useAuth();
  const { currentTrack } = usePlayer();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [attachTrack, setAttachTrack] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  if (!user) {
    return (
      <div className="p-4 border-t border-border-subtle">
        <button
          onClick={login}
          className="w-full flex items-center justify-center gap-2 py-3 bg-bg-card border border-border rounded-xl text-sm text-gray-400 hover:border-accent hover:text-accent transition-colors"
        >
          <LogIn size={16} />
          Sign in to chat and earn credits
        </button>
      </div>
    );
  }

  const handleSend = async () => {
    const body = text.trim();
    if (!body || sending) return;
    setSending(true);
    try {
      await onSend(body, attachTrack && currentTrack ? currentTrack : undefined);
      setText("");
      setAttachTrack(false);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="p-4 border-t border-border-subtle">
      {/* Attached track preview */}
      {attachTrack && currentTrack && (
        <div className="mb-2 flex items-center gap-2 p-2 bg-bg-card rounded-lg text-xs">
          <Music size={14} className="text-accent" />
          <span className="text-gray-300">{currentTrack.title} — {currentTrack.artist}</span>
          <button onClick={() => setAttachTrack(false)} className="ml-auto text-gray-500 hover:text-gray-300">&times;</button>
        </div>
      )}

      <div className="flex items-center gap-2">
        {/* Avatar */}
        {user.avatar_url ? (
          <img src={user.avatar_url} alt="" className="w-8 h-8 rounded-full flex-shrink-0" />
        ) : (
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-accent to-green-600 flex items-center justify-center text-[10px] font-bold text-black flex-shrink-0">
            {initials(user.display_name)}
          </div>
        )}

        {/* Input */}
        <div className="flex-1 flex items-center bg-bg-card border border-border rounded-xl px-3 focus-within:border-accent transition-colors">
          <input
            ref={inputRef}
            type="text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={handleKey}
            placeholder={`Message #${channelName}...`}
            className="flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-gray-600"
          />

          {/* Share now playing button */}
          {currentTrack && (
            <button
              onClick={() => setAttachTrack(!attachTrack)}
              className={`p-1.5 rounded-lg transition-colors ${attachTrack ? "text-accent" : "text-gray-500 hover:text-gray-300"}`}
              title="Share now playing"
            >
              <Music size={16} />
            </button>
          )}

          {/* Send */}
          <button
            onClick={handleSend}
            disabled={!text.trim() || sending}
            className="p-1.5 rounded-lg text-accent disabled:text-gray-600 disabled:cursor-not-allowed hover:bg-accent/10 transition-colors"
          >
            <Send size={16} />
          </button>
        </div>
      </div>

      <div className="text-[10px] text-gray-600 mt-1.5 px-10">
        +2◈ per message{currentTrack ? " · attach track for +3◈ bonus" : ""}
        {text.startsWith("@musicchat") ? " · AI will respond" : ""}
      </div>
    </div>
  );
}
