"use client";

import { timeAgo, initials, avatarGradient } from "@/lib/utils";
import { RANKS, REACTIONS } from "@/lib/constants";
import { TrackEmbed } from "./TrackEmbed";
import type { Message, Track } from "@/lib/types";

interface Props {
  message: Message;
  onReact: (messageId: string, emoji: string) => void;
  onFlag?: (track: Track) => void;
}

export function MessageBubble({ message, onReact, onFlag }: Props) {
  const rank = RANKS.find((r) => r.name === message.author_rank) || RANKS[0];
  const trackEmbed = message.track_embed ? (typeof message.track_embed === "string" ? JSON.parse(message.track_embed) : message.track_embed) as Track : null;

  return (
    <div className="flex gap-3 px-4 py-2.5 hover:bg-bg-raised/50 transition-colors group">
      {/* Avatar */}
      {message.avatar_url ? (
        <img src={message.avatar_url} alt="" className="w-9 h-9 rounded-full flex-shrink-0 mt-0.5" />
      ) : (
        <div className={`w-9 h-9 rounded-full bg-gradient-to-br ${avatarGradient(message.author_id)} flex items-center justify-center text-[11px] font-bold text-black flex-shrink-0 mt-0.5`}>
          {initials(message.display_name)}
        </div>
      )}

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-2">
          <span className="font-semibold text-sm">{message.display_name || message.username}</span>
          {message.author_rank && message.author_rank !== "listener" && (
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${rank.color} bg-current/10`}>
              {rank.label}
            </span>
          )}
          <span className="text-[11px] text-gray-500">{timeAgo(message.created_at)}</span>
        </div>

        <div className="text-sm text-gray-200 mt-0.5 leading-relaxed whitespace-pre-wrap">{message.body}</div>

        {/* Track embed */}
        {trackEmbed && (
          <div className="mt-2 max-w-md">
            <TrackEmbed track={trackEmbed} onFlag={onFlag} />
          </div>
        )}

        {/* Reactions */}
        <div className="flex items-center gap-1 mt-1.5 flex-wrap">
          {message.reactions?.map((r) => (
            <button
              key={r.emoji}
              onClick={() => onReact(message.id, r.emoji)}
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border transition-colors ${
                r.reacted
                  ? "border-accent/30 bg-accent/10 text-accent"
                  : "border-border bg-bg-card text-gray-400 hover:border-gray-500"
              }`}
            >
              <span>{r.emoji}</span>
              <span className="font-medium">{r.count}</span>
            </button>
          ))}

          {/* Add reaction (visible on hover) */}
          <div className="opacity-0 group-hover:opacity-100 transition-opacity flex gap-0.5">
            {REACTIONS.map((r) => (
              <button
                key={r.emoji}
                onClick={() => onReact(message.id, r.emoji)}
                className="p-1 rounded hover:bg-bg-hover transition-colors text-sm"
                title={r.label}
              >
                {r.emoji}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
