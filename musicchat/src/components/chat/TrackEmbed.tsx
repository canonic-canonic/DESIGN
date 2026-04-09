"use client";

import { usePlayer, coverUrl } from "@/lib/player";
import { formatDuration } from "@/lib/utils";
import type { Track } from "@/lib/types";
import { Play, Pause, Flag } from "lucide-react";

export function TrackEmbed({ track, onFlag }: { track: Track; onFlag?: (track: Track) => void }) {
  const { play, pause, currentTrack, isPlaying } = usePlayer();
  const isCurrent = currentTrack?.id === track.id;
  const playing = isCurrent && isPlaying;

  return (
    <div
      className="flex items-center gap-3 p-3 bg-bg-card border border-border rounded-xl hover:border-accent/50 transition-colors cursor-pointer group"
      onClick={() => (playing ? pause() : play(track))}
    >
      <div className="w-12 h-12 rounded-lg bg-bg-hover flex-shrink-0 relative overflow-hidden flex items-center justify-center">
        {track.coverArt ? (
          <img src={coverUrl(track.coverArt)} alt="" className="w-full h-full object-cover" />
        ) : (
          <span className="text-xl">🎵</span>
        )}
        <div className="absolute inset-0 bg-black/40 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
          {playing ? <Pause size={16} className="text-accent" /> : <Play size={16} className="text-accent ml-0.5" />}
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold truncate">{track.title}</div>
        <div className="text-xs text-gray-400 truncate">{track.artist}</div>
      </div>
      <div className="text-xs text-gray-500 font-mono flex-shrink-0">{formatDuration(track.duration)}</div>
      {onFlag && (
        <button
          onClick={(e) => { e.stopPropagation(); onFlag(track); }}
          className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-400/10 transition-colors opacity-0 group-hover:opacity-100"
          title="Flag this track"
        >
          <Flag size={14} />
        </button>
      )}
    </div>
  );
}
