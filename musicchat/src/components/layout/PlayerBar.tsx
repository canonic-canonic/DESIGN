"use client";

import { usePlayer, coverUrl } from "@/lib/player";
import { formatDuration } from "@/lib/utils";
import { SkipBack, SkipForward, Play, Pause, Volume2, Flag } from "lucide-react";
import { useState } from "react";
import { FlagForm } from "@/components/chat/FlagForm";

export function PlayerBar() {
  const { currentTrack, isPlaying, progress, currentTime, duration, toggle, next, prev, seek, setVolume } = usePlayer();

  const [showFlag, setShowFlag] = useState(false);

  if (!currentTrack) return null;

  return (
    <>
    {showFlag && <FlagForm track={currentTrack} onClose={() => setShowFlag(false)} />}
    <div className="fixed bottom-0 left-0 right-0 h-[72px] bg-bg-raised/90 backdrop-blur-xl border-t border-border-subtle z-50 flex items-center gap-4 px-6">
      {/* Cover art */}
      {currentTrack.coverArt ? (
        <img src={coverUrl(currentTrack.coverArt)} alt="" className="w-12 h-12 rounded-lg object-cover flex-shrink-0" />
      ) : (
        <div className="w-12 h-12 rounded-lg bg-bg-card flex items-center justify-center text-xl flex-shrink-0">🎵</div>
      )}

      {/* Track info */}
      <div className="w-[180px] min-w-0 flex-shrink-0">
        <div className="text-sm font-semibold truncate">{currentTrack.title}</div>
        <div className="text-xs text-gray-400 truncate">{currentTrack.artist}</div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 flex-shrink-0">
        <button onClick={prev} className="p-1.5 rounded-full hover:bg-bg-hover transition-colors">
          <SkipBack size={18} />
        </button>
        <button onClick={toggle} className="w-10 h-10 rounded-full bg-accent text-black flex items-center justify-center hover:bg-green-400 transition-colors">
          {isPlaying ? <Pause size={18} /> : <Play size={18} className="ml-0.5" />}
        </button>
        <button onClick={next} className="p-1.5 rounded-full hover:bg-bg-hover transition-colors">
          <SkipForward size={18} />
        </button>
      </div>

      {/* Progress */}
      <div className="flex-1 flex items-center gap-2">
        <span className="text-[11px] text-gray-500 font-mono w-10 text-center">{formatDuration(currentTime)}</span>
        <input
          type="range" min={0} max={100} value={progress * 100}
          onChange={(e) => seek(Number(e.target.value) / 100)}
          className="flex-1 h-1 appearance-none bg-bg-hover rounded-full cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-accent [&::-webkit-slider-thumb]:cursor-pointer"
        />
        <span className="text-[11px] text-gray-500 font-mono w-10 text-center">{formatDuration(duration)}</span>
      </div>

      {/* Flag + Volume */}
      <button onClick={() => setShowFlag(true)} className="p-1.5 rounded-full text-gray-500 hover:text-red-400 hover:bg-red-400/10 transition-colors" title="Flag this track">
        <Flag size={16} />
      </button>
      <div className="flex items-center gap-2 flex-shrink-0">
        <Volume2 size={16} className="text-gray-500" />
        <input
          type="range" min={0} max={100} defaultValue={80}
          onChange={(e) => setVolume(Number(e.target.value) / 100)}
          aria-label="Volume"
          className="w-20 h-1 appearance-none bg-bg-hover rounded-full cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-2.5 [&::-webkit-slider-thumb]:h-2.5 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-gray-400 [&::-webkit-slider-thumb]:cursor-pointer"
        />
      </div>
    </div>
    </>

  );
}
