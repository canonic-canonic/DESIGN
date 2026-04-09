"use client";

import { createContext, useContext, useState, useRef, useCallback, useEffect, type ReactNode } from "react";
import { streamUrl, coverUrl, getRandomTracks, sendMessage } from "./api";
import type { Track } from "./types";

interface PlayerContextType {
  currentTrack: Track | null;
  queue: Track[];
  isPlaying: boolean;
  progress: number; // 0-1
  currentTime: number;
  duration: number;
  play: (track: Track) => void;
  pause: () => void;
  resume: () => void;
  toggle: () => void;
  next: () => void;
  prev: () => void;
  seek: (pct: number) => void;
  setVolume: (vol: number) => void;
  addToQueue: (track: Track) => void;
  clearQueue: () => void;
  shufflePlay: () => void;
}

const PlayerContext = createContext<PlayerContextType>({
  currentTrack: null, queue: [], isPlaying: false, progress: 0,
  currentTime: 0, duration: 0,
  play: () => {}, pause: () => {}, resume: () => {}, toggle: () => {},
  next: () => {}, prev: () => {}, seek: () => {}, setVolume: () => {},
  addToQueue: () => {}, clearQueue: () => {}, shufflePlay: () => {},
});

export function PlayerProvider({ children }: { children: ReactNode }) {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [currentTrack, setCurrentTrack] = useState<Track | null>(null);
  const [queue, setQueue] = useState<Track[]>([]);
  const [queueIdx, setQueueIdx] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);

  // Create audio element once
  useEffect(() => {
    const audio = new Audio();
    audio.volume = 0.8;
    audioRef.current = audio;

    audio.addEventListener("timeupdate", () => {
      setCurrentTime(audio.currentTime);
      setDuration(audio.duration || 0);
      setProgress(audio.duration ? audio.currentTime / audio.duration : 0);
    });
    audio.addEventListener("ended", () => {
      // Auto-advance
      setQueueIdx((prev) => {
        const next = prev + 1;
        if (next < queue.length) {
          playByIndex(next);
        } else {
          // Load more random tracks
          getRandomTracks(10).then((data) => {
            if (data.songs?.length) {
              setQueue((q) => {
                const updated = [...q, ...data.songs];
                playByIndex(q.length, updated);
                return updated;
              });
            }
          });
        }
        return prev;
      });
    });
    audio.addEventListener("play", () => setIsPlaying(true));
    audio.addEventListener("pause", () => setIsPlaying(false));

    return () => { audio.pause(); audio.src = ""; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-post to #now-playing (debounced, once per track)
  const lastPosted = useRef<string>("");

  const playByIndex = useCallback((idx: number, q?: Track[]) => {
    const audio = audioRef.current;
    const list = q || queue;
    if (!audio || idx < 0 || idx >= list.length) return;
    const track = list[idx];
    audio.src = streamUrl(track.id);
    audio.play().catch(() => {});
    setCurrentTrack(track);
    setQueueIdx(idx);

    // Auto-post to #now-playing if not already posted this track
    if (track.id !== lastPosted.current) {
      lastPosted.current = track.id;
      sendMessage("now-playing", `Now playing: ${track.title} — ${track.artist}`, track).catch(() => {});
    }
  }, [queue]);

  const play = useCallback((track: Track) => {
    setQueue((q) => {
      const existing = q.findIndex((t) => t.id === track.id);
      if (existing >= 0) {
        playByIndex(existing, q);
        return q;
      }
      const updated = [...q, track];
      playByIndex(updated.length - 1, updated);
      return updated;
    });
  }, [playByIndex]);

  const pause = useCallback(() => { audioRef.current?.pause(); }, []);
  const resume = useCallback(() => { audioRef.current?.play().catch(() => {}); }, []);
  const toggle = useCallback(() => {
    if (audioRef.current?.paused) resume(); else pause();
  }, [pause, resume]);

  const next = useCallback(() => {
    const nextIdx = queueIdx + 1;
    if (nextIdx < queue.length) {
      playByIndex(nextIdx);
    } else {
      getRandomTracks(10).then((data) => {
        if (data.songs?.length) {
          setQueue((q) => {
            const updated = [...q, ...data.songs];
            playByIndex(q.length, updated);
            return updated;
          });
        }
      });
    }
  }, [queueIdx, queue.length, playByIndex]);

  const prev = useCallback(() => {
    const audio = audioRef.current;
    if (!audio) return;
    if (audio.currentTime > 3) { audio.currentTime = 0; return; }
    if (queueIdx > 0) playByIndex(queueIdx - 1);
  }, [queueIdx, playByIndex]);

  const seek = useCallback((pct: number) => {
    const audio = audioRef.current;
    if (audio?.duration) audio.currentTime = pct * audio.duration;
  }, []);

  const setVolume = useCallback((vol: number) => {
    if (audioRef.current) audioRef.current.volume = vol;
  }, []);

  const addToQueue = useCallback((track: Track) => {
    setQueue((q) => [...q, track]);
  }, []);

  const clearQueue = useCallback(() => {
    setQueue([]);
    setQueueIdx(-1);
  }, []);

  const shufflePlay = useCallback(async () => {
    const data = await getRandomTracks(20);
    if (data.songs?.length) {
      setQueue(data.songs);
      playByIndex(0, data.songs);
    }
  }, [playByIndex]);

  return (
    <PlayerContext.Provider value={{
      currentTrack, queue, isPlaying, progress, currentTime, duration,
      play, pause, resume, toggle, next, prev, seek, setVolume,
      addToQueue, clearQueue, shufflePlay,
    }}>
      {children}
    </PlayerContext.Provider>
  );
}

export function usePlayer() {
  return useContext(PlayerContext);
}

export { coverUrl };
