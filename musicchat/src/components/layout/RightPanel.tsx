"use client";

import useSWR from "swr";
import { usePlayer, coverUrl } from "@/lib/player";
import { getLeaderboard, getMusicStats } from "@/lib/api";
import { initials, avatarGradient } from "@/lib/utils";
import { RANKS } from "@/lib/constants";

export function RightPanel() {
  const { currentTrack, isPlaying, shufflePlay } = usePlayer();
  const { data: stats } = useSWR("music-stats", () => getMusicStats(), { refreshInterval: 60000 });
  const { data: leaders } = useSWR("leaderboard", () => getLeaderboard(5), { refreshInterval: 30000 });

  return (
    <aside className="w-[280px] h-full bg-bg border-l border-border-subtle overflow-y-auto flex-shrink-0 p-4 space-y-5">
      {/* Now Playing */}
      <div>
        <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 mb-2">Now Spinning</div>
        <div className="p-4 rounded-xl bg-gradient-to-br from-green-950/50 to-bg-card border border-accent/15 relative overflow-hidden">
          <div className="absolute -top-8 -right-8 w-24 h-24 bg-accent/20 rounded-full blur-2xl" />
          <div className="flex items-center gap-1.5 text-[10px] font-semibold text-accent uppercase tracking-wider mb-2">
            <div className={`w-1.5 h-1.5 rounded-full bg-accent ${isPlaying ? "animate-blink" : ""}`} />
            {isPlaying ? "Live" : "Paused"}
          </div>
          {currentTrack ? (
            <>
              <div className="font-bold text-sm">{currentTrack.title}</div>
              <div className="text-xs text-gray-400 mt-0.5">{currentTrack.artist}</div>
            </>
          ) : (
            <>
              <div className="font-bold text-sm">Nothing spinning</div>
              <div className="text-xs text-gray-400 mt-0.5">Queue something up</div>
            </>
          )}
          {!currentTrack && (
            <button onClick={shufflePlay} className="mt-3 text-xs font-semibold text-accent hover:underline">
              Shuffle Play
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div>
          <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 mb-2">Library</div>
          <div className="grid grid-cols-3 gap-2">
            <div className="text-center p-2 bg-bg-card rounded-lg">
              <div className="text-lg font-bold">{stats.tracks.toLocaleString()}</div>
              <div className="text-[10px] text-gray-500 uppercase">Tracks</div>
            </div>
            <div className="text-center p-2 bg-bg-card rounded-lg">
              <div className="text-lg font-bold">{stats.artists.toLocaleString()}</div>
              <div className="text-[10px] text-gray-500 uppercase">Artists</div>
            </div>
            <div className="text-center p-2 bg-bg-card rounded-lg">
              <div className="text-lg font-bold">{stats.genres}</div>
              <div className="text-[10px] text-gray-500 uppercase">Genres</div>
            </div>
          </div>
        </div>
      )}

      {/* Leaderboard */}
      <div>
        <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 mb-2">Top Contributors</div>
        {leaders?.leaders?.length ? (
          <div className="space-y-1">
            {leaders.leaders.map((u, i) => {
              const rank = RANKS.find((r) => r.name === u.rank) || RANKS[0];
              const medals = ["🥇", "🥈", "🥉", "4", "5"];
              return (
                <div key={u.id} className="flex items-center gap-2 p-1.5 rounded-lg">
                  <span className="text-sm w-5 text-center">{medals[i]}</span>
                  {u.avatar_url ? (
                    <img src={u.avatar_url} alt="" className="w-7 h-7 rounded-full" />
                  ) : (
                    <div className={`w-7 h-7 rounded-full bg-gradient-to-br ${avatarGradient(u.id)} flex items-center justify-center text-[10px] font-bold text-black`}>
                      {initials(u.display_name)}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{u.display_name || u.username}</div>
                    <div className="text-[10px] text-gray-500">{rank.label} · {u.post_count} posts</div>
                  </div>
                  <span className="text-xs font-bold text-accent font-mono">{u.credits}◈</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-xs text-gray-500 p-2">No contributors yet. Be the first!</div>
        )}
      </div>

      {/* Earn Credits */}
      <div>
        <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 mb-2">Earn Credits</div>
        <div className="bg-bg-card border border-border rounded-xl p-3 space-y-1.5">
          <div className="font-semibold text-sm mb-2">Knowledge = Currency</div>
          {[
            ["Send a message", "+2◈"],
            ["Share a track", "+3◈"],
            ["Get upvoted", "+1◈"],
            ["Flag bad data", "+4◈"],
          ].map(([action, amount]) => (
            <div key={action} className="flex items-center justify-between text-xs">
              <span className="text-gray-400">{action}</span>
              <span className="font-semibold text-accent font-mono">{amount}</span>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
