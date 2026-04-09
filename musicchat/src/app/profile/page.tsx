"use client";

import { useAuth } from "@/lib/auth";
import useSWR from "swr";
import { getCredits } from "@/lib/api";
import { RANKS } from "@/lib/constants";
import { timeAgo } from "@/lib/utils";

export default function ProfilePage() {
  const { user, loading } = useAuth();
  const { data } = useSWR(user ? "credits" : null, () => getCredits(30));

  if (loading) return <div className="flex-1 flex items-center justify-center text-gray-500">Loading...</div>;
  if (!user) return <div className="flex-1 flex items-center justify-center text-gray-500">Sign in to view your profile</div>;

  const rank = RANKS.find((r) => r.name === user.rank) || RANKS[0];
  const nextRank = RANKS.find((r) => r.threshold > user.credits);

  return (
    <>
      <div className="h-14 px-4 flex items-center border-b border-border-subtle flex-shrink-0">
        <span className="font-semibold">Your Profile</span>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {/* Profile card */}
        <div className="flex items-center gap-4 mb-8">
          {user.avatar_url ? (
            <img src={user.avatar_url} alt="" className="w-20 h-20 rounded-full" />
          ) : (
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-accent to-green-600 flex items-center justify-center text-2xl font-bold text-black">
              {user.display_name?.charAt(0) || "?"}
            </div>
          )}
          <div>
            <h1 className="text-2xl font-bold">{user.display_name || user.username}</h1>
            <div className="text-sm text-gray-400">@{user.username} · {user.post_count} posts</div>
            <div className="flex items-center gap-3 mt-2">
              <span className={`text-sm font-semibold ${rank.color}`}>{rank.icon} {rank.label}</span>
              <span className="text-lg font-bold text-accent">{user.credits}◈</span>
            </div>
            {nextRank && (
              <div className="text-xs text-gray-500 mt-1">
                {nextRank.threshold - user.credits}◈ to {nextRank.label}
              </div>
            )}
          </div>
        </div>

        {/* Credit history */}
        <h2 className="text-xs font-bold tracking-widest uppercase text-gray-500 mb-3">Credit History</h2>
        <div className="space-y-1 max-w-lg">
          {data?.history?.map((e) => (
            <div key={e.id} className="flex items-center justify-between py-2 border-b border-border-subtle">
              <div>
                <div className="text-sm">{e.reason.replace(/_/g, " ")}</div>
                <div className="text-[11px] text-gray-500">{timeAgo(e.created_at)}</div>
              </div>
              <span className={`font-bold font-mono text-sm ${e.amount > 0 ? "text-accent" : "text-red-400"}`}>
                {e.amount > 0 ? "+" : ""}{e.amount}◈
              </span>
            </div>
          ))}
          {!data?.history?.length && <div className="text-sm text-gray-500">No credit events yet</div>}
        </div>
      </div>
    </>
  );
}
