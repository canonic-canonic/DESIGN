"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { CHANNELS, RANKS } from "@/lib/constants";
import { initials } from "@/lib/utils";
import { Music, Library, Search, LogIn, LogOut, User } from "lucide-react";

export function ChannelSidebar({ onNavigate }: { onNavigate?: () => void } = {}) {
  const pathname = usePathname();
  const { user, loading, login, logout } = useAuth();

  const currentChannel = pathname.split("/chat/")[1]?.replace(/\/$/, "") || "general";
  const rankInfo = RANKS.find((r) => r.name === user?.rank) || RANKS[0];

  return (
    <aside className="w-[220px] h-full bg-bg-raised border-r border-border-subtle flex flex-col flex-shrink-0 overflow-y-auto">
      {/* Brand */}
      <div className="px-4 h-14 flex items-center gap-2.5 border-b border-border-subtle flex-shrink-0">
        <div className="w-7 h-7 rounded-full bg-accent flex items-center justify-center text-sm text-black font-bold">♫</div>
        <span className="font-bold text-[15px]">MusicChat</span>
      </div>

      {/* Channels */}
      <div className="px-2 py-3 flex-1">
        <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 px-2 mb-1.5">Channels</div>
        {CHANNELS.map((ch) => (
          <Link
            key={ch.id}
            href={`/chat/${ch.id}/`}
            onClick={onNavigate}
            className={`flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-sm transition-colors ${
              currentChannel === ch.id
                ? "bg-accent/15 text-accent font-medium"
                : "text-gray-400 hover:bg-bg-hover hover:text-gray-200"
            }`}
          >
            <span className="text-base">{ch.icon}</span>
            <span>{ch.name}</span>
          </Link>
        ))}

        <div className="h-px bg-border-subtle my-3 mx-2" />

        <div className="text-[10px] font-bold tracking-widest uppercase text-gray-500 px-2 mb-1.5">Browse</div>
        <Link
          href="/library/"
          className={`flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-sm transition-colors ${
            pathname.startsWith("/library") ? "bg-accent/15 text-accent font-medium" : "text-gray-400 hover:bg-bg-hover hover:text-gray-200"
          }`}
        >
          <Library size={16} />
          <span>Library</span>
        </Link>
        <Link
          href="/search/"
          onClick={onNavigate}
          className={`flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-sm transition-colors ${
            pathname.startsWith("/search") ? "bg-accent/15 text-accent font-medium" : "text-gray-400 hover:bg-bg-hover hover:text-gray-200"
          }`}
        >
          <Search size={16} />
          <span>Search</span>
        </Link>
        <Link
          href="/profile/"
          onClick={onNavigate}
          className={`flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-sm transition-colors ${
            pathname.startsWith("/profile") ? "bg-accent/15 text-accent font-medium" : "text-gray-400 hover:bg-bg-hover hover:text-gray-200"
          }`}
        >
          <User size={16} />
          <span>Profile</span>
        </Link>
      </div>

      {/* User panel at bottom */}
      <div className="p-3 border-t border-border-subtle flex-shrink-0">
        {loading ? (
          <div className="h-10 bg-bg-card rounded-lg animate-pulse" />
        ) : user ? (
          <div className="flex items-center gap-2.5">
            {user.avatar_url ? (
              <img src={user.avatar_url} alt="" className="w-8 h-8 rounded-full flex-shrink-0" />
            ) : (
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-accent to-green-600 flex items-center justify-center text-[11px] font-bold text-black flex-shrink-0">
                {initials(user.display_name)}
              </div>
            )}
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium truncate">{user.display_name || user.username}</div>
              <div className="text-[11px] text-gray-500">
                <span className={rankInfo.color}>{rankInfo.icon} {rankInfo.label}</span>
                {" · "}{user.credits}◈
              </div>
            </div>
            <button onClick={logout} className="p-1 text-gray-500 hover:text-gray-300 transition-colors" title="Sign out">
              <LogOut size={14} />
            </button>
          </div>
        ) : (
          <button
            onClick={login}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-accent text-black rounded-lg text-sm font-semibold hover:bg-green-400 transition-colors"
          >
            <LogIn size={14} />
            Sign in with GitHub
          </button>
        )}
      </div>
    </aside>
  );
}
