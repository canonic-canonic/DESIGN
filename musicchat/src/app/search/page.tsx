"use client";

import { useState } from "react";
import useSWR from "swr";
import { searchMusic } from "@/lib/api";
import { TrackEmbed } from "@/components/chat/TrackEmbed";
import { usePlayer } from "@/lib/player";
import { Search as SearchIcon } from "lucide-react";
import Link from "next/link";
import { initials, avatarGradient } from "@/lib/utils";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const { data } = useSWR(query.length >= 2 ? `search-${query}` : null, () => searchMusic(query), { dedupingInterval: 500 });

  return (
    <>
      <div className="h-14 px-4 flex items-center gap-3 border-b border-border-subtle flex-shrink-0">
        <SearchIcon size={18} className="text-gray-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search artists, tracks, albums..."
          className="flex-1 bg-transparent text-sm outline-none placeholder:text-gray-600"
          autoFocus
        />
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {!query && <div className="text-center text-gray-500 py-12">Type to search the library</div>}

        {data?.artists?.length ? (
          <div className="mb-6">
            <h3 className="text-xs font-bold tracking-widest uppercase text-gray-500 mb-3">Artists</h3>
            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-3">
              {data.artists.map((a) => (
                <Link key={a.id} href={`/library/artist/${a.id}/`} className="p-3 bg-bg-card border border-border rounded-xl hover:border-accent/50 transition-colors text-center">
                  <div className={`w-10 h-10 rounded-full mx-auto mb-2 bg-gradient-to-br ${avatarGradient(a.id)} flex items-center justify-center text-xs font-bold text-black`}>
                    {initials(a.name)}
                  </div>
                  <div className="text-xs font-medium truncate">{a.name}</div>
                </Link>
              ))}
            </div>
          </div>
        ) : null}

        {data?.songs?.length ? (
          <div>
            <h3 className="text-xs font-bold tracking-widest uppercase text-gray-500 mb-3">Tracks</h3>
            <div className="space-y-2 max-w-2xl">
              {data.songs.map((s) => (
                <TrackEmbed key={s.id} track={s} />
              ))}
            </div>
          </div>
        ) : null}

        {query && data && !data.artists?.length && !data.songs?.length && (
          <div className="text-center text-gray-500 py-12">No results for &ldquo;{query}&rdquo;</div>
        )}
      </div>
    </>
  );
}
