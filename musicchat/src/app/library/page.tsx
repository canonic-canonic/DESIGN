"use client";

import { useState } from "react";
import useSWR from "swr";
import { getArtists, getArtist, getAlbum } from "@/lib/api";
import { coverUrl } from "@/lib/player";
import { usePlayer } from "@/lib/player";
import { initials, avatarGradient, formatDuration } from "@/lib/utils";
import { Shuffle, ArrowLeft, Play, Plus, Flag } from "lucide-react";
import { FlagForm } from "@/components/chat/FlagForm";
import type { Track } from "@/lib/types";

export default function LibraryPage() {
  const [selectedArtist, setSelectedArtist] = useState<string | null>(null);
  const [selectedAlbum, setSelectedAlbum] = useState<string | null>(null);
  const [flagTrack, setFlagTrack] = useState<Track | null>(null);

  if (selectedAlbum) return <AlbumDetail id={selectedAlbum} onBack={() => setSelectedAlbum(null)} onFlag={setFlagTrack} flagTrack={flagTrack} onCloseFlag={() => setFlagTrack(null)} />;
  if (selectedArtist) return <ArtistDetail id={selectedArtist} onBack={() => setSelectedArtist(null)} onSelectAlbum={setSelectedAlbum} />;
  return <ArtistGrid onSelectArtist={setSelectedArtist} />;
}

function ArtistGrid({ onSelectArtist }: { onSelectArtist: (id: string) => void }) {
  const { data, error } = useSWR("artists", () => getArtists());
  const { shufflePlay } = usePlayer();

  return (
    <>
      <div className="h-14 px-4 flex items-center justify-between border-b border-border-subtle flex-shrink-0">
        <span className="font-semibold">Library</span>
        <button onClick={shufflePlay} className="flex items-center gap-2 px-4 py-1.5 bg-accent text-black rounded-full text-sm font-semibold hover:bg-green-400 transition-colors">
          <Shuffle size={14} /> Shuffle Play
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 sm:p-6">
        {error && <div className="text-red-400 text-center py-8">Failed to load artists</div>}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-3">
          {data?.artists?.map((artist) => (
            <button
              key={artist.id}
              onClick={() => onSelectArtist(artist.id)}
              className="group p-4 bg-bg-card border border-border rounded-xl hover:border-accent/50 hover:-translate-y-0.5 transition-all text-center"
            >
              {artist.coverArt ? (
                <img src={coverUrl(artist.coverArt)} alt="" className="w-14 h-14 rounded-full mx-auto mb-2 object-cover" />
              ) : (
                <div className={`w-14 h-14 rounded-full mx-auto mb-2 bg-gradient-to-br ${avatarGradient(artist.id)} flex items-center justify-center text-base font-bold text-black`}>
                  {initials(artist.name)}
                </div>
              )}
              <div className="font-semibold text-sm truncate">{artist.name}</div>
              <div className="text-xs text-gray-500 mt-0.5">{artist.albumCount} albums</div>
            </button>
          ))}
        </div>
      </div>
    </>
  );
}

function ArtistDetail({ id, onBack, onSelectAlbum }: { id: string; onBack: () => void; onSelectAlbum: (id: string) => void }) {
  const { data, error } = useSWR(id ? `artist-${id}` : null, () => getArtist(id));

  if (error) return <div className="flex-1 flex items-center justify-center text-red-400">Failed to load artist</div>;
  if (!data) return <div className="flex-1 flex items-center justify-center text-gray-500">Loading...</div>;

  return (
    <>
      <div className="h-14 px-4 flex items-center gap-3 border-b border-border-subtle flex-shrink-0">
        <button onClick={onBack} className="p-1 hover:bg-bg-hover rounded-lg transition-colors">
          <ArrowLeft size={18} />
        </button>
        <span className="font-semibold">{data.name}</span>
        <span className="text-xs text-gray-500">{data.albumCount} albums</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {/* Artist header with image */}
        <div className="p-6 flex items-start gap-5 border-b border-border-subtle">
          {data.artistImage ? (
            <img src={data.artistImage} alt={data.name} className="w-28 h-28 rounded-2xl object-cover flex-shrink-0 shadow-lg" />
          ) : data.coverArt ? (
            <img src={coverUrl(data.coverArt)} alt={data.name} className="w-28 h-28 rounded-2xl object-cover flex-shrink-0 shadow-lg" />
          ) : (
            <div className={`w-28 h-28 rounded-2xl bg-gradient-to-br ${avatarGradient(data.id)} flex items-center justify-center text-3xl font-bold text-black flex-shrink-0`}>
              {initials(data.name)}
            </div>
          )}
          <div className="min-w-0">
            <h1 className="text-2xl font-bold">{data.name}</h1>
            <p className="text-sm text-gray-400 mt-1">{data.albumCount} albums in library</p>
            {data.biography && (
              <p className="text-sm text-gray-400 mt-3 leading-relaxed line-clamp-4" dangerouslySetInnerHTML={{ __html: data.biography }} />
            )}
            {data.similarArtists?.length > 0 && (
              <div className="mt-3 flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-bold tracking-wider uppercase text-gray-500">Similar:</span>
                {data.similarArtists.map((s) => (
                  <span key={s.id} className="text-xs text-gray-400 bg-bg-card px-2 py-0.5 rounded-full">{s.name}</span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="p-4 sm:p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {data.albums?.map((album) => (
            <button
              key={album.id}
              onClick={() => onSelectAlbum(album.id)}
              className="flex items-center gap-3 p-3 bg-bg-card border border-border rounded-xl hover:border-accent/50 transition-colors text-left"
            >
              {album.coverArt ? (
                <img src={coverUrl(album.coverArt)} alt="" className="w-14 h-14 rounded-lg object-cover flex-shrink-0" />
              ) : (
                <div className="w-14 h-14 rounded-lg bg-bg-hover flex items-center justify-center text-xl flex-shrink-0">💿</div>
              )}
              <div className="min-w-0">
                <div className="font-semibold text-sm truncate">{album.name}</div>
                <div className="text-xs text-gray-500">{album.songCount} tracks{album.year ? ` · ${album.year}` : ""}</div>
                {album.genre && <div className="text-[10px] text-gray-600">{album.genre}</div>}
              </div>
            </button>
          ))}
        </div>
      </div>
    </>
  );
}

function AlbumDetail({ id, onBack, onFlag, flagTrack, onCloseFlag }: { id: string; onBack: () => void; onFlag: (t: Track) => void; flagTrack: Track | null; onCloseFlag: () => void }) {
  const { data, error } = useSWR(id ? `album-${id}` : null, () => getAlbum(id));
  const { play, addToQueue, currentTrack, isPlaying } = usePlayer();

  if (error) return <div className="flex-1 flex items-center justify-center text-red-400">Failed to load album</div>;
  if (!data) return <div className="flex-1 flex items-center justify-center text-gray-500">Loading...</div>;

  const playAll = () => {
    if (data.songs?.length) {
      play(data.songs[0]);
      data.songs.slice(1).forEach((s) => addToQueue(s));
    }
  };

  return (
    <>
      <div className="h-14 px-4 flex items-center gap-3 border-b border-border-subtle flex-shrink-0">
        <button onClick={onBack} className="p-1 hover:bg-bg-hover rounded-lg transition-colors">
          <ArrowLeft size={18} />
        </button>
        <span className="font-semibold truncate">{data.name}</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {/* Album header */}
        <div className="p-6 flex items-center gap-4 border-b border-border-subtle">
          {data.coverArt ? (
            <img src={coverUrl(data.coverArt)} alt="" className="w-24 h-24 rounded-xl object-cover flex-shrink-0 shadow-lg" />
          ) : (
            <div className="w-24 h-24 rounded-xl bg-bg-hover flex items-center justify-center text-3xl flex-shrink-0">💿</div>
          )}
          <div>
            <h1 className="text-xl font-bold">{data.name}</h1>
            <p className="text-sm text-gray-400">{data.artist}</p>
            <p className="text-xs text-gray-500 mt-1">{data.songCount} tracks{data.year ? ` · ${data.year}` : ""}{data.genre ? ` · ${data.genre}` : ""}</p>
            <button onClick={playAll} className="mt-3 flex items-center gap-2 px-4 py-1.5 bg-accent text-black rounded-full text-sm font-semibold hover:bg-green-400 transition-colors">
              <Play size={14} /> Play All
            </button>
          </div>
        </div>

        {/* Track list */}
        <div className="divide-y divide-border-subtle">
          {data.songs?.map((song, i) => {
            const isCurrent = currentTrack?.id === song.id;
            return (
              <div
                key={song.id}
                className={`flex items-center gap-3 px-6 py-3 hover:bg-bg-raised/50 transition-colors cursor-pointer group ${isCurrent ? "bg-accent/5" : ""}`}
                onClick={() => play(song)}
              >
                <span className="w-6 text-center text-xs text-gray-500 group-hover:hidden">{(song.track || i + 1)}</span>
                <span className="w-6 text-center text-xs text-accent hidden group-hover:block">
                  {isCurrent && isPlaying ? "❚❚" : "▶"}
                </span>
                <div className="flex-1 min-w-0">
                  <div className={`text-sm truncate ${isCurrent ? "text-accent font-semibold" : ""}`}>{song.title}</div>
                  <div className="text-xs text-gray-500 truncate">{song.artist}</div>
                </div>
                <span className="text-xs text-gray-500 font-mono flex-shrink-0">{formatDuration(song.duration)}</span>
                <button
                  onClick={(e) => { e.stopPropagation(); addToQueue(song); }}
                  className="p-1 rounded text-gray-600 hover:text-gray-300 opacity-0 group-hover:opacity-100 transition-all"
                  title="Add to queue"
                >
                  <Plus size={14} />
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); onFlag(song); }}
                  className="p-1 rounded text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                  title="Flag track"
                >
                  <Flag size={14} />
                </button>
              </div>
            );
          })}
        </div>
      </div>
      {flagTrack && <FlagForm track={flagTrack} onClose={onCloseFlag} />}
    </>
  );
}
