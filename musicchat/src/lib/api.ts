import { API_BASE, TOKEN_KEY } from "./constants";
import type { User, Track, Artist, ArtistDetail, Album, Message, MusicStats, NowPlaying, CreditEvent } from "./types";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { ...(options.headers as Record<string, string>) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as Record<string, string>).error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Auth ──
export async function authGitHub(code: string) {
  return request<{ token: string; user: User }>("/auth/github", {
    method: "POST", body: JSON.stringify({ code }),
  });
}

export async function authMe() {
  return request<{ user: User }>("/auth/me");
}

// ── Music (Navidrome proxy) ──
export async function getMusicStats() {
  return request<MusicStats>("/music/stats");
}

export async function getNowPlaying() {
  return request<NowPlaying>("/music/now-playing");
}

export async function getArtists(q?: string) {
  return request<{ artists: Artist[] }>(`/music/artists?q=${encodeURIComponent(q || "")}`);
}

export async function getArtist(id: string) {
  return request<ArtistDetail>(`/music/artist/${id}`);
}

export async function getAlbum(id: string) {
  return request<{ id: string; name: string; artist: string; artistId: string; songCount: number; year?: number; genre?: string; coverArt?: string; songs: Track[] }>(`/music/album/${id}`);
}

export async function searchMusic(q: string) {
  return request<{ artists: Artist[]; songs: Track[]; albums: Album[] }>(`/music/search?q=${encodeURIComponent(q)}`);
}

export async function getRandomTracks(count = 10) {
  return request<{ songs: Track[] }>(`/music/random?count=${count}`);
}

export function streamUrl(trackId: string) {
  return `${API_BASE}/music/stream/${trackId}`;
}

export function coverUrl(coverArt: string) {
  return `${API_BASE}/music/cover/${coverArt}`;
}

// ── Messages (chat) ──
export async function getChannels() {
  return request<{ channels: { id: string; name: string; description: string }[] }>("/channels");
}

export async function getMessages(channel: string, since?: string, limit = 50) {
  const params = new URLSearchParams({ channel, limit: String(limit) });
  if (since) params.set("since", since);
  return request<{ messages: Message[]; total: number }>(`/messages?${params}`);
}

export async function sendMessage(channel_id: string, body: string, track_embed?: Track) {
  return request<{ message: Message; credits_earned: number }>("/messages", {
    method: "POST",
    body: JSON.stringify({ channel_id, body, track_embed: track_embed || null }),
  });
}

export async function addReaction(messageId: string, emoji: string) {
  return request<{ toggled: boolean }>(`/messages/${messageId}/react`, {
    method: "POST", body: JSON.stringify({ emoji }),
  });
}

// ── Track flags ──
export async function flagTrack(trackId: string, reason: string, detail?: string) {
  return request<{ flag: { id: string }; credits_earned: number }>(`/tracks/${trackId}/flag`, {
    method: "POST", body: JSON.stringify({ reason, detail }),
  });
}

// ── Credits ──
export async function getCredits(limit = 20) {
  return request<{ credits: number; rank: string; history: CreditEvent[] }>(`/credits?limit=${limit}`);
}

export async function getLeaderboard(limit = 10) {
  return request<{ leaders: User[] }>(`/leaderboard?limit=${limit}`);
}

// ── Users ──
export async function getUser(username: string) {
  return request<{ user: User; threads: unknown[] }>(`/users/${username}`);
}
