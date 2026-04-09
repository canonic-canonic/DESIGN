export const API_BASE = "/api/v1";
export const TALK_API = "https://api.canonic.org/chat";
export const GITHUB_CLIENT_ID = "Ov23liHeqKVLbxp7DCHh";
export const TOKEN_KEY = "musicchat_session_token";

export const CHANNELS = [
  { id: "talk", name: "talk", icon: "🤖", description: "AI music assistant — play, search, ask" },
  { id: "general", name: "general", icon: "💬", description: "Talk about anything music" },
  { id: "now-playing", name: "now-playing", icon: "🎵", description: "What everyone's listening to" },
  { id: "artist-talk", name: "artist-talk", icon: "🎤", description: "Artist discussions and deep dives" },
  { id: "riddim-tracing", name: "riddim-tracing", icon: "🥁", description: "Map riddim connections" },
  { id: "feedback", name: "feedback", icon: "🚩", description: "Flag bad data, correct metadata" },
] as const;

export const RANKS = [
  { name: "listener", threshold: 0, color: "text-rank-listener", label: "Listener", icon: "🎵" },
  { name: "selector", threshold: 50, color: "text-rank-selector", label: "Selector", icon: "🎵" },
  { name: "curator", threshold: 200, color: "text-rank-curator", label: "Curator", icon: "🎶" },
  { name: "archivist", threshold: 500, color: "text-rank-archivist", label: "Archivist", icon: "📚" },
  { name: "elder", threshold: 1000, color: "text-rank-elder", label: "Elder", icon: "👑" },
] as const;

export const REACTIONS = [
  { emoji: "👍", label: "Upvote" },
  { emoji: "🔥", label: "Fire" },
  { emoji: "❤️", label: "Love" },
  { emoji: "🎯", label: "Facts" },
  { emoji: "🚩", label: "Flag" },
] as const;

export const CREDIT_AMOUNTS = {
  post_message: 2,
  share_track: 3,
  upvote_received: 1,
  flag_track: 4,
} as const;
