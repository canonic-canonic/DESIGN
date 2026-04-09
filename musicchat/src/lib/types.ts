export interface User {
  id: string;
  username: string;
  display_name: string;
  avatar_url: string;
  bio: string;
  credits: number;
  rank: string;
  post_count: number;
  created_at: string;
}

export interface Track {
  id: string;
  title: string;
  artist: string;
  album?: string;
  duration?: number;
  coverArt?: string;
  track?: number;
}

export interface Artist {
  id: string;
  name: string;
  albumCount: number;
  coverArt?: string | null;
}

export interface ArtistDetail {
  id: string;
  name: string;
  albumCount: number;
  artistImage?: string | null;
  coverArt?: string | null;
  biography?: string | null;
  similarArtists: { id: string; name: string }[];
  albums: (Album & { coverArt?: string })[];
}

export interface Album {
  id: string;
  name: string;
  songCount: number;
  year?: number;
  genre?: string;
}

export interface Message {
  id: string;
  channel_id: string;
  author_id: string;
  username: string;
  display_name: string;
  avatar_url: string;
  author_rank: string;
  body: string;
  track_embed: Track | null;
  reactions: ReactionSummary[];
  created_at: string;
}

export interface ReactionSummary {
  emoji: string;
  count: number;
  reacted: boolean; // whether current user reacted
}

export interface Channel {
  id: string;
  name: string;
  description: string;
}

export interface TrackFlag {
  id: string;
  track_id: string;
  user_id: string;
  reason: string;
  detail: string;
  status: string;
  created_at: string;
}

export interface MusicStats {
  tracks: number;
  artists: number;
  genres: number;
  topGenres: { name: string; tracks: number; albums: number }[];
}

export interface NowPlaying {
  playing: boolean;
  track?: string;
  artist?: string;
  album?: string;
  duration?: number;
  coverArt?: string;
}

export interface CreditEvent {
  id: string;
  user_id: string;
  amount: number;
  reason: string;
  ref_type?: string;
  ref_id?: string;
  created_at: string;
}
