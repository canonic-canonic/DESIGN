"use client";

import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/lib/auth";
import { usePlayer } from "@/lib/player";
import { useTalkBot, type BotAction } from "@/hooks/useTalkBot";
import { searchMusic, flagTrack as apiFlagTrack } from "@/lib/api";
import { Send, Bot, LogIn } from "lucide-react";
import { TrackEmbed } from "@/components/chat/TrackEmbed";
import type { Track } from "@/lib/types";
import { toast } from "sonner";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  tracks?: Track[];
  timestamp: string;
}

export function TalkView() {
  const { user, login, refreshUser } = useAuth();
  const { play, addToQueue, currentTrack } = usePlayer();
  const { botResponse, streaming, actions, askBot } = useTalkBot();
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "assistant",
      content: "Welcome to MusicChat. I know the library — 3,000+ tracks, 1,380 artists, Trinidad reggae.\n\nTell me what you want to hear, ask about an artist, or flag something wrong. I control the player.",
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState("");
  const [waiting, setWaiting] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const actionsHandled = useRef(false);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, botResponse]);

  // Execute actions when bot finishes
  useEffect(() => {
    if (!streaming && actions.length > 0 && !actionsHandled.current) {
      actionsHandled.current = true;
      executeActions(actions);
    }
  }, [streaming, actions]);

  // Save bot response when streaming finishes
  useEffect(() => {
    if (!streaming && botResponse && waiting) {
      const msg: ChatMessage = {
        id: Date.now().toString(),
        role: "assistant",
        content: botResponse,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, msg]);
      setWaiting(false);
    }
  }, [streaming, botResponse, waiting]);

  async function executeActions(acts: BotAction[]) {
    for (const action of acts) {
      if (action.type === "play") {
        const results = await searchMusic(action.query);
        if (results.songs?.length) {
          play(results.songs[0]);
          results.songs.slice(1, 5).forEach(s => addToQueue(s));
          // Add tracks to the last assistant message
          setMessages(prev => {
            const updated = [...prev];
            const last = updated[updated.length - 1];
            if (last?.role === "assistant") {
              last.tracks = results.songs.slice(0, 5);
            }
            return updated;
          });
          toast.success(`Playing: ${results.songs[0].title}`);
        } else {
          toast.error(`No tracks found for "${action.query}"`);
        }
      } else if (action.type === "search") {
        const results = await searchMusic(action.query);
        if (results.songs?.length) {
          setMessages(prev => {
            const updated = [...prev];
            const last = updated[updated.length - 1];
            if (last?.role === "assistant") {
              last.tracks = results.songs.slice(0, 8);
            }
            return updated;
          });
        }
      } else if (action.type === "flag") {
        if (currentTrack) {
          try {
            const result = await apiFlagTrack(currentTrack.id, action.query);
            toast.success(`Flagged! +${result.credits_earned}◈`);
            refreshUser();
          } catch {
            toast.error("Failed to flag track");
          }
        }
      }
    }
  }

  const handleSend = async () => {
    const text = input.trim();
    if (!text || waiting) return;
    setInput("");
    actionsHandled.current = false;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMsg]);
    setWaiting(true);

    const history = messages.filter(m => m.id !== "welcome").map(m => ({
      role: m.role,
      content: m.content,
    }));

    // Include current track context
    let contextMessage = text;
    if (currentTrack) {
      contextMessage = `[Currently playing: ${currentTrack.title} by ${currentTrack.artist}]\n\n${text}`;
    }

    await askBot(contextMessage, history);
  };

  if (!user) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <Bot size={48} className="mx-auto mb-4 text-accent" />
          <h2 className="text-xl font-bold mb-2">MusicChat AI</h2>
          <p className="text-gray-400 text-sm mb-4">Sign in to talk to the music bot</p>
          <button onClick={login} className="flex items-center gap-2 px-5 py-2.5 bg-accent text-black rounded-xl font-semibold hover:bg-green-400 transition-colors mx-auto">
            <LogIn size={16} /> Sign in with GitHub
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="h-14 px-4 flex items-center gap-2 border-b border-border-subtle flex-shrink-0">
        <Bot size={18} className="text-accent" />
        <span className="font-semibold">@musicchat</span>
        <span className="text-xs text-gray-500 ml-2">AI music assistant — plays, searches, flags, knows the culture</span>
        {streaming && <span className="ml-auto text-xs text-accent animate-pulse">typing...</span>}
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-2xl mx-auto py-4 px-4 space-y-4">
          {messages.map((msg) => (
            <div key={msg.id} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : ""}`}>
              {msg.role === "assistant" && (
                <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0 mt-1">
                  <Bot size={16} className="text-accent" />
                </div>
              )}
              <div className={`max-w-[85%] ${msg.role === "user" ? "bg-accent/10 border-accent/20" : "bg-bg-card border-border"} border rounded-2xl px-4 py-3`}>
                <div className="text-sm whitespace-pre-wrap leading-relaxed">{msg.content}</div>
                {msg.tracks?.map((t) => (
                  <div key={t.id} className="mt-2">
                    <TrackEmbed track={t} />
                  </div>
                ))}
              </div>
              {msg.role === "user" && user.avatar_url && (
                <img src={user.avatar_url} alt="" className="w-8 h-8 rounded-full flex-shrink-0 mt-1" />
              )}
            </div>
          ))}

          {streaming && botResponse && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0 mt-1">
                <Bot size={16} className="text-accent animate-pulse" />
              </div>
              <div className="bg-bg-card border border-border rounded-2xl px-4 py-3 max-w-[85%]">
                <div className="text-sm whitespace-pre-wrap leading-relaxed">{botResponse}</div>
              </div>
            </div>
          )}

          {waiting && !botResponse && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0 mt-1">
                <Bot size={16} className="text-accent animate-pulse" />
              </div>
              <div className="bg-bg-card border border-border rounded-2xl px-4 py-3">
                <div className="flex gap-1"><span className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{animationDelay:"0ms"}} /><span className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{animationDelay:"150ms"}} /><span className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" style={{animationDelay:"300ms"}} /></div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      </div>

      <div className="p-4 border-t border-border-subtle">
        <div className="max-w-2xl mx-auto flex items-center gap-2">
          <div className="flex-1 flex items-center bg-bg-card border border-border rounded-xl px-3 focus-within:border-accent transition-colors">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
              placeholder={currentTrack ? `Ask about "${currentTrack.title}" or request something...` : "Play me something, ask about an artist..."}
              disabled={waiting}
              className="flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-gray-600 disabled:opacity-50"
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || waiting}
              className="p-1.5 rounded-lg text-accent disabled:text-gray-600 disabled:cursor-not-allowed hover:bg-accent/10 transition-colors"
            >
              <Send size={16} />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
