"use client";

import { useState, useEffect, useRef } from "react";
import { useMessages } from "@/hooks/useMessages";
import { useAuth } from "@/lib/auth";
import { usePlayer } from "@/lib/player";
import { useTalkBot, type BotAction } from "@/hooks/useTalkBot";
import { searchMusic, flagTrack as apiFlagTrack } from "@/lib/api";
import { MessageList } from "@/components/chat/MessageList";
import { ChatInput } from "@/components/chat/ChatInput";
import { FlagForm } from "@/components/chat/FlagForm";
import { CHANNELS } from "@/lib/constants";
import { Hash, Bot } from "lucide-react";
import type { Track, Message } from "@/lib/types";
import { toast } from "sonner";

export function ChannelView({ channel }: { channel: string }) {
  const { messages, send, react, mutate } = useMessages(channel);
  const { user, refreshUser } = useAuth();
  const { play, addToQueue, currentTrack } = usePlayer();
  const { botResponse, streaming, actions, askBot } = useTalkBot();
  const [flagTrack, setFlagTrack] = useState<Track | null>(null);
  const botPersistedRef = useRef(false);
  const actionsHandledRef = useRef(false);

  const channelInfo = CHANNELS.find((c) => c.id === channel) || CHANNELS[0];

  // Persist bot response when streaming finishes
  useEffect(() => {
    if (!streaming && botResponse && !botPersistedRef.current) {
      botPersistedRef.current = true;
      send(`🤖 ${botResponse}`).then(() => mutate()).catch(() => {});
    }
    if (streaming) {
      botPersistedRef.current = false;
    }
  }, [streaming, botResponse, send, mutate]);

  // Execute bot actions (play, search, flag)
  useEffect(() => {
    if (!streaming && actions.length > 0 && !actionsHandledRef.current) {
      actionsHandledRef.current = true;
      for (const action of actions) {
        if (action.type === "play") {
          searchMusic(action.query).then(results => {
            if (results.songs?.length) {
              play(results.songs[0]);
              results.songs.slice(1, 5).forEach(s => addToQueue(s));
              toast.success(`Playing: ${results.songs[0].title}`);
            }
          });
        } else if (action.type === "flag" && currentTrack) {
          apiFlagTrack(currentTrack.id, action.query).then(result => {
            toast.success(`Flagged! +${result.credits_earned}◈`);
            refreshUser();
          }).catch(() => toast.error("Failed to flag"));
        }
      }
    }
    if (streaming) actionsHandledRef.current = false;
  }, [streaming, actions, play, addToQueue, currentTrack, refreshUser]);

  // Build display messages including bot streaming response
  const displayMessages = [...messages];
  if (streaming && botResponse) {
    const botMsg: Message = {
      id: "bot-streaming",
      channel_id: channel,
      author_id: "musicchat-bot",
      username: "musicchat",
      display_name: "🤖 MusicChat",
      avatar_url: "",
      author_rank: "elder",
      body: botResponse,
      track_embed: null,
      reactions: [],
      created_at: new Date().toISOString(),
    };
    displayMessages.push(botMsg);
  }

  const handleSend = async (body: string, trackEmbed?: Track) => {
    const botTrigger = body.match(/^@musicchat\s+(.+)/i);

    try {
      const result = await send(body, trackEmbed);
      if (result.credits_earned) {
        toast.success(`+${result.credits_earned}◈ earned`);
        refreshUser();
      }

      if (botTrigger) {
        let question = botTrigger[1];
        if (currentTrack) {
          question = `[Currently playing: ${currentTrack.title} by ${currentTrack.artist}]\n\n${question}`;
        }
        askBot(question);
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to send");
    }
  };

  return (
    <>
      <div className="h-14 px-4 flex items-center gap-2 border-b border-border-subtle flex-shrink-0">
        <Hash size={18} className="text-gray-500" />
        <span className="font-semibold">{channelInfo.name}</span>
        <span className="text-xs text-gray-500 ml-2">{channelInfo.description}</span>
        {streaming && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-accent">
            <Bot size={14} className="animate-pulse" />
            @musicchat is typing...
          </span>
        )}
      </div>
      <MessageList messages={displayMessages} onReact={react} onFlag={setFlagTrack} />
      <ChatInput onSend={handleSend} channelName={channelInfo.name} />
      {flagTrack && <FlagForm track={flagTrack} onClose={() => setFlagTrack(null)} />}
    </>
  );
}
