"use client";

import useSWR from "swr";
import { useState, useCallback } from "react";
import { getMessages, sendMessage as apiSendMessage, addReaction as apiReaction } from "@/lib/api";
import type { Message, Track } from "@/lib/types";

export function useMessages(channel: string) {
  const [optimistic, setOptimistic] = useState<Message[]>([]);

  const { data, error, mutate } = useSWR(
    channel ? `messages-${channel}` : null,
    () => getMessages(channel),
    { refreshInterval: 3000 }
  );

  const messages = [...(data?.messages || []), ...optimistic];

  const send = useCallback(async (body: string, trackEmbed?: Track) => {
    const result = await apiSendMessage(channel, body, trackEmbed);
    setOptimistic([]);
    mutate();
    return result;
  }, [channel, mutate]);

  const react = useCallback(async (messageId: string, emoji: string) => {
    await apiReaction(messageId, emoji);
    mutate();
  }, [mutate]);

  return { messages, total: data?.total || 0, error, send, react, mutate };
}
