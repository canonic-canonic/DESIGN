"use client";

import { useState, useCallback, useRef } from "react";
import { TALK_API } from "@/lib/constants";

const MUSIC_SYSTEM_PROMPT = `You are MusicChat, the community intelligence for Trinidad reggae and Caribbean roots music. You know the Navidrome library (3,000+ tracks, 1,380 artists).

You can control the player by including action tags in your response:
- <PLAY>artist or track name</PLAY> — searches and plays
- <SEARCH>query</SEARCH> — searches and shows results
- <FLAG>reason</FLAG> — flags the currently playing track

Examples:
User: "play me some Prophet Benjamin"
You: "Prophet Benjamin — conscious roots from Trinidad. Let me pull him up. <PLAY>Prophet Benjamin</PLAY>"

User: "this isn't reggae, flag it"
You: "Flagging the current track as not Trinidad reggae. <FLAG>not_trini_reggae</FLAG>"

User: "find me something like Khari Kill"
You: "Khari Kill walks that roots-fusion edge. Let me search for similar vibes. <SEARCH>roots reggae trinidad</SEARCH>"

Key knowledge:
- Trinidad reggae is NOT Jamaican reggae played in Trinidad. Own sound: roots, conscious, one-drop, dub, lovers rock + rapso, calypso, chutney.
- Seed artists: D Rebel, Prophet Benjamin, Queen Omega, Khari Kill, Levi Myaz, Jamelody, King David, Brother Resistance, 3 Canal, Kindred, Isasha, Jah Defender, Jahllano, Ziggy Ranking, Maximus Dan, Black Loyalty
- If a track doesn't belong: be direct, flag it.

Be concise. Community voice. Include action tags when the user wants to hear music or take action.`;

export interface BotAction {
  type: "play" | "search" | "flag";
  query: string;
}

export function useTalkBot() {
  const [botResponse, setBotResponse] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [actions, setActions] = useState<BotAction[]>([]);
  const accumulatedRef = useRef("");

  // Parse action tags from response
  function parseActions(text: string): BotAction[] {
    const found: BotAction[] = [];
    const playMatch = text.matchAll(/<PLAY>(.*?)<\/PLAY>/gi);
    for (const m of playMatch) found.push({ type: "play", query: m[1] });
    const searchMatch = text.matchAll(/<SEARCH>(.*?)<\/SEARCH>/gi);
    for (const m of searchMatch) found.push({ type: "search", query: m[1] });
    const flagMatch = text.matchAll(/<FLAG>(.*?)<\/FLAG>/gi);
    for (const m of flagMatch) found.push({ type: "flag", query: m[1] });
    return found;
  }

  // Strip action tags from display text
  function cleanResponse(text: string): string {
    return text
      .replace(/<PLAY>.*?<\/PLAY>/gi, "")
      .replace(/<SEARCH>.*?<\/SEARCH>/gi, "")
      .replace(/<FLAG>.*?<\/FLAG>/gi, "")
      .trim();
  }

  const askBot = useCallback(async (question: string, history: { role: string; content: string }[] = []) => {
    setBotResponse("");
    setActions([]);
    setStreaming(true);
    accumulatedRef.current = "";

    try {
      const resp = await fetch(TALK_API, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/event-stream" },
        body: JSON.stringify({
          message: question,
          history: history.slice(-6),
          system: MUSIC_SYSTEM_PROMPT,
          scope: "MUSIC",
          stream: true,
          tier: "FREE",
        }),
      });

      if (!resp.ok) {
        const err = await resp.text();
        setBotResponse(`Error: ${err}`);
        setStreaming(false);
        return;
      }

      const contentType = resp.headers.get("content-type") || "";

      if (contentType.includes("text/event-stream")) {
        const reader = resp.body?.getReader();
        const decoder = new TextDecoder();

        if (reader) {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value, { stream: true });
            for (const line of chunk.split("\n")) {
              if (!line.startsWith("data: ")) continue;
              const data = line.slice(6);
              if (data === "[DONE]") continue;
              try {
                const parsed = JSON.parse(data);
                if (parsed.done) continue;
                const token = parsed.token || parsed.delta?.text || parsed.content || parsed.text || "";
                accumulatedRef.current += token;
                setBotResponse(cleanResponse(accumulatedRef.current));
              } catch {
                accumulatedRef.current += data;
                setBotResponse(cleanResponse(accumulatedRef.current));
              }
            }
          }
        }
      } else {
        const data = await resp.json();
        accumulatedRef.current = data.message || data.reply || data.content || data.text || "";
        setBotResponse(cleanResponse(accumulatedRef.current));
      }

      // Parse actions from complete response
      const foundActions = parseActions(accumulatedRef.current);
      setActions(foundActions);
    } catch (e) {
      setBotResponse(`Error: ${e instanceof Error ? e.message : "Failed to reach MusicChat"}`);
    } finally {
      setStreaming(false);
    }
  }, []);

  return { botResponse, streaming, actions, askBot, cleanResponse };
}
