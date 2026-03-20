"use client";

import { useState, useCallback, useRef } from "react";
import type { ChatMessage } from "@/lib/chatTypes";
import { beforeSend, afterReceive } from "@/lib/chatEngine";
import type { UserContext } from "@/lib/chatEngine";
import { sendChat } from "@/lib/api";

interface TaskContext {
  id: string;
  type: string;
  title: string;
  status: string;
  address?: string;
  notes?: string;
}

interface UseChatOptions {
  userContext: UserContext;
  taskId?: string | null;
  taskContext?: TaskContext | null;
}

interface ChatThread {
  messages: ChatMessage[];
}

export function useChat({ userContext, taskId, taskContext }: UseChatOptions) {
  const [threads, setThreads] = useState<Map<string, ChatThread>>(new Map());
  const [sending, setSending] = useState(false);
  const activeKey = taskId || "__home__";
  const contextRef = useRef(userContext);
  contextRef.current = userContext;

  const messages = threads.get(activeKey)?.messages || [];

  const addMessages = useCallback(
    (key: string, msgs: ChatMessage[]) => {
      setThreads((prev) => {
        const next = new Map(prev);
        const thread = next.get(key) || { messages: [] };
        next.set(key, { messages: [...thread.messages, ...msgs] });
        return next;
      });
    },
    []
  );

  const sendMessage = useCallback(
    async (text: string) => {
      if (!text.trim() || sending) return;

      const userMsg: ChatMessage = {
        type: "text",
        role: "user",
        content: text.trim(),
        timestamp: new Date(),
      };
      addMessages(activeKey, [userMsg]);
      setSending(true);

      try {
        // Phase 1: beforeSend — check for local commands
        const result = await beforeSend(text, contextRef.current);

        if (result.handled && result.localMessages) {
          addMessages(activeKey, result.localMessages);
          setSending(false);
          return;
        }

        // Phase 2: send to LLM via TALK /chat
        const chatConfig: Record<string, unknown> = {
          runner_user: {
            id: contextRef.current.userId,
            role: contextRef.current.role,
            principal: contextRef.current.principal,
          },
        };
        if (taskId) chatConfig.task_id = taskId;
        if (taskContext) {
          chatConfig.task_context = `Task: ${taskContext.title} (${taskContext.type}). Status: ${taskContext.status}. Address: ${taskContext.address || "N/A"}. Notes: ${taskContext.notes || "None"}.`;
        }

        const res = await sendChat(
          result.enrichedText || text,
          chatConfig
        );
        const reply = res.reply || "I'm here to help with your tasks.";

        const assistantMsg: ChatMessage = {
          type: "text",
          role: "assistant",
          content: reply,
          timestamp: new Date(),
        };
        addMessages(activeKey, [assistantMsg]);

        // Phase 3: afterReceive — scan for task IDs, inject cards
        const injected = await afterReceive(reply, contextRef.current);
        if (injected.length > 0) {
          addMessages(activeKey, injected);
        }
      } catch {
        addMessages(activeKey, [
          {
            type: "text",
            role: "assistant",
            content: "Connection issue. Please try again.",
            timestamp: new Date(),
          },
        ]);
      } finally {
        setSending(false);
      }
    },
    [activeKey, sending, addMessages, taskId]
  );

  const addSystemMessage = useCallback(
    (msg: ChatMessage) => {
      addMessages(activeKey, [msg]);
    },
    [activeKey, addMessages]
  );

  return {
    messages,
    sendMessage,
    sending,
    activeKey,
    addSystemMessage,
  };
}
