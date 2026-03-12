"use client";

import type { QuickAction } from "@/lib/types";
import { TASK_ICONS } from "@/lib/types";
import { cn } from "@/lib/utils";

interface QuickActionsProps {
  actions: QuickAction[];
  onSelect: (action: QuickAction) => void;
  className?: string;
}

export function QuickActions({
  actions,
  onSelect,
  className,
}: QuickActionsProps) {
  return (
    <div className={cn("flex flex-wrap gap-2", className)}>
      {actions.map((action) => (
        <button
          key={action.key}
          onClick={() => onSelect(action)}
          className="inline-flex items-center gap-1.5 rounded-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-gray-300 hover:border-purple-300 hover:text-purple-600 dark:hover:border-purple-600 dark:hover:text-purple-400 transition-colors"
        >
          <span>{TASK_ICONS[action.key] || "📋"}</span>
          {action.label}
        </button>
      ))}
    </div>
  );
}
