"use client";

import type { Task, Canon } from "@/lib/types";
import { TASK_ICONS } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";
import { CoinBadge } from "./CoinBadge";
import { TaskProgressBar } from "./ProgressBar";
import { MapPin, Clock, User } from "lucide-react";
import { cn } from "@/lib/utils";

interface TaskCardProps {
  task: Task;
  canon: Canon | null;
  onClick?: () => void;
  actions?: React.ReactNode;
  className?: string;
}

export function TaskCard({
  task,
  canon,
  onClick,
  actions,
  className,
}: TaskCardProps) {
  const taskType = canon?.task_types?.find((t) => t.key === task.type);
  const icon = TASK_ICONS[task.type] || "📋";
  const label = taskType?.label || task.type;
  const coin = taskType?.coin ?? 0;

  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm hover:shadow-md transition-all",
        onClick && "cursor-pointer",
        className
      )}
      onClick={onClick}
    >
      {/* Gradient header — absorbed from Robert's design */}
      <div className="bg-gradient-pro px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <span className="font-semibold text-white text-sm">{label}</span>
        </div>
        <StatusBadge status={task.status} />
      </div>

      <div className="p-4 space-y-3">
        {/* Title */}
        <h3 className="font-semibold text-gray-900 dark:text-white text-sm leading-tight">
          {task.title || `${label} Task`}
        </h3>

        {/* Location */}
        {task.location?.address && (
          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <MapPin className="h-3.5 w-3.5 flex-shrink-0" />
            <span className="truncate">{task.location.address}</span>
          </div>
        )}

        {/* Schedule */}
        {task.scheduled_time && (
          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <Clock className="h-3.5 w-3.5 flex-shrink-0" />
            <span>
              {new Date(task.scheduled_time).toLocaleDateString(undefined, {
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "2-digit",
              })}
            </span>
          </div>
        )}

        {/* Runner info */}
        {task.assigned_runner_id && (
          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <User className="h-3.5 w-3.5 flex-shrink-0" />
            <span>Runner assigned</span>
          </div>
        )}

        {/* COIN + USD */}
        <div className="flex items-center justify-between">
          <CoinBadge coin={coin} usd={task.offered_fee_usd} size="sm" />
          {task.rating && (
            <span className="text-xs text-amber-500">
              {"★".repeat(task.rating)}
            </span>
          )}
        </div>

        {/* Progress bar */}
        <TaskProgressBar status={task.status} />

        {/* Action buttons */}
        {actions && (
          <div className="pt-2 border-t border-gray-100 dark:border-gray-800">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}
