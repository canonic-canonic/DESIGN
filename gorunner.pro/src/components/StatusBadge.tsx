"use client";

import type { TaskStatus } from "@/lib/types";
import { STATUS_COLORS } from "@/lib/types";

const STATUS_LABELS: Record<TaskStatus, string> = {
  posted: "Posted",
  assigned: "Assigned",
  accepted: "Accepted",
  in_progress: "In Progress",
  completed: "Completed",
  rated: "Rated",
  cancelled: "Cancelled",
};

export function StatusBadge({ status }: { status: TaskStatus }) {
  const color = STATUS_COLORS[status] || "#6b7280";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold text-white"
      style={{ backgroundColor: color }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full bg-white/60"
        aria-hidden
      />
      {STATUS_LABELS[status] || status}
    </span>
  );
}
