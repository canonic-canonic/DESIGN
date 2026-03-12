"use client";

import type { TaskStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const LIFECYCLE_STEPS: TaskStatus[] = [
  "posted",
  "assigned",
  "in_progress",
  "completed",
  "rated",
];

const STEP_LABELS: Record<string, string> = {
  posted: "Posted",
  assigned: "Matched",
  in_progress: "Active",
  completed: "Done",
  rated: "Rated",
};

export function TaskProgressBar({ status }: { status: TaskStatus }) {
  const activeIndex = LIFECYCLE_STEPS.indexOf(
    status === "accepted" ? "assigned" : status
  );

  return (
    <div className="flex items-center gap-1 w-full">
      {LIFECYCLE_STEPS.map((step, i) => {
        const isActive = i <= activeIndex && activeIndex >= 0;
        const isCurrent = i === activeIndex;
        return (
          <div key={step} className="flex-1 flex flex-col items-center gap-1">
            <div className="w-full flex items-center">
              <div
                className={cn(
                  "h-1.5 w-full rounded-full transition-colors",
                  isActive
                    ? "bg-gradient-to-r from-blue-500 to-purple-500"
                    : "bg-gray-200 dark:bg-gray-700"
                )}
              />
            </div>
            <span
              className={cn(
                "text-[10px] font-medium",
                isCurrent
                  ? "text-purple-600 dark:text-purple-400"
                  : isActive
                    ? "text-gray-600 dark:text-gray-400"
                    : "text-gray-400 dark:text-gray-600"
              )}
            >
              {STEP_LABELS[step]}
            </span>
          </div>
        );
      })}
    </div>
  );
}
