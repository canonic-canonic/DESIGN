"use client";

import type { RunnerProfile } from "@/lib/types";
import { CredentialBadge } from "./CredentialBadge";
import { MapPin } from "lucide-react";

interface RunnerProfileCardProps {
  runner: RunnerProfile;
  rank?: number;
}

export function RunnerProfileCard({ runner, rank }: RunnerProfileCardProps) {
  const name = runner.profile
    ? `${runner.profile.first_name} ${runner.profile.last_name}`
    : `Runner ${runner.id.slice(0, 8)}`;

  const initials = runner.profile
    ? `${runner.profile.first_name[0]}${runner.profile.last_name[0]}`
    : "R";

  const rankBadge =
    rank === 1 ? "🥇" : rank === 2 ? "🥈" : rank === 3 ? "🥉" : null;

  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 space-y-3">
      <div className="flex items-center gap-3">
        {/* Avatar */}
        <div className="relative">
          <div className="h-12 w-12 rounded-full bg-gradient-runner flex items-center justify-center text-white font-bold">
            {initials}
          </div>
          {rankBadge && (
            <span className="absolute -top-1 -right-1 text-sm">
              {rankBadge}
            </span>
          )}
          {runner.available && (
            <span className="absolute bottom-0 right-0 h-3 w-3 rounded-full bg-green-400 border-2 border-white dark:border-gray-900" />
          )}
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="font-semibold text-sm truncate">{name}</div>
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span className="text-amber-500">
              {"★".repeat(Math.round(runner.rating_avg))}
              {"☆".repeat(5 - Math.round(runner.rating_avg))}
            </span>
            <span>({runner.total_ratings})</span>
          </div>
        </div>

        {/* Stats */}
        <div className="text-right">
          <div className="text-lg font-bold">{runner.completed_tasks}</div>
          <div className="text-[10px] text-gray-500">tasks</div>
        </div>
      </div>

      {/* Vehicle */}
      {runner.vehicle && (
        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <MapPin className="h-3 w-3" />
          {runner.vehicle.color} {runner.vehicle.year} {runner.vehicle.make}{" "}
          {runner.vehicle.model}
        </div>
      )}

      {/* Credentials — from KYC attestations */}
      {runner.onboarding_completed && (
        <div className="flex flex-wrap gap-1">
          <CredentialBadge credentialKey="business_license" />
        </div>
      )}
    </div>
  );
}
