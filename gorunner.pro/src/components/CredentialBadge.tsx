"use client";

import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";

const CREDENTIAL_MAP: Record<string, { label: string; color: string }> = {
  business_license: { label: "Business", color: "bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300" },
  FL_468: { label: "FL Inspector", color: "bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-300" },
  FL_FREAB_USPAP: { label: "FL Appraiser", color: "bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-300" },
  FL_626: { label: "FL Title", color: "bg-amber-100 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300" },
  FL_626_NMLS: { label: "FL Closing", color: "bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-300" },
  real_estate_license: { label: "RE License", color: "bg-indigo-100 text-indigo-700 dark:bg-indigo-900/20 dark:text-indigo-300" },
};

export function CredentialBadge({
  credentialKey,
  size = "sm",
}: {
  credentialKey: string;
  size?: "sm" | "md";
}) {
  const cred = CREDENTIAL_MAP[credentialKey];
  if (!cred) return null;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full font-medium",
        cred.color,
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"
      )}
    >
      <Shield className={size === "sm" ? "h-2.5 w-2.5" : "h-3 w-3"} />
      {cred.label}
    </span>
  );
}
