"use client";

import { cn } from "@/lib/utils";

interface CoinBadgeProps {
  coin: number;
  usd?: number;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function CoinBadge({
  coin,
  usd,
  size = "md",
  className,
}: CoinBadgeProps) {
  const sizes = {
    sm: "text-xs px-2 py-0.5",
    md: "text-sm px-3 py-1",
    lg: "text-base px-4 py-1.5",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full bg-gradient-coin font-bold text-white",
        sizes[size],
        className
      )}
    >
      <span className="text-yellow-200">∩</span>
      {coin} Credits
      {usd !== undefined && (
        <span className="text-white/70 font-normal">
          · ${usd}
        </span>
      )}
    </span>
  );
}

export function CoinBalance({
  balance,
  className,
}: {
  balance: number;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-1 rounded-lg bg-amber-500/10 px-3 py-1 text-amber-500 font-semibold",
        className
      )}
    >
      <span>∩</span>
      <span>{balance}</span>
    </div>
  );
}
