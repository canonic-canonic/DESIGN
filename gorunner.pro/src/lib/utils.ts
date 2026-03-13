import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Haversine distance (same formula as runner.js)
export function haversineDistance(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number
): number {
  const R = 3959; // Earth radius in miles
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLng = ((lng2 - lng1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

export function estimateEta(distanceMiles: number): number {
  // ~30 mph average in urban driving
  return Math.ceil((distanceMiles / 30) * 60);
}

export function formatCoin(amount: number): string {
  return `∩${amount}`;
}

export function formatUsd(amount: number): string {
  return `$${amount.toFixed(0)}`;
}

// 145495 → "145.5K", 1200000 → "1.2M"
export function formatCompact(n: number | undefined | null): string {
  if (n == null) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return n.toString();
}

// 145495 → "145,495"
export function formatNumber(n: number | undefined | null): string {
  if (n == null) return "0";
  return n.toLocaleString();
}
