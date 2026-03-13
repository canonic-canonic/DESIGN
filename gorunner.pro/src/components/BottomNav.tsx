"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { MessageCircle, LayoutDashboard, Wallet, BarChart3, Trophy, Plus, List } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth";

const PRO_TABS = [
  { href: "/pro", icon: MessageCircle, label: "Chat" },
  { href: "/pro/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { href: "/pro/create", icon: Plus, label: "Post Task" },
  { href: "/board", icon: Trophy, label: "Board" },
];

const RUNNER_TABS = [
  { href: "/runner", icon: MessageCircle, label: "Chat" },
  { href: "/runner/active", icon: List, label: "Active" },
  { href: "/runner/earnings", icon: Wallet, label: "Earnings" },
  { href: "/board", icon: Trophy, label: "Board" },
];

const OPS_TABS = [
  { href: "/ops", icon: BarChart3, label: "Dashboard" },
  { href: "/board", icon: Trophy, label: "Board" },
];

export function BottomNav() {
  const pathname = usePathname();
  const { identity } = useAuth();

  const role = identity?.role;
  const tabs =
    role === "Runner"
      ? RUNNER_TABS
      : role === "Ops"
        ? OPS_TABS
        : PRO_TABS;

  if (!identity) return null;

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-50 border-t border-gray-200 dark:border-gray-800 bg-white/90 dark:bg-gray-950/90 backdrop-blur-xl safe-area-pb">
      <div className="flex items-center justify-around h-14 max-w-lg mx-auto">
        {tabs.map(({ href, icon: Icon, label }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex flex-col items-center gap-0.5 px-3 py-1 rounded-lg transition-all",
                active
                  ? "text-purple-600 dark:text-purple-400 scale-105"
                  : "text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              )}
            >
              <Icon className={cn("h-5 w-5", active && "drop-shadow-sm")} />
              <span className={cn(
                "text-[10px]",
                active ? "font-semibold" : "font-medium"
              )}>{label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
