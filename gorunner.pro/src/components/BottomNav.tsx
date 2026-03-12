"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { Home, List, Wallet, Settings, BarChart3 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth";

const PRO_TABS = [
  { href: "/pro", icon: Home, label: "Home" },
  { href: "/pro/create", icon: List, label: "Post Task" },
];

const RUNNER_TABS = [
  { href: "/runner", icon: Home, label: "Home" },
  { href: "/runner/active", icon: List, label: "Active" },
  { href: "/runner/earnings", icon: Wallet, label: "Earnings" },
];

const OPS_TABS = [
  { href: "/ops", icon: BarChart3, label: "Dashboard" },
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
    <nav className="fixed bottom-0 left-0 right-0 z-50 border-t border-gray-200 dark:border-gray-800 bg-white/80 dark:bg-gray-950/80 backdrop-blur-lg safe-area-pb">
      <div className="flex items-center justify-around h-14 max-w-lg mx-auto">
        {tabs.map(({ href, icon: Icon, label }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex flex-col items-center gap-0.5 px-3 py-1 rounded-lg transition-colors",
                active
                  ? "text-purple-600 dark:text-purple-400"
                  : "text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
              )}
            >
              <Icon className="h-5 w-5" />
              <span className="text-[10px] font-medium">{label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
