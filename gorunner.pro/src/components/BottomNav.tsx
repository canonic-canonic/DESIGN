"use client";

import { useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";
import { MessageCircle, LayoutDashboard, Wallet, BarChart3, Trophy, Plus, List, LogOut, UserCircle } from "lucide-react";
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
  const router = useRouter();
  const { identity, user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  // Use identity role, but also detect from URL as fallback
  const pathRole = pathname.startsWith("/runner") ? "Runner" : pathname.startsWith("/ops") ? "Ops" : null;
  const role = identity?.role || pathRole;
  const tabs =
    role === "Runner"
      ? RUNNER_TABS
      : role === "Ops"
        ? OPS_TABS
        : PRO_TABS;

  if (!identity) return null;

  return (
    <>
      {/* User menu popover */}
      {menuOpen && (
        <div className="fixed inset-0 z-[60]" onClick={() => setMenuOpen(false)}>
          <div
            className="absolute bottom-16 right-4 w-48 bg-white dark:bg-gray-900 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 p-2"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-3 py-2 border-b border-gray-100 dark:border-gray-800">
              <div className="text-sm font-medium truncate">{user?.name || user?.user}</div>
              <div className="text-[10px] text-gray-400 uppercase">{role}</div>
            </div>
            <button
              type="button"
              onClick={() => { logout(); setMenuOpen(false); router.replace("/"); }}
              className="w-full flex items-center gap-2 px-3 py-2 mt-1 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
            >
              <LogOut className="h-4 w-4" />
              Sign Out
            </button>
          </div>
        </div>
      )}

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
          <button
            type="button"
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex flex-col items-center gap-0.5 px-3 py-1 rounded-lg transition-all text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <UserCircle className="h-5 w-5" />
            <span className="text-[10px] font-medium">Account</span>
          </button>
        </div>
      </nav>
    </>
  );
}
