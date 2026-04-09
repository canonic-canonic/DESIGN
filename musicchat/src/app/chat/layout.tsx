"use client";

import { useState } from "react";
import { ChannelSidebar } from "@/components/layout/ChannelSidebar";
import { RightPanel } from "@/components/layout/RightPanel";
import { Menu, X } from "lucide-react";

export default function ChatLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex h-screen relative">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Left sidebar — hidden on mobile unless toggled */}
      <div className={`fixed inset-y-0 left-0 z-50 lg:static lg:z-auto transition-transform duration-200 ${sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}>
        <ChannelSidebar onNavigate={() => setSidebarOpen(false)} />
      </div>

      {/* Main content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Mobile header with hamburger */}
        <div className="lg:hidden h-12 px-3 flex items-center gap-2 border-b border-border-subtle flex-shrink-0">
          <button onClick={() => setSidebarOpen(true)} className="p-1.5 rounded-lg hover:bg-bg-hover transition-colors">
            <Menu size={20} />
          </button>
          <div className="flex items-center gap-1.5">
            <span className="text-accent font-bold text-sm">♫</span>
            <span className="font-semibold text-sm">MusicChat</span>
          </div>
        </div>
        {children}
      </main>

      {/* Right sidebar — hidden on smaller screens */}
      <div className="hidden xl:block">
        <RightPanel />
      </div>
    </div>
  );
}
