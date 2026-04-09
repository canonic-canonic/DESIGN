"use client";

import { SWRConfig } from "swr";
import { Toaster } from "sonner";
import { AuthProvider } from "@/lib/auth";
import { PlayerProvider } from "@/lib/player";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ revalidateOnFocus: false }}>
      <AuthProvider>
        <PlayerProvider>
          {children}
          <Toaster position="bottom-right" theme="dark" />
        </PlayerProvider>
      </AuthProvider>
    </SWRConfig>
  );
}
