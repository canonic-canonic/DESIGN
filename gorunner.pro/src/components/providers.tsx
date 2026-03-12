"use client";

import { SWRConfig } from "swr";
import { AuthProvider } from "@/lib/auth";
import { Toaster } from "sonner";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig
      value={{
        revalidateOnFocus: false,
        dedupingInterval: 5_000,
      }}
    >
      <AuthProvider>
        {children}
        <Toaster position="top-center" richColors />
      </AuthProvider>
    </SWRConfig>
  );
}
