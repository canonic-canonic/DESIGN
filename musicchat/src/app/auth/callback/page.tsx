"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";

function CallbackInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { handleCallback } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");
    if (!code) { setError("No code received from GitHub"); return; }

    handleCallback(code).then((ok) => {
      if (ok) router.replace("/chat/general/");
      else setError("Authentication failed. Try again.");
    });
  }, [searchParams, handleCallback, router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <div className="text-center">
        {error ? (
          <>
            <div className="text-red-400 font-semibold mb-2">{error}</div>
            <a href="/" className="text-accent hover:underline">Back to MusicChat</a>
          </>
        ) : (
          <>
            <div className="text-4xl mb-4 animate-pulse">🎵</div>
            <div className="text-gray-400">Signing you in...</div>
          </>
        )}
      </div>
    </div>
  );
}

export default function AuthCallback() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center bg-bg"><div className="text-4xl animate-pulse">🎵</div></div>}>
      <CallbackInner />
    </Suspense>
  );
}
