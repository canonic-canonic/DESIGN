"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  useEffect(() => { router.replace("/chat/talk/"); }, [router]);
  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <div className="text-center">
        <div className="text-4xl mb-4">🎵</div>
        <div className="text-accent font-bold text-xl">MusicChat</div>
        <div className="text-gray-500 text-sm mt-2">Loading the village...</div>
      </div>
    </div>
  );
}
