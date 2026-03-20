"use client";

import { Suspense, useEffect, useState, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";

function CallbackInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { handleCallback, identity } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [authDone, setAuthDone] = useState(false);
  const called = useRef(false);

  // Step 1: Exchange code for token + resolve identity
  useEffect(() => {
    if (called.current) return;
    called.current = true;

    const code = searchParams.get("code");
    if (!code) {
      setError("No authorization code received");
      return;
    }

    handleCallback(code).then((success) => {
      if (success) {
        setAuthDone(true);
      } else {
        setError("Authentication failed");
      }
    });
  }, [searchParams, handleCallback]);

  // Step 2: Once auth is done, redirect to role-appropriate dashboard
  // New users (no principal) get the landing page to choose role
  useEffect(() => {
    if (!authDone) return;
    if (identity) {
      const role = identity.role;
      if (role === "Runner") router.replace("/runner");
      else if (role === "Ops") router.replace("/ops");
      else router.replace("/pro");
    } else {
      // Identity resolved but no principal — still redirect to default
      // The auth provider will have set identity from the /runner/auth response
      const timer = setTimeout(() => {
        // If identity still not resolved after 3s, go to pro as default
        router.replace("/pro");
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [authDone, identity, router]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="text-center space-y-4">
          <p className="text-red-500 font-medium">{error}</p>
          <button
            onClick={() => router.replace("/")}
            className="text-sm text-purple-600 underline"
          >
            Back to home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-3">
        <div className="h-8 w-8 mx-auto border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-gray-500">
          {authDone ? "Loading your dashboard..." : "Signing in..."}
        </p>
      </div>
    </div>
  );
}

export default function AuthCallback() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center">
          <div className="h-8 w-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <CallbackInner />
    </Suspense>
  );
}
