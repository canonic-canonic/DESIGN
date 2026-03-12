"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { updateLocation } from "@/lib/api";

export function useLocation(userId?: string, active = false) {
  const watchRef = useRef<number | null>(null);
  const [position, setPosition] = useState<{
    lat: number;
    lng: number;
  } | null>(null);

  const start = useCallback(() => {
    if (!userId || !active || watchRef.current !== null) return;
    if (!navigator.geolocation) return;

    watchRef.current = navigator.geolocation.watchPosition(
      (pos) => {
        const { latitude: lat, longitude: lng } = pos.coords;
        setPosition({ lat, lng });
        updateLocation(userId, lat, lng).catch(() => {});
      },
      () => {},
      { enableHighAccuracy: true, maximumAge: 5000, timeout: 10000 }
    );
  }, [userId, active]);

  const stop = useCallback(() => {
    if (watchRef.current !== null) {
      navigator.geolocation.clearWatch(watchRef.current);
      watchRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (active) start();
    else stop();
    return stop;
  }, [active, start, stop]);

  return { position, start, stop };
}
