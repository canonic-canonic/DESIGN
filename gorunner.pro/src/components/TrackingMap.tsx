"use client";

import { useEffect, useRef } from "react";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Fix Leaflet default icon issue in Next.js
const destIcon = new L.Icon({
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

const runnerIcon = new L.DivIcon({
  html: `<div style="background: linear-gradient(135deg, #f97316, #ef4444); width: 20px; height: 20px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 10px rgba(249,115,22,0.5);"></div>`,
  iconSize: [20, 20],
  iconAnchor: [10, 10],
  className: "",
});

function FitBounds({
  destination,
  runnerPosition,
}: {
  destination: { lat: number; lng: number };
  runnerPosition: { lat: number; lng: number } | null;
}) {
  const map = useMap();

  useEffect(() => {
    if (runnerPosition) {
      const bounds = L.latLngBounds(
        [destination.lat, destination.lng],
        [runnerPosition.lat, runnerPosition.lng]
      );
      map.fitBounds(bounds, { padding: [50, 50] });
    } else {
      map.setView([destination.lat, destination.lng], 14);
    }
  }, [map, destination, runnerPosition]);

  return null;
}

interface TrackingMapProps {
  destination: { lat: number; lng: number; address?: string };
  runnerPosition?: { lat: number; lng: number } | null;
}

export default function TrackingMap({
  destination,
  runnerPosition,
}: TrackingMapProps) {
  return (
    <div className="h-64 rounded-xl overflow-hidden border border-gray-200 dark:border-gray-800">
      <MapContainer
        center={[destination.lat, destination.lng]}
        zoom={14}
        style={{ height: "100%", width: "100%" }}
        zoomControl={false}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <Marker
          position={[destination.lat, destination.lng]}
          icon={destIcon}
        >
          <Popup>{destination.address || "Destination"}</Popup>
        </Marker>
        {runnerPosition && (
          <Marker
            position={[runnerPosition.lat, runnerPosition.lng]}
            icon={runnerIcon}
          >
            <Popup>Runner</Popup>
          </Marker>
        )}
        <FitBounds
          destination={destination}
          runnerPosition={runnerPosition ?? null}
        />
      </MapContainer>
    </div>
  );
}
