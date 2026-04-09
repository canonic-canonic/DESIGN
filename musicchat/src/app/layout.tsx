import type { Metadata } from "next";
import { Providers } from "@/components/providers";
import { PlayerBar } from "@/components/layout/PlayerBar";
import "./globals.css";

export const metadata: Metadata = {
  title: "MusicChat — The Village",
  description: "Trinidad reggae community. Share vibes. Earn credit. Source the culture.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="font-sans">
        <Providers>
          {children}
          <PlayerBar />
        </Providers>
      </body>
    </html>
  );
}
