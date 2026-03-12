import type { Metadata, Viewport } from "next";
import { Providers } from "@/components/providers";
import { BottomNav } from "@/components/BottomNav";
import "./globals.css";

export const metadata: Metadata = {
  title: "GoRunner — Real Estate Task Marketplace",
  description:
    "Post a task. A pro handles it. You earn COIN. The operations partner every Lake Nona realtor wishes they had.",
  openGraph: {
    title: "GoRunner",
    description: "Real Estate Task Marketplace — powered by CANONIC",
    siteName: "GoRunner",
    type: "website",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: "#0f172a",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen">
        <Providers>
          <main className="pb-16">{children}</main>
          <BottomNav />
        </Providers>
      </body>
    </html>
  );
}
