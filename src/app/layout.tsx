import type { Metadata, Viewport } from "next";
import "./globals.css";

export const viewport: Viewport = { themeColor: "#14121a", width: "device-width", initialScale: 1 };

export const metadata: Metadata = {
  title: "Daywalker Auth",
  description: "Authentication and user management for your apps",
  robots: { index: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">{children}</body>
    </html>
  );
}
