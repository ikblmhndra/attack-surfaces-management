import type { Metadata, Viewport } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { Providers } from "@/components/layout/Providers";

export const metadata: Metadata = {
  title: {
    default: "ASM Platform",
    template: "%s | ASM Platform",
  },
  description: "Attack Surface Management & External Security Posture Management",
  keywords: ["ASM", "attack surface", "security", "vulnerability", "exposure management"],
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f8fafc" },
    { media: "(prefers-color-scheme: dark)", color: "#030712" },
  ],
  width: "device-width",
  initialScale: 1,
};

// Applies the persisted theme class before first paint so switching themes
// doesn't flash the wrong one on reload. Reads the same localStorage key
// zustand's persist middleware writes (store/workspace.ts) directly, since
// this has to run before React/zustand hydrate.
const THEME_INIT_SCRIPT = `
  (function () {
    try {
      var raw = localStorage.getItem("asm-workspace");
      var theme = raw ? JSON.parse(raw).state.theme : "dark";
      if (theme !== "light") document.documentElement.classList.add("dark");
    } catch (e) {
      document.documentElement.classList.add("dark");
    }
  })();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body className={`${GeistSans.variable} ${GeistMono.variable} font-sans antialiased bg-background`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
