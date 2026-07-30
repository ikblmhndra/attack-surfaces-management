/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,

  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**",
      },
      {
        protocol: "http",
        hostname: "localhost",
      },
    ],
    formats: ["image/avif", "image/webp"],
  },

  // Promoted out of `experimental` in Next.js 15 (was
  // experimental.serverComponentsExternalPackages).
  serverExternalPackages: ["@tanstack/react-table"],

  experimental: {
    optimizePackageImports: [
      "lucide-react",
      "recharts",
      "framer-motion",
    ],
  },

  // Security headers
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options",           value: "DENY" },
          { key: "X-Content-Type-Options",    value: "nosniff" },
          { key: "Referrer-Policy",           value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy",        value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },

  // Rewrites for development proxy. WebSocket connections (useRealtimeEvents.ts,
  // lib/api.ts) always `new WebSocket(NEXT_PUBLIC_WS_URL)` directly from the
  // browser, bypassing Next's server-side rewrite proxy entirely — a `/ws/:path*`
  // rewrite here was unused dead code, and its `ws://` destination isn't a
  // protocol Next's rewrite validator accepts anyway (only `/`, `http://`,
  // `https://`), which broke `next dev` startup outright.
  async rewrites() {
    if (process.env.NODE_ENV === "development") {
      return [
        {
          source: "/api/:path*",
          destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api"}/:path*`,
        },
      ];
    }
    return [];
  },

  webpack: (config) => {
    // Cytoscape SSR fix
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      net: false,
      tls: false,
    };
    return config;
  },
};

module.exports = nextConfig;
