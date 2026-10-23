import path from "node:path";
import type { NextConfig } from "next";

const prod = process.env.NODE_ENV === "production";

// Page CSPs are set per request in src/proxy.ts (they need a nonce). JSON API responses never render
// anything, so they get the tightest possible policy here.
const apiCsp = "default-src 'none'; frame-ancestors 'none'";

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  ...(prod ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }] : []),
];

const config: NextConfig = {
  poweredByHeader: false,
  // Self-contained server for Docker / DigitalOcean App Platform (.next/standalone/server.js).
  output: "standalone",
  outputFileTracingRoot: path.resolve(import.meta.dirname),
  transpilePackages: ["@daywalker/auth"],
  // Native argon2 bindings must not be bundled.
  serverExternalPackages: ["@node-rs/argon2", "@peculiar/x509", "tsyringe", "reflect-metadata"],
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      // API responses carry tokens and user data: never cache them anywhere.
      { source: "/v1/:path*", headers: [{ key: "Cache-Control", value: "no-store" }, { key: "Content-Security-Policy", value: apiCsp }] },
      { source: "/i/:path*", headers: [{ key: "Content-Security-Policy", value: apiCsp }] },
    ];
  },
};

export default config;
