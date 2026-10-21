import path from "node:path";
import type { NextConfig } from "next";

const prod = process.env.NODE_ENV === "production";

// Pages ship no third-party scripts. Next needs inline styles/scripts in dev for HMR.
const csp = [
  "default-src 'self'",
  `script-src 'self'${prod ? "" : " 'unsafe-eval' 'unsafe-inline'"}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'", // hosted auth pages must never be framed (clickjacking)
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
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
  serverExternalPackages: ["@node-rs/argon2"],
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      // API responses carry tokens and user data: never cache them anywhere.
      { source: "/v1/:path*", headers: [{ key: "Cache-Control", value: "no-store" }] },
    ];
  },
};

export default config;
