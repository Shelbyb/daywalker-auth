import type { NextConfig } from "next";

const config: NextConfig = {
  // While the SDK lives in this repo it ships as TypeScript source; drop this once it's published with a build.
  transpilePackages: ["@daywalker/auth"],
  poweredByHeader: false,
  // Only optimize avatars from hosts you trust; set to where user images live.
  images: { remotePatterns: [{ protocol: "https", hostname: "**.daywalker.dev" }], formats: ["image/avif", "image/webp"] },
};
export default config;
