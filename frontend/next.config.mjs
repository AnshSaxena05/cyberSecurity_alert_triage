/** @type {import('next').NextConfig} */
const nextConfig = {
  // The BFF is API-first for v1 — no static export, no image optimisation.
  reactStrictMode: true,
  experimental: {
    // Server-only modules (pg, ioredis, nats, argon2) must stay out of the
    // client bundle. App Router does this by default for files marked with
    // "import 'server-only'" — we still scope packages here to be explicit.
    serverComponentsExternalPackages: ["pg", "ioredis", "nats", "argon2"],
  },
  // Don't pull DOM types into Edge runtime — auth routes are Node runtime.
  experimental: {
    serverComponentsExternalPackages: ["pg", "ioredis", "nats", "argon2"],
  },
};

export default nextConfig;
