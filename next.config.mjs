/** @type {import('next').NextConfig} */

// ─── Security headers ──────────────────────────────────────────────────────────
// Applied to every route. Baseline hardening against clickjacking, MIME sniffing,
// referrer leakage, and unwanted browser features, plus HSTS for TLS enforcement.
//
// CSP: PAGE responses get a per-request NONCE policy from the middleware
// (src/lib/security/csp.ts — script-src 'nonce-…' 'strict-dynamic', no
// unsafe-inline / unsafe-eval in production, Supabase pinned to this project).
// API responses get a policy that lets nothing run or frame (below).


const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];
// SEC-03: PAGE responses get a per-request nonce CSP from the middleware
// (src/lib/security/csp.ts). API responses (JSON / files) get one that lets
// nothing run or frame.
const apiCsp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

const nextConfig = {
  reactStrictMode: true,
  // Do not leak the framework version in the Server/X-Powered-By header.
  poweredByHeader: false,
  // next/image is not used anywhere; with remotePatterns on **.supabase.co the
  // optimizer was an unauthenticated image proxy for ANY Supabase project (SEC-15).
  images: { unoptimized: true },
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      { source: "/api/:path*", headers: [{ key: "Content-Security-Policy", value: apiCsp }] },
    ];
  },
};

export default nextConfig;
