/** @type {import('next').NextConfig} */

// ─── Security headers ──────────────────────────────────────────────────────────
// Applied to every route. Baseline hardening against clickjacking, MIME sniffing,
// referrer leakage, and unwanted browser features, plus HSTS for TLS enforcement.
//
// CSP is shipped in *Report-Only* mode first: it does NOT block anything yet, it
// only reports violations. This is the safe rollout — it lets us discover what
// inline scripts/styles the app (Next.js runtime, framer-motion, recharts) needs
// before switching to an enforcing policy, so we never break the running app.
// TODO(prod): after collecting reports, tighten to an enforcing Content-Security-Policy
// with per-request nonces for inline scripts, and remove 'unsafe-inline'/'unsafe-eval'.
const cspReportOnly = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  { key: "Content-Security-Policy-Report-Only", value: cspReportOnly },
];

const nextConfig = {
  reactStrictMode: true,
  // Do not leak the framework version in the Server/X-Powered-By header.
  poweredByHeader: false,
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "**.supabase.co" },
      { protocol: "https", hostname: "avatars.githubusercontent.com" },
    ],
  },
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
