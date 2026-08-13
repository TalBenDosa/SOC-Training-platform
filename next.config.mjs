/** @type {import('next').NextConfig} */

// ─── Security headers ──────────────────────────────────────────────────────────
// Applied to every route. Baseline hardening against clickjacking, MIME sniffing,
// referrer leakage, and unwanted browser features, plus HSTS for TLS enforcement.
//
// CSP is now ENFORCING (was Report-Only). The structural directives below are
// actively blocked: no plugins (object-src 'none'), no <base> hijack
// (base-uri 'self'), no cross-origin form posts (form-action 'self'), no framing
// (frame-ancestors 'none'), and default-src/connect/img/font are pinned to the
// origin + the few hosts the app legitimately needs (Supabase over https, data/
// blob images). This shrinks the XSS/exfiltration blast radius immediately.
//
// KNOWN REMAINING GAP: script-src still allows 'unsafe-inline'/'unsafe-eval'.
// Next.js injects inline bootstrap scripts and some deps eval, so removing these
// requires switching CSP emission to the middleware with a per-request nonce
// (script-src 'self' 'nonce-<rand>' 'strict-dynamic'). Tracked as the final CSP
// hardening step — until then, injected inline <script> is still permitted, which
// is why the app ALSO neutralises XSS at the source (HTML-escaping in the
// markdown renderer, Mermaid securityLevel:"strict"). Defense in depth, both ends.
// connect-src / img-src are now ALLOWLISTED to the origin + Supabase (was a
// blanket `https:`, which permitted exfiltration to any HTTPS host). Supabase
// covers auth, PostgREST and Realtime (wss). Browser image loads are same-origin
// or Supabase/GitHub avatars (mirrors images.remotePatterns below); data:/blob:
// cover inline/generated images. LLM calls are all server-side, so the browser
// never needs a third-party connect origin.
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://*.supabase.co https://avatars.githubusercontent.com",
  "font-src 'self' data:",
  "connect-src 'self' https://*.supabase.co wss://*.supabase.co",
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
  { key: "Content-Security-Policy", value: csp },
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
