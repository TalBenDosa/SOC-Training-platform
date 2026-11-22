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
  // Clickjacking: nothing may frame the app. DENY matches the CSP
  // `frame-ancestors 'none'` the middleware sets on pages (browsers that know CSP
  // use that; older ones use this). The one thing the app frames itself, the
  // static slide decks in /lesson-decks, gets SAMEORIGIN below.
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), interest-cohort=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  // A page we open in another window (or that opens ours) cannot reach back into
  // this one through window.opener. Same-origin windows keep their link, which the
  // Team Training two-window console relies on (src/lib/team/twoWindows.ts).
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  // Legacy Flash/PDF plug-ins may not load cross-domain policy files from here.
  { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
];
// SEC-03: PAGE responses get a per-request nonce CSP from the middleware
// (src/lib/security/csp.ts). API responses (JSON / files) get one that lets
// nothing run or frame.
const apiCsp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
// The static slide decks (public/lesson-decks/*.html) bypass the middleware, so they
// had no CSP at all. They are our own files: one inline script, inline styles, data:
// images and Google Fonts, nothing else. frame-ancestors 'self' (with X-Frame-Options
// SAMEORIGIN for older browsers): only the in-app SlideDeckViewer may frame them.
const deckCsp = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "img-src 'self' data:",
  "frame-ancestors 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

const nextConfig = {
  reactStrictMode: true,
  // A second local dev server (parallel sessions) needs its own build dir, or
  // the two corrupt each other's .next. Unset = the normal ".next".
  distDir: process.env.NEXT_DIST_DIR || ".next",
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
      // Later entries override earlier ones for the same key: the decks may be framed by
      // the app itself (SlideDeckViewer), and by nothing else.
      { source: "/lesson-decks/:path*", headers: [
        { key: "Content-Security-Policy", value: deckCsp },
        { key: "X-Frame-Options", value: "SAMEORIGIN" },
      ] },
    ];
  },
};

export default nextConfig;
