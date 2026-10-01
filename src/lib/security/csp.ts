/**
 * Content-Security-Policy for PAGE responses, emitted per request by the
 * middleware with a fresh nonce (QA phase 6, SEC-03).
 *
 * script-src was 'self' 'unsafe-inline' 'unsafe-eval' — any HTML injection could
 * run script and read the (JS-readable, by Supabase-SSR design) session cookie.
 * Now only scripts carrying this response's nonce run; 'strict-dynamic' lets
 * them load Next's chunks. Next.js reads the nonce from the request's CSP header
 * and stamps it on its own inline/bootstrap scripts (pages render dynamically —
 * the root layout reads headers()). 'unsafe-eval' remains in DEVELOPMENT only
 * (React's dev tooling needs it).
 *
 * Supabase is pinned to THIS project's host (SEC-15) — `*.supabase.co` let an
 * injected script post data to any attacker-owned Supabase project.
 *
 * Edge-safe: no Node APIs.
 */
export function supabaseHost(url: string | undefined): string | null {
  if (!url) return null;
  try { return new URL(url).host; } catch { return null; }
}

export function makeNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function buildPageCsp(opts: { nonce: string; dev: boolean; supabaseUrl: string | undefined }): string {
  const host = supabaseHost(opts.supabaseUrl);
  const sbHttps = host ? `https://${host}` : "https://*.supabase.co";
  const sbWss = host ? `wss://${host}` : "wss://*.supabase.co";
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${opts.nonce}' 'strict-dynamic'${opts.dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${sbHttps} https://avatars.githubusercontent.com`,
    "font-src 'self' data:",
    `connect-src 'self' ${sbHttps} ${sbWss}`,
    // In-app materials: PDFs in a same-origin blob: iframe; PPTX in the Office viewer.
    "frame-src 'self' blob: https://view.officeapps.live.com https://*.officeapps.live.com",
    `media-src 'self' blob: ${sbHttps}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; ");
}

/** API responses are JSON / files — nothing in them may run or be framed. */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
