/**
 * Analysts work in two windows at once: the team room is the SIEM, XDR is where they investigate
 * (Tal, 2026-11-07). Each session has one window of each. "Investigate in XDR" brings the open
 * XDR window forward on the incident, instead of opening another tab or reloading the one the
 * analyst is working in, which would lose their open queries. Window and channel names keep their
 * old "sentinel-" prefix, so a window opened before the rename is still found.
 */
export const sentinelWindowName = (sessionId: string) => `sentinel-${sessionId}`;
export const siemWindowName = (sessionId: string) => `siem-${sessionId}`;
export const sentinelChannelName = (sessionId: string) => `sentinel-goto-${sessionId}`;

export interface SentinelTarget { incident?: string; host?: string }

/** The console's address. /sentinel is its old one and redirects here. */
export const XDR_PATH = "/xdr";

export type SearchParams = Record<string, string | string[] | undefined>;

/** /xdr with the same query as the request (repeated keys kept), for the /sentinel redirect. */
export function xdrHref(params: SearchParams | URLSearchParams | null | undefined): string {
  const q = new URLSearchParams();
  if (params instanceof URLSearchParams) params.forEach((v, k) => q.append(k, v));
  else for (const [k, v] of Object.entries(params ?? {})) {
    if (Array.isArray(v)) for (const x of v) q.append(k, x);
    else if (typeof v === "string") q.append(k, v);
  }
  const s = q.toString();
  return s ? `${XDR_PATH}?${s}` : XDR_PATH;
}

/** Whether window.open("", name) gave back a window that is already showing the page. */
function isOpenOn(w: Window, path: string): boolean {
  try { return w.location.pathname.startsWith(path); } catch { return false; }   // not readable: treat as new
}

/** Opens the session's XDR window, or brings it forward. Returns false when a pop-up blocker stopped it. */
export function showSentinelWindow(sessionId: string, url: string, target: SentinelTarget = {}): boolean {
  const w = window.open("", sentinelWindowName(sessionId));
  if (!w) return false;
  // A window still on /sentinel (opened before the rename) is the same console.
  if (isOpenOn(w, XDR_PATH) || isOpenOn(w, "/sentinel")) {
    try {
      const ch = new BroadcastChannel(sentinelChannelName(sessionId));
      ch.postMessage(target);
      ch.close();
    } catch { /* no channel in this browser: the analyst opens the incident from the grid */ }
  } else {
    w.location.href = url;
  }
  w.focus();
  return true;
}

/** From XDR: back to the session's SIEM window, opening it if the analyst closed it. */
export function showSiemWindow(sessionId: string, url: string): void {
  const w = window.open("", siemWindowName(sessionId));
  if (!w) { window.location.href = url; return; }
  if (!isOpenOn(w, "/team/")) w.location.href = url;
  w.focus();
}
