/**
 * Analysts work in two windows at once: the team room is the SIEM, Sentinel is where they investigate
 * (Tal, 2026-11-07). Each session has one window of each. "Investigate in Sentinel" brings the open
 * Sentinel window forward on the incident, instead of opening another tab or reloading the one the
 * analyst is working in, which would lose their open queries.
 */
export const sentinelWindowName = (sessionId: string) => `sentinel-${sessionId}`;
export const siemWindowName = (sessionId: string) => `siem-${sessionId}`;
export const sentinelChannelName = (sessionId: string) => `sentinel-goto-${sessionId}`;

export interface SentinelTarget { incident?: string; host?: string }

/** Whether window.open("", name) gave back a window that is already showing the page. */
function isOpenOn(w: Window, path: string): boolean {
  try { return w.location.pathname.startsWith(path); } catch { return false; }   // not readable: treat as new
}

/** Opens the session's Sentinel window, or brings it forward. Returns false when a pop-up blocker stopped it. */
export function showSentinelWindow(sessionId: string, url: string, target: SentinelTarget = {}): boolean {
  const w = window.open("", sentinelWindowName(sessionId));
  if (!w) return false;
  if (isOpenOn(w, "/sentinel")) {
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

/** From Sentinel: back to the session's SIEM window, opening it if the analyst closed it. */
export function showSiemWindow(sessionId: string, url: string): void {
  const w = window.open("", siemWindowName(sessionId));
  if (!w) { window.location.href = url; return; }
  if (!isOpenOn(w, "/team/")) w.location.href = url;
  w.focus();
}
