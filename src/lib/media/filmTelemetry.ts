/**
 * Room-film playback telemetry (learner feedback 2026-11-21: films stall). Fire-and-forget: one small
 * JSON beacon per event to /api/media/film-event, which records it for signed-in learners only.
 * Never throws and never blocks playback.
 */
export type FilmEventKind = "start" | "stall" | "recovered" | "retry" | "continue" | "error" | "ended" | "skipped";

export interface FilmEvent {
  kind: FilmEventKind;
  roomId?: string;
  clipKey?: string;
  src: string;
  /** How long the film waited for data (stall episodes only). */
  waitMs?: number;
  positionS?: number;
  durationS?: number;
}

interface NetworkInformationLike { effectiveType?: string; downlink?: number }

export function sendFilmEvent(e: FilmEvent): void {
  try {
    if (typeof window === "undefined") return;
    const conn = (navigator as Navigator & { connection?: NetworkInformationLike }).connection;
    const body = JSON.stringify({
      ...e,
      positionS: e.positionS != null && Number.isFinite(e.positionS) ? Math.round(e.positionS * 10) / 10 : undefined,
      durationS: e.durationS != null && Number.isFinite(e.durationS) ? Math.round(e.durationS * 10) / 10 : undefined,
      netType: conn?.effectiveType,
      downlinkMbps: conn?.downlink,
    });
    const blob = new Blob([body], { type: "application/json" });
    if (navigator.sendBeacon?.("/api/media/film-event", blob)) return;
    void fetch("/api/media/film-event", { method: "POST", body, keepalive: true, headers: { "Content-Type": "application/json" } }).catch(() => {});
  } catch {
    /* telemetry is best effort */
  }
}
