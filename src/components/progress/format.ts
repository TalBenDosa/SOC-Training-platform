/** Formatting shared by the Progress page tabs. */

export function fmtMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "–";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), r = s % 60;
  if (m < 60) return r ? `${m}m ${r}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function fmtMinutes(min: number): string {
  if (min < 60) return `${min}m`;
  return `${Math.floor(min / 60)}h ${min % 60}m`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

/** "Today" / "Yesterday" / "Mon 27 Oct" — the day headings of the activity timeline. */
export function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const that = new Date(d); that.setHours(0, 0, 0, 0);
  const diff = Math.round((today.getTime() - that.getTime()) / 86_400_000);
  if (diff === 0) return "Today";
  if (diff === 1) return "Yesterday";
  return d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short" });
}

/** "+3", "-2", "±0" against the previous period (null when there is nothing to compare). */
export function delta(now: number | null, prev: number | null, unit = ""): string | null {
  if (now === null || prev === null) return null;
  const d = Math.round(now - prev);
  if (d === 0) return `same as before`;
  return `${d > 0 ? "+" : ""}${d}${unit} vs previous`;
}

export const scoreTone = (s: number) => (s >= 80 ? "text-neon-green" : s >= 60 ? "text-severity-medium" : "text-severity-critical");

export const LEVEL_STYLE: Record<string, { label: string; cls: string; bar: string }> = {
  strong:       { label: "Strong",          cls: "border-neon-green/40 bg-neon-green/10 text-neon-green", bar: "bg-neon-green" },
  developing:   { label: "Developing",      cls: "border-severity-medium/40 bg-severity-medium/10 text-severity-medium", bar: "bg-severity-medium" },
  weak:         { label: "Weak",            cls: "border-severity-critical/40 bg-severity-critical/10 text-severity-critical", bar: "bg-severity-critical" },
  insufficient: { label: "Not enough data", cls: "border-border bg-bg text-slate-400", bar: "bg-slate-500" },
};
