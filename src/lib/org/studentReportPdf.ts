/**
 * The per-student PDF report an org admin downloads (demo feedback 2026-11: "a PDF file to
 * track each employee"). Built in the browser from the same data the student page shows
 * (GET /api/org/students/[id] and its /plan), so it holds nothing the admin cannot already
 * see, and no answer key: mistakes list the question and the learner's answer only.
 *
 * It looks like the platform: the same dark surfaces, panels with a hairline border, the cyan
 * accent, uppercase tracked labels and the green / amber / red status colours (globals.css and
 * tailwind.config.ts are the source of every colour below).
 *
 * jsPDF's built-in font covers Latin text; any text in Hebrew (a name, an organisation, a
 * sentence that starts with a name) is drawn through src/lib/certificate/pdfText.ts, which
 * renders it on a canvas, so nothing prints as "????".
 */
import type { jsPDF } from "jspdf";
import type { StudentDetail } from "@/app/api/org/students/[id]/route";
import type { PersonalPlanResponse } from "@/app/api/org/students/[id]/plan/route";
import { pdfText, needsCanvas } from "@/lib/certificate/pdfText";
import { lastSeenAt, metricsOf, reportNarrative, type Narrative, type ReportMetrics } from "./reportMetrics";
import type { ReportSnapshotResponse } from "@/app/api/org/students/[id]/report-snapshot/route";

type RGB = [number, number, number];
const PAGE_W = 210, PAGE_H = 297, M = 14, W = PAGE_W - 2 * M, BOTTOM = PAGE_H - 16;

// ── The platform's palette (globals.css :root, tailwind.config.ts) ──
const BG: RGB = [7, 11, 20];            // --bg
const PANEL: RGB = [11, 18, 32];        // --bg-elevated
const BORDER: RGB = [30, 41, 59];       // --border
const WHITE: RGB = [255, 255, 255];
const INK: RGB = [226, 232, 240];       // slate-200, body text
const MUTED: RGB = [148, 163, 184];     // slate-400
const DIM: RGB = [129, 144, 165];       // slate-500 (lifted for contrast)
const ACCENT: RGB = [34, 211, 238];     // cyber-400
const ACCENT_SOFT: RGB = [103, 232, 249]; // cyber-300
const GOOD: RGB = [0, 255, 157];        // neon green
const WARN: RGB = [255, 176, 32];       // neon amber
const BAD: RGB = [255, 107, 53];        // severity high

const MIN_ITEMS = 5;
const VERDICT: Record<string, string> = { true_positive: "True positive", benign_true_positive: "Benign true positive", false_positive: "False positive", escalate: "Escalate", benign: "Benign", malicious: "Malicious", informational: "Informational" };

/** A white-label organisation's own logo, ready to place (loadReportLogo). */
export interface ReportLogo {
  dataUrl: string;
  width: number;
  height: number;
  /** The logo already spells the name: the name is not written beside it. */
  hasName: boolean;
}

export interface ReportInput {
  /** The organisation's logo for a white-label brand; null or absent = the platform lockup. */
  logo?: ReportLogo | null;
  student: StudentDetail;
  plan?: PersonalPlanResponse | null;
  /** Shown in the header and footer ("HACK THE SOC", or the white-label brand). */
  brand: string;
  orgName?: string | null;
  /** The previous report's figures (migration 0110), for "since the previous report". */
  previous?: { created_at: string; metrics: ReportMetrics } | null;
}

const DAY = 86_400_000;
const fmtDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "n/a");
const fmtShort = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
const fmtTime = (iso: string) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
const fmtMs = (ms: number | null) => (ms === null ? "n/a" : ms < 60_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`);
const pct = (n: number | null | undefined) => (n === null || n === undefined ? "n/a" : `${Math.round(n)}%`);
const nameOf = (s: StudentDetail) => s.display_name || s.handle || s.user_id.slice(0, 8);
const agoLabel = (iso: string, now = Date.now()) => { const d = Math.floor((now - Date.parse(iso)) / DAY); return d <= 0 ? "today" : d === 1 ? "yesterday" : `${d} days ago`; };
/** A colour at `a` opacity over the page background (the platform's `bg-x/10`, `border-x/40`). */
const tint = (c: RGB, a: number, over: RGB = BG): RGB => [0, 1, 2].map(i => Math.round(c[i] * a + over[i] * (1 - a))) as RGB;
/** Same length, Latin only: lets jsPDF measure a line that will be drawn on a canvas. */
const measurable = (s: string) => (needsCanvas(s) ? s.replace(/[^\x20-\x7E\xA0-\xFF]/g, "x") : s);
const statusRgb = (st: Narrative["status"]): RGB => (st === "on track" ? GOOD : st === "needs attention" ? WARN : st === "inactive" ? BAD : MUTED);

function levelOf(acc: number | null, items: number): { label: string; rgb: RGB } {
  if (acc === null || items < MIN_ITEMS) return { label: "Not enough answers", rgb: DIM };
  if (acc >= 80) return { label: "Strong", rgb: GOOD };
  if (acc >= 60) return { label: "Developing", rgb: WARN };
  return { label: "Weak", rgb: BAD };
}

interface TextStyle { size: number; rgb: RGB; bold?: boolean; align?: "left" | "right" | "center" }
interface CardItem { label: string; value: string; hint?: string; tone?: RGB }

class Writer {
  y = M;
  constructor(public pdf: jsPDF, private brand: string, private subject: string) {}

  /** The dark page: background, a faint grid at the top like the app shell, the accent line. */
  paint(grid = false) {
    const p = this.pdf;
    p.setFillColor(...BG); p.rect(0, 0, PAGE_W, PAGE_H, "F");
    if (grid) this.grid();
    p.setFillColor(...ACCENT); p.rect(0, 0, PAGE_W, 1.4, "F");
    p.setLineWidth(0.2);
  }

  private grid() {
    const p = this.pdf;
    // The grid fades into the page, band by band.
    const bands = 5, step = 8.5;
    p.setLineWidth(0.1);
    for (let r = 0; r < bands; r++) {
      p.setDrawColor(...tint(BORDER, 0.5 * (1 - r / bands)));
      for (let x = 0; x <= PAGE_W; x += step) p.line(x, r * step, x, (r + 1) * step);
      p.line(0, (r + 1) * step, PAGE_W, (r + 1) * step);
    }
  }

  ensure(h: number) { if (this.y + h > BOTTOM) this.page(); }
  page() { this.pdf.addPage(); this.paint(); this.y = M + 8; this.runningHeader(); }

  runningHeader() {
    this.text(`${this.brand.toUpperCase()}  ·  PROGRESS REPORT  ·  ${this.subject}`, M, M - 2, { size: 7, rgb: DIM, bold: true });
    this.pdf.setDrawColor(...BORDER); this.pdf.line(M, M + 1, PAGE_W - M, M + 1);
  }

  /** Text with its baseline at (x, y). Anything jsPDF's font cannot draw goes through a canvas. */
  text(s: string, x: number, y: number, st: TextStyle) {
    const p = this.pdf;
    if (needsCanvas(s)) {
      // pdfText aligns left or centre; a right-aligned canvas line is placed by its measured width.
      p.setFont("helvetica", st.bold ? "bold" : "normal"); p.setFontSize(st.size);
      const left = st.align === "right" ? x - p.getTextWidth(measurable(s)) : x;
      pdfText(p, s, left, y, { size: st.size, rgb: st.rgb, bold: st.bold, align: st.align === "center" ? "center" : "left" });
      return;
    }
    p.setFont("helvetica", st.bold ? "bold" : "normal"); p.setFontSize(st.size); p.setTextColor(...st.rgb);
    p.text(s, x, y, st.align && st.align !== "left" ? { align: st.align } : undefined);
  }

  /** Word wrap that also works for a line with Hebrew in it. */
  wrap(s: string, width: number, size: number, bold = false): string[] {
    const p = this.pdf;
    p.setFont("helvetica", bold ? "bold" : "normal"); p.setFontSize(size);
    const out: string[] = [];
    for (const block of String(s ?? "").split("\n")) {
      let line = "";
      for (const word of block.split(/\s+/).filter(Boolean)) {
        const next = line ? `${line} ${word}` : word;
        if (line && p.getTextWidth(measurable(next)) > width) { out.push(line); line = word; } else line = next;
      }
      out.push(line);
    }
    return out.length ? out : [""];
  }

  /** A panel like the app's cards: elevated surface, hairline border. */
  panel(x: number, y: number, w: number, h: number, fill: RGB = PANEL, border: RGB = BORDER) {
    const p = this.pdf;
    p.setFillColor(...fill); p.setDrawColor(...border); p.setLineWidth(0.2);
    p.roundedRect(x, y, w, h, 1.6, 1.6, "FD");
  }

  /** Uppercase tracked label, as on the app's metric tiles. */
  label(s: string, x: number, y: number, rgb: RGB = MUTED, size = 6.2, align: "left" | "right" = "left") {
    this.tracked(s.toUpperCase(), x, y, { size, rgb, bold: true, align }, 0.25);
  }

  /** Letter-spaced text; returns its width. jsPDF does not count the spacing when it aligns or
   *  measures, so the width is worked out here and a right-aligned line is placed by hand. */
  tracked(s: string, x: number, y: number, st: TextStyle, space: number): number {
    const p = this.pdf;
    if (needsCanvas(s)) { this.text(s, x, y, st); p.setFont("helvetica", st.bold ? "bold" : "normal"); p.setFontSize(st.size); return p.getTextWidth(measurable(s)); }
    p.setFont("helvetica", st.bold ? "bold" : "normal"); p.setFontSize(st.size); p.setTextColor(...st.rgb);
    const width = p.getTextWidth(s) + Math.max(0, s.length - 1) * space;
    p.setCharSpace(space);
    p.text(s, st.align === "right" ? x - width : x, y);
    p.setCharSpace(0);
    return width;
  }

  heading(text: string) {
    this.ensure(16);
    this.y += 5;
    const p = this.pdf;
    p.setFillColor(...ACCENT); p.roundedRect(M, this.y - 3.1, 1.1, 4, 0.5, 0.5, "F");
    this.text(text, M + 3.2, this.y, { size: 11, rgb: WHITE, bold: true });
    p.setFont("helvetica", "bold"); p.setFontSize(11);
    const end = M + 3.2 + p.getTextWidth(measurable(text)) + 3;
    p.setDrawColor(...BORDER); p.line(end, this.y - 1.2, PAGE_W - M, this.y - 1.2);
    this.y += 6.5;
  }

  para(text: string, size = 9, rgb: RGB = INK, x = M, width = W) {
    const lh = size * 0.47;
    for (const l of this.wrap(text, width, size)) { this.ensure(lh + 1); this.text(l, x, this.y, { size, rgb }); this.y += lh; }
    this.y += 1.5;
  }

  /** A pill like the app's status badges: tinted fill, coloured border and text. */
  chip(label: string, rgb: RGB, x: number, y: number): number {
    const p = this.pdf;
    p.setFont("helvetica", "bold"); p.setFontSize(6.6);
    const w = p.getTextWidth(label.toUpperCase()) + Math.max(0, label.length - 1) * 0.2 + 5.6;
    p.setFillColor(...tint(rgb, 0.12)); p.setDrawColor(...tint(rgb, 0.45)); p.setLineWidth(0.2);
    p.roundedRect(x, y - 3.4, w, 5, 2.5, 2.5, "FD");
    this.tracked(label.toUpperCase(), x + 2.8, y, { size: 6.6, rgb, bold: true }, 0.2);
    return w;
  }

  /** A titled paragraph in its own panel with an accent edge (the written summary). */
  note(title: string, text: string, accent: RGB = ACCENT) {
    const p = this.pdf;
    const lines = this.wrap(text, W - 11, 8.8);
    const h = 8.5 + lines.length * 4.1 + 2;
    this.ensure(h + 2);
    this.panel(M, this.y, W, h);
    p.setFillColor(...accent); p.roundedRect(M + 1.4, this.y + 1.6, 0.8, h - 3.2, 0.4, 0.4, "F");
    this.label(title, M + 5, this.y + 5.2, accent);
    let ty = this.y + 9.8;
    for (const l of lines) { this.text(l, M + 5, ty, { size: 8.8, rgb: INK }); ty += 4.1; }
    this.y += h + 2.2;
  }

  /** Metric tiles: tracked label, big value, small hint. */
  cards(items: CardItem[], per = 4) {
    const gap = 2.4, w = (W - gap * (per - 1)) / per, h = 19;
    for (let i = 0; i < items.length; i += per) {
      this.ensure(h + 3);
      items.slice(i, i + per).forEach((f, j) => {
        const x = M + j * (w + gap);
        this.panel(x, this.y, w, h);
        this.label(f.label, x + 3, this.y + 5);
        const size = f.value.length > 16 ? 9 : f.value.length > 11 ? 10.5 : 13.5;
        this.text(f.value, x + 3, this.y + 11.6, { size, rgb: f.tone ?? WHITE, bold: true });
        if (f.hint) this.text(this.wrap(f.hint, w - 6, 6.6)[0], x + 3, this.y + 16, { size: 6.6, rgb: DIM });
      });
      this.y += h + gap;
    }
    this.y += 1;
  }

  /** The last 30 days as bars: lit when the learner was active, height = graded answers. */
  days(days: NonNullable<NonNullable<StudentDetail["activity"]>["days"]>, caption: string) {
    const p = this.pdf;
    const h = 31;
    this.ensure(h + 3);
    this.panel(M, this.y, W, h);
    this.label("Last 30 days", M + 4, this.y + 5.4);
    this.text(caption, PAGE_W - M - 4, this.y + 5.4, { size: 6.6, rgb: DIM, align: "right" });
    const x0 = M + 4, base = this.y + h - 7.5, top = this.y + 9, span = W - 8, gap = 0.9;
    const bw = (span - gap * (days.length - 1)) / days.length;
    const max = Math.max(1, ...days.map(d => d.answers));
    days.forEach((d, i) => {
      const x = x0 + i * (bw + gap);
      if (!d.active) { p.setFillColor(...BORDER); p.roundedRect(x, base - 0.9, bw, 0.9, 0.3, 0.3, "F"); return; }
      const bh = Math.max(3, (d.answers / max) * (base - top));
      p.setFillColor(...(d.answers > 0 ? ACCENT : tint(ACCENT, 0.5, PANEL)));
      p.roundedRect(x, base - bh, bw, bh, 0.5, 0.5, "F");
    });
    this.text(fmtShort(`${days[0].date}T12:00:00Z`), x0, this.y + h - 2.6, { size: 6.2, rgb: DIM });
    this.text("today", PAGE_W - M - 4, this.y + h - 2.6, { size: 6.2, rgb: DIM, align: "right" });
    this.y += h + 3;
  }

  /** One skill area: name, a bar filled to the right-first-try share, the figures, the level. */
  skill(label: string, items: number, accuracy: number | null) {
    const p = this.pdf;
    const l = levelOf(accuracy, items);
    this.ensure(8);
    this.text(this.wrap(label, 58, 8.6)[0], M + 1, this.y, { size: 8.6, rgb: INK });
    const bx = M + 62, bw = 62;
    p.setFillColor(...BORDER); p.roundedRect(bx, this.y - 2.3, bw, 2.2, 1.1, 1.1, "F");
    if (accuracy !== null && accuracy > 0) { p.setFillColor(...l.rgb); p.roundedRect(bx, this.y - 2.3, Math.max(2.2, (bw * Math.min(100, accuracy)) / 100), 2.2, 1.1, 1.1, "F"); }
    this.text(pct(accuracy), bx + bw + 13, this.y, { size: 8.6, rgb: WHITE, bold: true, align: "right" });
    this.text(`${items} answered`, bx + bw + 16, this.y, { size: 7, rgb: DIM });
    this.text(l.label, PAGE_W - M - 1, this.y, { size: 7.4, rgb: l.rgb, bold: true, align: "right" });
    this.y += 4;
    p.setDrawColor(...tint(BORDER, 0.6)); p.line(M, this.y - 1.4, PAGE_W - M, this.y - 1.4);
    this.y += 2.6;
  }

  /** A table like the app's: uppercase muted header between hairlines, divided rows. */
  table(cols: { label: string; w: number; align?: "left" | "right" }[], rows: { cells: string[]; rgb?: (RGB | null)[] }[], empty = "Nothing recorded yet.") {
    const p = this.pdf;
    const header = () => {
      this.ensure(9);
      p.setDrawColor(...BORDER); p.line(M, this.y - 4.2, PAGE_W - M, this.y - 4.2); p.line(M, this.y + 1.8, PAGE_W - M, this.y + 1.8);
      let x = M + 1.5;
      for (const c of cols) {
        this.label(c.label, c.align === "right" ? x + c.w - 3 : x, this.y, MUTED, 6.2, c.align ?? "left");
        x += c.w;
      }
      this.y += 6.3;
    };
    if (rows.length === 0) { this.para(empty, 8.6, DIM); return; }
    header();
    for (const r of rows) {
      const wrapped = r.cells.map((c, i) => this.wrap(c || "-", cols[i].w - 3, 8.3));
      const h = Math.max(...wrapped.map(w => w.length)) * 3.8 + 2.2;
      if (this.y + h > BOTTOM) { this.page(); header(); }
      let x = M + 1.5;
      wrapped.forEach((lines, i) => {
        const st: TextStyle = { size: 8.3, rgb: r.rgb?.[i] ?? INK, align: cols[i].align };
        lines.forEach((l, k) => this.text(l, cols[i].align === "right" ? x + cols[i].w - 3 : x, this.y + k * 3.8, st));
        x += cols[i].w;
      });
      this.y += h;
      p.setDrawColor(...tint(BORDER, 0.6)); p.line(M, this.y - 3.2, PAGE_W - M, this.y - 3.2);
    }
    this.y += 2;
  }

  /**
   * The logo, top left; returns its width. The platform's lockup is drawn as in the app (the
   * shield in its tile, then HACK THE SOC with THE in the accent); a white-label organisation
   * gets its own logo, with its name beside it unless the logo already spells it.
   */
  logo(brand: string, logo?: ReportLogo | null): number {
    const p = this.pdf;
    const top = 6.8, size = 7.4, base = 12;
    if (logo) {
      const w = Math.min(46, (logo.width / Math.max(1, logo.height)) * size);
      const h = (w * logo.height) / Math.max(1, logo.width);
      try { p.addImage(logo.dataUrl, "PNG", M, top + (size - h) / 2, w, h); } catch { return this.tracked(brand.toUpperCase(), M, base, { size: 8.5, rgb: ACCENT, bold: true }, 0.35); }
      if (logo.hasName) return w;
      this.text(brand, M + w + 2.5, base, { size: 10.5, rgb: WHITE, bold: true });
      p.setFont("helvetica", "bold"); p.setFontSize(10.5);
      return w + 2.5 + p.getTextWidth(measurable(brand));
    }
    if (brand.trim().toUpperCase() !== "HACK THE SOC") {
      // Another name without a logo image: the name alone, in the accent.
      return this.tracked(brand.toUpperCase(), M, base, { size: 8.5, rgb: ACCENT, bold: true }, 0.35);
    }
    // The tile: accent border, tinted fill (border-cyber-500/60 bg-cyber-500/10).
    p.setFillColor(...tint(ACCENT, 0.1)); p.setDrawColor(...tint(ACCENT, 0.6)); p.setLineWidth(0.25);
    p.roundedRect(M, top, size, size, 1.4, 1.4, "FD");
    // The shield and its tick, from the app's 24-unit icon.
    const k = (size * 0.6) / 24, ox = M + size * 0.2, oy = top + size * 0.2;
    p.setDrawColor(...ACCENT_SOFT); p.setLineWidth(0.38); p.setLineJoin("round"); p.setLineCap("round");
    p.lines([[-9, 4], [0, 6], [0, 5, 3.5, 9.5, 9, 10], [5.5, -0.5, 9, -5, 9, -10], [0, -6]], ox + 12 * k, oy + 2 * k, [k, k], "S", true);
    p.lines([[2, 2], [4, -4]], ox + 9 * k, oy + 12 * k, [k, k], "S", false);
    p.setLineWidth(0.2); p.setLineJoin("miter"); p.setLineCap("butt");
    // The wordmark, monospaced and tracked like the app's.
    let x = M + size + 2.6;
    for (const [word, rgb] of [["HACK", WHITE], ["THE", ACCENT], ["SOC", WHITE]] as [string, RGB][]) {
      p.setFont("courier", "bold"); p.setFontSize(11.5); p.setTextColor(...rgb);
      p.setCharSpace(0.45);
      p.text(word, x, base - 0.1);
      p.setCharSpace(0);
      x += p.getTextWidth(word) + word.length * 0.45 + 1.5;
    }
    return x - 1.9 - M;
  }

  /** The top of a report: brand line, generated date, big title, sub lines. */
  masthead(brand: string, orgName: string | null | undefined, title: string, sub: string[], logo?: ReportLogo | null) {
    this.paint(true);
    const bw = this.logo(brand, logo);
    if (orgName) this.text(`·  ${orgName}`, M + bw + 3, 12, { size: 8.5, rgb: MUTED });
    this.text(`Generated ${new Date().toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}`, PAGE_W - M, 12, { size: 7.4, rgb: DIM, align: "right" });
    this.label("Progress report", M, 19.5, DIM);
    this.text(title, M, 28.5, { size: 21, rgb: WHITE, bold: true });
    let y = 34.5;
    for (const line of sub) { this.text(line, M, y, { size: 8.2, rgb: MUTED }); y += 4.2; }
    this.y = y + 2.5;
  }
}

/** Draws one student's report starting on the current page of `pdf`. */
export function drawStudentReport(pdf: jsPDF, input: ReportInput): void {
  const s = input.student;
  const name = nameOf(s);
  const w = new Writer(pdf, input.brand, name);
  const story = reportNarrative(s, input.plan, input.previous ?? null);
  const act = s.activity;
  const seen = lastSeenAt(s);

  // ── Masthead ──
  const affDays = s.affiliation_expires_at ? Math.ceil((Date.parse(s.affiliation_expires_at) - Date.now()) / DAY) : null;
  w.masthead(input.brand, input.orgName, name, [
    `${s.handle ? `@${s.handle}  ·  ` : ""}${s.role}  ·  ${s.status}  ·  joined ${fmtDate(s.joined_at)}${affDays !== null ? `  ·  ${affDays < 0 ? "enrolment lapsed" : `enrolment ends in ${affDays} days`}` : ""}`,
  ], input.logo);
  w.chip(story.status, statusRgb(story.status), M, w.y + 1.5);
  w.y += 8;

  // ── Presence: when the learner was really here ──
  const stale = seen ? (Date.now() - Date.parse(seen)) / DAY > 14 : false;
  const tracked = typeof act?.visits_30 === "number";
  w.cards([
    { label: "Last seen", value: seen ? fmtDate(seen) : "Never", hint: seen ? `${agoLabel(seen)} at ${fmtTime(seen)}` : "has not opened the platform", tone: !seen ? BAD : stale ? WARN : ACCENT_SOFT },
    { label: "Active days (last 30)", value: act ? `${act.active_days_30} / 30` : "n/a", hint: act ? `${act.active_days_7} in the last 7 days` : undefined },
    { label: "Visits (last 30 days)", value: tracked ? String(act?.visits_30) : "n/a", hint: tracked ? `${act?.active_minutes_30 ?? 0} active minutes` : "recorded from the next visit on" },
    { label: "Last login", value: act?.last_sign_in_at ? fmtDate(act.last_sign_in_at) : "Never", hint: "start of the current session", tone: MUTED },
  ]);
  if (act?.days?.length) w.days(act.days, `${act.answered_30} graded answers  ·  bar height = answers that day`);

  // ── Written summary ──
  w.heading("Overview");
  for (const p of story.paragraphs) {
    w.note(p.title, p.text, p.title === "Needs action" ? WARN : p.title === "Strengths and topics to strengthen" ? GOOD : ACCENT);
  }

  // ── Key figures, with the change since the previous report ──
  const ft = s.summary.first_try;
  const cur = metricsOf(s, input.plan);
  const prev = input.previous?.metrics;
  const delta = (a: number | null, b: number | null | undefined, unit = "") => (prev && a !== null && b !== null && b !== undefined && a !== b ? ` (${a > b ? "+" : ""}${Math.round((a - b) * 10) / 10}${unit})` : "");
  w.heading(prev && input.previous ? `Key figures  ·  change since ${fmtDate(input.previous.created_at)}` : "Key figures");
  w.cards([
    { label: "XP", value: s.xp.toLocaleString() + delta(cur.xp, prev?.xp), hint: `level ${s.level}`, tone: ACCENT_SOFT },
    { label: "Right first try", value: pct(ft.accuracy) + delta(cur.first_try_pct, prev?.first_try_pct, " pts"), hint: `${ft.firstTryCorrect} of ${ft.items} questions`, tone: levelOf(ft.accuracy, ft.items).rgb === DIM ? WHITE : levelOf(ft.accuracy, ft.items).rgb },
    { label: "Rooms", value: `${s.summary.rooms_completed} / ${s.summary.rooms_started}` + delta(cur.rooms_completed, prev?.rooms_completed), hint: "completed / started" },
    { label: "Open mistakes", value: String(cur.open_mistakes) + delta(cur.open_mistakes, prev?.open_mistakes), hint: "not yet corrected", tone: cur.open_mistakes > 0 ? WARN : GOOD },
    { label: "Scenarios", value: String(s.summary.scenarios_completed) + delta(cur.scenarios_completed, prev?.scenarios_completed), hint: `average score ${pct(s.summary.scenario_avg_score)}` },
    { label: "Live SOC shifts", value: String(s.summary.sessions) + delta(cur.sessions, prev?.sessions), hint: `detection ${pct(s.summary.avg_detect_rate)}` },
    { label: "Median time to decide", value: fmtMs(s.summary.median_decision_latency_ms), hint: `${s.summary.tasks_answered} tasks timed` },
    { label: "Answers (30 days)", value: act ? String(act.answered_30) : "n/a", hint: act ? `${act.answered_7} in the last 7 days` : undefined },
  ]);

  // ── Skills ──
  w.heading("Skills by area");
  const answered = s.skills.filter(a => a.items > 0);
  if (answered.length === 0) w.para("No graded answers yet.", 8.6, DIM);
  else {
    w.y += 1;
    for (const a of [...answered].sort((x, y) => (y.accuracy ?? -1) - (x.accuracy ?? -1))) w.skill(a.label, a.items, a.accuracy);
  }
  if (s.recommendations.length) w.para(`Recommended next rooms: ${s.recommendations.map(r => `${r.title} (${r.area_label})`).join("; ")}.`, 8.2, MUTED);

  // ── Learning plan, with time against target ──
  if (input.plan) {
    const plans = [...(input.plan.personal ? [{ title: `Personal plan: ${input.plan.personal.title}`, due: input.plan.personal.due_at, items: input.plan.personal.items }] : []),
      ...input.plan.assigned.map(p => ({ title: p.title, due: p.due_at, items: p.items }))];
    w.heading("Learning plan");
    if (plans.length === 0) w.para("No learning plan assigned.", 8.6, DIM);
    for (const p of plans) {
      w.para(`${p.title}${p.due ? `  ·  due ${fmtDate(p.due)}` : ""}`, 9.2, WHITE);
      w.y += 2;
      w.table(
        [{ label: "Item", w: 86 }, { label: "Kind", w: 20 }, { label: "Status", w: 26 }, { label: "Time / target", w: 50 }],
        p.items.map(it => {
          const status = it.status === "done" ? "Done" : it.status === "in_progress" ? "In progress" : it.status === "untracked" ? "Not tracked" : "Not started";
          const target = it.target_minutes;
          const spent = it.minutes_spent;
          const time = !target ? "-" : spent === null || spent === undefined ? `not measured / ${target} min` : `${Math.round(spent)} / ${target} min`;
          return {
            cells: [it.title, it.kind, status, time],
            rgb: [null, MUTED, it.status === "done" ? GOOD : it.status === "in_progress" ? WARN : MUTED, target && spent !== null && spent !== undefined ? (spent >= target ? GOOD : WARN) : MUTED],
          };
        }),
      );
    }
  }

  // ── Rooms ──
  w.heading("Learning rooms");
  w.y += 1;
  w.table(
    [{ label: "Room", w: 92 }, { label: "Status", w: 26 }, { label: "Tasks", w: 16, align: "right" }, { label: "XP", w: 16, align: "right" }, { label: "Completed", w: 32 }],
    [...s.rooms].sort((a, b) => Number(b.completed) - Number(a.completed)).map(r => ({
      cells: [r.title, r.completed ? "Completed" : "In progress", String(r.tasks_done), String(r.xp_earned), r.completed_at ? fmtDate(r.completed_at) : "-"],
      rgb: [null, r.completed ? GOOD : WARN, MUTED, ACCENT_SOFT, MUTED],
    })),
  );

  // ── Scenarios ──
  w.heading("Scenarios");
  w.y += 1;
  w.table(
    [{ label: "Scenario", w: 84 }, { label: "Score", w: 18, align: "right" }, { label: "Verdict", w: 30 }, { label: "Report", w: 18 }, { label: "Date", w: 32 }],
    s.scenarios.map(sc => ({
      cells: [sc.title, sc.score === null ? "-" : `${sc.score}%`, VERDICT[sc.report?.verdict ?? ""] ?? sc.report?.verdict ?? "-", sc.report?.passed === undefined ? "-" : sc.report.passed ? "Passed" : "Failed", fmtDate(sc.completed_at)],
      rgb: [null, sc.score !== null && sc.score < 60 ? BAD : WHITE, MUTED, sc.report?.passed === undefined ? MUTED : sc.report.passed ? GOOD : BAD, MUTED],
    })),
  );

  // ── Live SOC shifts ──
  w.heading("Live SOC dashboard shifts");
  w.y += 1;
  w.table(
    [{ label: "Date", w: 50 }, { label: "Detection rate", w: 40, align: "right" }, { label: "Duration", w: 40, align: "right" }],
    s.sessions.slice(0, 15).map(se => ({
      cells: [fmtDate(se.played_at), pct(se.detect_rate), se.duration_ms ? fmtMs(se.duration_ms) : "-"],
      rgb: [null, se.detect_rate !== null && se.detect_rate < 60 ? BAD : WHITE, MUTED],
    })),
  );

  // ── Mistakes ──
  w.heading("Where mistakes were made");
  w.y += 1;
  const groups = [...s.mistake_groups].filter(g => g.mistakes.length > 0).sort((a, b) => b.mistakes.length - a.mistakes.length);
  w.table(
    [{ label: "Room", w: 92 }, { label: "Right first try", w: 34, align: "right" }, { label: "Mistakes", w: 24, align: "right" }, { label: "Still open", w: 32, align: "right" }],
    groups.map(g => {
      const open = g.mistakes.filter(m => !m.solved).length;
      return { cells: [g.room_title, `${g.first_try_correct}/${g.items}`, String(g.mistakes.length), String(open)], rgb: [null, MUTED, null, open > 0 ? WARN : GOOD] };
    }),
    "No mistakes recorded.",
  );
  const sample = groups.flatMap(g => g.mistakes.filter(m => !m.solved).slice(0, 2).map(m => ({ room: g.room_title, m }))).slice(0, 8);
  if (sample.length) {
    w.y += 1;
    w.label("Open mistakes: question and first answer", M, w.y, MUTED);
    w.y += 4.5;
    for (const { room, m } of sample) {
      w.para(`${room}: ${m.prompt ?? "question"}${m.chosen ? `  First answer: ${m.chosen}` : ""}`, 7.8, INK);
    }
  }
}

function footer(pdf: jsPDF, brand: string) {
  const n = pdf.getNumberOfPages();
  for (let i = 1; i <= n; i++) {
    pdf.setPage(i);
    pdf.setDrawColor(...BORDER); pdf.setLineWidth(0.2); pdf.line(M, PAGE_H - 12, PAGE_W - M, PAGE_H - 12);
    pdf.setFont("helvetica", "normal"); pdf.setFontSize(7); pdf.setTextColor(...DIM);
    pdf.text(`${needsCanvas(brand) ? "" : `${brand}  ·  `}Confidential: learner records for the organisation's training staff`, M, PAGE_H - 7.5);
    pdf.text(`Page ${i} of ${n}`, PAGE_W - M, PAGE_H - 7.5, { align: "right" });
  }
}

const safeName = (s: string) => s.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "student";

/** One student's report, downloaded as a PDF. */
export async function downloadStudentReport(input: ReportInput): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const pdf = new jsPDF({ unit: "mm", format: "a4" });
  drawStudentReport(pdf, input);
  footer(pdf, input.brand);
  pdf.save(`student-report_${safeName(nameOf(input.student))}_${new Date().toISOString().slice(0, 10)}.pdf`);
}

/** Every student of a list in one PDF, each starting on a new page. */
export async function downloadClassReport(inputs: ReportInput[], brand: string, orgName?: string | null, logo?: ReportLogo | null): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const pdf = new jsPDF({ unit: "mm", format: "a4" });
  drawClassOverview(pdf, inputs, brand, orgName, logo);
  inputs.forEach(input => {
    pdf.addPage();
    drawStudentReport(pdf, { ...input, orgName: input.orgName ?? orgName, logo: input.logo ?? logo });
  });
  footer(pdf, brand);
  pdf.save(`class-report_${new Date().toISOString().slice(0, 10)}.pdf`);
}

/** Page 1 of the class report: one line per learner, the ones needing action first. */
export function drawClassOverview(pdf: jsPDF, inputs: ReportInput[], brand: string, orgName?: string | null, logo?: ReportLogo | null) {
  const w = new Writer(pdf, brand, "Class overview");
  const rows = inputs.map(i => ({ i, n: reportNarrative(i.student, i.plan, i.previous ?? null), seen: lastSeenAt(i.student) }));
  const order = { "not started": 0, inactive: 1, "needs attention": 2, "on track": 3 } as const;
  rows.sort((a, b) => order[a.n.status] - order[b.n.status] || nameOf(a.i.student).localeCompare(nameOf(b.i.student)));
  const count = (st: Narrative["status"]) => rows.filter(r => r.n.status === st).length;
  const week = rows.filter(r => r.seen && Date.now() - Date.parse(r.seen) < 7 * DAY).length;

  w.masthead(brand, orgName, "Class progress report", [
    `${rows.length} ${rows.length === 1 ? "learner" : "learners"}  ·  ${week} on the platform in the last 7 days. The learners who need action are listed first; each learner's full report follows.`,
  ], logo);
  w.y += 2;
  w.cards([
    { label: "On track", value: String(count("on track")), hint: "active, no weak topic", tone: GOOD },
    { label: "Need attention", value: String(count("needs attention")), hint: "a weak topic or many open mistakes", tone: count("needs attention") ? WARN : WHITE },
    { label: "Inactive", value: String(count("inactive")), hint: "not seen for 14 days, or no activity in 30", tone: count("inactive") ? BAD : WHITE },
    { label: "Not started", value: String(count("not started")), hint: "never opened the platform", tone: count("not started") ? MUTED : WHITE },
  ]);
  w.heading("Learners");
  w.y += 1;
  w.table(
    [{ label: "Learner", w: 40 }, { label: "Status", w: 27 }, { label: "Last seen", w: 25 }, { label: "Active days", w: 21, align: "right" }, { label: "Right 1st try", w: 25, align: "right" }, { label: "Since last report", w: 44 }],
    rows.map(({ i, n, seen }) => {
      const s = i.student;
      const stale = seen ? (Date.now() - Date.parse(seen)) / DAY > 14 : false;
      return {
        cells: [nameOf(s), n.status, seen ? fmtDate(seen) : "never", String(s.activity?.active_days_30 ?? "-"), pct(s.summary.first_try.accuracy), n.change],
        rgb: [WHITE, statusRgb(n.status), !seen ? BAD : stale ? WARN : null, null, null, MUTED],
      };
    }),
    "No learners in this class.",
  );
  w.para("Last seen: the last time the learner was on the platform, also without logging in again. Active days: days with any activity in the last 30 days. Right 1st try: share of graded questions answered right on the first attempt.", 7.2, DIM);
}

/**
 * A white-label organisation's logo as a PNG the PDF can hold (the logo route may serve SVG or
 * WebP, which jsPDF cannot place). Null for the platform's own brand, which is drawn, and when
 * the image cannot be read: the report then shows the name.
 */
export async function loadReportLogo(brand: { whiteLabel: boolean; logoSrc: string | null; logoHasName: boolean }): Promise<ReportLogo | null> {
  if (!brand.whiteLabel || !brand.logoSrc || typeof document === "undefined") return null;
  try {
    const img = await new Promise<HTMLImageElement | null>(resolve => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => resolve(null);
      el.src = brand.logoSrc as string;
    });
    if (!img || !img.naturalWidth || !img.naturalHeight) return null;
    const scale = Math.min(1, 600 / img.naturalWidth);
    const canvas = document.createElement("canvas");
    canvas.width = Math.round(img.naturalWidth * scale);
    canvas.height = Math.round(img.naturalHeight * scale);
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return { dataUrl: canvas.toDataURL("image/png"), width: canvas.width, height: canvas.height, hasName: brand.logoHasName };
  } catch { return null; }
}

/** Reads one student's detail and plan the way the student page does (org-admin routes). */
export async function loadReportInput(userId: string, brand: string, orgName?: string | null, logo?: ReportLogo | null): Promise<ReportInput> {
  const [d, p] = await Promise.all([
    fetch(`/api/org/students/${encodeURIComponent(userId)}`),
    fetch(`/api/org/students/${encodeURIComponent(userId)}/plan`).catch(() => null),
  ]);
  if (!d.ok) throw new Error((await d.json().catch(() => ({})))?.error ?? "Could not load the student.");
  const student = (await d.json()) as StudentDetail;
  const plan = p && p.ok ? ((await p.json()) as PersonalPlanResponse) : null;
  // Keep this report's figures and get the previous report's (0110); the report works without.
  let previous: ReportInput["previous"] = null;
  try {
    const r = await fetch(`/api/org/students/${encodeURIComponent(userId)}/report-snapshot`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ metrics: metricsOf(student, plan) }),
    });
    if (r.ok) previous = ((await r.json()) as ReportSnapshotResponse).previous;
  } catch { /* no comparison this time */ }
  return { student, plan, brand, orgName, previous, logo };
}
