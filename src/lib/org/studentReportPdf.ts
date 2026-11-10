/**
 * The per-student PDF report an org admin downloads (demo feedback 2026-11: "a PDF file to
 * track each employee"). Built in the browser from the same data the student page shows
 * (GET /api/org/students/[id] and its /plan), so it holds nothing the admin cannot already
 * see, and no answer key: mistakes list the question and the learner's answer only.
 *
 * jsPDF's built-in font covers Latin text; a name in Hebrew (or any other script) is drawn
 * through src/lib/certificate/pdfText.ts, which renders it on a canvas.
 */
import type { jsPDF } from "jspdf";
import type { StudentDetail } from "@/app/api/org/students/[id]/route";
import type { PersonalPlanResponse } from "@/app/api/org/students/[id]/plan/route";
import { pdfText, needsCanvas } from "@/lib/certificate/pdfText";

const PAGE_W = 210, PAGE_H = 297, M = 14, BOTTOM = PAGE_H - 16;
const INK: [number, number, number] = [20, 28, 40];
const MUTED: [number, number, number] = [96, 108, 124];
const ACCENT: [number, number, number] = [8, 145, 178];
const LINE: [number, number, number] = [214, 220, 228];
const GOOD: [number, number, number] = [22, 128, 61];
const WARN: [number, number, number] = [180, 110, 0];
const BAD: [number, number, number] = [185, 28, 28];
const MIN_ITEMS = 5;
const VERDICT: Record<string, string> = { true_positive: "True positive", benign_true_positive: "Benign true positive", false_positive: "False positive", escalate: "Escalate", benign: "Benign", malicious: "Malicious", informational: "Informational" };

export interface ReportInput {
  student: StudentDetail;
  plan?: PersonalPlanResponse | null;
  /** Shown in the header and footer ("HACK THE SOC", or the white-label brand). */
  brand: string;
  orgName?: string | null;
}

const fmtDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "n/a");
const fmtMs = (ms: number | null) => (ms === null ? "n/a" : ms < 60_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`);
const pct = (n: number | null | undefined) => (n === null || n === undefined ? "n/a" : `${Math.round(n)}%`);
const ascii = (s: string) => (needsCanvas(s) ? s.replace(/[^\x20-\x7E\xA0-\xFF]/g, "?") : s);
const nameOf = (s: StudentDetail) => s.display_name || s.handle || s.user_id.slice(0, 8);

function levelOf(acc: number | null, items: number): { label: string; rgb: [number, number, number] } {
  if (acc === null || items < MIN_ITEMS) return { label: "Not enough answers", rgb: MUTED };
  if (acc >= 80) return { label: "Strong", rgb: GOOD };
  if (acc >= 60) return { label: "Developing", rgb: WARN };
  return { label: "Weak", rgb: BAD };
}

class Writer {
  y = M;
  constructor(public pdf: jsPDF, private brand: string, private student: string) {}

  ensure(h: number) { if (this.y + h > BOTTOM) this.page(); }
  page() { this.pdf.addPage(); this.y = M + 6; this.runningHeader(); }

  runningHeader() {
    const p = this.pdf;
    p.setFont("helvetica", "normal"); p.setFontSize(8); p.setTextColor(...MUTED);
    p.text(`${this.brand} · Student progress report · ${ascii(this.student)}`, M, M);
    p.setDrawColor(...LINE); p.line(M, M + 2, PAGE_W - M, M + 2);
  }

  heading(text: string) {
    this.ensure(14);
    this.y += 4;
    const p = this.pdf;
    p.setFont("helvetica", "bold"); p.setFontSize(12); p.setTextColor(...ACCENT);
    p.text(text, M, this.y);
    this.y += 2;
    p.setDrawColor(...ACCENT); p.setLineWidth(0.4); p.line(M, this.y, M + 30, this.y); p.setLineWidth(0.2);
    this.y += 5;
  }

  para(text: string, size = 9, rgb: [number, number, number] = INK) {
    const p = this.pdf;
    p.setFont("helvetica", "normal"); p.setFontSize(size); p.setTextColor(...rgb);
    const lines = p.splitTextToSize(ascii(text), PAGE_W - 2 * M) as string[];
    for (const l of lines) { this.ensure(5); p.text(l, M, this.y); this.y += size * 0.45; }
    this.y += 1.5;
  }

  /** A simple table: header row, wrapped cells, page breaks that repeat the header. */
  table(cols: { label: string; w: number; align?: "left" | "right" }[], rows: { cells: string[]; rgb?: ([number, number, number] | null)[] }[], empty = "Nothing recorded yet.") {
    const p = this.pdf;
    const x0 = M;
    const header = () => {
      this.ensure(8);
      p.setFillColor(240, 244, 248); p.rect(x0, this.y - 4, PAGE_W - 2 * M, 6.5, "F");
      p.setFont("helvetica", "bold"); p.setFontSize(8); p.setTextColor(...MUTED);
      let x = x0 + 1.5;
      for (const c of cols) { p.text(c.label, c.align === "right" ? x + c.w - 3 : x, this.y, c.align === "right" ? { align: "right" } : undefined); x += c.w; }
      this.y += 5;
    };
    if (rows.length === 0) { this.para(empty, 9, MUTED); return; }
    header();
    for (const r of rows) {
      p.setFont("helvetica", "normal"); p.setFontSize(8.5);
      const wrapped = r.cells.map((c, i) => p.splitTextToSize(ascii(c || "-"), cols[i].w - 3) as string[]);
      const h = Math.max(...wrapped.map(w => w.length)) * 3.8 + 1.6;
      if (this.y + h > BOTTOM) { this.page(); header(); }
      let x = x0 + 1.5;
      wrapped.forEach((lines, i) => {
        p.setTextColor(...(r.rgb?.[i] ?? INK));
        lines.forEach((l, k) => p.text(l, cols[i].align === "right" ? x + cols[i].w - 3 : x, this.y + k * 3.8, cols[i].align === "right" ? { align: "right" } : undefined));
        x += cols[i].w;
      });
      this.y += h;
      p.setDrawColor(...LINE); p.line(x0, this.y - 3, PAGE_W - M, this.y - 3);
    }
    this.y += 2;
  }

  /** A row of key figures: big value, small label. */
  figures(items: { value: string; label: string }[]) {
    const p = this.pdf;
    const per = 4, w = (PAGE_W - 2 * M) / per;
    for (let i = 0; i < items.length; i += per) {
      this.ensure(16);
      items.slice(i, i + per).forEach((f, j) => {
        const x = M + j * w;
        p.setDrawColor(...LINE); p.roundedRect(x + 0.5, this.y - 4, w - 2, 14, 1.5, 1.5, "S");
        p.setFont("helvetica", "bold"); p.setFontSize(13); p.setTextColor(...INK);
        p.text(f.value, x + 3, this.y + 3);
        p.setFont("helvetica", "normal"); p.setFontSize(7.5); p.setTextColor(...MUTED);
        p.text(f.label, x + 3, this.y + 7.5);
      });
      this.y += 17;
    }
  }
}

/** Draws one student's report starting on the current page of `pdf`. */
export function drawStudentReport(pdf: jsPDF, input: ReportInput): void {
  const s = input.student;
  const name = nameOf(s);
  const w = new Writer(pdf, input.brand, name);

  // ── Title block ──
  pdf.setFillColor(...ACCENT); pdf.rect(0, 0, PAGE_W, 4, "F");
  pdf.setFont("helvetica", "bold"); pdf.setFontSize(9); pdf.setTextColor(...ACCENT);
  pdf.text(`${input.brand.toUpperCase()}${input.orgName ? ` · ${ascii(input.orgName)}` : ""}`, M, 14);
  pdf.setFont("helvetica", "normal"); pdf.setFontSize(8); pdf.setTextColor(...MUTED);
  pdf.text(`Generated ${new Date().toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}`, PAGE_W - M, 14, { align: "right" });
  pdfText(pdf, name, M, 26, { size: 20, rgb: INK, bold: true });
  pdf.setFont("helvetica", "normal"); pdf.setFontSize(9); pdf.setTextColor(...MUTED);
  const affDays = s.affiliation_expires_at ? Math.ceil((Date.parse(s.affiliation_expires_at) - Date.now()) / 86_400_000) : null;
  pdf.text([
    `${s.handle ? `@${ascii(s.handle)} · ` : ""}${s.role} · ${s.status}`,
    `Joined ${fmtDate(s.joined_at)} · last active ${fmtDate(s.last_active_at)}${affDays !== null ? ` · ${affDays < 0 ? "enrolment lapsed" : `enrolment ends in ${affDays} days`}` : ""}`,
  ], M, 33);
  w.y = 46;

  // ── Key figures ──
  const ft = s.summary.first_try;
  const unsolved = s.mistake_groups.reduce((n, g) => n + g.mistakes.filter(m => !m.solved).length, 0);
  w.heading("Summary");
  w.figures([
    { value: s.xp.toLocaleString(), label: `XP · level ${s.level}` },
    { value: pct(ft.accuracy), label: `Right first try (${ft.firstTryCorrect}/${ft.items})` },
    { value: `${s.summary.rooms_completed}/${s.summary.rooms_started}`, label: "Rooms completed / started" },
    { value: String(s.summary.tasks_answered), label: "Tasks answered" },
    { value: String(s.summary.scenarios_completed), label: `Scenarios · avg ${pct(s.summary.scenario_avg_score)}` },
    { value: String(s.summary.sessions), label: `Live SOC shifts · detect ${pct(s.summary.avg_detect_rate)}` },
    { value: fmtMs(s.summary.median_decision_latency_ms), label: "Median time to decide" },
    { value: String(unsolved), label: "Mistakes not yet corrected" },
  ]);

  // ── Skills ──
  w.heading("Skills by area");
  const judged = s.skills.filter(a => a.items >= MIN_ITEMS);
  const strong = judged.filter(a => (a.accuracy ?? 0) >= 80).map(a => a.label);
  const weak = judged.filter(a => (a.accuracy ?? 100) < 60).map(a => a.label);
  if (strong.length || weak.length) {
    w.para(`Strong: ${strong.join(", ") || "none yet"}. Needs work: ${weak.join(", ") || "none"}.`);
  }
  w.table(
    [{ label: "Area", w: 78 }, { label: "Answered", w: 26, align: "right" }, { label: "Right first try", w: 34, align: "right" }, { label: "Level", w: 44 }],
    s.skills.filter(a => a.items > 0).map(a => {
      const l = levelOf(a.accuracy, a.items);
      return { cells: [a.label, String(a.items), pct(a.accuracy), l.label], rgb: [null, null, null, l.rgb] };
    }),
    "No graded answers yet.",
  );
  if (s.recommendations.length) w.para(`Recommended next rooms: ${s.recommendations.map(r => `${r.title} (${r.area_label})`).join("; ")}.`, 8.5, MUTED);

  // ── Learning plan, with time against target ──
  if (input.plan) {
    const plans = [...(input.plan.personal ? [{ title: `Personal plan: ${input.plan.personal.title}`, due: input.plan.personal.due_at, items: input.plan.personal.items }] : []),
      ...input.plan.assigned.map(p => ({ title: p.title, due: p.due_at, items: p.items }))];
    w.heading("Learning plan");
    if (plans.length === 0) w.para("No learning plan assigned.", 9, MUTED);
    for (const p of plans) {
      w.para(`${p.title}${p.due ? ` · due ${fmtDate(p.due)}` : ""}`, 9.5, INK);
      w.table(
        [{ label: "Item", w: 86 }, { label: "Kind", w: 20 }, { label: "Status", w: 26 }, { label: "Time / target", w: 50 }],
        p.items.map(it => {
          const status = it.status === "done" ? "Done" : it.status === "in_progress" ? "In progress" : it.status === "untracked" ? "Not tracked" : "Not started";
          const target = it.target_minutes;
          const spent = it.minutes_spent;
          const time = !target ? "-" : spent === null || spent === undefined ? `not measured / ${target} min` : `${Math.round(spent)} / ${target} min`;
          return {
            cells: [it.title, it.kind, status, time],
            rgb: [null, MUTED, it.status === "done" ? GOOD : null, target && spent !== null && spent !== undefined ? (spent >= target ? GOOD : WARN) : MUTED],
          };
        }),
      );
    }
  }

  // ── Rooms ──
  w.heading("Learning rooms");
  w.table(
    [{ label: "Room", w: 92 }, { label: "Status", w: 26 }, { label: "Tasks", w: 16, align: "right" }, { label: "XP", w: 16, align: "right" }, { label: "Completed", w: 32 }],
    [...s.rooms].sort((a, b) => Number(b.completed) - Number(a.completed)).map(r => ({
      cells: [r.title, r.completed ? "Completed" : "In progress", String(r.tasks_done), String(r.xp_earned), fmtDate(r.completed_at)],
      rgb: [null, r.completed ? GOOD : WARN, null, null, MUTED],
    })),
  );

  // ── Scenarios ──
  w.heading("Scenarios");
  w.table(
    [{ label: "Scenario", w: 84 }, { label: "Score", w: 18, align: "right" }, { label: "Verdict", w: 30 }, { label: "Report", w: 18 }, { label: "Date", w: 32 }],
    s.scenarios.map(sc => ({
      cells: [sc.title, sc.score === null ? "-" : `${sc.score}%`, VERDICT[sc.report?.verdict ?? ""] ?? sc.report?.verdict ?? "-", sc.report?.passed === undefined ? "-" : sc.report.passed ? "Passed" : "Failed", fmtDate(sc.completed_at)],
      rgb: [null, null, null, sc.report?.passed === undefined ? MUTED : sc.report.passed ? GOOD : BAD, MUTED],
    })),
  );

  // ── Live SOC shifts ──
  w.heading("Live SOC dashboard shifts");
  w.table(
    [{ label: "Date", w: 50 }, { label: "Detection rate", w: 40, align: "right" }, { label: "Duration", w: 40, align: "right" }],
    s.sessions.slice(0, 15).map(se => ({ cells: [fmtDate(se.played_at), pct(se.detect_rate), se.duration_ms ? fmtMs(se.duration_ms) : "-"] })),
  );

  // ── Mistakes ──
  w.heading("Where mistakes were made");
  const groups = [...s.mistake_groups].filter(g => g.mistakes.length > 0).sort((a, b) => b.mistakes.length - a.mistakes.length);
  w.table(
    [{ label: "Room", w: 92 }, { label: "Right first try", w: 34, align: "right" }, { label: "Mistakes", w: 24, align: "right" }, { label: "Still open", w: 32, align: "right" }],
    groups.map(g => ({
      cells: [g.room_title, `${g.first_try_correct}/${g.items}`, String(g.mistakes.length), String(g.mistakes.filter(m => !m.solved).length)],
    })),
    "No mistakes recorded.",
  );
  const sample = groups.flatMap(g => g.mistakes.filter(m => !m.solved).slice(0, 2).map(m => ({ room: g.room_title, m }))).slice(0, 8);
  if (sample.length) {
    w.para("Open mistakes (question and first answer):", 9, MUTED);
    for (const { room, m } of sample) {
      w.para(`${room}: ${m.prompt ?? "question"}${m.chosen ? `  First answer: ${m.chosen}` : ""}`, 8, INK);
    }
  }
}

function footer(pdf: jsPDF, brand: string) {
  const n = pdf.getNumberOfPages();
  for (let i = 1; i <= n; i++) {
    pdf.setPage(i);
    pdf.setFont("helvetica", "normal"); pdf.setFontSize(7.5); pdf.setTextColor(...MUTED);
    pdf.text(`${brand} · Confidential: learner records for the organisation's training staff`, M, PAGE_H - 8);
    pdf.text(`Page ${i} of ${n}`, PAGE_W - M, PAGE_H - 8, { align: "right" });
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
export async function downloadClassReport(inputs: ReportInput[], brand: string): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const pdf = new jsPDF({ unit: "mm", format: "a4" });
  inputs.forEach((input, i) => {
    if (i > 0) pdf.addPage();
    drawStudentReport(pdf, input);
  });
  footer(pdf, brand);
  pdf.save(`class-report_${new Date().toISOString().slice(0, 10)}.pdf`);
}

/** Reads one student's detail and plan the way the student page does (org-admin routes). */
export async function loadReportInput(userId: string, brand: string, orgName?: string | null): Promise<ReportInput> {
  const [d, p] = await Promise.all([
    fetch(`/api/org/students/${encodeURIComponent(userId)}`),
    fetch(`/api/org/students/${encodeURIComponent(userId)}/plan`).catch(() => null),
  ]);
  if (!d.ok) throw new Error((await d.json().catch(() => ({})))?.error ?? "Could not load the student.");
  const student = (await d.json()) as StudentDetail;
  const plan = p && p.ok ? ((await p.json()) as PersonalPlanResponse) : null;
  return { student, plan, brand, orgName };
}
