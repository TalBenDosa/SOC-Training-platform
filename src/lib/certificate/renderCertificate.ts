/**
 * Rank-up certificate renderer.
 *
 * Draws the shareable certificate onto a <canvas> at a fixed 1200×630 (1.91:1 —
 * the LinkedIn / Open-Graph card ratio) so the same pixels serve BOTH the modal
 * preview and the downloaded PNG. There is deliberately no html2canvas here: the
 * design is a small, fixed set of primitives, and a hand-drawn canvas is exact,
 * dependency-free, and does not depend on a DOM node being on screen or on
 * html2canvas's shaky gradient/box-shadow support.
 *
 * FONTS. The app loads Inter and JetBrains Mono through next/font, which mangles
 * the family names (e.g. "__Inter_e8ce0c"). Canvas text must use those exact
 * names or it silently falls back, so we read them from the CSS variables the
 * layout sets (`--font-inter` / `--font-jetbrains`) and wait for the specific
 * weights to load before drawing.
 */
import type { Rank } from "@/lib/progression/ranks";

const W = 1200;
const H = 630;
const CX = W / 2;

/** The one place a rank's certificate identity lives — colour, glyph, wording. */
export interface CertMeta {
  /** Big title, e.g. "SOC Analyst". Not always the ladder label. */
  title: string;
  /** Tier line under the title, e.g. "Tier 1 · Triage". */
  tier: string;
  /** Medallion glyph. */
  glyph: string;
  /** Accent hex (medallion, tier line, glyph). Matches tailwind palette. */
  accent: string;
  /** The "Track" cell in the meta row. */
  track: string;
}

/**
 * Map a ladder Rank to its certificate identity. The certificate says
 * "SOC Analyst" where the ladder label is just "Analyst" (a certificate is an
 * external artefact — it should read like a credential, not an internal enum),
 * and gives each rank a distinct accent from the platform palette so a shared
 * image reads its tier at a glance.
 */
export function certMetaForRank(rank: Rank): CertMeta {
  switch (rank.id) {
    case "trainee":
      return { title: "SOC Trainee", tier: "Foundations", glyph: "◈", accent: "#00ff9d", track: "Log Analysis" };
    case "tier-1":
      return { title: "SOC Analyst", tier: "Tier 1 · Triage", glyph: "◆", accent: "#22d3ee", track: "SOC Analyst" };
    case "tier-2":
      return { title: "SOC Analyst", tier: "Tier 2 · Investigation", glyph: "✦", accent: "#a855f7", track: "Incident Response" };
    case "tier-3":
      return { title: "Senior Analyst", tier: "Tier 3 · Hunt", glyph: "★", accent: "#ffb020", track: "Threat Hunt" };
    default:
      // student / anything unmapped — never normally certified, but degrade
      // gracefully rather than throwing inside a render loop.
      return { title: rank.label, tier: "Enrolled", glyph: rank.glyph || "◇", accent: "#94a3b8", track: "Foundations" };
  }
}

export interface CertData {
  meta: CertMeta;
  /** The learner's name as it should appear on the certificate. */
  name: string;
  /** XP milestone reached (the rank threshold). */
  xp: number;
  /** Pre-formatted date, e.g. "25 Jul 2026". */
  date: string;
  /** Issuing college (multi-tenant). When set, printed in the footer. */
  orgName?: string | null;
}

/** Read a next/font family list from a CSS variable, with a safe fallback. */
function familyFromVar(varName: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
  return v || fallback;
}

/** First concrete family in a comma list, unquoted — what fonts.load() wants. */
function firstFamily(list: string): string {
  const first = list.split(",")[0].trim().replace(/^["']|["']$/g, "");
  return first || list;
}

function commas(n: number): string {
  return n.toLocaleString("en-US");
}

/**
 * Draw the certificate. Async because it waits for the exact font weights to be
 * ready — drawing before that yields a fallback-font render that then never
 * refreshes. `scale` controls raster density (2 = crisp for download/retina).
 */
export async function drawCertificate(canvas: HTMLCanvasElement, data: CertData, scale = 2): Promise<void> {
  const SANS = familyFromVar("--font-inter", "Inter, system-ui, sans-serif");
  const MONO = familyFromVar("--font-jetbrains", "ui-monospace, SFMono-Regular, monospace");
  const sansF = firstFamily(SANS);
  const monoF = firstFamily(MONO);

  // Wait for every weight we actually paint. Failures are swallowed — a
  // fallback render beats no render.
  if (typeof document !== "undefined" && document.fonts) {
    try {
      await Promise.all([
        document.fonts.load(`900 52px "${sansF}"`),
        document.fonts.load(`700 18px "${sansF}"`),
        document.fonts.load(`400 18px "${sansF}"`),
        document.fonts.load(`800 42px "${monoF}"`),
        document.fonts.load(`800 26px "${monoF}"`),
      ]);
      await document.fonts.ready;
    } catch {
      /* draw with whatever is available */
    }
  }

  canvas.width = W * scale;
  canvas.height = H * scale;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.scale(scale, scale);
  ctx.textBaseline = "middle";

  const { meta, name, xp, date, orgName } = data;
  const accent = meta.accent;

  // ── helpers ──────────────────────────────────────────────────────────────
  const drawCentered = (text: string, cx: number, y: number, font: string, color: string) => {
    ctx.font = font;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = color;
    ctx.fillText(text, cx, y);
  };

  type Run = { text: string; color: string };
  const measureTracked = (runs: Run[], font: string, tracking: number): number => {
    ctx.font = font;
    let total = 0;
    const chars = runs.flatMap(r => [...r.text]);
    chars.forEach((ch, i) => {
      total += ctx.measureText(ch).width;
      if (i < chars.length - 1) total += tracking;
    });
    return total;
  };
  const drawTracked = (runs: Run[], cx: number, y: number, font: string, tracking: number) => {
    ctx.font = font;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    const total = measureTracked(runs, font, tracking);
    let x = cx - total / 2;
    for (const r of runs) {
      ctx.fillStyle = r.color;
      for (const ch of r.text) {
        ctx.fillText(ch, x, y);
        x += ctx.measureText(ch).width + tracking;
      }
    }
  };

  // ── background ───────────────────────────────────────────────────────────
  const base = ctx.createLinearGradient(0, 0, W * 0.35, H);
  base.addColorStop(0, "#0b1220");
  base.addColorStop(0.6, "#070b14");
  base.addColorStop(1, "#050810");
  ctx.fillStyle = base;
  ctx.fillRect(0, 0, W, H);

  const topGlow = ctx.createRadialGradient(CX, -70, 0, CX, -70, 720);
  topGlow.addColorStop(0, "rgba(6,182,212,0.16)");
  topGlow.addColorStop(1, "rgba(6,182,212,0)");
  ctx.fillStyle = topGlow;
  ctx.fillRect(0, 0, W, H);

  const cornerGlow = ctx.createRadialGradient(W * 0.9, H * 1.1, 0, W * 0.9, H * 1.1, 620);
  cornerGlow.addColorStop(0, "rgba(157,0,255,0.10)");
  cornerGlow.addColorStop(1, "rgba(157,0,255,0)");
  ctx.fillStyle = cornerGlow;
  ctx.fillRect(0, 0, W, H);

  // faint grid, strongest at the top, gone by 75% height (mirrors the CSS mask)
  const GRID = 52;
  const fade = (y: number) => Math.max(0, 1 - y / (H * 0.75));
  ctx.lineWidth = 1;
  const vGrad = ctx.createLinearGradient(0, 0, 0, H);
  vGrad.addColorStop(0, "rgba(30,41,59,0.35)");
  vGrad.addColorStop(0.75, "rgba(30,41,59,0)");
  vGrad.addColorStop(1, "rgba(30,41,59,0)");
  ctx.strokeStyle = vGrad;
  for (let x = GRID; x < W; x += GRID) {
    ctx.beginPath();
    ctx.moveTo(x + 0.5, 0);
    ctx.lineTo(x + 0.5, H * 0.75);
    ctx.stroke();
  }
  for (let y = GRID; y < H * 0.75; y += GRID) {
    ctx.strokeStyle = `rgba(30,41,59,${(0.35 * fade(y)).toFixed(3)})`;
    ctx.beginPath();
    ctx.moveTo(0, y + 0.5);
    ctx.lineTo(W, y + 0.5);
    ctx.stroke();
  }

  // ── corner ticks (fixed cyan, like the reference art) ─────────────────────
  const tick = (x: number, y: number, dx: number, dy: number) => {
    const len = 26;
    ctx.strokeStyle = "rgba(34,211,238,0.6)";
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(x + dx * len, y);
    ctx.lineTo(x, y);
    ctx.lineTo(x, y + dy * len);
    ctx.stroke();
  };
  const M = 26;
  tick(M, M, 1, 1);
  tick(W - M, M, -1, 1);
  tick(M, H - M, 1, -1);
  tick(W - M, H - M, -1, -1);

  // ── logo: shield + HACK THE SOC ───────────────────────────────────────────
  const logoY = 78;
  const wordFont = `800 28px "${monoF}", monospace`;
  const wordRuns: Run[] = [
    { text: "HACK", color: "#fff" },
    { text: " THE ", color: "#22d3ee" },
    { text: "SOC", color: "#fff" },
  ];
  const wordTracking = 4;
  const wordW = measureTracked(wordRuns, wordFont, wordTracking);
  const iconSize = 38;
  const iconGap = 16;
  const groupW = iconSize + iconGap + wordW;
  const groupStart = CX - groupW / 2;

  ctx.save();
  ctx.translate(groupStart, logoY - iconSize / 2);
  ctx.scale(iconSize / 24, iconSize / 24);
  const shield = new Path2D("M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z");
  ctx.fillStyle = "rgba(34,211,238,0.08)";
  ctx.strokeStyle = "#22d3ee";
  ctx.lineWidth = 1.6;
  ctx.fill(shield);
  ctx.stroke(shield);
  const check = new Path2D("M9 12l2 2 4-4");
  ctx.lineWidth = 1.8;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  ctx.stroke(check);
  ctx.restore();

  drawTracked(wordRuns, groupStart + iconSize + iconGap + wordW / 2, logoY, wordFont, wordTracking);
  drawTracked([{ text: "CERTIFICATE OF RANK", color: "#94a3b8" }], CX, 112, `700 16px "${sansF}"`, 8);

  // ── medallion ──────────────────────────────────────────────────────────────
  const medalY = 214;
  const R = 66;
  ctx.save();
  ctx.shadowColor = accent;
  ctx.shadowBlur = 46;
  ctx.beginPath();
  ctx.arc(CX, medalY, R, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(6,182,212,0.08)";
  ctx.fill();
  ctx.restore();
  ctx.beginPath();
  ctx.arc(CX, medalY, R, 0, Math.PI * 2);
  ctx.strokeStyle = accent;
  ctx.lineWidth = 3;
  ctx.stroke();
  drawCentered(meta.glyph, CX, medalY + 2, `86px "${sansF}"`, accent);

  // ── titles ─────────────────────────────────────────────────────────────────
  drawCentered(meta.title, CX, 326, `900 50px "${sansF}"`, "#ffffff");
  drawTracked([{ text: meta.tier.toUpperCase(), color: accent }], CX, 366, `700 19px "${sansF}"`, 6);

  // ── name ────────────────────────────────────────────────────────────────────
  drawCentered("This certifies that", CX, 400, `400 19px "${sansF}"`, "#94a3b8");
  drawCentered(name, CX, 444, `800 42px "${monoF}", monospace`, "#ffffff");
  const ruleGrad = ctx.createLinearGradient(CX - 170, 0, CX + 170, 0);
  ruleGrad.addColorStop(0, "rgba(148,163,184,0)");
  ruleGrad.addColorStop(0.5, "rgba(148,163,184,0.7)");
  ruleGrad.addColorStop(1, "rgba(148,163,184,0)");
  ctx.fillStyle = ruleGrad;
  ctx.fillRect(CX - 170, 470, 340, 2);

  // ── meta row: MILESTONE · ACHIEVED · TRACK ──────────────────────────────────
  const valueFont = `800 26px "${monoF}", monospace`;
  const labelFont = `700 13px "${sansF}"`;
  const cells = [
    { v: `${commas(xp)} XP`, l: "MILESTONE" },
    { v: date, l: "ACHIEVED" },
    { v: meta.track, l: "TRACK" },
  ];
  const gap = 44;
  ctx.font = valueFont;
  const cellW = cells.map(c => {
    const vw = ctx.measureText(c.v).width;
    const lw = measureTracked([{ text: c.l, color: "#000" }], labelFont, 2);
    return Math.max(vw, lw);
  });
  const totalW = cellW.reduce((a, b) => a + b, 0) + gap * (cells.length - 1);
  let cursor = CX - totalW / 2;
  const valueY = 528;
  const labelY = 554;
  cells.forEach((c, i) => {
    const cx = cursor + cellW[i] / 2;
    drawCentered(c.v, cx, valueY, valueFont, "#e2e8f0");
    drawTracked([{ text: c.l, color: "#64748b" }], cx, labelY, labelFont, 2);
    if (i > 0) {
      const sepX = cursor - gap / 2;
      ctx.strokeStyle = "rgba(148,163,184,0.2)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(sepX, valueY - 14);
      ctx.lineTo(sepX, labelY + 6);
      ctx.stroke();
    }
    cursor += cellW[i] + gap;
  });

  // ── footer ───────────────────────────────────────────────────────────────
  const footerText = orgName
    ? `Issued by ${orgName} · HACK THE SOC · hack-the-soc.vercel.app`
    : "SOC Analyst Training Platform · hack-the-soc.vercel.app";
  drawTracked([{ text: footerText, color: "#475569" }], CX, 604, `400 15px "${sansF}"`, 0.5);
}

/** Turn the current canvas into a PNG Blob. */
export function canvasToPng(canvas: HTMLCanvasElement): Promise<Blob | null> {
  return new Promise(resolve => canvas.toBlob(b => resolve(b), "image/png"));
}
