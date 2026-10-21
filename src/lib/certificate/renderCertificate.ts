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
import { certificateIssuer, PRODUCTION_HOST } from "./issuer";
import type { Brand } from "@/lib/brand/brand";
import { tokenHex, tokenRgb, tokenRgba } from "@/lib/brand/theme";

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
  /** Learner's org name (multi-tenant). A real org is printed as the issuer. */
  orgName?: string | null;
  /** Learner's org id — the platform's own system org is never the issuer. */
  orgId?: string | null;
  /** White label (src/lib/brand): the organization's logo / name replace the platform lockup. */
  brand?: Brand | null;
  /** The host printed in the footer (certificateHost); defaults to the production host. */
  host?: string;
}

/** Minimal slice of CanvasRenderingContext2D the meta-row measurement needs. */
export interface MeasureCtx {
  font: string;
  measureText(text: string): { width: number };
}

/**
 * Width of each meta-row cell: max(value width in the VALUE font, tracked label
 * width in the LABEL font). The old inline version set the value font once and
 * then measured the label — which switched `ctx.font` to the 13px label font —
 * so every value after the first was measured at 13px instead of 26px. Cells
 * came out too narrow and neighbours overlapped ("1,500 XP28 Sep 2026"). Each
 * measurement now sets its own font.
 */
export function measureMetaCells(
  ctx: MeasureCtx,
  cells: { v: string; l: string }[],
  valueFont: string,
  labelFont: string,
  labelTracking: number,
): number[] {
  return cells.map(c => {
    ctx.font = valueFont;
    const vw = ctx.measureText(c.v).width;
    ctx.font = labelFont;
    const chars = [...c.l];
    let lw = 0;
    chars.forEach((ch, i) => {
      lw += ctx.measureText(ch).width;
      if (i < chars.length - 1) lw += labelTracking;
    });
    return Math.max(vw, lw);
  });
}

/** Footer line: the issuer (a real org, else the platform) and the production domain. */
export function certificateFooter(orgId: string | null | undefined, orgName: string | null | undefined, host: string = PRODUCTION_HOST): string {
  return `Issued by ${certificateIssuer(orgId, orgName)} · SOC Analyst Training${host ? ` · ${host}` : ""}`;
}

/** Load a same-origin image for the canvas (null when it can't be loaded). */
function loadImage(src: string): Promise<HTMLImageElement | null> {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => resolve(null);
    img.src = src;
  });
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

  const { meta, name, xp, date, orgName, orgId, brand } = data;
  const brandLogo = brand?.whiteLabel && brand.logoSrc ? await loadImage(brand.logoSrc) : null;
  const accent = meta.accent;
  // The tenant's theme (src/lib/brand/theme.ts): the frame, glow and ticks use its colours.
  const theme = brand?.whiteLabel ? brand.theme : null;
  const tk = (name: string, a: number) => tokenRgba(theme, name, a);

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
  base.addColorStop(0, tokenHex(theme, "--bg-elevated"));
  base.addColorStop(0.6, tokenHex(theme, "--bg"));
  base.addColorStop(1, `rgb(${tokenRgb(theme, "--bg").map(c => Math.round(c * 0.7)).join(",")})`);
  ctx.fillStyle = base;
  ctx.fillRect(0, 0, W, H);

  const topGlow = ctx.createRadialGradient(CX, -70, 0, CX, -70, 720);
  topGlow.addColorStop(0, tk("--cyber-500", 0.16));
  topGlow.addColorStop(1, tk("--cyber-500", 0));
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
  vGrad.addColorStop(0, tk("--border", 0.35));
  vGrad.addColorStop(0.75, tk("--border", 0));
  vGrad.addColorStop(1, tk("--border", 0));
  ctx.strokeStyle = vGrad;
  for (let x = GRID; x < W; x += GRID) {
    ctx.beginPath();
    ctx.moveTo(x + 0.5, 0);
    ctx.lineTo(x + 0.5, H * 0.75);
    ctx.stroke();
  }
  for (let y = GRID; y < H * 0.75; y += GRID) {
    ctx.strokeStyle = tk("--border", Number((0.35 * fade(y)).toFixed(3)));
    ctx.beginPath();
    ctx.moveTo(0, y + 0.5);
    ctx.lineTo(W, y + 0.5);
    ctx.stroke();
  }

  // ── corner ticks (the accent, like the reference art) ─────────────────────
  const tick = (x: number, y: number, dx: number, dy: number) => {
    const len = 26;
    ctx.strokeStyle = tk("--cyber-400", 0.6);
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

  // ── logo: shield + HACK THE SOC, or a white-label organization's own ──────
  const logoY = 78;
  if (brand?.whiteLabel) {
    const showName = !(brandLogo && brand.logoHasName);
    const nameFont = `800 28px "${sansF}", sans-serif`;
    ctx.font = nameFont;
    const nameW = showName ? ctx.measureText(brand.productName).width : 0;
    const logoH = 44;
    const logoW = brandLogo ? Math.min(220, (brandLogo.naturalWidth / Math.max(1, brandLogo.naturalHeight)) * logoH) : 0;
    const gapW = brandLogo && showName ? 16 : 0;
    let x = CX - (logoW + gapW + nameW) / 2;
    if (brandLogo) { ctx.drawImage(brandLogo, x, logoY - logoH / 2, logoW, logoH); x += logoW + gapW; }
    if (showName) { ctx.fillStyle = "#fff"; ctx.textAlign = "left"; ctx.fillText(brand.productName, x, logoY); }
  } else {
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
  }
  drawTracked([{ text: "CERTIFICATE OF RANK", color: "#94a3b8" }], CX, 112, `700 16px "${sansF}"`, 8);

  // ── medallion ──────────────────────────────────────────────────────────────
  const medalY = 214;
  const R = 66;
  ctx.save();
  ctx.shadowColor = accent;
  ctx.shadowBlur = 46;
  ctx.beginPath();
  ctx.arc(CX, medalY, R, 0, Math.PI * 2);
  ctx.fillStyle = tk("--cyber-500", 0.08);
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
  const gap = 56;
  const cellW = measureMetaCells(ctx, cells, valueFont, labelFont, 2);
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
  const footerText = certificateFooter(orgId, orgName, data.host ?? PRODUCTION_HOST);
  drawTracked([{ text: footerText, color: "#475569" }], CX, 604, `400 15px "${sansF}"`, 0.5);
}

/** Turn the current canvas into a PNG Blob. */
export function canvasToPng(canvas: HTMLCanvasElement): Promise<Blob | null> {
  return new Promise(resolve => canvas.toBlob(b => resolve(b), "image/png"));
}
