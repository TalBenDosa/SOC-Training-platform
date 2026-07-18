/**
 * POST /api/lessons/export-pptx
 * Server-side PPTX generation using pptxgenjs (Node.js only).
 * Accepts lesson JSON, returns a .pptx binary stream.
 */
import PptxGenJS from "pptxgenjs";
import type { LessonForExport } from "@/lib/lessons/exportPptx";

// ─── Theme ────────────────────────────────────────────────────────────────────

const T = {
  bg:       "0B0F1E",
  border:   "1E2D4A",
  primary:  "06B6D4",
  white:    "FFFFFF",
  body:     "94A3B8",
  muted:    "475569",
  codeBg:   "060D1A",
  codeText: "34D399",
  violet:   "8B5CF6",
  green:    "10B981",
};

const DIFF_COLOR: Record<string, string> = {
  beginner:     "22C55E",
  intermediate: "EAB308",
  advanced:     "F97316",
  expert:       "EF4444",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function stripMd(text: string): string {
  return text
    .replace(/^#{1,4} /gm, "")
    .replace(/\*\*/g, "")
    .replace(/`[^`]+`/g, s => s.slice(1, -1))
    .trim();
}

function truncateAtSentence(text: string, maxChars: number): string {
  const clean = stripMd(text);
  if (clean.length <= maxChars) return clean;
  const slice = clean.slice(0, maxChars);
  const lastPeriod = slice.lastIndexOf(". ");
  if (lastPeriod > maxChars * 0.5) return slice.slice(0, lastPeriod + 1);
  return slice + "…";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addBackground(slide: any) {
  slide.background = { color: T.bg };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addFooter(slide: any, text = "SOC Training Platform") {
  slide.addText(text, {
    x: 0.4, y: 7.1, w: 7, h: 0.3,
    fontSize: 8, color: T.muted, fontFace: "Calibri",
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addSlideNumber(slide: any, current: number, total: number) {
  slide.addText(`${current} / ${total}`, {
    x: 11.5, y: 7.1, w: 1.5, h: 0.3,
    fontSize: 8, color: T.muted, fontFace: "Calibri", align: "right",
  });
}

// ─── Slide builders ───────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildTitleSlide(pptx: any, lesson: LessonForExport, total: number) {
  const slide = pptx.addSlide();
  addBackground(slide);

  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0, w: 0.08, h: 7.5,
    fill: { color: T.primary },
    line: { color: T.primary, width: 0 },
  });

  slide.addText("SOC TRAINING PLATFORM", {
    x: 0.4, y: 0.55, w: 12, h: 0.35,
    fontSize: 10, color: T.primary, bold: true,
    fontFace: "Calibri", charSpacing: 3,
  });

  slide.addShape(pptx.ShapeType.line, {
    x: 0.4, y: 1.0, w: 12.5, h: 0,
    line: { color: T.border, width: 1 },
  });

  slide.addText(lesson.title, {
    x: 0.4, y: 1.3, w: 12.5, h: 2.4,
    fontSize: 32, color: T.white, bold: true,
    fontFace: "Calibri", wrap: true, valign: "top",
  });

  slide.addText(lesson.topic, {
    x: 0.4, y: 3.8, w: 9, h: 0.5,
    fontSize: 16, color: T.body, fontFace: "Calibri",
  });

  const diffColor = DIFF_COLOR[lesson.difficulty.toLowerCase()] ?? T.primary;
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 0.4, y: 4.5, w: 1.6, h: 0.38,
    fill: { color: diffColor, transparency: 80 },
    line: { color: diffColor, width: 1.5 },
    rectRadius: 0.1,
  });
  slide.addText(lesson.difficulty.toUpperCase(), {
    x: 0.4, y: 4.5, w: 1.6, h: 0.38,
    fontSize: 9, color: diffColor, bold: true,
    fontFace: "Calibri", align: "center", valign: "middle",
  });

  slide.addText(`${lesson.estimatedMinutes} min read  ·  ${lesson.xp} XP  ·  ${lesson.sections.length} sections`, {
    x: 0.4, y: 5.05, w: 8, h: 0.3,
    fontSize: 10, color: T.muted, fontFace: "Calibri",
  });

  addFooter(slide);
  addSlideNumber(slide, 1, total);
}

function buildSectionSlide(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pptx: any,
  section: LessonForExport["sections"][number],
  index: number,
  total: number,
) {
  const slide = pptx.addSlide();
  addBackground(slide);

  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0, w: 13.33, h: 0.06,
    fill: { color: T.primary },
    line: { color: T.primary, width: 0 },
  });

  slide.addText(`SECTION ${index}`, {
    x: 0.5, y: 0.3, w: 4, h: 0.3,
    fontSize: 8, color: T.primary, bold: true,
    fontFace: "Calibri", charSpacing: 2,
  });

  slide.addText(section.heading, {
    x: 0.5, y: 0.65, w: 12.33, h: 0.9,
    fontSize: 22, color: T.white, bold: true,
    fontFace: "Calibri", wrap: true,
  });

  slide.addShape(pptx.ShapeType.line, {
    x: 0.5, y: 1.6, w: 12.33, h: 0,
    line: { color: T.border, width: 1 },
  });

  const hasCode = Boolean(section.codeExample);
  const contentWidth = hasCode ? 7.2 : 12.33;
  const contentText  = truncateAtSentence(section.content, hasCode ? 480 : 900);

  slide.addText(contentText, {
    x: 0.5, y: 1.75, w: contentWidth, h: 5.1,
    fontSize: 11, color: T.body, fontFace: "Calibri",
    wrap: true, valign: "top", paraSpaceAfter: 6,
  });

  if (hasCode && section.codeExample) {
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 8.0, y: 1.75, w: 4.83, h: 5.1,
      fill: { color: T.codeBg },
      line: { color: T.border, width: 1 },
      rectRadius: 0.08,
    });
    slide.addText("CODE EXAMPLE", {
      x: 8.1, y: 1.85, w: 4.63, h: 0.25,
      fontSize: 7, color: T.primary, bold: true,
      fontFace: "Calibri", charSpacing: 1.5,
    });
    slide.addText(section.codeExample.slice(0, 600), {
      x: 8.1, y: 2.15, w: 4.63, h: 4.55,
      fontSize: 8, color: T.codeText, fontFace: "Courier New",
      wrap: true, valign: "top",
    });
  }

  addFooter(slide);
  addSlideNumber(slide, index + 1, total);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildTakeawaysSlide(pptx: any, lesson: LessonForExport, slideNum: number, total: number) {
  const slide = pptx.addSlide();
  addBackground(slide);

  slide.addShape(pptx.ShapeType.rect, {
    x: 0, y: 0, w: 0.08, h: 7.5,
    fill: { color: T.violet },
    line: { color: T.violet, width: 0 },
  });

  slide.addText("KEY TAKEAWAYS", {
    x: 0.4, y: 0.45, w: 10, h: 0.35,
    fontSize: 10, color: T.violet, bold: true,
    fontFace: "Calibri", charSpacing: 3,
  });

  slide.addShape(pptx.ShapeType.line, {
    x: 0.4, y: 0.9, w: 12.5, h: 0,
    line: { color: T.border, width: 1 },
  });

  (lesson.keyTakeaways ?? []).slice(0, 7).forEach((t, i) => {
    const y = 1.1 + i * 0.78;
    slide.addShape(pptx.ShapeType.ellipse, {
      x: 0.4, y: y + 0.08, w: 0.22, h: 0.22,
      fill: { color: T.green },
      line: { color: T.green, width: 0 },
    });
    slide.addText(stripMd(t), {
      x: 0.75, y, w: 12.1, h: 0.65,
      fontSize: 12, color: T.body, fontFace: "Calibri",
      wrap: true, valign: "middle",
    });
  });

  addFooter(slide, `${lesson.title}  ·  SOC Training Platform`);
  addSlideNumber(slide, slideNum, total);
}

// ─── Route ────────────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const lesson = await req.json().catch(() => null) as LessonForExport | null;

  if (!lesson?.title || !Array.isArray(lesson.sections)) {
    return new Response("Invalid lesson data", { status: 400 });
  }

  const pptx = new PptxGenJS();
  pptx.layout  = "LAYOUT_WIDE";
  pptx.author  = "SOC Training Platform";
  pptx.subject = lesson.topic;
  pptx.title   = lesson.title;

  const totalSlides = 1 + lesson.sections.length + 1;
  buildTitleSlide(pptx, lesson, totalSlides);
  lesson.sections.forEach((sec, i) => buildSectionSlide(pptx, sec, i + 1, totalSlides));
  buildTakeawaysSlide(pptx, lesson, totalSlides, totalSlides);

  // Generate as arraybuffer (browser-compatible output type)
  const buffer = await pptx.write({ outputType: "arraybuffer" }) as ArrayBuffer;

  const fileName = lesson.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);

  return new Response(buffer, {
    headers: {
      "Content-Type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "Content-Disposition": `attachment; filename="${fileName}.pptx"`,
    },
  });
}
