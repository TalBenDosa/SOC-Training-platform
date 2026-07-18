/**
 * exportPptx.ts — Client-side helper that calls the server-side PPTX generator.
 * pptxgenjs uses node:fs and can't run in the browser, so generation happens
 * on the server at POST /api/lessons/export-pptx and the result is streamed
 * back as a binary download.
 */

export interface LessonForExport {
  title:            string;
  topic:            string;
  difficulty:       string;
  intro:            string;
  sections:         { heading: string; content: string; codeExample?: string }[];
  keyTakeaways:     string[];
  estimatedMinutes: number;
  xp:               number;
}

/**
 * Sends the lesson to the server, receives a .pptx binary, and triggers
 * a browser download — no client-side bundle required.
 */
export async function exportLessonToPptx(lesson: LessonForExport): Promise<void> {
  const res = await fetch("/api/lessons/export-pptx", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(lesson),
  });

  if (!res.ok) {
    throw new Error(`Export failed: ${res.status} ${res.statusText}`);
  }

  // Extract filename from Content-Disposition header, fall back to slug
  const disposition = res.headers.get("content-disposition") ?? "";
  const nameMatch   = disposition.match(/filename="([^"]+)"/);
  const fileName    = nameMatch?.[1] ?? `${lesson.title.slice(0, 50).replace(/\s+/g, "-").toLowerCase()}.pptx`;

  // Trigger browser download
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
