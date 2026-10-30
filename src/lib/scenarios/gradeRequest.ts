import { z } from "zod";

/**
 * Request body for `POST /api/scenarios/[slug]/grade`.
 *
 * The route used to accept any JSON object and coerce each field by hand. That
 * was enough to stop crashes, but it also meant a submission could omit almost
 * everything and still be scored — and scoring is where the verdict leaks
 * (verdictCorrect / verdictWrong, the rubric's 25-vs-5 verdict points, the
 * "your verdict was wrong" note). `{"verdict":"tp"}` alone answered "is this
 * scenario a false positive?" for any slug.
 *
 * The schema requires exactly what the real client already sends: a verdict and
 * an answers map. Completeness (every question answered with a real option) is
 * checked in the route after option tokens are decoded, because only the route
 * has the bundle. Bounds stop oversized payloads reaching the scorer or the LLM.
 */

const MAX_TEXT = 10_000;
const MAX_ANSWER_KEYS = 100;

const answerValue = z.union([
  z.string().max(256),
  z.array(z.string().max(256)).max(50),
]);

export const gradeRequestSchema = z.object({
  answers: z
    .record(z.string().max(64), answerValue)
    .refine(o => Object.keys(o).length <= MAX_ANSWER_KEYS, { message: `at most ${MAX_ANSWER_KEYS} answers` }),
  verdict: z.enum(["tp", "fp"]),
  verdictReason: z.string().max(MAX_TEXT).default(""),
  analystNotes: z.string().max(MAX_TEXT).default(""),
  indicators: z
    .array(z.object({ type: z.string().max(32), value: z.string().max(512) }).loose())
    .max(200)
    .default([]),
  // Stored on the history row only (clamped there); never graded.
  timeTaken: z.unknown().optional(),
  // Legacy client field. Ignored: XP for indicators is computed server-side.
  iocTagged: z.unknown().optional(),
});

export type GradeRequest = z.infer<typeof gradeRequestSchema>;

export function parseGradeRequest(body: unknown):
  | { ok: true; data: GradeRequest }
  | { ok: false; error: string } {
  const r = gradeRequestSchema.safeParse(body);
  if (r.success) return { ok: true, data: r.data };
  const first = r.error.issues[0];
  const where = first?.path.length ? first.path.join(".") : "body";
  return { ok: false, error: `Invalid submission: ${where} — ${first?.message ?? "malformed"}.` };
}
