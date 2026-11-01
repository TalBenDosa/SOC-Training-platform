/**
 * POST /api/me/edr-results — keeps the verdict of a standalone /edr practice case for the
 * learner's own Progress page (edr_case_results, 0101).
 *
 * The client sends only WHICH process it flagged; the server re-grades it with the same
 * rule the console uses (lib/edr/grade), so a stored "correct" can't be claimed. Only the
 * built-in practice cases are recorded (a live-shift case is judged by its incident report).
 */
import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { EDR_INVESTIGATIONS } from "@/lib/edr/investigations";
import { gradeEdrChoice } from "@/lib/edr/grade";
import { recordEdrResult } from "@/lib/progress/record";

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ saved: false, guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ saved: false }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const inv = EDR_INVESTIGATIONS.find(i => i.id === body.caseId);
  if (!inv) return NextResponse.json({ saved: false, error: "Not a practice case." }, { status: 404 });
  const choice = typeof body.choice === "number" && Number.isInteger(body.choice) ? body.choice : null;
  if (choice === null || (choice !== -1 && !inv.processes.some(p => p.pid === choice))) {
    return NextResponse.json({ error: "choice must be a process id from this case, or -1." }, { status: 400 });
  }

  const correct = gradeEdrChoice(inv, choice);
  const proc = choice === -1 ? null : inv.processes.find(p => p.pid === choice);
  const saved = await recordEdrResult(admin, {
    userId: user.id, orgId: user.orgId, caseId: inv.id, title: inv.title,
    chosen: proc ? `${proc.name} (pid ${proc.pid})` : "Resolved as benign",
    correct, durationMs: typeof body.durationMs === "number" ? body.durationMs : null,
  });
  return NextResponse.json({ saved, correct });
}
