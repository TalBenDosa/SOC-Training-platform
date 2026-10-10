import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { activeSeat } from "@/lib/team/membership";
import { indicatorsAfter, cardScore } from "@/lib/team/manager/director";
import { loadSession, loadTeamEvents, loadDecisionInjects, loadQuestionInjects } from "@/lib/team/manager/server";
import { checkReply } from "@/lib/team/manager/questions";

/**
 * GET /api/team/sessions/[id]/manager - the SOC Manager's view of his own decisions.
 *
 * For every decision card that is DECIDED (answered) or EXPIRED, the grading: the rank of the
 * chosen option, the best option, the note for each option, and the indicator change; plus the
 * four consequence indicators after all decided cards. Open cards return nothing of the key,
 * so the answer cannot be read before the decision. Only the seated manager (or lead) and
 * staff may read it.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const sess = await loadSession(admin, id);
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  const iAmStaff = user.isPlatformAdmin || ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmStaff) {
    const seat = await activeSeat(admin, id, sess.org_id, user.id);
    if (!seat || (seat.role !== "mgr" && seat.role !== "lead")) return NextResponse.json({ error: "Only the SOC Manager can read this." }, { status: 403 });
  }

  try {
    const [events, injects, qInjects] = await Promise.all([loadTeamEvents(admin, id), loadDecisionInjects(admin, id), loadQuestionInjects(admin, id)]);
    const answers = new Map(events.filter(e => e.type === "decision.answered").map(e => [String((e.payload as { inject_id?: unknown }).inject_id), e]));
    const firedAt = new Map(events.filter(e => e.type === "staff.inject").map(e => [e.seq, e.occurred_at ? Date.parse(e.occurred_at) : Date.now()]));
    const now = Date.now();
    const decided: { answer: (typeof injects)[number]["expected_action"]; option: string | null }[] = [];
    const cards = injects.map(inj => {
      const key = inj.expected_action;
      const a = answers.get(inj.id);
      const at = inj.fired_seq != null ? firedAt.get(inj.fired_seq) ?? now : now;
      const deadline = Number((inj.body as { deadline_s?: unknown }).deadline_s) || 240;
      const expired = !a && now > at + deadline * 1000;
      if (!a && !expired) return { inject_id: inj.id, card: key.card, state: "open" as const };
      const option = a ? String((a.payload as { option?: unknown }).option) : null;
      const confidence = a ? String((a.payload as { confidence?: unknown }).confidence) : null;
      decided.push({ answer: key, option });
      return {
        inject_id: inj.id, card: key.card, state: a ? ("answered" as const) : ("expired" as const),
        option, confidence, rank: option ? key.ranks[option] ?? null : null, best: key.best,
        score: cardScore(option ? key.ranks[option] : undefined, confidence ?? undefined),
        notes: key.notes, delta: option ? key.deltas[option] ?? {} : key.timeout_delta, objective: key.objective,
      };
    });
    // Stakeholder questions: the checks on a reply (and the model answer) once it is answered or expired.
    const replies = new Map(events.filter(e => e.type === "stakeholder.replied").map(e => [String((e.payload as { inject_id?: unknown }).inject_id), e]));
    const askedAt = new Map(events.filter(e => e.type === "stakeholder.asked").map(e => [e.seq, e.occurred_at ? Date.parse(e.occurred_at) : now]));
    const questions = qInjects.map(inj => {
      const key = inj.expected_action;
      const r = replies.get(inj.id);
      const at = inj.fired_seq != null ? askedAt.get(inj.fired_seq) ?? now : now;
      const deadline = Number((inj.body as { deadline_s?: unknown }).deadline_s) || 240;
      if (!r && now <= at + deadline * 1000) return { inject_id: inj.id, qid: key.qid, state: "open" as const };
      const text = r ? String((r.payload as { text?: unknown }).text ?? "") : "";
      const rt = r?.occurred_at ? Date.parse(r.occurred_at) : null;
      const graded = r ? checkReply(text, key) : { checks: [], score: 0 };
      return { inject_id: inj.id, qid: key.qid, state: r ? ("answered" as const) : ("expired" as const), late: rt != null && rt > at + deadline * 1000, ...graded, model: key.model, objective: key.objective };
    });
    return NextResponse.json({ cards, questions, indicators: indicatorsAfter(decided) }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error("[team/manager] failed:", (e as Error).message);
    return NextResponse.json({ error: "Couldn't load the manager view." }, { status: 500 });
  }
}
