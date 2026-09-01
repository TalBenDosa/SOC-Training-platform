import { notFound } from "next/navigation";
import { resolveScenarioBundle } from "@/lib/scenarios/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { ScenarioClient } from "./ScenarioClient";

export default async function ScenarioPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  // orgId scopes org-authored scenarios; static built-ins ignore it.
  const user = await getAuthedUser();
  const bundle = await resolveScenarioBundle(slug, user?.orgId ?? null);
  if (!bundle) notFound();

  // Anything handed to a client component is serialised into the page payload
  // and readable in view-source, so the entire answer key is stripped here and
  // re-delivered by the grade response only after a genuine attempt:
  //   - narrative / learning_objectives  → the debrief the analyst reconstructs
  //   - threat_actor                     → attribution is a conclusion, not a given
  //     (and ScenarioClient RENDERED it in the subtitle — a giant hint)
  //   - attack_kind                      → this IS the verdict (esp. "false_positive")
  //   - iocs / killchain                 → the evidence + attack sequence to find
  //   - per-question answer / explanation→ the quiz answer key
  // ScenarioClient reads none of the stripped fields (verified), so removing
  // them changes nothing on screen while closing the leak for EVERY scenario,
  // static and org-authored alike. Server-side grading is the real gate.
  const withheld = {
    ...bundle,
    narrative: "",
    learning_objectives: [],
    threat_actor: "",
    attack_kind: "",
    iocs: [],
    killchain: [],
    // F-02 — the events table is something to INVESTIGATE, not read. Each event's
    // analyst `description` and its MITRE mapping are the exercise (the student
    // writes the description and picks the technique); they are stripped here and
    // revealed only in the graded debrief. Conclusion-carrying raw fields (a
    // "*.description" is the tool's own analyst write-up, e.g.
    // crowdstrike.detection.description — the answer to Q1 verbatim) are dropped
    // too. The analyst still sees every observable: process/file/network/auth
    // fields and the rest of the raw block. Server-enforced, so none of this is
    // readable in view-source during the investigation. Grading uses the real
    // bundle on the server, so nothing here affects the score.
    events: (bundle.events ?? []).map(e => {
      const raw: Record<string, unknown> = { ...(e.raw ?? {}) };
      for (const k of Object.keys(raw)) {
        if (/\.description$/i.test(k)) delete raw[k];
      }
      return { ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined, raw };
    }),
    questions: bundle.questions.map(q => ({
      ...q,
      answer: Array.isArray(q.answer) ? [] : "",
      explanation: "",
    })),
  };
  return <ScenarioClient bundle={withheld} slug={slug} />;
}
