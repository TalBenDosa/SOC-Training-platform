import { notFound } from "next/navigation";
import { resolveScenarioBundle } from "@/lib/scenarios/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { buildIocTruth } from "@/lib/edr/iocIntel";
import { optionToken, eventIdMap, maskEventIds } from "@/lib/scenarios/optionToken";
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
    // `alerts` is derived server-side by withAlerts() from every event with a
    // MITRE id — each carries mitre_technique/mitre_tactic and a title built
    // from the event, i.e. the very mapping stripped from `events` below. The
    // client no longer reads it: the alert count and badges are computed from
    // the events themselves (src/lib/scenarios/eventClass.ts, finding #5).
    alerts: [],
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
    //
    // The same rule applies to a handful of TYPED fields that exist ONLY to carry
    // the answer key on the object itself — these were missed by the original F-02
    // pass because they are not literally named "description":
    //   - fp_explanation            → an analyst write-up of why an FP event LOOKS
    //                                 alarming but is actually benign — a verdict
    //                                 and its reasoning, in prose, on the event.
    //   - expected_verdict          → literally "tp"/"fp" ground truth for the event.
    //   - it_verify_result/_message → "confirmed" means "mark benign", "unverified"
    //                                 means "treat as suspicious" — the verdict
    //                                 spelled out as an enum.
    // All three survive untouched through `...e` and were readable in full via the
    // per-row "Raw JSON" toggle (`JSON.stringify(ev, null, 2)` in ScenarioClient),
    // i.e. the exact leak F-02 was written to close, just on different field names.
    events: (bundle.events ?? []).map(e => {
      const raw: Record<string, unknown> = { ...(e.raw ?? {}) };
      for (const k of Object.keys(raw)) {
        if (/\.description$/i.test(k)) delete raw[k];
      }
      return {
        ...e,
        description: undefined,
        mitre_technique: undefined,
        mitre_tactic: undefined,
        fp_explanation: undefined,
        expected_verdict: undefined,
        it_verify_result: undefined,
        it_verify_message: undefined,
        raw,
      };
    }),
    // Option values are swapped for keyed tokens — authored ids like
    // "wrong_folder" would otherwise name the answer in the page payload.
    questions: bundle.questions.map(q => ({
      ...q,
      options: q.options?.map(o => ({ ...o, value: optionToken(slug, q.id, o.value) })),
      answer: Array.isArray(q.answer) ? [] : "",
      explanation: "",
    })),
  };
  // Threat-intel truth (finding #2 contract): computed HERE from the FULL bundle
  // (authored iocs + attack events), because the client copy above has both
  // stripped. It ships as digest-keyed verdicts only — not a readable list of
  // the malicious IOCs — and makes every TI lookup and EDR hash lookup on the
  // page agree with the scenario's own detections.
  const iocTruth = buildIocTruth({ events: bundle.events ?? [], iocs: bundle.iocs ?? [] });
  // Authored event ids name the answer ("…_beacon", "…_exfil…") and show in each
  // row's Raw JSON — ship opaque ids instead (question text is rewritten to match).
  const idMap = eventIdMap(slug, (bundle.events ?? []).map(e => e.id));
  return <ScenarioClient bundle={maskEventIds(withheld, idMap)} slug={slug} iocTruth={iocTruth} />;
}
