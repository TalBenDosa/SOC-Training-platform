import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { toClientBundle } from "@/lib/sim/types";
import { notFound } from "next/navigation";
import { ScenarioClient } from "./ScenarioClient";

export default function ScenarioPage({ params }: { params: { slug: string } }) {
  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) notFound();

  // Anything passed to a client component is serialised into the page payload
  // and readable in view-source. `toClientBundle` keeps only what the SOC would
  // actually have on an open ticket: the briefing, the telemetry, the IOC values
  // and the question prompts. The narrative, objectives, killchain, answer key,
  // explanations and IOC reputations are the analyst's findings, and the grade
  // response delivers them once the report is submitted.
  return <ScenarioClient bundle={toClientBundle(bundle)} slug={params.slug} />;
}
