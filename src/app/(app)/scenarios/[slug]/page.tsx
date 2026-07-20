import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { notFound } from "next/navigation";
import { ScenarioClient } from "./ScenarioClient";

export default function ScenarioPage({ params }: { params: { slug: string } }) {
  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) notFound();

  // The narrative and the learning objectives are the debrief — they describe
  // the intrusion in order and name the techniques, which is exactly what the
  // analyst is meant to reconstruct. The UI already hides them until the report
  // is submitted, but anything passed to a client component is serialised into
  // the page payload, so they stayed readable in view-source. Strip them here
  // and let the grade response deliver them once the work is done.
  const withheld = { ...bundle, narrative: "", learning_objectives: [] };
  return <ScenarioClient bundle={withheld} slug={params.slug} />;
}
