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
  //
  // `threat_actor` belongs in that same set and was missed when this was first
  // written. It was not merely serialised — ScenarioClient RENDERED it in the
  // page subtitle for the whole investigation. So the student was told
  // "LockBit 3.0 Affiliate" before reading a single log, and on the two
  // false-positive scenarios the field reads "None — authorised backup
  // activity" / "None — authorised software deployment", which is the entire
  // verdict those exercises exist to make the analyst reach. Attribution is a
  // conclusion drawn from tradecraft; handing it over up front removes the
  // exercise.
  const withheld = {
    ...bundle,
    narrative: "",
    learning_objectives: [],
    threat_actor: "",
  };
  return <ScenarioClient bundle={withheld} slug={params.slug} />;
}
