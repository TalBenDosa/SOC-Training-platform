import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { notFound } from "next/navigation";
import { ScenarioClient } from "./ScenarioClient";

export default function ScenarioPage({ params }: { params: { slug: string } }) {
  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) notFound();
  return <ScenarioClient bundle={bundle} slug={params.slug} />;
}
