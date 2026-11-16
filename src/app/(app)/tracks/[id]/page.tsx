import { notFound } from "next/navigation";
import { findTrack } from "@/data/recommendedTracks";
import { TrackDetail } from "./TrackDetail";

export default async function TrackPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!findTrack(id)) notFound();
  return <TrackDetail trackId={id} />;
}
