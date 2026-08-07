import { notFound } from "next/navigation";
import { ROOMS } from "@/data/rooms";
import { sanitizeRoom } from "@/lib/rooms/sanitize";
import { RoomClient } from "./RoomClient";

interface PageProps {
  params: Promise<{ id: string }>;
}

export function generateStaticParams() {
  return ROOMS.map(r => ({ id: r.id }));
}

export default async function RoomPage({ params }: PageProps) {
  const { id } = await params;
  const room = ROOMS.find(r => r.id === id);
  if (!room) notFound();
  // See src/data/rooms.ts's file doc: ROOMS carries the full answer key and
  // must never reach a client bundle / SSR payload as-is.
  return <RoomClient room={sanitizeRoom(room)} />;
}
