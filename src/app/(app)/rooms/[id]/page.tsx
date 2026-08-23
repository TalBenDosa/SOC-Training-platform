import { notFound } from "next/navigation";
import { ROOMS } from "@/data/rooms";
import { sanitizeRoom } from "@/lib/rooms/sanitize";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { RoomClient } from "./RoomClient";

interface PageProps {
  params: Promise<{ id: string }>;
}

// Only the static built-ins are pre-rendered; org-authored rooms (org-* ids)
// render on demand.
export function generateStaticParams() {
  return ROOMS.map(r => ({ id: r.id }));
}

export default async function RoomPage({ params }: PageProps) {
  const { id } = await params;

  // Static built-ins resolve without touching the session, so they stay
  // statically rendered. Only an org-* id reads the session (for org context)
  // and goes to the DB resolver — which merges the answer key server-side.
  let room = ROOMS.find(r => r.id === id) ?? null;
  if (!room && id.startsWith("org-")) {
    const user = await getAuthedUser();
    room = await getEffectiveRoom(id, user?.orgId ?? null);
  }
  if (!room) notFound();

  // See src/data/rooms.ts's file doc: a full Room carries the answer key and
  // must never reach a client bundle / SSR payload as-is. sanitizeRoom strips it.
  return <RoomClient room={sanitizeRoom(room)} />;
}
