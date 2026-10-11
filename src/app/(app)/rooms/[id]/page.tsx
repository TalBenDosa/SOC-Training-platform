import { notFound } from "next/navigation";
import { ROOMS, type Room } from "@/data/rooms";
import { sanitizeRoom, type SanitizedRoom } from "@/lib/rooms/sanitize";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser, canPreviewDrafts } from "@/lib/auth/apiGuard";
import { scrambleAwayFromAnswer } from "@/lib/rooms/shuffle";
import { RoomClient } from "./RoomClient";

interface PageProps {
  params: Promise<{ id: string }>;
}

// Only the static built-ins are pre-rendered; org-authored rooms (org-* ids)
// render on demand.
export function generateStaticParams() {
  return ROOMS.map(r => ({ id: r.id }));
}

/**
 * FB-002: sanitizeRoom shuffles matching/ordering boards randomly, but a random
 * permutation of 4 items IS the answer 1 time in 24 — and static rooms render
 * once at build, so an unlucky order would be baked in for every learner. With
 * the full room still in hand (server-side only), make sure no board is
 * presented in — or close to — its answer order: ordering pools vs
 * `correct_order`, and matching right-hand items vs sitting directly across from
 * their own left item. Grading never depends on these orders.
 */
function scrambleBoards(full: Room, safe: SanitizedRoom): SanitizedRoom {
  return {
    ...safe,
    tasks: safe.tasks.map((t, i) => {
      const src = full.tasks[i];
      if (!src || src.id !== t.id) return t;
      if (t.type === "ordering" && src.type === "ordering") {
        return { ...t, items: scrambleAwayFromAnswer(t.items, src.correct_order, it => it.id) };
      }
      if (t.type === "matching" && src.type === "matching") {
        return { ...t, right: scrambleAwayFromAnswer(t.right, src.pairs.map(p => p.right), r => r) };
      }
      return t;
    }),
  };
}

export default async function RoomPage({ params }: PageProps) {
  const { id } = await params;

  // Static built-ins resolve without touching the session, so they stay
  // statically rendered. Only an org-* id reads the session (for org context)
  // and goes to the DB resolver — which merges the answer key server-side.
  let room = ROOMS.find(r => r.id === id) ?? null;
  if (!room && id.startsWith("org-")) {
    const user = await getAuthedUser();
    room = await getEffectiveRoom(id, user?.orgId ?? null, canPreviewDrafts(user));
  }
  if (!room) notFound();

  // See src/data/rooms.ts's file doc: a full Room carries the answer key and
  // must never reach a client bundle / SSR payload as-is. sanitizeRoom strips it.
  return <RoomClient room={scrambleBoards(room, sanitizeRoom(room))} />;
}
