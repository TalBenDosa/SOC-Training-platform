import { notFound } from "next/navigation";
import { ROOMS } from "@/data/rooms";
import { RoomClient } from "./RoomClient";

interface PageProps {
  params: { id: string };
}

export function generateStaticParams() {
  return ROOMS.map(r => ({ id: r.id }));
}

export default function RoomPage({ params }: PageProps) {
  const room = ROOMS.find(r => r.id === params.id);
  if (!room) notFound();
  return <RoomClient room={room} />;
}
