import { notFound } from "next/navigation";
import { ROOMS } from "@/data/rooms";
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
  return <RoomClient room={room} />;
}
