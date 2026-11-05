import { brandMetadata } from "@/lib/brand/metadata";
import { ROOMS_META } from "@/data/roomsMeta";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand: the tab
// names the room, and a bad link says so. Here and not on the page, because a missing room
// renders not-found under this layout, and the page's metadata never runs for it.
export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return brandMetadata(ROOMS_META.find(r => r.id === id)?.title ?? (id.startsWith("org-") ? "Room" : "Page not found"), "app")();
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
