import { brandMetadata } from "@/lib/brand/metadata";
import { requireFeature } from "@/lib/brand/requireFeature";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand.
export const generateMetadata = brandMetadata("Learning Rooms");

// Only when this environment's plan includes it (tenant config features).
export default async function Layout({ children }: { children: React.ReactNode }) {
  await requireFeature("learning_rooms");
  return children;
}
