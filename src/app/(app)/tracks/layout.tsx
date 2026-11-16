import { brandMetadata } from "@/lib/brand/metadata";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand.
// No feature gate: a track only shows the steps this environment's plan includes.
export const generateMetadata = brandMetadata("Recommended Tracks", "app");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
