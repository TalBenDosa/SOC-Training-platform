import { brandMetadata } from "@/lib/brand/metadata";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand.
export const generateMetadata = brandMetadata("Super Admin", "app");

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
