import { brandMetadata } from "@/lib/brand/metadata";
import { requireFeature } from "@/lib/brand/requireFeature";

// The console's old address: its page redirects to /xdr, so the tab title is already XDR's.
export const generateMetadata = brandMetadata("XDR", "app");

// Only when this environment's plan includes it (tenant config features).
export default async function Layout({ children }: { children: React.ReactNode }) {
  await requireFeature("live_soc");
  return children;
}
