import { brandMetadata } from "@/lib/brand/metadata";
import { DecoderProvider } from "@/components/dashboard/Decoder";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand.
export const generateMetadata = brandMetadata("Team Exercise", "app");

export default function Layout({ children }: { children: React.ReactNode }) {
  // The analyst's Decoder, as on the single-player console.
  return <DecoderProvider>{children}</DecoderProvider>;
}
