import { IBM_Plex_Mono, Manrope } from "next/font/google";
import { brandMetadata } from "@/lib/brand/metadata";
import { requireFeature } from "@/lib/brand/requireFeature";

// Unique, descriptive tab title per route (WCAG 2.4.2), with the request's brand.
export const generateMetadata = brandMetadata("XDR", "app");

// XDR's own type (owner, 2026-11-08): Manrope for the interface, IBM Plex Mono for KQL and values.
// Loaded on this route only, so the rest of the platform keeps its fonts; the console reads the two
// variables (sentinel.css) and falls back to system fonts where they are not set (tests).
const sans = Manrope({ subsets: ["latin"], variable: "--font-xdr-sans", display: "swap" });
const mono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-xdr-mono", display: "swap" });

// Only when this environment's plan includes it (tenant config features).
export default async function Layout({ children }: { children: React.ReactNode }) {
  await requireFeature("live_soc");
  return <div className={`${sans.variable} ${mono.variable}`} style={{ display: "contents" }}>{children}</div>;
}
