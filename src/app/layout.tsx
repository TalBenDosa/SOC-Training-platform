import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Inter, JetBrains_Mono, Heebo, Rubik, Assistant } from "next/font/google";
import { AuthProvider } from "@/lib/auth/AuthContext";
import { ProgressProvider } from "@/lib/storage/ProgressProvider";
import { BrandProvider } from "@/lib/brand/BrandContext";
import { getRequestBrand } from "@/lib/brand/server";
import { themeCss } from "@/lib/brand/theme";
import { PLATFORM_NAME } from "@/lib/brand/brand";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", display: "swap" });
// The other UI fonts a white-label theme can choose (src/lib/brand/theme.ts FONTS). Not
// preloaded: a browser only downloads one when the page's theme actually uses it.
const heebo = Heebo({ subsets: ["latin", "hebrew"], variable: "--font-heebo", display: "swap", preload: false });
const rubik = Rubik({ subsets: ["latin", "hebrew"], variable: "--font-rubik", display: "swap", preload: false });
const assistant = Assistant({ subsets: ["latin", "hebrew"], variable: "--font-assistant", display: "swap", preload: false });

export const viewport: Viewport = {
  themeColor: "#070b14",
};

const KEYWORDS = [
  "SOC", "SIEM", "EDR", "MITRE ATT&CK", "threat hunting", "incident response",
  "detection engineering", "cybersecurity training", "blue team", "purple team",
];

// Titles, app name and icon follow the request's brand (white label, src/lib/brand): on a
// white-label organization's own domain no page names HACK THE SOC. Route layouts set only
// their page name; the template adds the brand.
export async function generateMetadata(): Promise<Metadata> {
  const brand = await getRequestBrand();
  if (brand.whiteLabel) {
    return {
      title: { default: `${brand.productName} // SOC Training`, template: `%s // ${brand.productName}` },
      description: `${brand.productName}: hands-on SOC analyst training on realistic enterprise telemetry.`,
      applicationName: brand.productName,
      icons: brand.logoSrc ? { icon: brand.logoSrc, apple: brand.logoSrc } : undefined,
      robots: { index: false, follow: false },
    };
  }
  return {
    title: {
      default: `${PLATFORM_NAME} // Enterprise SOC Training`,
      template: `%s // ${PLATFORM_NAME}`,
    },
    description:
      "Train as a SOC analyst on realistic enterprise telemetry: SIEM alerts, EDR process trees, MITRE ATT&CK, threat hunting, detection engineering, and AI-assisted investigations.",
    applicationName: PLATFORM_NAME,
    keywords: KEYWORDS,
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading the request headers renders every page per request, which is what
  // lets Next.js stamp the middleware's CSP nonce on its scripts (SEC-03) — a
  // statically prerendered page would carry no nonce and be blocked.
  await headers();
  const brand = await getRequestBrand();
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} ${heebo.variable} ${rubik.variable} ${assistant.variable} dark`}>
      <body className="antialiased">
        {/* A white-label domain's own colours, server-rendered so there's no flash of the platform palette. */}
        {brand.whiteLabel && brand.theme && <style>{themeCss(brand.theme)}</style>}
        {/* Skip link (WCAG 2.4.1): first focusable element, hidden until focused,
            lets keyboard/screen-reader users jump past the repeated nav to the
            page's <main id="main-content">. */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:bg-cyber-500 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-on-accent focus:shadow-lg"
        >
          Skip to content
        </a>
        <AuthProvider>
          <BrandProvider initial={brand}>
            <ProgressProvider>{children}</ProgressProvider>
          </BrandProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
