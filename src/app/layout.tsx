import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Inter, JetBrains_Mono } from "next/font/google";
import { AuthProvider } from "@/lib/auth/AuthContext";
import { ProgressProvider } from "@/lib/storage/ProgressProvider";
import { BrandProvider } from "@/lib/brand/BrandContext";
import { getRequestBrand } from "@/lib/brand/server";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", display: "swap" });

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
      default: "HACK THE SOC // Enterprise SOC Training",
      template: "%s // HACK THE SOC",
    },
    description:
      "Train as a SOC analyst on realistic enterprise telemetry: SIEM alerts, EDR process trees, MITRE ATT&CK, threat hunting, detection engineering, and AI-assisted investigations.",
    applicationName: "HACK THE SOC",
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
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} dark`}>
      <body className="antialiased">
        {/* Skip link (WCAG 2.4.1): first focusable element, hidden until focused,
            lets keyboard/screen-reader users jump past the repeated nav to the
            page's <main id="main-content">. */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:bg-cyber-500 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-black focus:shadow-lg"
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
