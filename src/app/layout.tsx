import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { Inter, JetBrains_Mono } from "next/font/google";
import { AuthProvider } from "@/lib/auth/AuthContext";
import { ProgressProvider } from "@/lib/storage/ProgressProvider";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", display: "swap" });

export const viewport: Viewport = {
  themeColor: "#070b14",
};

export const metadata: Metadata = {
  title: {
    default: "HACK THE SOC // Enterprise SOC Training",
    template: "%s // HACK THE SOC",
  },
  description:
    "Train as a SOC analyst on realistic enterprise telemetry: SIEM alerts, EDR process trees, MITRE ATT&CK, threat hunting, detection engineering, and AI-assisted investigations.",
  applicationName: "HACK THE SOC",
  keywords: [
    "SOC", "SIEM", "EDR", "MITRE ATT&CK", "threat hunting", "incident response",
    "detection engineering", "cybersecurity training", "blue team", "purple team",
  ],
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading the request headers renders every page per request, which is what
  // lets Next.js stamp the middleware's CSP nonce on its scripts (SEC-03) — a
  // statically prerendered page would carry no nonce and be blocked.
  await headers();
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
          <ProgressProvider>{children}</ProgressProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
