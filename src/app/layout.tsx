import type { Metadata, Viewport } from "next";
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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} dark`}>
      <body className="antialiased">
        <AuthProvider>
          <ProgressProvider>{children}</ProgressProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
