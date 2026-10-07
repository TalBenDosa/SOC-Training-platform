import type { Metadata } from "next";

// Unique, descriptive tab title per route (WCAG 2.4.2) — the page itself is a client component.
export const metadata: Metadata = { title: "Lesson" };

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
