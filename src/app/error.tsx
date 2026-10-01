"use client";
import { ErrorPanel } from "@/components/errors/ErrorPanel";

// Boundary for routes outside the app shell (sign-in, join, renew, public pages).
export default function RootError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <div className="min-h-screen bg-bg"><ErrorPanel error={error} reset={reset} /></div>;
}
