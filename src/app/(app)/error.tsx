"use client";
import { ErrorPanel } from "@/components/errors/ErrorPanel";

// In-app boundary: the sidebar and "Report a problem" stay usable around it.
export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <ErrorPanel error={error} reset={reset} />;
}
