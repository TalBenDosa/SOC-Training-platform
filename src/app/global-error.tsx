"use client";
import "./globals.css";
import { ErrorPanel } from "@/components/errors/ErrorPanel";

// Last-resort boundary (an error in the root layout itself). It replaces the
// root layout, so it renders its own <html>/<body>.
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg antialiased">
        <ErrorPanel error={error} reset={reset} />
      </body>
    </html>
  );
}
