import Link from "next/link";

// Branded 404 with a way back (it used to be Next's bare "This page could not be found.").
export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-bg px-6 py-16 text-center">
      <p className="font-mono text-4xl font-bold text-slate-500">404</p>
      <h1 className="mt-3 text-lg font-semibold text-white">This page doesn&apos;t exist</h1>
      <p className="mt-2 max-w-md text-sm text-slate-400">The link may be out of date, or the content was moved.</p>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        <Link href="/dashboard" className="rounded-md border border-cyber-500/40 bg-cyber-500/10 px-4 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20">Go to the dashboard</Link>
        <Link href="/rooms" className="rounded-md border border-border px-4 py-2 text-sm text-slate-300 hover:bg-white/5">Learning Rooms</Link>
      </div>
    </div>
  );
}
