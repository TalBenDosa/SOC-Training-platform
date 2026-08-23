"use client";
/**
 * College Materials — a per-org resource library (migration 0038, Phase 1 of
 * per-org content). Shows ONLY the current org's PUBLISHED presentations/videos
 * (RLS-scoped via fetchOrgResources). Files open through short-lived signed URLs
 * (GET /api/org/media/[id]/url) — never a public object path.
 */
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import { FileText, Presentation, Video, Loader2, ExternalLink, Library } from "lucide-react";
import { fetchOrgResources, type OrgResource } from "@/lib/content/publicContent";

const KIND_META: Record<OrgResource["kind"], { label: string; icon: typeof FileText; cls: string }> = {
  pdf:   { label: "PDF",          icon: FileText,     cls: "text-severity-high border-severity-high/40 bg-severity-high/10" },
  pptx:  { label: "Presentation", icon: Presentation, cls: "text-neon-amber border-neon-amber/40 bg-neon-amber/10" },
  video: { label: "Video",        icon: Video,        cls: "text-neon-purple border-neon-purple/40 bg-neon-purple/10" },
};

function fmtSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function ResourcesPage() {
  const [items, setItems] = useState<OrgResource[] | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { fetchOrgResources().then(setItems).catch(() => setItems([])); }, []);

  async function open(id: string) {
    setError(null);
    setOpening(id);
    try {
      const res = await fetch(`/api/org/media/${id}/url`);
      const data = await res.json();
      if (!res.ok || !data.url) { setError(data?.error ?? "Could not open the file."); return; }
      window.open(data.url, "_blank", "noopener,noreferrer");
    } catch {
      setError("Could not open the file. Please try again.");
    } finally {
      setOpening(null);
    }
  }

  return (
    <div>
      <Topbar title="College Materials" subtitle="Presentations, videos and documents from your college" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-4">
        {error && (
          <div className="rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">{error}</div>
        )}

        {items === null ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : items.length === 0 ? (
          <Card className="flex flex-col items-center gap-2 py-12 text-center">
            <Library className="h-8 w-8 text-slate-500" />
            <p className="text-sm font-semibold text-white">No materials yet</p>
            <p className="max-w-sm text-xs text-slate-400">Your college hasn&apos;t published any presentations or videos yet. They&apos;ll appear here when they do.</p>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {items.map(r => {
              const m = KIND_META[r.kind];
              return (
                <button
                  key={r.id}
                  onClick={() => open(r.id)}
                  disabled={opening === r.id}
                  className="group flex items-start gap-3 rounded-lg border border-border bg-bg-elevated px-4 py-3 text-left transition hover:border-cyber-500/50 disabled:opacity-60"
                >
                  <span className={cn("mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border", m.cls)}>
                    <m.icon className="h-4 w-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-white group-hover:text-cyber-300">{r.title}</span>
                    <span className="mt-0.5 block text-[11px] text-slate-500">{m.label} · {fmtSize(r.size_bytes)}</span>
                  </span>
                  {opening === r.id
                    ? <Loader2 className="mt-1 h-4 w-4 shrink-0 animate-spin text-slate-400" />
                    : <ExternalLink className="mt-1 h-4 w-4 shrink-0 text-slate-600 transition group-hover:text-cyber-300" />}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
