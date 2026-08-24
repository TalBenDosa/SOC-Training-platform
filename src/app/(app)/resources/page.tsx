"use client";
/**
 * College Materials — a per-org resource library (migration 0038, Phase 1 of
 * per-org content). Shows ONLY the current org's PUBLISHED presentations/videos
 * (RLS-scoped via fetchOrgResources). Files open through short-lived signed URLs
 * (GET /api/org/media/[id]/url) — never a public object path.
 *
 * Materials open in an IN-APP viewer (a modal), not a separate browser tab:
 *  - PDF   → fetched as a blob and shown in a same-origin blob: <iframe>, so the
 *            private signed URL never touches the DOM (CSP frame-src 'self' blob:).
 *  - video → streamed from Supabase in an inline <video> (CSP media-src).
 *  - pptx  → no safe inline renderer, so the modal offers a download.
 */
import { useEffect, useRef, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { LibraryCard } from "@/components/ui/LibraryCard";
import { cn } from "@/lib/utils";
import { FileText, Presentation, Video, Loader2, Library, Eye, X, Download, AlertTriangle } from "lucide-react";
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

/** What the viewer is currently showing. `blobUrl` is set for PDFs (same-origin
 *  object URL); `url` is the raw signed URL (used for video streaming + download). */
type ViewerState = {
  resource: OrgResource;
  url: string;
  blobUrl?: string;
  loading: boolean;
  error: string | null;
};

export default function ResourcesPage() {
  const [items, setItems] = useState<OrgResource[] | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [viewer, setViewer] = useState<ViewerState | null>(null);
  // Track the live blob URL so it can be revoked on close/unmount (no leaks).
  const blobRef = useRef<string | null>(null);

  useEffect(() => { fetchOrgResources().then(setItems).catch(() => setItems([])); }, []);

  function revokeBlob() {
    if (blobRef.current) { URL.revokeObjectURL(blobRef.current); blobRef.current = null; }
  }
  useEffect(() => () => revokeBlob(), []); // revoke on unmount

  // Close on Escape, and lock body scroll while the viewer is open.
  useEffect(() => {
    if (!viewer) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer]);

  function close() {
    revokeBlob();
    setViewer(null);
  }

  async function open(r: OrgResource) {
    setError(null);
    setOpening(r.id);
    try {
      const res = await fetch(`/api/org/media/${r.id}/url`);
      const data = await res.json();
      if (!res.ok || !data.url) { setError(data?.error ?? "Could not open the file."); return; }

      // PDFs: pull the bytes over connect-src and hand the viewer a same-origin
      // blob URL, so the signed URL never appears in the DOM and the browser's
      // PDF viewer renders it INSIDE our modal.
      if (r.kind === "pdf") {
        revokeBlob();
        setViewer({ resource: r, url: data.url, loading: true, error: null });
        try {
          const fileRes = await fetch(data.url);
          if (!fileRes.ok) throw new Error("fetch failed");
          // Force application/pdf so the browser's built-in viewer renders the
          // blob inline instead of treating an octet-stream as a download.
          const buf = await fileRes.arrayBuffer();
          const blob = new Blob([buf], { type: "application/pdf" });
          const blobUrl = URL.createObjectURL(blob);
          blobRef.current = blobUrl;
          setViewer(v => (v && v.resource.id === r.id ? { ...v, blobUrl, loading: false } : v));
        } catch {
          setViewer(v => (v && v.resource.id === r.id ? { ...v, loading: false, error: "Could not load this document." } : v));
        }
        return;
      }

      // Video streams directly; pptx has no inline renderer (download in modal).
      setViewer({ resource: r, url: data.url, loading: false, error: null });
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
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {items.map((r, i) => {
              const m = KIND_META[r.kind];
              return (
                <LibraryCard
                  key={r.id}
                  onClick={() => open(r)}
                  disabled={opening === r.id}
                  seed={r.id}
                  index={i}
                  icon={m.icon}
                  typeLabel={m.label}
                  title={r.title}
                  meta={<>{m.label} · {fmtSize(r.size_bytes)}</>}
                  cta={opening === r.id
                    ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-slate-400" />
                    : <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition group-hover:bg-cyber-500/25"><Eye className="h-3.5 w-3.5" /> Open</span>}
                />
              );
            })}
          </div>
        )}
      </div>

      {viewer && (
        <ResourceViewer state={viewer} onClose={close} />
      )}
    </div>
  );
}

/** In-app viewer modal. Renders the material inside the platform. */
function ResourceViewer({ state, onClose }: { state: ViewerState; onClose: () => void }) {
  const { resource: r, url, blobUrl, loading, error } = state;
  const m = KIND_META[r.kind];
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={r.title}
      onClick={onClose}
    >
      <div
        className="flex h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-border bg-bg-elevated shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex shrink-0 items-center gap-3 border-b border-border bg-bg px-4 py-3">
          <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border", m.cls)}>
            <m.icon className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-white">{r.title}</p>
            <p className="text-[11px] text-slate-500">{m.label} · {fmtSize(r.size_bytes)}</p>
          </div>
          <a
            href={blobUrl ?? url}
            download={r.kind === "pptx" ? undefined : r.title}
            target={r.kind === "pptx" ? "_blank" : undefined}
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-cyber-500/50 hover:text-cyber-300"
          >
            <Download className="h-3.5 w-3.5" /> Download
          </a>
          <button
            onClick={onClose}
            aria-label="Close"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-bg-elevated text-slate-400 transition hover:border-severity-high/50 hover:text-severity-high"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="relative flex-1 bg-[#0b0f1e]">
          {r.kind === "pdf" && (
            loading ? (
              <div className="flex h-full items-center justify-center gap-2 text-sm text-slate-400">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading document…
              </div>
            ) : error ? (
              <ViewerError message={error} />
            ) : blobUrl ? (
              <iframe src={blobUrl} title={r.title} className="h-full w-full border-0" />
            ) : null
          )}

          {r.kind === "video" && (
            <video src={url} controls autoPlay className="h-full w-full bg-black">
              Your browser can&apos;t play this video.
            </video>
          )}

          {r.kind === "pptx" && (
            <div className="flex h-full flex-col items-center justify-center gap-3 px-6 text-center">
              <Presentation className="h-10 w-10 text-neon-amber" />
              <p className="text-sm font-semibold text-white">PowerPoint presentation</p>
              <p className="max-w-sm text-xs text-slate-400">
                This presentation opens in PowerPoint. Download it to view the slides.
              </p>
              <a
                href={url}
                download={r.title}
                className="mt-1 flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/10 px-4 py-2 text-sm font-semibold text-cyber-300 transition hover:bg-cyber-500/20"
              >
                <Download className="h-4 w-4" /> Download presentation
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ViewerError({ message }: { message: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      <AlertTriangle className="h-8 w-8 text-severity-high" />
      <p className="text-sm font-semibold text-white">{message}</p>
      <p className="text-xs text-slate-400">The secure link may have expired. Close and open it again.</p>
    </div>
  );
}
