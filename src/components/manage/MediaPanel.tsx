"use client";
/**
 * College Materials manager (org-admin) — upload/publish/delete per-org media
 * (migration 0038, Phase 1 of per-org content). This is the platform's first
 * file-upload UI. Uploads POST to /api/org/media (magic-byte validated,
 * org-scoped, service-role storage); published items appear to that org's
 * students on the /resources page.
 */
import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { Upload, FileText, Presentation, Video, Trash2, Eye, EyeOff, Loader2, Library, Download, DownloadCloud } from "lucide-react";

interface Resource {
  id: string;
  kind: "pdf" | "pptx" | "video";
  title: string;
  mime: string;
  size_bytes: number;
  status: "draft" | "published";
  allow_download: boolean;
  created_at: string;
}

const KIND_ICON = { pdf: FileText, pptx: Presentation, video: Video } as const;

function fmtSize(b: number): string {
  return b < 1024 * 1024 ? `${Math.max(1, Math.round(b / 1024))} KB` : `${(b / 1024 / 1024).toFixed(1)} MB`;
}

export function MediaPanel() {
  const [items, setItems] = useState<Resource[] | null>(null);
  const [title, setTitle] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function load() {
    const res = await fetch("/api/org/media");
    if (res.ok) setItems((await res.json()).resources ?? []);
    else setItems([]);
  }
  useEffect(() => { load(); }, []);

  // Two-step upload: (1) the server signs a storage upload URL, (2) the browser
  // PUTs the file DIRECTLY to Supabase Storage — bypassing Vercel's ~4.5MB
  // serverless request-body limit that made mid-size PPTX/PDF/video uploads fail
  // — then (3) the server re-validates the stored bytes and creates the row.
  async function upload() {
    setError(null); setNotice(null);
    if (!file) { setError("Choose a file to upload."); return; }
    if (!title.trim()) { setError("Give the material a title."); return; }
    const supabase = getSupabaseBrowserClient();
    if (!supabase) { setError("Uploads aren't configured on this deployment."); return; }
    const ext = (file.name.split(".").pop() ?? "").toLowerCase();
    setBusy(true);
    try {
      // 1. sign
      const signRes = await fetch("/api/org/media/sign", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ext }),
      });
      const sign = await signRes.json().catch(() => ({}));
      if (!signRes.ok) { setError(sign?.error ?? "Could not start the upload."); return; }
      // 2. direct upload to storage (no function body limit)
      const up = await supabase.storage.from("org-media").uploadToSignedUrl(sign.path, sign.token, file);
      if (up.error) { setError(up.error.message || "Upload failed while sending the file."); return; }
      // 3. finalize — server re-validates + creates the row
      const finRes = await fetch("/api/org/media", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ storageKey: sign.path, title: title.trim() }),
      });
      const fin = await finRes.json().catch(() => ({}));
      if (!finRes.ok) { setError(fin?.error ?? "Upload failed."); return; }
      setNotice("Uploaded as a draft. Publish it to show students.");
      setTitle(""); setFile(null); if (fileRef.current) fileRef.current.value = "";
      await load();
    } catch {
      setError("Upload failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(id: string, status: "published" | "draft") {
    setRowBusy(id); setError(null);
    const res = await fetch(`/api/org/media/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }),
    });
    setRowBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Update failed."); return; }
    await load();
  }

  async function setDownload(id: string, allow: boolean) {
    setRowBusy(id); setError(null);
    const res = await fetch(`/api/org/media/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ allow_download: allow }),
    });
    setRowBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Update failed."); return; }
    await load();
  }

  async function remove(id: string, title: string) {
    if (!confirm(`Delete "${title}"? This removes the file for good.`)) return;
    setRowBusy(id); setError(null);
    const res = await fetch(`/api/org/media/${id}`, { method: "DELETE" });
    setRowBusy(null);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Delete failed."); return; }
    await load();
  }

  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white">
        <Library className="h-4 w-4 text-cyber-300" /> College Materials
      </h2>
      <p className="mt-1 text-xs text-slate-400">
        Upload presentations (PDF/PPTX) and videos unique to your college. Published items appear to your students under &quot;College Materials&quot;. Drafts are visible only to you.
      </p>

      {error && <div className="mt-3 rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">{error}</div>}
      {notice && <div className="mt-3 rounded border border-neon-green/30 bg-neon-green/10 px-3 py-2 text-xs text-neon-green">{notice}</div>}

      {/* Upload row */}
      <div className="mt-4 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 py-3">
        <input
          value={title}
          onChange={e => setTitle(e.target.value)}
          placeholder="Title (e.g. Week 1 — Intro deck)"
          className="min-w-[180px] flex-1 rounded border border-border bg-bg px-2.5 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyber-500/50 focus:outline-none"
        />
        <input
          ref={fileRef}
          type="file"
          accept=".pdf,.pptx,video/mp4,video/webm,application/pdf,application/vnd.openxmlformats-officedocument.presentationml.presentation"
          onChange={e => setFile(e.target.files?.[0] ?? null)}
          className="text-xs text-slate-400 file:mr-2 file:rounded file:border-0 file:bg-cyber-500/15 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-cyber-300 hover:file:bg-cyber-500/25"
        />
        <Button variant="primary" size="sm" disabled={busy} onClick={upload}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />} Upload
        </Button>
      </div>
      <p className="mt-1.5 text-[10px] text-slate-500">PDF/PPTX up to 25MB · video (MP4/WebM) up to 200MB. File type is verified on the server.</p>

      {/* List */}
      <div className="mt-4 space-y-2">
        {items === null ? (
          <div className="flex items-center gap-2 text-xs text-slate-400"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</div>
        ) : items.length === 0 ? (
          <p className="text-xs text-slate-500">No materials uploaded yet.</p>
        ) : items.map(r => {
          const Icon = KIND_ICON[r.kind];
          const pub = r.status === "published";
          return (
            <div key={r.id} className="flex items-center gap-3 rounded-lg border border-border bg-bg px-3 py-2.5">
              <Icon className="h-4 w-4 shrink-0 text-slate-400" />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm text-slate-100">{r.title}</p>
                <p className="text-[10px] text-slate-500">{r.kind.toUpperCase()} · {fmtSize(r.size_bytes)}</p>
              </div>
              <span className={cn("shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide border",
                pub ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-slate-500/40 bg-slate-500/10 text-slate-400")}>
                {pub ? "Published" : "Draft"}
              </span>
              {/* Download permission — OFF by default; students can only view
                  until the admin opts this resource in. */}
              <button
                onClick={() => setDownload(r.id, !r.allow_download)}
                disabled={rowBusy === r.id}
                title={r.allow_download ? "Downloads allowed — click to disable" : "View-only — click to allow download"}
                className={cn("rounded p-1.5 transition disabled:opacity-50",
                  r.allow_download ? "text-cyber-300 hover:bg-cyber-500/10" : "text-slate-500 hover:bg-slate-500/10 hover:text-slate-300")}
              >
                {r.allow_download ? <DownloadCloud className="h-4 w-4" /> : <Download className="h-4 w-4" />}
              </button>
              <button
                onClick={() => setStatus(r.id, pub ? "draft" : "published")}
                disabled={rowBusy === r.id}
                title={pub ? "Unpublish" : "Publish to students"}
                className="rounded p-1.5 text-slate-400 transition hover:bg-cyber-500/10 hover:text-cyber-300 disabled:opacity-50"
              >
                {pub ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
              <button
                onClick={() => remove(r.id, r.title)}
                disabled={rowBusy === r.id}
                title="Delete"
                className="rounded p-1.5 text-slate-400 transition hover:bg-severity-high/10 hover:text-severity-high disabled:opacity-50"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
