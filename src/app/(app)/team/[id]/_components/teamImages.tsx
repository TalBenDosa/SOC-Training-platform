"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { ImagePlus, X } from "lucide-react";
import { Button } from "@/components/ui/Button";

/**
 * Screenshots in the team exercise — shared by the war-room chat and the Tier-1
 * escalation card. Images are downsized in the browser, uploaded to the session's
 * private bucket through /api/team/sessions/[id]/chat-image, and referenced from the
 * action payload as `{ path, w, h }`; viewing goes back through the same route, which
 * checks membership and redirects to a short-lived signed URL.
 */

/** The server stores up to 4 MB (chat-image route); screenshots are downsized well below it. */
export const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
const MAX_IMAGE_EDGE = 1920;

export type TeamImage = { path: string; w?: number; h?: number };
export type PendingImage = { blob: Blob; url: string; w: number; h: number };

export const teamImageSrc = (sessionId: string, path: string) =>
  `/api/team/sessions/${sessionId}/chat-image?path=${encodeURIComponent(path)}`;

/** Images carried by an action payload (ignores anything malformed). */
export function imagesOf(v: unknown): TeamImage[] {
  const one = (x: unknown): TeamImage | null => (x && typeof x === "object" && typeof (x as TeamImage).path === "string" ? (x as TeamImage) : null);
  if (Array.isArray(v)) return v.map(one).filter((x): x is TeamImage => !!x);
  const single = one(v);
  return single ? [single] : [];
}

/** Downsize to 1920px max and re-encode (WebP, else JPEG). GIFs stay as they are. */
export async function prepareImage(file: Blob): Promise<PendingImage> {
  const bmp = await createImageBitmap(file);
  if (file.type === "image/gif") return { blob: file, url: URL.createObjectURL(file), w: bmp.width, h: bmp.height };
  const scale = Math.min(1, MAX_IMAGE_EDGE / Math.max(bmp.width, bmp.height));
  const w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale);
  const canvas = document.createElement("canvas");
  canvas.width = w; canvas.height = h;
  canvas.getContext("2d")!.drawImage(bmp, 0, 0, w, h);
  const encode = (type: string, q: number) => new Promise<Blob | null>(res => canvas.toBlob(res, type, q));
  let blob = await encode("image/webp", 0.9);
  if (!blob || blob.type !== "image/webp") blob = await encode("image/jpeg", 0.88);
  if (!blob) throw new Error("encode");
  return { blob, url: URL.createObjectURL(blob), w, h };
}

/** Upload one prepared image; resolves to its stored reference or throws with a user-facing message. */
export async function uploadTeamImage(sessionId: string, img: PendingImage): Promise<TeamImage> {
  const fd = new FormData();
  fd.append("file", img.blob, "screenshot");
  let res: Response;
  try { res = await fetch(`/api/team/sessions/${sessionId}/chat-image`, { method: "POST", body: fd }); }
  catch { throw new Error("The image couldn't be uploaded. Check your connection."); }
  const j = await res.json().catch(() => ({} as { path?: string; error?: string }));
  if (!res.ok || !j.path) throw new Error(j.error || "The image couldn't be uploaded. Try again.");
  return { path: j.path, w: img.w, h: img.h };
}

/** Local attachment state: add from a file / paste / drop, preview, remove, upload all. */
export function useImageAttachments(max: number) {
  const [items, setItems] = useState<PendingImage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const itemsRef = useRef(items);
  itemsRef.current = items;
  useEffect(() => () => { for (const i of itemsRef.current) URL.revokeObjectURL(i.url); }, []);

  const add = useCallback(async (file: Blob | null | undefined) => {
    setError(null);
    if (!file) return;
    if (!file.type.startsWith("image/")) { setError("Only images can be attached."); return; }
    if (itemsRef.current.length >= max) { setError(max === 1 ? "One image per message." : `Up to ${max} images.`); return; }
    try {
      const p = await prepareImage(file);
      if (p.blob.size > MAX_IMAGE_BYTES) { URL.revokeObjectURL(p.url); setError("That image is still larger than 4 MB after resizing."); return; }
      setItems(list => (max === 1 ? (list.forEach(i => URL.revokeObjectURL(i.url)), [p]) : [...list, p].slice(0, max)));
    } catch { setError("That image couldn't be read."); }
  }, [max]);
  const remove = useCallback((idx: number) => setItems(list => { const x = list[idx]; if (x) URL.revokeObjectURL(x.url); return list.filter((_, i) => i !== idx); }), []);
  const clear = useCallback(() => setItems(list => { list.forEach(i => URL.revokeObjectURL(i.url)); return []; }), []);
  /** Paste handler: attaches the first image on the clipboard (text paste is untouched). */
  const onPaste = useCallback((e: React.ClipboardEvent) => {
    const f = [...e.clipboardData.items].find(i => i.type.startsWith("image/"))?.getAsFile();
    if (f) { e.preventDefault(); void add(f); }
  }, [add]);
  const dropProps = {
    onDragOver: (e: React.DragEvent) => { if ([...e.dataTransfer.items].some(i => i.type.startsWith("image/"))) e.preventDefault(); },
    onDrop: (e: React.DragEvent) => { const f = [...e.dataTransfer.files].find(x => x.type.startsWith("image/")); if (f) { e.preventDefault(); void add(f); } },
  };
  return { items, error, setError, add, remove, clear, onPaste, dropProps };
}

/** The paper-clip button + hidden file input. */
export function AttachImageButton({ onPick, label = "Attach an image or screenshot" }: { onPick: (f: Blob | undefined) => void; label?: string }) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <>
      <input ref={ref} type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden" aria-hidden="true" tabIndex={-1}
        onChange={e => { onPick(e.target.files?.[0]); e.target.value = ""; }} />
      <Button variant="secondary" size="sm" type="button" onClick={() => ref.current?.click()} aria-label={label} title={`${label} (or paste one with Ctrl+V)`}>
        <ImagePlus className="h-3.5 w-3.5" aria-hidden="true" />
      </Button>
    </>
  );
}

/** Previews of images waiting to be sent. */
export function PendingImages({ items, onRemove }: { items: PendingImage[]; onRemove: (idx: number) => void }) {
  if (!items.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((p, i) => (
        <div key={p.url} className="relative">
          {/* eslint-disable-next-line @next/next/no-img-element -- local preview (blob: URL) before upload */}
          <img src={p.url} alt={`Attached image ${i + 1}, ${p.w} by ${p.h}`} className="h-20 w-auto rounded border border-border/60 object-contain" />
          <button type="button" onClick={() => onRemove(i)} aria-label={`Remove attached image ${i + 1}`}
            className="absolute -right-1.5 -top-1.5 rounded-full border border-border bg-bg p-0.5 text-slate-300 hover:text-white">
            <X className="h-3 w-3" aria-hidden="true" />
          </button>
        </div>
      ))}
    </div>
  );
}

/** A stored image as a clickable thumbnail (opens full size in a new tab). */
export function TeamImageThumb({ sessionId, image, alt, className = "max-h-60" }: { sessionId: string; image: TeamImage; alt: string; className?: string }) {
  const src = teamImageSrc(sessionId, image.path);
  return (
    <a href={src} target="_blank" rel="noopener noreferrer" className="block" aria-label={`${alt} (opens full size)`}>
      {/* eslint-disable-next-line @next/next/no-img-element -- a private, signed, per-session image behind our own route */}
      <img src={src} alt={alt} width={image.w} height={image.h} loading="lazy"
        className={`h-auto w-auto max-w-full cursor-zoom-in rounded-md border border-border/60 bg-bg object-contain ${className}`} />
    </a>
  );
}
