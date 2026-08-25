import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Per-org media resources ("College Materials") — the platform's first upload API.
 * Files land in the private `org-media` bucket under an org-prefixed key and are
 * served only via short-lived signed URLs (see ./[id]/url). Writes are service-
 * role (bypassing RLS), so every query re-asserts org_id from the JWT — never a
 * request parameter. See migration 0038.
 */

const BUCKET = "org-media";
const MAX_DOC_BYTES = 25 * 1024 * 1024;   // PDF / PPTX
const MAX_VIDEO_BYTES = 200 * 1024 * 1024; // video

type Kind = "pdf" | "pptx" | "video";

/** Sniff the true file type from magic bytes — never trust the client MIME/name.
 *  Returns the detected kind + the canonical extension/mime, or null if unknown. */
function sniff(bytes: Uint8Array): { kind: Kind; ext: string; mime: string } | null {
  const b = bytes;
  // PDF: "%PDF"
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) {
    return { kind: "pdf", ext: "pdf", mime: "application/pdf" };
  }
  // ZIP (PK\x03\x04) — PPTX is a zip. (allowed_mime_types on the bucket is the
  // second guard; a full OPC "ppt/" entry check would require unzipping.)
  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) {
    return { kind: "pptx", ext: "pptx", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation" };
  }
  // MP4/QuickTime: "ftyp" box at offset 4
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) {
    return { kind: "video", ext: "mp4", mime: "video/mp4" };
  }
  // WebM / Matroska: EBML header 1A 45 DF A3
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) {
    return { kind: "video", ext: "webm", mime: "video/webm" };
  }
  return null;
}

/** GET — list this org's materials (staff view: all statuses). Org re-asserted. */
export async function GET() {
  const gate = await requireOrgAdmin("org.media.list");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from("org_resources")
    .select("id, kind, title, mime, size_bytes, status, created_at")
    .eq("org_id", orgId)                     // service role bypasses RLS — re-assert
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ resources: data ?? [] });
}

/** POST — upload a file (multipart) + create the row. */
export async function POST(req: Request) {
  const gate = await requireOrgAdmin("org.media.upload");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  // ── Two-step (direct-to-storage) finalize ──────────────────────────────────
  // The browser already PUT the bytes to a signed upload URL (POST /sign),
  // bypassing Vercel's ~4.5MB serverless request-body limit that made mid-size
  // PPTX/PDF/video uploads fail. Here we re-validate the ACTUAL stored object by
  // its magic bytes + size (never a client claim), then create the row.
  if ((req.headers.get("content-type") ?? "").includes("application/json")) {
    const body = await req.json().catch(() => ({}));
    const storageKey = String(body?.storageKey ?? "");
    const title = String(body?.title ?? "").trim();
    if (!title) return NextResponse.json({ error: "A title is required." }, { status: 400 });
    // The key MUST live under this org's prefix — never trust a client path.
    if (!storageKey || !storageKey.startsWith(`${orgId}/`)) {
      return NextResponse.json({ error: "Invalid upload reference." }, { status: 400 });
    }
    const { data: signed, error: signErr } = await admin.storage.from(BUCKET).createSignedUrl(storageKey, 60);
    if (signErr || !signed) return NextResponse.json({ error: "Could not read the uploaded file." }, { status: 500 });

    // Read only the first bytes (Range) so a 200MB video isn't pulled into the
    // function; fall back to the reader's first chunk if Range is ignored.
    let magic = new Uint8Array();
    let size = 0;
    try {
      const head = await fetch(signed.signedUrl, { headers: { Range: "bytes=0-15" } });
      if (!head.ok && head.status !== 206) throw new Error("read");
      const cr = head.headers.get("content-range");
      size = parseInt(cr?.split("/")[1] ?? head.headers.get("content-length") ?? "0", 10);
      const reader = head.body?.getReader();
      if (reader) { const { value } = await reader.read(); reader.cancel().catch(() => {}); if (value) magic = value.subarray(0, 16); }
    } catch {
      await admin.storage.from(BUCKET).remove([storageKey]).catch(() => {});
      return NextResponse.json({ error: "Upload did not complete. Please try again." }, { status: 400 });
    }

    const kind = sniff(magic);
    if (!kind) {
      await admin.storage.from(BUCKET).remove([storageKey]).catch(() => {});
      return NextResponse.json({ error: "Unsupported file type. Allowed: PDF, PPTX, MP4/WebM video." }, { status: 415 });
    }
    const cap = kind.kind === "video" ? MAX_VIDEO_BYTES : MAX_DOC_BYTES;
    if (size > cap) {
      await admin.storage.from(BUCKET).remove([storageKey]).catch(() => {});
      return NextResponse.json({ error: `File too large (max ${Math.round(cap / 1024 / 1024)}MB for ${kind.kind}).` }, { status: 413 });
    }
    const { data: row, error: insErr } = await admin
      .from("org_resources")
      .insert({
        org_id: orgId, kind: kind.kind, title, storage_key: storageKey,
        mime: kind.mime, size_bytes: size, status: "draft", created_by: gate.user.id,
      })
      .select("id, kind, title, mime, size_bytes, status, created_at")
      .single();
    if (insErr) {
      await admin.storage.from(BUCKET).remove([storageKey]).catch(() => {});
      return NextResponse.json({ error: insErr.message }, { status: 500 });
    }
    await logAudit({
      actorId: gate.user.id, action: "org.media.uploaded",
      targetTable: "org_resources", targetId: row.id, metadata: { org_id: orgId, kind: kind.kind, size },
    });
    return NextResponse.json({ resource: row });
  }

  let form: FormData;
  try { form = await req.formData(); } catch { return NextResponse.json({ error: "Invalid upload." }, { status: 400 }); }
  const file = form.get("file");
  const title = String(form.get("title") ?? "").trim();
  if (!(file instanceof File)) return NextResponse.json({ error: "No file provided." }, { status: 400 });
  if (!title) return NextResponse.json({ error: "A title is required." }, { status: 400 });

  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length < 12) return NextResponse.json({ error: "File is empty or too small." }, { status: 400 });

  // Magic-byte detection — the client-declared type is ignored.
  const kind = sniff(bytes);
  if (!kind) {
    return NextResponse.json({ error: "Unsupported file type. Allowed: PDF, PPTX, MP4/WebM video." }, { status: 415 });
  }
  const cap = kind.kind === "video" ? MAX_VIDEO_BYTES : MAX_DOC_BYTES;
  if (bytes.length > cap) {
    return NextResponse.json({ error: `File too large (max ${Math.round(cap / 1024 / 1024)}MB for ${kind.kind}).` }, { status: 413 });
  }

  // Storage key is generated server-side (never the uploaded filename → no path traversal).
  const storageKey = `${orgId}/${kind.kind}/${randomUUID()}.${kind.ext}`;
  const up = await admin.storage.from(BUCKET).upload(storageKey, bytes, {
    contentType: kind.mime, upsert: false,
  });
  if (up.error) return NextResponse.json({ error: up.error.message }, { status: 500 });

  const { data: row, error: insErr } = await admin
    .from("org_resources")
    .insert({
      org_id: orgId, kind: kind.kind, title, storage_key: storageKey,
      mime: kind.mime, size_bytes: bytes.length, status: "draft", created_by: gate.user.id,
    })
    .select("id, kind, title, mime, size_bytes, status, created_at")
    .single();
  if (insErr) {
    // best-effort cleanup of the orphaned object
    await admin.storage.from(BUCKET).remove([storageKey]).catch(() => {});
    return NextResponse.json({ error: insErr.message }, { status: 500 });
  }

  await logAudit({
    actorId: gate.user.id, action: "org.media.uploaded",
    targetTable: "org_resources", targetId: row.id, metadata: { org_id: orgId, kind: kind.kind, size: bytes.length },
  });
  return NextResponse.json({ resource: row });
}
