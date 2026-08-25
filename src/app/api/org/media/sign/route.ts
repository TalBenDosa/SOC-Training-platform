import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Step 1 of the two-step upload: mint a short-lived signed UPLOAD url so the
 * browser can PUT the file DIRECTLY to Supabase Storage, bypassing the Vercel
 * serverless request-body limit (~4.5MB) that made mid-size PPTX/PDF/video
 * uploads fail with a confusing generic error. The storage key is generated
 * server-side (never the client filename → no path traversal). The bytes are
 * re-validated server-side in the finalize step (POST /api/org/media), so a
 * spoofed extension here can't smuggle an unexpected file into the library.
 */

const BUCKET = "org-media";

// Map a client-declared extension to our folder kind + canonical extension.
// This only shapes the storage KEY; the true type is re-sniffed at finalize.
const EXT_KIND: Record<string, { kind: "pdf" | "pptx" | "video"; ext: string }> = {
  pdf: { kind: "pdf", ext: "pdf" },
  pptx: { kind: "pptx", ext: "pptx" },
  mp4: { kind: "video", ext: "mp4" },
  webm: { kind: "video", ext: "webm" },
  mov: { kind: "video", ext: "mp4" },
  m4v: { kind: "video", ext: "mp4" },
};

export async function POST(req: Request) {
  const gate = await requireOrgAdmin("org.media.upload");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const body = await req.json().catch(() => ({}));
  const rawExt = String(body?.ext ?? "").toLowerCase().replace(/^\./, "");
  const mapped = EXT_KIND[rawExt];
  if (!mapped) {
    return NextResponse.json({ error: "Unsupported file type. Allowed: PDF, PPTX, MP4/WebM video." }, { status: 415 });
  }

  const storageKey = `${orgId}/${mapped.kind}/${randomUUID()}.${mapped.ext}`;
  const { data, error } = await admin.storage.from(BUCKET).createSignedUploadUrl(storageKey);
  if (error || !data) {
    return NextResponse.json({ error: error?.message ?? "Could not start the upload." }, { status: 500 });
  }
  // token + path are what the browser passes to uploadToSignedUrl().
  return NextResponse.json({ path: data.path, token: data.token, kind: mapped.kind });
}
