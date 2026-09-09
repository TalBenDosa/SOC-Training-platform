import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

const BUCKET = "org-media";
const TTL_SECONDS = 300; // 5-minute signed URL

/**
 * Mint a short-lived signed URL for a media resource. Available to any MEMBER of
 * the resource's org for a PUBLISHED resource (this is how a student opens their
 * college's materials); drafts are staff-only. Org membership is re-asserted
 * from the JWT — the bucket itself denies all client access, so a URL can only
 * be obtained through this checked path.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (!user.orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { id } = await params;
  const { data: row, error } = await admin
    .from("org_resources").select("org_id, status, storage_key, mime, allow_download").eq("id", id).maybeSingle();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  if (!row || row.org_id !== user.orgId) return NextResponse.json({ error: "Not found." }, { status: 404 });

  // Drafts are staff-only; students see published materials only.
  const isStaff = user.isPlatformAdmin || (user.orgRole === "org_admin" || user.orgRole === "instructor");
  if (row.status !== "published" && !isStaff) {
    return NextResponse.json({ error: "Not found." }, { status: 404 });
  }

  // Honour the resource's download policy at delivery: allow_download files are
  // served with Content-Disposition: attachment (a real "Save as"); view-only
  // files are served inline. The flag is also returned so the UI hides the
  // download control for view-only materials.
  const { data: signed, error: signErr } = await admin.storage
    .from(BUCKET).createSignedUrl(row.storage_key, TTL_SECONDS, row.allow_download ? { download: true } : undefined);
  if (signErr || !signed) return NextResponse.json({ error: signErr?.message ?? "Could not sign URL." }, { status: 500 });

  return NextResponse.json({ url: signed.signedUrl, mime: row.mime, allow_download: row.allow_download ?? false, expires_in: TTL_SECONDS });
}
