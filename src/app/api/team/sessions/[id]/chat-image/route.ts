import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { activeSeat } from "@/lib/team/membership";

/**
 * Team chat images (screenshots shared in the war room).
 *
 *  POST  multipart `file` → stores the image in the PRIVATE `team-chat` bucket under
 *        `<sessionId>/<uuid>.<ext>` and returns `{ path, mime }`. The client then posts a
 *        normal `message.sent` whose payload carries `image.path`.
 *  GET   `?path=<sessionId>/<uuid>.<ext>` → 302 to a 5-minute signed URL.
 *
 * Writes go through the service role, so every check is re-asserted here: an active seat
 * in THIS session (not an observer) to upload; any member (a `left` one included, so the
 * after-action view still shows the images) or staff of the session's org to view. The
 * file type is sniffed from its magic bytes, never trusted from the browser, and the path
 * on GET must belong to the session in the URL.
 */

const BUCKET = "team-chat";
// The browser downsizes screenshots before upload (WarRoom.tsx), so real uploads are far
// smaller; this stays under Vercel's ~4.5 MB serverless body limit.
const MAX_BYTES = 4 * 1024 * 1024;
const LIVE = new Set(["lobby", "running", "paused"]);
const PATH_RE = /^[0-9a-f-]{36}\/[0-9a-f-]{36}\.(png|jpg|webp|gif)$/;

function sniff(b: Uint8Array): { ext: string; mime: string } | null {
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return { ext: "png", mime: "image/png" };
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { ext: "jpg", mime: "image/jpeg" };
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return { ext: "webp", mime: "image/webp" };
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return { ext: "gif", mime: "image/gif" };
  return null;
}

let bucketReady = false;
async function ensureBucket(admin: NonNullable<ReturnType<typeof getSupabaseAdminClient>>) {
  if (bucketReady) return;
  const { data } = await admin.storage.getBucket(BUCKET);
  if (!data) {
    const { error } = await admin.storage.createBucket(BUCKET, {
      public: false, fileSizeLimit: MAX_BYTES, allowedMimeTypes: ["image/png", "image/jpeg", "image/webp", "image/gif"],
    });
    if (error && !/already exists/i.test(error.message)) throw new Error(error.message);
  }
  bucketReady = true;
}

async function sessionOf(admin: NonNullable<ReturnType<typeof getSupabaseAdminClient>>, id: string) {
  const { data } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  return data as { id: string; org_id: string; status: string } | null;
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const sess = await sessionOf(admin, id);
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!LIVE.has(sess.status)) return NextResponse.json({ error: "This session has ended." }, { status: 409 });
  const seat = await activeSeat(admin, id, sess.org_id, user.id);
  if (!seat || seat.role === "observer") return NextResponse.json({ error: "Only team members can share images here." }, { status: 403 });

  let form: FormData;
  try { form = await req.formData(); } catch { return NextResponse.json({ error: "Send the image as a file upload." }, { status: 400 }); }
  const file = form.get("file");
  if (!(file instanceof Blob) || file.size === 0) return NextResponse.json({ error: "No image attached." }, { status: 400 });
  if (file.size > MAX_BYTES) return NextResponse.json({ error: "The image is larger than 4 MB." }, { status: 413 });
  const bytes = new Uint8Array(await file.arrayBuffer());
  const kind = sniff(bytes);
  if (!kind) return NextResponse.json({ error: "Only PNG, JPEG, WebP or GIF images can be shared." }, { status: 415 });

  try { await ensureBucket(admin); } catch (e) {
    console.error("[team chat-image] bucket:", e instanceof Error ? e.message : String(e));
    return NextResponse.json({ error: "Image sharing isn't available right now." }, { status: 503 });
  }
  const path = `${id}/${randomUUID()}.${kind.ext}`;
  const { error } = await admin.storage.from(BUCKET).upload(path, bytes, { contentType: kind.mime, upsert: false });
  if (error) {
    console.error("[team chat-image] upload:", error.message);
    return NextResponse.json({ error: "The image couldn't be uploaded. Try again." }, { status: 500 });
  }
  return NextResponse.json({ path, mime: kind.mime });
}

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const path = new URL(req.url).searchParams.get("path") ?? "";
  if (!PATH_RE.test(path) || !path.startsWith(`${id}/`)) return NextResponse.json({ error: "Not found." }, { status: 404 });
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const sess = await sessionOf(admin, id);
  if (!sess) return NextResponse.json({ error: "Not found." }, { status: 404 });
  const iAmStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmStaff) {
    const { data: mem } = await admin.from("team_session_members").select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    if (!mem) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }
  const { data, error } = await admin.storage.from(BUCKET).createSignedUrl(path, 300);
  if (error || !data?.signedUrl) return NextResponse.json({ error: "Not found." }, { status: 404 });
  return NextResponse.redirect(data.signedUrl, { status: 302, headers: { "Cache-Control": "private, max-age=240" } });
}
