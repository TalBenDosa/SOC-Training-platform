import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { studentInviteEmail } from "@/lib/email/templates";

/** Org-admin invite links, always for the caller's own org (from the JWT). */

function joinLink(req: Request, token: string): string {
  return `${new URL(req.url).origin}/join?token=${token}`;
}

async function ctx() {
  const gate = await requireOrgAdmin("org.invites");
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, admin };
}

export async function GET(req: Request) {
  const c = await ctx();
  if ("error" in c) return c.error;
  const { data, error } = await c.admin
    .from("invitations")
    .select("id, email, role, token, expires_at, accepted_at, created_at")
    .eq("org_id", c.orgId)
    .is("accepted_at", null)
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ invites: (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) })) });
}

export async function POST(req: Request) {
  const c = await ctx();
  if ("error" in c) return c.error;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  // Org-admins hand out student/instructor links only.
  const role = ["student", "instructor"].includes(String(body.role)) ? String(body.role) : "student";
  const rawEmails = Array.isArray(body.emails) ? (body.emails as unknown[]).map(e => String(e).trim().toLowerCase()) : [];
  // Cap the recipient list: an oversized array would balloon into one giant
  // insert + that many outbound emails (provider cost + sender-reputation risk).
  // 200 comfortably covers any real class roster.
  const MAX_INVITES = 200;
  const emails = [...new Set(rawEmails.filter(e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)))].slice(0, MAX_INVITES);

  // 0029: invitations are NAMED-ONLY. The anonymous class-link shape (email
  // null) was the one student door that bypassed the affiliation code, so the
  // trigger now rejects it — refusing to mint one here keeps the API honest
  // rather than issuing links that can never be redeemed.
  if (emails.length === 0) {
    return NextResponse.json(
      { error: "Invites are named-only. Students join with your class code — generate it in the Class code panel." },
      { status: 400 },
    );
  }
  const expiresAt = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();

  const rows = emails.map(email => ({
    org_id: c.orgId, role, email, token: crypto.randomUUID(), expires_at: expiresAt,
  }));
  const { data, error } = await c.admin.from("invitations").insert(rows).select("id, email, role, token, expires_at");
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  const invites = (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) }));

  // Best-effort email to each named recipient (generic links have no recipient).
  const { data: org } = await c.admin.from("organizations").select("name").eq("id", c.orgId).maybeSingle();
  const orgName = org?.name ?? "your course";
  await Promise.allSettled(
    invites.filter(i => i.email).map(i => {
      const mail = studentInviteEmail({ orgName, joinLink: i.link });
      return sendEmail({ to: i.email, subject: mail.subject, html: mail.html, text: mail.text });
    }),
  );

  return NextResponse.json({ invites }, { status: 201 });
}
