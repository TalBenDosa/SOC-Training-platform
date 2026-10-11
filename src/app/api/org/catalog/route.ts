import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { getPlanCatalog } from "@/lib/plans/catalog";

/**
 * The module tree for the learning-plan editors (Learning plans panel and a
 * student's Personal priorities). Built server-side from the content corpora and
 * this org's published authored content, so the browser receives ids + titles
 * only — never the corpus modules (which carry answer keys) themselves.
 */
export const runtime = "nodejs";

export async function GET() {
  const gate = await requireOrgAdmin("org.catalog.read");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { tree } = await getPlanCatalog(admin, orgId);
  return NextResponse.json({ tree }, { headers: { "Cache-Control": "private, max-age=60" } });
}
