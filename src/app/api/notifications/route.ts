import { NextResponse } from "next/server";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { NOTIFICATION_LIMITS, isSafeLink, type NotificationItem, type NotificationsResponse } from "@/lib/notifications/types";

/**
 * GET /api/notifications — the caller's own in-app notifications (migration
 * 0076) for the Topbar bell: newest first (max 30) + the unread count.
 *
 * Read through the caller's OWN Supabase client (not the service role), so the
 * "notifications own read" RLS policy is what scopes the rows; the explicit
 * user_id / org_id filters only narrow further (the current org's inbox).
 * Users without an org get `enabled: false` and the bell hides itself.
 *
 * Polled by the bell (every 60 s while visible + on focus), so it deliberately
 * skips the profiles read that getAuthedUser() does — one validated auth call
 * and two indexed queries.
 */

export const runtime = "nodejs";

const EMPTY = (enabled: boolean): NotificationsResponse => ({ enabled, notifications: [], unread: 0 });
const noStore = { "Cache-Control": "private, no-store" };

export async function GET() {
  const auth = await getValidatedAuth();
  if (!auth) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const { supabase, user, session } = auth;
  const { orgId } = decodeOrgClaim(session?.access_token);
  if (!orgId) return NextResponse.json(EMPTY(false), { headers: noStore });

  const [list, count] = await Promise.all([
    supabase.from("notifications")
      .select("id, kind, title, body, link, created_at, read_at")
      .eq("user_id", user.id).eq("org_id", orgId)
      .order("created_at", { ascending: false }).order("id", { ascending: false })
      .limit(NOTIFICATION_LIMITS.page),
    supabase.from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", user.id).eq("org_id", orgId).is("read_at", null),
  ]);

  if (list.error || count.error) {
    const e = list.error ?? count.error!;
    // Code ahead of migration 0076 → an empty inbox, not an error.
    if (["42P01", "PGRST205", "42703", "PGRST204"].includes(e.code ?? "")) return NextResponse.json(EMPTY(true), { headers: noStore });
    console.error("[notifications] read failed:", e.message);
    return NextResponse.json({ error: "Could not load notifications." }, { status: 500 });
  }

  const notifications: NotificationItem[] = (list.data ?? []).map(r => ({
    id: r.id as string,
    kind: r.kind as NotificationItem["kind"],
    title: r.title as string,
    body: (r.body as string | null) ?? null,
    link: isSafeLink(r.link) ? r.link : null,
    created_at: r.created_at as string,
    read_at: (r.read_at as string | null) ?? null,
  }));
  const body: NotificationsResponse = { enabled: true, notifications, unread: count.count ?? 0 };
  return NextResponse.json(body, { headers: noStore });
}
