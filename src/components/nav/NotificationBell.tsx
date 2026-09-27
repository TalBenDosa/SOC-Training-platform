"use client";
/**
 * The Topbar notification bell (migration 0076). Fully functional by design —
 * the old decorative bell was removed precisely because it did nothing:
 *
 *  - polls GET /api/notifications every 60 s while the tab is visible, and
 *    again whenever the window regains focus (no realtime needed);
 *  - the badge shows the real unread count;
 *  - the dropdown lists the latest notifications (title, body, relative time,
 *    unread dot); clicking one marks it read and opens its link;
 *  - "Mark all read" clears the badge.
 *
 * Hidden entirely for guests and for users without an organisation (the API
 * answers `enabled: false`), so it never shows as an empty control.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, CheckCheck, Loader2 } from "lucide-react";
import { useAuth } from "@/lib/auth/AuthContext";
import { cn } from "@/lib/utils";
import { isSafeLink, timeAgo, type NotificationItem, type NotificationsResponse } from "@/lib/notifications/types";

const POLL_MS = 60_000;
// Every page renders its own Topbar, so the bell remounts on navigation. The
// last response is kept for a few seconds so clicking around doesn't refetch
// on every page; the poll and focus refreshes always go to the server.
const REUSE_MS = 15_000;
let last: { userId: string; at: number; data: NotificationsResponse } | null = null;

export function NotificationBell() {
  const { user } = useAuth();
  const router = useRouter();
  const cached = user && last?.userId === user.id ? last.data : null;
  const [enabled, setEnabled] = useState(Boolean(cached?.enabled));
  const [items, setItems] = useState<NotificationItem[]>(cached?.notifications ?? []);
  const [unread, setUnread] = useState(cached?.unread ?? 0);
  const [open, setOpen] = useState(false);
  const [loaded, setLoaded] = useState(Boolean(cached));
  const [error, setError] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const userIdRef = useRef<string | null>(user?.id ?? null);
  userIdRef.current = user?.id ?? null;

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/notifications", { cache: "no-store" });
      if (!res.ok) { setError(true); return; }
      const d: NotificationsResponse = await res.json();
      if (userIdRef.current) last = { userId: userIdRef.current, at: Date.now(), data: d };
      setEnabled(Boolean(d.enabled));
      setItems(Array.isArray(d.notifications) ? d.notifications : []);
      setUnread(typeof d.unread === "number" ? d.unread : 0);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoaded(true);
    }
  }, []);

  // Poll while visible + refresh on focus / when the tab becomes visible again.
  useEffect(() => {
    if (!user) { setEnabled(false); setItems([]); setUnread(0); last = null; return; }
    if (!(last && last.userId === user.id && Date.now() - last.at < REUSE_MS)) refresh();
    const tick = () => { if (document.visibilityState === "visible") refresh(); };
    const id = window.setInterval(tick, POLL_MS);
    window.addEventListener("focus", tick);
    document.addEventListener("visibilitychange", tick);
    return () => {
      window.clearInterval(id);
      window.removeEventListener("focus", tick);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [user, refresh]);

  // Close on outside click / Escape.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); buttonRef.current?.focus(); } };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);

  async function markRead(body: { ids: string[] } | { all: true }) {
    try {
      await fetch("/api/notifications/read", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
    } catch { /* the next poll reconciles */ }
  }

  function openItem(n: NotificationItem) {
    if (!n.read_at) {
      // Optimistic: the badge drops at once; the POST persists it.
      const now = new Date().toISOString();
      setItems(list => list.map(x => (x.id === n.id ? { ...x, read_at: now } : x)));
      setUnread(u => Math.max(0, u - 1));
      last = null;
      void markRead({ ids: [n.id] });
    }
    setOpen(false);
    if (isSafeLink(n.link)) router.push(n.link);
  }

  function markAll() {
    if (unread === 0) return;
    const now = new Date().toISOString();
    setItems(list => list.map(x => (x.read_at ? x : { ...x, read_at: now })));
    setUnread(0);
    last = null;
    void markRead({ all: true }).then(refresh);
  }

  if (!user || !enabled) return null;

  const badge = unread > 9 ? "9+" : String(unread);
  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => { setOpen(v => !v); if (!open) refresh(); }}
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-haspopup="true"
        aria-expanded={open}
        className={cn(
          "relative flex items-center rounded-md border px-2 py-1.5 transition-colors",
          open ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-200" : "border-border bg-bg-elevated text-slate-300 hover:border-cyber-500/40 hover:text-white",
        )}
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute -right-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-neon-purple px-1 text-[9px] font-bold leading-none text-white ring-2 ring-bg">
            {badge}
          </span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Notifications"
          className="absolute right-0 top-full z-50 mt-2 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-2xl"
        >
          <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
            <p className="text-xs font-bold uppercase tracking-wider text-slate-300">Notifications</p>
            <button
              type="button"
              onClick={markAll}
              disabled={unread === 0}
              className="inline-flex items-center gap-1 text-[11px] text-cyber-300 transition hover:text-white disabled:cursor-default disabled:text-slate-600"
            >
              <CheckCheck className="h-3.5 w-3.5" /> Mark all read
            </button>
          </div>

          <div className="max-h-[min(24rem,70vh)] overflow-y-auto">
            {!loaded ? (
              <p className="flex items-center gap-2 px-3 py-6 text-xs text-slate-400"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</p>
            ) : error && items.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-slate-400">Couldn&apos;t load notifications. They&apos;ll refresh shortly.</p>
            ) : items.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-slate-400">You&apos;re all caught up — nothing new.</p>
            ) : (
              <ul className="divide-y divide-border/60">
                {items.map(n => (
                  <li key={n.id}>
                    <button
                      type="button"
                      onClick={() => openItem(n)}
                      className={cn(
                        "flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition hover:bg-white/5",
                        !n.read_at && "bg-neon-purple/5",
                      )}
                    >
                      <span
                        aria-hidden
                        className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", n.read_at ? "bg-transparent" : "bg-neon-purple")}
                      />
                      <span className="min-w-0 flex-1">
                        <span className={cn("block text-[12px] leading-snug", n.read_at ? "text-slate-300" : "font-semibold text-white")}>
                          {n.title}
                          {!n.read_at && <span className="sr-only"> (unread)</span>}
                        </span>
                        {n.body && <span className="mt-0.5 block text-[11px] leading-snug text-slate-400 line-clamp-2">{n.body}</span>}
                        <span className="mt-1 block text-[10px] text-slate-500">{timeAgo(n.created_at)}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
