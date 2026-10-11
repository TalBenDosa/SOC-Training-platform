"use client";
/**
 * The Topbar notification bell (migration 0076). Fully functional by design —
 * the old decorative bell was removed precisely because it did nothing:
 *
 *  - reads the shared notifications store (one poll for the bell AND the
 *    plan-announcement popup): GET /api/notifications every 60 s while the tab is visible, and
 *    again (debounced to ONE request) when the window regains focus / the tab
 *    becomes visible; stops polling entirely once the server says the feature
 *    isn't available to this user (`enabled: false`, e.g. no organisation);
 *  - the panel is a dialog: focus moves into it on open, Escape closes it
 *    (focus returns to the bell), and it closes when focus leaves it;
 *  - the badge shows the real unread count;
 *  - the dropdown lists the latest notifications (title, body, relative time,
 *    unread dot); clicking one marks it read and opens its link;
 *  - "Mark all read" clears the badge.
 *
 * Hidden entirely for guests and for users without an organisation (the API
 * answers `enabled: false`), so it never shows as an empty control.
 */
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, CheckCheck, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { isSafeLink, timeAgo, type NotificationItem } from "@/lib/notifications/types";
import { useNotifications } from "@/lib/notifications/useNotifications";

// Every page renders its own Topbar, so the bell remounts on navigation. The
// inbox lives in the shared store (lib/notifications/store.ts) — the same one
// the plan-announcement popup reads — so remounting reuses the last response
// and there is only ever ONE poll, whichever consumers are mounted.

export function NotificationBell() {
  const router = useRouter();
  const { userId, enabled, items, unread, loaded, error, refresh, markRead, markAllRead } = useNotifications();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  // Dialog behaviour: focus into the panel on open; Escape / outside click close.
  useEffect(() => {
    if (!open) return;
    panelRef.current?.focus();
    const onDown = (e: MouseEvent) => { if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); buttonRef.current?.focus(); } };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);

  /** Close when keyboard focus moves outside the bell + panel. */
  function onBlurWithin(e: React.FocusEvent<HTMLDivElement>) {
    if (!open) return;
    const next = e.relatedTarget as Node | null;
    if (next && rootRef.current?.contains(next)) return;
    // relatedTarget is null when focus goes to the page body / another window.
    setOpen(false);
  }

  function openItem(n: NotificationItem) {
    // Optimistic: the badge drops at once; the POST persists it.
    if (!n.read_at) void markRead([n.id]);
    setOpen(false);
    if (isSafeLink(n.link)) router.push(n.link);
  }

  function markAll() {
    if (unread === 0) return;
    void markAllRead();
  }

  if (!userId || !enabled) return null;

  const badge = unread > 9 ? "9+" : String(unread);
  return (
    <div ref={rootRef} className="relative" onBlur={onBlurWithin}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => { setOpen(v => !v); if (!open) void refresh(); }}
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? "notification-panel" : undefined}
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
          ref={panelRef}
          id="notification-panel"
          role="dialog"
          aria-label="Notifications"
          tabIndex={-1}
          className="absolute right-0 top-full z-50 outline-none mt-2 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-2xl"
        >
          <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
            <p className="text-xs font-bold uppercase tracking-wider text-slate-300">Notifications</p>
            <button
              type="button"
              onClick={markAll}
              disabled={unread === 0}
              className="inline-flex items-center gap-1 text-[11px] text-cyber-300 transition hover:text-white disabled:cursor-default disabled:text-slate-500"
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
