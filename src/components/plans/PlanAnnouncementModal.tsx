"use client";
/**
 * The plan-announcement popup. Learners are NOT emailed when a manager assigns
 * or changes a learning plan (owner decision) — they hear about it here, plus
 * the Topbar bell.
 *
 * Mounted once in the (app) layout, so it never appears on the auth /
 * onboarding pages (the (auth) group and /welcome are outside that layout).
 * It reads the SAME notifications store as the bell (one poll between them) and
 * shows nothing for guests, for users without an organisation (the API answers
 * `enabled: false`), or for anyone without an unread plan notification — staff
 * normally never get one (the acting manager is skipped), but a manager who is
 * themselves a plan recipient sees it like anyone else.
 *
 * When there IS one: the newest unread plan notice is announced with the live
 * plan (GET /api/org/assignments?view=mine, matched by assignment_id — fetched
 * only at that moment), falling back to the notification's own text if the
 * plan is gone. "Open my plan" marks every unread plan notice read and opens
 * the plan; "Later" (or Escape) just hides it for this browser session — the
 * notices stay unread in the bell. A notice is never announced twice in one
 * session (sessionStorage, fail-safe). It waits while another modal dialog or
 * the dashboard's onboarding (briefing / tour) is on screen.
 *
 * Accessibility: role="dialog" + aria-modal, labelled by its heading and
 * described by the plan summary; focus moves in (to the primary action), Tab is
 * trapped inside, focus returns to where it was on close; page scroll is locked
 * while open; motion follows the OS "reduce motion" setting (MotionProvider +
 * motion-reduce utilities).
 */
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { CalendarClock, ClipboardList, User, X } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { StatusIcon, KIND_LABEL } from "@/components/plans/PlanItemsEditor";
import { cn } from "@/lib/utils";
import { useNotifications } from "@/lib/notifications/useNotifications";
import {
  buildAnnouncementView, readShown, rememberShown, selectAnnouncement, unreadPlanNoticeIds,
  type AnnouncementGroup, type AnnouncementView,
} from "@/lib/notifications/planAnnouncement";
import { formatDueDate, type LearnerPlan } from "@/lib/plans/types";

const RECHECK_MS = 3_000;

function session(): Storage | null {
  try { return typeof window === "undefined" ? null : window.sessionStorage; } catch { return null; }
}

/** Another modal dialog, or the dashboard's briefing / tour, is on screen. */
function somethingElseOnScreen(): boolean {
  if (typeof document === "undefined") return true;
  return Boolean(document.querySelector('[aria-modal="true"]:not([data-plan-announcement]), [data-blocks-announcements]'));
}

const FOCUSABLE = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

const PRIORITY_CHIP: Record<number, string> = {
  1: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  2: "border-cyber-500/30 bg-cyber-500/10 text-cyber-300",
  3: "border-slate-600/60 bg-slate-700/30 text-slate-400",
};

function isPastDue(iso: string | null): boolean {
  if (!iso) return false;
  const t = Date.parse(iso);
  return !Number.isNaN(t) && t < Date.now();
}

export function PlanAnnouncementModal() {
  const router = useRouter();
  const pathname = usePathname();
  const { userId, enabled, items, markRead } = useNotifications();

  // The session "already shown" set, read after mount (sessionStorage is client-only).
  const [shown, setShown] = useState<Set<string> | null>(null);
  const shownRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const s = readShown(session());
    shownRef.current = s;
    setShown(s);
  }, []);

  const [current, setCurrent] = useState<{ group: AnnouncementGroup; view: AnnouncementView } | null>(null);
  const [recheck, setRecheck] = useState(0);

  const candidate = useMemo(
    () => (shown && userId && enabled ? selectAnnouncement(items, shown) : null),
    [shown, userId, enabled, items],
  );
  const candidateRef = useRef(candidate);
  candidateRef.current = candidate;
  // Keyed by ids, so a routine poll returning the same inbox doesn't restart the plan fetch.
  const candidateKey = candidate ? candidate.ids.join(",") : "";

  // Signed out / lost the org mid-session → close.
  useEffect(() => { if (!userId || !enabled) setCurrent(null); }, [userId, enabled]);

  // Announce the newest pending notice (after loading its plan).
  useEffect(() => {
    if (!candidateKey || current) return;
    if (somethingElseOnScreen()) {
      const t = setTimeout(() => setRecheck(n => n + 1), RECHECK_MS);
      return () => clearTimeout(t);
    }
    const ctrl = new AbortController();
    let alive = true;
    (async () => {
      let plans: LearnerPlan[] | null = null;
      try {
        const r = await fetch("/api/org/assignments?view=mine", { cache: "no-store", signal: ctrl.signal });
        if (r.ok) {
          const d = await r.json();
          plans = Array.isArray(d?.plans) ? d.plans : null;
        }
      } catch { /* network / aborted → fall back to the notification text */ }
      const group = candidateRef.current;
      if (!alive || !group) return;
      if (somethingElseOnScreen()) { setRecheck(n => n + 1); return; }
      const next = rememberShown(session(), group.ids, shownRef.current);
      shownRef.current = next;
      setShown(next);
      setCurrent({ group, view: buildAnnouncementView(group.notice, plans) });
    })();
    return () => { alive = false; ctrl.abort(); };
  }, [candidateKey, current, recheck, pathname]);

  const close = useCallback(() => setCurrent(null), []);

  /** "Open my plan" (or an item link): everything plan-related is now seen. */
  const acknowledge = useCallback(() => {
    if (!current) return;
    const ids = [...new Set([...current.group.ids, ...unreadPlanNoticeIds(items)])];
    const next = rememberShown(session(), ids, shownRef.current);
    shownRef.current = next;
    setShown(next);
    void markRead(ids);
    setCurrent(null);
  }, [current, items, markRead]);

  const openPlan = useCallback(() => {
    if (!current) return;
    const to = current.view.link;
    acknowledge();
    router.push(to);
  }, [current, acknowledge, router]);

  if (!current) return null;
  return createPortal(
    <AnnouncementDialog view={current.view} more={current.group.more} onLater={close} onOpen={openPlan} onItem={acknowledge} />,
    document.body,
  );
}

function AnnouncementDialog({
  view, more, onLater, onOpen, onItem,
}: {
  view: AnnouncementView;
  more: number;
  onLater: () => void;
  onOpen: () => void;
  onItem: () => void;
}) {
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const primaryRef = useRef<HTMLButtonElement>(null);

  // Focus in, trap Tab, Escape = Later, lock page scroll; restore everything on close.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    primaryRef.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); onLater(); return; }
      if (e.key !== "Tab" || !dialogRef.current) return;
      const nodes = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(n => n.offsetParent !== null || n === document.activeElement);
      if (nodes.length === 0) { e.preventDefault(); dialogRef.current.focus(); return; }
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const active = document.activeElement as HTMLElement | null;
      const inside = active ? dialogRef.current.contains(active) : false;
      if (e.shiftKey && (active === first || !inside)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (active === last || !inside)) { e.preventDefault(); first.focus(); }
    };
    // Focus that escapes by any other route (e.g. a click on the backdrop) is pulled back.
    const onFocusIn = (e: FocusEvent) => {
      if (dialogRef.current && e.target instanceof Node && !dialogRef.current.contains(e.target)) primaryRef.current?.focus();
    };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("focusin", onFocusIn);
      document.body.style.overflow = overflow;
      if (previous && document.contains(previous)) previous.focus();
    };
  }, [onLater]);

  const overdue = isPastDue(view.dueAt);

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center overflow-y-auto bg-black/75 p-4 backdrop-blur-sm">
      <motion.div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        data-plan-announcement
        tabIndex={-1}
        initial={{ opacity: 0, y: 12, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", damping: 24, stiffness: 260 }}
        className="relative my-auto flex max-h-[calc(100dvh-2rem)] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-neon-purple/30 bg-bg-elevated shadow-2xl shadow-black/60 outline-none motion-reduce:transition-none"
      >
        <div className="h-[3px] w-full shrink-0 bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-amber" aria-hidden />

        <div className="flex items-start gap-3 px-5 pt-5 sm:px-6">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-neon-purple/30 bg-neon-purple/10" aria-hidden>
            <ClipboardList className="h-5 w-5 text-neon-purple" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyber-400">Learning plan</p>
            <h2 id={titleId} className="text-[17px] font-bold leading-tight text-white">{view.heading}</h2>
          </div>
          <button
            type="button"
            onClick={onLater}
            aria-label="Close — remind me later"
            className="shrink-0 rounded-md border border-border p-1.5 text-slate-400 transition hover:border-cyber-500/40 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyber-400/50"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 pb-2 pt-4 sm:px-6">
          <div id={descId} className="rounded-lg border border-border bg-bg p-3.5">
            <p className="break-words text-sm font-semibold text-white">{view.title}</p>

            {(view.via || view.priorityLabel || view.dueAt) && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {view.via === "Personal" ? (
                  <span className="inline-flex items-center gap-1 rounded border border-neon-purple/40 bg-neon-purple/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-neon-purple">
                    <User className="h-2.5 w-2.5" aria-hidden /> Personal
                  </span>
                ) : view.via ? (
                  <span className="max-w-full truncate rounded border border-border bg-bg-elevated px-1.5 py-0.5 text-[10px] text-slate-300">
                    <span className="text-slate-500">via </span>{view.via}
                  </span>
                ) : null}
                {view.priority && view.priorityLabel && (
                  <span className={cn("rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider", PRIORITY_CHIP[view.priority])}>
                    {view.priorityLabel} priority
                  </span>
                )}
                {view.dueAt && (
                  <span className={cn("inline-flex items-center gap-1 text-[11px]", overdue ? "font-semibold text-severity-high" : "text-slate-400")}>
                    <CalendarClock className="h-3 w-3" aria-hidden />
                    {overdue ? "Overdue — " : "Due "}{formatDueDate(view.dueAt)}
                  </span>
                )}
              </div>
            )}

            {view.fallback && view.fallbackBody && (
              <p className="mt-2 break-words text-[12px] leading-relaxed text-slate-300">{view.fallbackBody}</p>
            )}

            {view.instructions && (
              <div className="mt-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">From your manager</p>
                <p className="mt-1 max-h-32 overflow-y-auto whitespace-pre-line break-words text-[12px] leading-relaxed text-slate-300">{view.instructions}</p>
              </div>
            )}
          </div>

          {view.items.length > 0 && (
            <div className="mt-3">
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">In this plan</p>
              <ul className="space-y-1.5">
                {view.items.map(it => {
                  const done = it.status === "done";
                  return (
                    <li key={it.key}>
                      <Link
                        href={it.href}
                        onClick={onItem}
                        className={cn(
                          "group flex items-center gap-2 rounded-md border px-2.5 py-2 transition focus:outline-none focus:ring-2 focus:ring-cyber-400/50",
                          done ? "border-neon-green/20 bg-neon-green/5" : "border-border bg-bg hover:border-cyber-500/50",
                        )}
                      >
                        <StatusIcon status={it.status} />
                        <span className={cn("min-w-0 flex-1 truncate text-[12px]", done ? "text-slate-400 line-through decoration-slate-600" : "text-slate-100 group-hover:text-white")}>
                          {it.title}
                        </span>
                        <span className="shrink-0 text-[9px] uppercase tracking-wider text-slate-500">{KIND_LABEL[it.kind] ?? it.kind}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
              {view.moreItems > 0 && (
                <p className="mt-1.5 text-[11px] text-slate-500">+{view.moreItems} more in this plan</p>
              )}
            </div>
          )}

          {more > 0 && (
            <p className="mt-3 text-[11px] text-cyber-300">
              and {more} more plan update{more === 1 ? "" : "s"} — all in your plan and the bell.
            </p>
          )}
        </div>

        <div className="flex shrink-0 flex-col-reverse gap-2 border-t border-border/60 bg-bg/40 px-5 py-4 sm:flex-row sm:justify-end sm:px-6">
          <Button type="button" variant="secondary" onClick={onLater}>Later</Button>
          <Button ref={primaryRef} type="button" onClick={onOpen}>Open my plan</Button>
        </div>
      </motion.div>
    </div>
  );
}
