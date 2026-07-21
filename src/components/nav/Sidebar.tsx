"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Logo } from "../Logo";
import { useAuth } from "@/lib/auth/AuthContext";
import {
  LayoutDashboard, BookOpen, TrendingUp, Target, ClipboardList, Wrench, DoorOpen, Menu, X, LogOut, LogIn,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/rooms",     label: "Learning Rooms", icon: DoorOpen        },
  { href: "/dashboard", label: "SOC Dashboard",  icon: LayoutDashboard },
  { href: "/learn",     label: "Learning Path",  icon: BookOpen        },
  { href: "/progress",  label: "Progress",       icon: TrendingUp      },
  { href: "/scenarios", label: "Scenarios",      icon: Target          },
  { href: "/quizzes",   label: "Quizzes",        icon: ClipboardList   },
];

// Content-authoring tools (log validator, scenario/quiz generator) — deliberately
// NOT in the primary learner nav. It's a build tool for the content team, not
// something a student is meant to have, so it's a small de-emphasized footer
// link rather than sitting next to Rooms/Dashboard/Progress with equal weight.
const DEV_TOOLS_ITEM = { href: "/admin", label: "Content Tools", icon: Wrench };

// Shared nav list — rendered in both the desktop rail and the mobile drawer.
function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { user, authEnabled, signOut } = useAuth();
  return (
    <>
      <nav className="flex-1 px-3 py-2">
        <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
          Navigation
        </p>
        <ul className="space-y-0.5">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || pathname?.startsWith(href + "/");
            return (
              <li key={href}>
                <Link
                  href={href}
                  onClick={onNavigate}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                    active
                      ? "bg-[#0e2a2e] text-cyber-300"
                      : "text-slate-300 hover:bg-white/5 hover:text-white"
                  )}
                >
                  <Icon className="h-[18px] w-[18px] shrink-0" />
                  <span>{label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* User — real auth state. Guest (no account / Supabase not configured)
          keeps working exactly as before: progress just lives on this device. */}
      <div className="border-t border-border px-3 py-4">
        <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
          {user ? "Account" : "Guest"}
        </p>
        {user ? (
          <div className="flex items-center gap-2 rounded-md px-3 py-2">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyber-500/40 bg-cyber-500/10 text-[11px] font-bold text-cyber-300">
              {(user.email ?? "?")[0].toUpperCase()}
            </span>
            <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-100" title={user.email ?? undefined}>
              {user.email}
            </span>
            <button
              onClick={() => { signOut(); onNavigate?.(); }}
              aria-label="Sign out"
              className="shrink-0 rounded p-1.5 text-slate-500 hover:bg-white/5 hover:text-slate-200 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : authEnabled ? (
          <Link
            href="/login"
            onClick={onNavigate}
            className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-cyber-300 hover:bg-white/5 transition-colors"
          >
            <LogIn className="h-4 w-4" />
            Sign in
          </Link>
        ) : (
          <div className="flex items-center gap-3 rounded-md px-3 py-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full border border-border bg-bg-elevated text-[11px] font-bold text-slate-400">
              G
            </span>
            <span className="text-sm font-medium text-slate-300">Guest — progress saved on this device</span>
          </div>
        )}
      </div>

      {/* Content-authoring tools — small, visually de-emphasized, separate from
          the learner nav above so it doesn't read as part of the student's
          own toolkit (see PLATFORM_REVIEW.md P2.2). */}
      <div className="border-t border-border px-3 py-2">
        <Link
          href={DEV_TOOLS_ITEM.href}
          onClick={onNavigate}
          className="flex items-center gap-2.5 rounded-md px-3 py-1.5 text-xs text-slate-600 hover:bg-white/5 hover:text-slate-400 transition-colors"
        >
          <DEV_TOOLS_ITEM.icon className="h-3.5 w-3.5 shrink-0" />
          <span>{DEV_TOOLS_ITEM.label}</span>
        </Link>
      </div>
    </>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Close the mobile drawer whenever the route changes (belt-and-suspenders
  // alongside the per-link onNavigate handler).
  useEffect(() => { setDrawerOpen(false); }, [pathname]);

  return (
    <>
      {/* ── Desktop rail (unchanged) ─────────────────────────────────── */}
      <aside className="hidden md:flex md:w-60 flex-col border-r border-border bg-[#0d1520] sticky top-0 h-screen">
        <div className="px-5 py-5">
          <Link href="/" className="block">
            <Logo />
          </Link>
        </div>
        <NavList />
      </aside>

      {/* ── Mobile: floating hamburger + slide-in drawer ─────────────── */}
      <button
        onClick={() => setDrawerOpen(true)}
        aria-label="Open navigation menu"
        className="md:hidden fixed top-3 left-3 z-40 flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-[#0d1520]/95 text-slate-200 shadow-lg backdrop-blur"
      >
        <Menu className="h-5 w-5" />
      </button>

      {drawerOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setDrawerOpen(false)}
            aria-hidden="true"
          />
          {/* Drawer panel */}
          <aside className="relative flex w-64 max-w-[80vw] flex-col border-r border-border bg-[#0d1520] h-full">
            <div className="flex items-center justify-between px-5 py-5">
              <Link href="/" className="block" onClick={() => setDrawerOpen(false)}>
                <Logo />
              </Link>
              <button
                onClick={() => setDrawerOpen(false)}
                aria-label="Close navigation menu"
                className="rounded p-1 text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <NavList onNavigate={() => setDrawerOpen(false)} />
          </aside>
        </div>
      )}
    </>
  );
}
