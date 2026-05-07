"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { Logo } from "../Logo";
import {
  LayoutDashboard, Siren, ShieldCheck, Crosshair, FileSearch,
  GraduationCap, Trophy, Bot, Cog, Activity, Database, Network,
  Sparkles, BookOpen,
} from "lucide-react";

const NAV: { section: string; items: { href: string; label: string; icon: any; soon?: boolean }[] }[] = [
  {
    section: "Operations",
    items: [
      { href: "/dashboard",      label: "SOC Dashboard",   icon: LayoutDashboard },
      { href: "/alerts",         label: "Alerts / SIEM",   icon: Siren },
      { href: "/investigations", label: "Investigations",  icon: FileSearch },
      { href: "/hunts",          label: "Threat Hunting",  icon: Crosshair },
      { href: "/detections",     label: "Detection Lab",   icon: ShieldCheck },
      { href: "/telemetry",      label: "Live Telemetry",  icon: Activity },
    ],
  },
  {
    section: "Training",
    items: [
      { href: "/learn",       label: "Learning Paths", icon: GraduationCap },
      { href: "/scenarios",   label: "Attack Scenarios", icon: Sparkles },
      { href: "/playbooks",   label: "IR Playbooks",   icon: BookOpen },
      { href: "/leaderboard", label: "Leaderboard",    icon: Trophy },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { href: "/mitre",      label: "MITRE ATT&CK",   icon: Network },
      { href: "/iocs",       label: "IOC Database",   icon: Database },
      { href: "/ai",         label: "AI Assistant",   icon: Bot },
    ],
  },
  {
    section: "System",
    items: [
      { href: "/admin",   label: "Admin Panel", icon: Cog },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="hidden md:flex md:w-64 lg:w-72 flex-col border-r border-border bg-bg-elevated/40 backdrop-blur sticky top-0 h-screen">
      <div className="px-5 py-5 border-b border-border">
        <Link href="/" className="block">
          <Logo />
        </Link>
        <div className="mt-3 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-neon-green">SOC ONLINE</span>
          <span className="ml-auto text-[10px] font-mono text-slate-500">v1.0.0</span>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {NAV.map(group => (
          <div key={group.section}>
            <p className="px-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">
              {group.section}
            </p>
            <ul className="mt-2 space-y-0.5">
              {group.items.map(it => {
                const active = pathname === it.href || pathname?.startsWith(it.href + "/");
                const Icon = it.icon;
                return (
                  <li key={it.href}>
                    <Link href={it.href}
                      className={cn(
                        "group flex items-center gap-3 rounded-md px-2.5 py-2 text-sm",
                        active
                          ? "bg-cyber-500/10 text-cyber-200 border border-cyber-500/30"
                          : "text-slate-400 hover:bg-bg-hover hover:text-slate-100 border border-transparent"
                      )}>
                      <Icon className={cn("h-4 w-4 shrink-0", active && "text-cyber-300")} />
                      <span className="truncate">{it.label}</span>
                      {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyber-400 shadow-glow" />}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="m-3 rounded-lg border border-cyber-500/30 bg-gradient-to-br from-cyber-500/10 to-neon-purple/10 p-3">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Tip</p>
        <p className="mt-1 text-xs text-slate-300">
          Press <kbd className="rounded bg-bg px-1 font-mono text-[10px] text-cyber-200 border border-border">⌘K</kbd> to open the SOC command palette.
        </p>
      </div>
    </aside>
  );
}
