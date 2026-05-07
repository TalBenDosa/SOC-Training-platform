import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, format } from "date-fns";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function timeAgo(d: string | Date): string {
  return formatDistanceToNow(new Date(d), { addSuffix: true });
}

export function formatTs(d: string | Date, pattern = "yyyy-MM-dd HH:mm:ss"): string {
  return format(new Date(d), pattern);
}

export function severityColor(s: string): string {
  switch (s) {
    case "critical": return "text-severity-critical bg-severity-critical/10 border-severity-critical/30";
    case "high":     return "text-severity-high bg-severity-high/10 border-severity-high/30";
    case "medium":   return "text-severity-medium bg-severity-medium/10 border-severity-medium/30";
    case "low":      return "text-severity-low bg-severity-low/10 border-severity-low/30";
    default:         return "text-severity-info bg-severity-info/10 border-severity-info/30";
  }
}

export function severityDot(s: string): string {
  switch (s) {
    case "critical": return "bg-severity-critical shadow-glow-red";
    case "high":     return "bg-severity-high";
    case "medium":   return "bg-severity-medium";
    case "low":      return "bg-severity-low";
    default:         return "bg-severity-info";
  }
}

export function statusColor(s: string): string {
  switch (s) {
    case "new":            return "text-cyber-300 bg-cyber-500/10 border-cyber-500/30";
    case "triaging":       return "text-neon-amber bg-neon-amber/10 border-neon-amber/30";
    case "investigating":  return "text-neon-blue bg-neon-blue/10 border-neon-blue/30";
    case "contained":      return "text-neon-green bg-neon-green/10 border-neon-green/30";
    case "resolved":       return "text-neon-green bg-neon-green/10 border-neon-green/30";
    case "false_positive": return "text-slate-400 bg-slate-500/10 border-slate-500/30";
    case "escalated":      return "text-severity-critical bg-severity-critical/10 border-severity-critical/30";
    default:               return "text-slate-300 bg-slate-500/10 border-slate-500/30";
  }
}

export const fmtBytes = (n?: number) => {
  if (!n && n !== 0) return "—";
  const u = ["B","KB","MB","GB","TB"];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
};

export const truncate = (s: string, n = 64) => s.length > n ? s.slice(0, n - 1) + "…" : s;

export const xpForLevel = (lvl: number) => lvl * 1000;
export const levelFromXp = (xp: number) => Math.min(99, Math.floor(xp / 1000) + 1);
export const rankFromXp = (xp: number): string => {
  if (xp <  1000) return "Recruit";
  if (xp <  3000) return "Tier 1 Analyst";
  if (xp <  7000) return "Tier 2 Analyst";
  if (xp < 15000) return "Tier 3 Analyst";
  if (xp < 30000) return "Threat Hunter";
  if (xp < 60000) return "IR Lead";
  return "SOC Architect";
};
