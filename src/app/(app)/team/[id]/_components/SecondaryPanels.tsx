"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { ChevronDown } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { ActivityLog } from "./ActivityLog";

// ── G-03: the team's action log, folded so the role panel stays dominant ──
// (The war-room chat used to be a second tab here; it is now its own always-visible
// card next to the feed — WarRoom. Team intel has its own card too.)
export function SecondaryPanels({ activity, nameOf }: { activity: Ev[]; nameOf: (u: string | null) => string }) {
  const [open, setOpen] = useState(false);
  return (
    <Card>
      <button onClick={() => setOpen(o => !o)} aria-expanded={open} className="flex w-full items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <span className="text-sm font-bold text-white">Team activity</span>
        <span className="ml-auto text-[10px] text-slate-500">{activity.length} actions</span>
      </button>
      {open && <div className="mt-3"><ActivityLog activity={activity} nameOf={nameOf} /></div>}
    </Card>
  );
}
