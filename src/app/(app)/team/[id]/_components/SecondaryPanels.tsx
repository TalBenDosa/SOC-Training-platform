"use client";
import { useState, useMemo } from "react";
import { Card } from "@/components/ui/Card";
import { ChevronDown } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { ActivityLog } from "./ActivityLog";
import { WarRoom } from "./WarRoom";

// ── G-03: secondary shared panels folded into tabs so the role panel stays dominant ──
// (G-13 adds the war-room chat as a second tab. Team intel moved OUT of this fold to
// its own always-visible card — TI playtest: new intel sat unseen in a closed tab.)
export function SecondaryPanels({ events, activity, me, nameOf, act }: { events: Ev[]; activity: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"activity" | "chat">("activity");
  const chatCount = useMemo(() => events.filter(e => e.type === "message.sent").length, [events]);
  return (
    <Card>
      <button onClick={() => setOpen(o => !o)} className="flex w-full items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <span className="text-sm font-bold text-white">Team context</span>
        <span className="ml-auto text-[10px] text-slate-500">{activity.length} actions · {chatCount} chat</span>
      </button>
      {open && (
        <div className="mt-3">
          <div className="mb-2 flex gap-1">
            {(["activity", "chat"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`rounded px-2 py-0.5 text-[11px] font-semibold capitalize transition ${tab === t ? "border border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>{t === "chat" ? "War room" : t}</button>
            ))}
          </div>
          {tab === "activity" ? <ActivityLog activity={activity} nameOf={nameOf} />
            : <WarRoom events={events} me={me} nameOf={nameOf} act={act} />}
        </div>
      )}
    </Card>
  );
}
