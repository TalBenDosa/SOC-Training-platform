"use client";
/**
 * Room access: open (every Learning Room available) or locked (a room unlocks after
 * its prerequisite rooms are passed). Open is the default; the college admin decides
 * (organizations.rooms_locked, 0102). Either way the rooms page lists rooms by level
 * and recommends the next room in prerequisite order.
 *
 * RoomAccessChoice is the presentational switch, shared with the super-admin org page;
 * RoomAccessPanel is the /manage card that reads and writes /api/org/settings.
 */
import { useEffect, useState } from "react";
import { safeFetch, NETWORK_ERROR } from "@/lib/http/safeFetch";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import { DoorOpen, Lock, Loader2 } from "lucide-react";

const OPTIONS = [
  {
    locked: false, icon: DoorOpen, title: "Open",
    body: "Every room is available from day one. Students still see rooms by level and a recommended next room.",
  },
  {
    locked: true, icon: Lock, title: "Locked by prerequisites",
    body: "A room opens only after its prerequisite rooms are passed, so students follow the order step by step.",
  },
] as const;

export function RoomAccessChoice({ locked, disabled, busy, onChange, name = "room-access" }: {
  locked: boolean; disabled?: boolean; busy?: boolean; onChange: (locked: boolean) => void; name?: string;
}) {
  return (
    <div role="radiogroup" aria-label="Room access" className="grid gap-2 sm:grid-cols-2">
      {OPTIONS.map(o => {
        const on = o.locked === locked;
        const Icon = o.icon;
        return (
          <label key={o.title}
            className={cn(
              "flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition-colors",
              on ? "border-cyber-500/60 bg-cyber-500/10" : "border-border hover:border-cyber-500/30",
              (disabled || busy) && "cursor-not-allowed opacity-60",
            )}>
            <input type="radio" name={name} className="mt-1" checked={on} disabled={disabled || busy}
              onChange={() => { if (!on) onChange(o.locked); }} />
            <span className="min-w-0">
              <span className="flex items-center gap-1.5 text-sm font-semibold text-white">
                <Icon className={cn("h-4 w-4", on ? "text-cyber-300" : "text-slate-400")} /> {o.title}
                {on && busy && <Loader2 className="h-3.5 w-3.5 animate-spin text-slate-400" />}
              </span>
              <span className="mt-0.5 block text-[11px] leading-relaxed text-slate-400">{o.body}</span>
            </span>
          </label>
        );
      })}
    </div>
  );
}

export function RoomAccessPanel() {
  const [state, setState] = useState<{ rooms_locked: boolean; forced_open?: boolean; available: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    safeFetch("/api/org/settings").then(async r => {
      if (r?.ok) setState(await r.json());
      else setMsg({ ok: false, text: "Couldn't load the room access setting. Reload the page to try again." });
    });
  }, []);

  async function change(locked: boolean) {
    setBusy(true); setMsg(null);
    const res = await safeFetch("/api/org/settings", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rooms_locked: locked }),
    });
    setBusy(false);
    if (!res) { setMsg({ ok: false, text: NETWORK_ERROR }); return; }
    if (!res.ok) { setMsg({ ok: false, text: (await res.json().catch(() => ({})))?.error ?? "Couldn't save the setting." }); return; }
    setState(s => s ? { ...s, rooms_locked: locked } : s);
    setMsg({ ok: true, text: locked ? "Rooms now open in prerequisite order." : "Every room is now open to your students." });
  }

  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white"><DoorOpen className="h-4 w-4 text-cyber-300" /> Room access</h2>
      <p className="mb-3 mt-1 text-[11px] text-slate-400">Choose whether your students can open any Learning Room or must pass each room&apos;s prerequisites first.</p>
      {!state ? (
        msg ? null : <p className="flex items-center gap-2 text-xs text-slate-400"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</p>
      ) : (
        <RoomAccessChoice locked={state.rooms_locked} busy={busy} disabled={!state.available || state.forced_open} onChange={change} />
      )}
      {state && !state.available && <p className="mt-2 text-[11px] text-slate-400">Every room is open. Locking will be available shortly.</p>}
      {state?.forced_open && <p className="mt-2 text-[11px] text-slate-400">Your platform administrator has opened every room for this college.</p>}
      {msg && <p role="status" className={cn("mt-2 text-[11px]", msg.ok ? "text-neon-green" : "text-severity-high")}>{msg.text}</p>}
    </Card>
  );
}
