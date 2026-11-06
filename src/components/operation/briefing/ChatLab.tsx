"use client";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Bot, Check, SendHorizontal, Target, User } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";

// A chat window with a simulated assistant. Nothing reaches a real model: each
// message is matched against the lab's rules, and a reply that wins the current
// goal moves the learner on. It teaches and awards nothing, and reports once
// when done.

interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

export function ChatLab({ lab, onDone }: LabProps<"chat">) {
  const [lines, setLines] = useState<{ from: "user" | "bot"; text: string }[]>([{ from: "bot", text: lab.greeting }]);
  const [input, setInput] = useState("");
  const [gi, setGi] = useState(0);
  const [won, setWon] = useState<string | null>(null);
  const [fired, setFired] = useState(false);
  const [said, setSaid] = useState("");
  const screen = useRef<HTMLDivElement>(null);
  const rules = useMemo(() => lab.rules.map(r => ({ ...r, re: new RegExp(r.match, "i") })), [lab.rules]);
  const goal = lab.goals[gi];
  const done = gi >= lab.goals.length;

  useEffect(() => { screen.current?.scrollTo({ top: screen.current.scrollHeight }); }, [lines]);
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);

  function send(raw: string) {
    const text = raw.trim();
    if (!text || won || done) return;
    setInput("");
    // With memory, a winning rule reads everything said toward this goal, so a learner who
    // answers follow-ups one at a time can still get there. Every other rule reads this message.
    const pool = (said ? `${said}. ${text}` : text).slice(-600); // keep the rules quick on long chats
    setSaid(pool);
    const hit = rules.find(r => r.re.test(lab.memory && r.wins ? pool : text) && (!r.goal || r.goal === goal.id));
    setLines(l => [...l, { from: "user", text }, { from: "bot", text: hit?.reply ?? lab.fallback }]);
    if (hit?.wins) setWon(goal.why);
  }

  function next() { setGi(i => i + 1); setWon(null); setSaid(""); }

  return (
    <div className="space-y-3">
      {goal ? (
        <div className="rounded-xl border bg-[#081120] p-3" style={{ borderColor: "color-mix(in srgb, var(--room-accent, #38bdf8) 55%, transparent)" }}>
          <div className="flex items-center gap-2">
            <Target className="h-4 w-4 shrink-0" style={{ color: "var(--room-accent, #38bdf8)" }} />
            <span className="text-[11px] font-black uppercase tracking-[0.18em] text-white">Your goal {gi + 1} of {lab.goals.length}</span>
          </div>
          <p className="mt-2 text-base font-semibold leading-snug text-white">{goal.task}</p>
          <p className="mt-1 text-xs text-slate-300">Tap a message to send it, or write your own.</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {goal.tries.map(t => (
              <button key={t} onClick={() => send(t)} disabled={!!won}
                className="max-w-full rounded-full border border-white/15 bg-white/[0.04] px-3 py-1 text-left text-xs text-slate-200 hover:border-white/40 disabled:opacity-40">
                {t}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <p className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3 text-sm font-semibold text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{lab.doneNote}</p>
      )}

      <div className="min-w-0 overflow-hidden rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
        <div className="flex items-center gap-2 border-b border-white/10 bg-white/[0.04] px-3 py-2">
          <span className="grid h-7 w-7 place-items-center rounded-full" style={{ background: "color-mix(in srgb, var(--room-accent, #38bdf8) 30%, transparent)" }}><Bot className="h-4 w-4 text-white" /></span>
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-white">{lab.bot}</p>
            <p className="truncate text-[11px] text-slate-400">{lab.botRole}</p>
          </div>
          <span className="ml-auto font-mono text-[10px] text-slate-500">simulated</span>
        </div>
        <div ref={screen} className="h-72 space-y-2 overflow-auto p-3 sm:h-80" aria-live="polite">
          {lines.map((l, i) => (
            <div key={i} className={cn("flex items-end gap-2", l.from === "user" && "flex-row-reverse")}>
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-white/10">{l.from === "user" ? <User className="h-3.5 w-3.5 text-slate-200" /> : <Bot className="h-3.5 w-3.5 text-slate-200" />}</span>
              <p className={cn("max-w-[80%] whitespace-pre-wrap break-words rounded-2xl px-3 py-2 text-sm leading-relaxed", l.from === "user" ? "rounded-br-sm text-white" : "rounded-bl-sm bg-white/[0.07] text-slate-100")}
                style={l.from === "user" ? { background: "color-mix(in srgb, var(--room-accent, #38bdf8) 35%, transparent)" } : undefined}>
                {l.text}
              </p>
            </div>
          ))}
        </div>
        <form className="flex items-center gap-2 border-t border-white/10 p-2" onSubmit={e => { e.preventDefault(); send(input); }}>
          <input value={input} onChange={e => setInput(e.target.value)} disabled={!!won || done} aria-label={`Message ${lab.bot}`} placeholder={`Message ${lab.bot}...`} autoComplete="off" spellCheck={false}
            className="min-w-0 flex-1 rounded-lg bg-black/30 px-3 py-2 text-sm text-white outline-none placeholder:text-slate-500 focus:ring-1 focus:ring-white/30" />
          <button type="submit" disabled={!!won || done} aria-label="Send" className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-white/10 text-white hover:bg-white/20 disabled:opacity-40"><SendHorizontal className="h-4 w-4" /></button>
        </form>
      </div>

      {won && (
        <div className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3">
          <p className="text-sm font-semibold text-emerald-100"><Check className="mr-1 inline h-4 w-4" />{won}</p>
          <button onClick={next} className="mt-2 rounded-lg border border-emerald-400/50 px-3 py-1.5 text-sm font-bold text-emerald-100 hover:bg-emerald-500/20">{gi + 1 < lab.goals.length ? "Next goal" : "Finish"}</button>
        </div>
      )}
    </div>
  );
}
