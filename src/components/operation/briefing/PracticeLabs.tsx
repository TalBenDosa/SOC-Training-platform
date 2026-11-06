"use client";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Check, X, Terminal as TerminalIcon, Lightbulb, Search, ClipboardList, ChevronRight, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";

// Professional practice labs: a simulated shell, a cross-log trace and a
// packet builder. Everything is simulated in the browser; they teach and
// award nothing, and report once when done.

interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

function useDoneOnce(done: boolean, onDone: () => void) {
  const [fired, setFired] = useState(false);
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);
}

// "9.0" and "9" are the same answer, and so are "1,200" and "1200".
const norm = (s: string) => {
  const t = s.trim().toLowerCase().replace(/\s+/g, " ");
  const n = t.replace(/,/g, "");
  return /^-?\d+(\.\d+)?$/.test(n) ? String(Number(n)) : t;
};

// ─── Terminal: type commands, answer from the output ─────────────────────────
const NOT_FOUND: Record<"cmd" | "powershell" | "bash", (c: string) => string> = {
  cmd: c => `'${c}' is not recognized as an internal or external command,\noperable program or batch file.`,
  powershell: c => `${c} : The term '${c}' is not recognized as the name of a cmdlet, function, script file, or operable program.`,
  bash: c => `bash: ${c}: command not found`,
};

export function TerminalLab({ lab, onDone }: LabProps<"terminal">) {
  const [lines, setLines] = useState<{ kind: "in" | "out" | "err"; text: string }[]>([
    { kind: "out", text: "Start here: tap a command above (or type it here and press Enter), then read the output." },
  ]);
  const [input, setInput] = useState("");
  const [past, setPast] = useState<string[]>([]);
  const [back, setBack] = useState(-1);
  const [oi, setOi] = useState(0);
  const [answer, setAnswer] = useState("");
  const [result, setResult] = useState<"ok" | "bad" | null>(null);
  const [hint, setHint] = useState(false);
  const [ran, setRan] = useState(false);
  const screen = useRef<HTMLDivElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const answerField = useRef<HTMLInputElement>(null);
  const done = oi >= lab.objectives.length;
  useDoneOnce(done, onDone);
  const obj = lab.objectives[oi];
  const rules = useMemo(() => lab.commands.map(c => ({ ...c, re: new RegExp(`^(?:${c.match})$`, "i") })), [lab.commands]);
  // Runnable commands, taken from each command's help text ("command   what it does").
  const menu = useMemo(() => lab.commands.flatMap(c => {
    if (!c.help) return [];
    const [cmd, ...rest] = c.help.split(/\s{3,}/);
    const text = cmd.trim();
    if (!rules.some(r => r.re.test(text))) return [];
    return [{ cmd: text, what: rest.join(" ").trim() }];
  }), [lab.commands, rules]);
  // The command this objective's hint names, when it is one you can run as-is.
  const suggested = obj && rules.some(r => r.re.test(obj.hint.trim())) ? obj.hint.trim() : null;

  useEffect(() => { screen.current?.scrollTo({ top: screen.current.scrollHeight }); }, [lines]);

  function run(raw: string) {
    const cmd = raw.trim();
    setInput(""); setBack(-1);
    if (!cmd) { setLines(l => [...l, { kind: "in", text: "" }]); return; }
    setPast(p => [cmd, ...p].slice(0, 30));
    if (/^(cls|clear)$/i.test(cmd)) { setLines([]); return; }
    if (/^help$/i.test(cmd)) {
      const list = lab.commands.filter(c => c.help).map(c => `  ${c.help}`).join("\n");
      setLines(l => [...l, { kind: "in", text: cmd }, { kind: "out", text: `Commands you can use here:\n${list}\n  cls / clear      clear the screen` }]);
      return;
    }
    const hit = rules.find(r => r.re.test(cmd));
    if (hit) setRan(true);
    setLines(l => [...l, { kind: "in", text: cmd }, hit ? { kind: "out", text: hit.output } : { kind: "err", text: `${NOT_FOUND[lab.shell](cmd.split(/\s+/)[0])}\n(Tip: tap one of the commands above, or type help.)` }]);
  }

  function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") run(input);
    else if (e.key === "ArrowUp" && past.length) { e.preventDefault(); const b = Math.min(past.length - 1, back + 1); setBack(b); setInput(past[b]); }
    else if (e.key === "ArrowDown") { e.preventDefault(); const b = back - 1; setBack(b); setInput(b >= 0 ? past[b] : ""); }
  }

  function check() {
    if (!obj) return;
    if (obj.answer.some(a => norm(a) === norm(answer))) { setResult("ok"); }
    else setResult("bad");
  }
  function nextObjective() { setOi(i => i + 1); setAnswer(""); setResult(null); setHint(false); }

  return (
    <div className="space-y-3">
      {/* 1. What to find: the current objective, always above the console */}
      {obj ? (
        <div className="rounded-xl border bg-[#081120] p-3" style={{ borderColor: "color-mix(in srgb, var(--room-accent, #38bdf8) 55%, transparent)" }}>
          <div className="flex items-center gap-2">
            <span className="rounded-md px-2 py-0.5 text-[11px] font-black uppercase tracking-[0.18em] text-white" style={{ background: "color-mix(in srgb, var(--room-accent, #38bdf8) 30%, transparent)" }}>Your task {oi + 1} of {lab.objectives.length}</span>
            <div className="ml-auto flex gap-1" aria-hidden>
              {lab.objectives.map((o, i) => <span key={o.id} className={cn("h-1.5 w-5 rounded-full", i < oi ? "bg-emerald-400" : i === oi ? "bg-sky-300" : "bg-white/15")} />)}
            </div>
          </div>
          <p className="mt-2 text-base font-semibold leading-snug text-white">{obj.task}</p>
          <ol className="mt-2 space-y-0.5 text-xs text-slate-300">
            <li className={cn(ran && "text-emerald-300")}><b>Step 1.</b> Run a command below to get the data{ran && " ✓"}</li>
            <li><b>Step 2.</b> Read the output in the console</li>
            <li><b>Step 3.</b> Type what you found in the answer box under the console</li>
          </ol>
          {suggested ? (
            <button onClick={() => run(suggested)} className="mt-3 flex w-full items-center gap-2 rounded-lg border border-emerald-400/50 bg-emerald-500/10 px-3 py-2 text-left hover:bg-emerald-500/20">
              <TerminalIcon className="h-4 w-4 shrink-0 text-emerald-300" />
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-emerald-100">{suggested}</span>
              <span className="shrink-0 text-xs font-bold text-emerald-200">Run ▶</span>
            </button>
          ) : hint ? (
            <p className="mt-2 text-xs text-amber-200">Hint: <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono">{obj.hint}</code></p>
          ) : (
            <button onClick={() => setHint(true)} className="mt-2 inline-flex items-center gap-1 text-xs text-amber-300 hover:underline"><Lightbulb className="h-3.5 w-3.5" />Which command?</button>
          )}
        </div>
      ) : (
        <p className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3 text-sm font-semibold text-emerald-200"><Check className="mr-1 inline h-4 w-4" />All tasks complete. These are the same commands analysts run on a live host.</p>
      )}

      {/* 2. Commands you can run here, as tappable chips */}
      {menu.length > 0 && (
        <div>
          <p className="mb-1.5 text-[11px] font-bold uppercase tracking-[0.18em] text-slate-400">Commands available (tap to run)</p>
          <div className="flex flex-wrap gap-1.5">
            {menu.map(m => (
              <button key={m.cmd} onClick={() => run(m.cmd)} title={m.what}
                className="max-w-full whitespace-normal break-all rounded-md border border-white/15 bg-white/[0.04] px-2 py-1 text-left font-mono text-[11px] text-slate-200 hover:border-emerald-400/60 hover:text-emerald-100">
                <span className="mr-1 text-emerald-300">▶</span>{m.cmd}
                {m.what && <span className="ml-1.5 break-normal font-sans text-[10px] text-slate-500">{m.what}</span>}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* 3. The console */}
      <div className="min-w-0 overflow-hidden rounded-xl border border-white/10 bg-[#0a0c10] shadow-2xl" onClick={() => field.current?.focus()}>
        <div className="flex items-center gap-2 bg-[#1b1f27] px-3 py-1.5 text-[11px] font-semibold text-slate-300">
          <TerminalIcon className="h-3.5 w-3.5 text-emerald-300" />
          {lab.shell === "cmd" ? "Command Prompt" : lab.shell === "powershell" ? "Windows PowerShell" : "Terminal"}
          <span className="ml-auto font-mono text-[10px] text-slate-500">simulated</span>
        </div>
        <div ref={screen} className="h-64 overflow-auto px-3 py-2 font-mono text-[12px] leading-relaxed sm:h-80" aria-live="polite">
          {lines.map((l, i) => (
            <pre key={i} className={cn(/ {2,}|\t/.test(l.text) ? "w-max min-w-full whitespace-pre" : "whitespace-pre-wrap break-all", l.kind === "in" ? "text-slate-100" : l.kind === "err" ? "text-rose-300" : "text-emerald-200/90")}>
              {l.kind === "in" ? `${lab.host} ${l.text}` : l.text}
            </pre>
          ))}
          <div className="flex items-center gap-1 text-slate-100">
            <span className="shrink-0">{lab.host}</span>
            <input ref={field} value={input} onChange={e => setInput(e.target.value)} onKeyDown={onKey}
              aria-label="Type a command" placeholder="type a command, or tap one above" autoCapitalize="off" autoCorrect="off" spellCheck={false}
              className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-slate-100 caret-emerald-300 outline-none placeholder:text-slate-600" />
          </div>
        </div>
      </div>

      {/* 4. The answer, right under the console */}
      {obj && (
        <div className="rounded-xl border border-white/10 bg-[#081120] p-3">
          {result !== "ok" ? (
            <>
              <label htmlFor="term-answer" className="text-[11px] font-bold uppercase tracking-[0.18em] text-sky-300">Your answer to task {oi + 1}</label>
              <div className="mt-1.5 flex gap-2">
                <input id="term-answer" ref={answerField} value={answer} onChange={e => { setAnswer(e.target.value); setResult(null); }} onKeyDown={e => e.key === "Enter" && check()}
                  placeholder="What did the output show?" aria-label="Your answer"
                  className={cn("min-w-0 flex-1 rounded-lg border bg-black/30 px-3 py-2 font-mono text-sm text-white outline-none", result === "bad" ? "border-rose-500" : "border-white/15 focus:border-sky-400")} />
                <button onClick={check} className="rounded-lg border border-sky-300/60 px-3 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Check</button>
              </div>
              {result === "bad" && <p className="mt-2 text-xs text-rose-300"><X className="mr-1 inline h-3.5 w-3.5" />Not what the output says. Run the command for this task and read it again.</p>}
            </>
          ) : (
            <>
              <p className="text-sm leading-relaxed text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{obj.why}</p>
              <button onClick={nextObjective} className="mt-2 inline-flex items-center gap-1 rounded-lg border border-emerald-300/60 px-3 py-1.5 text-sm font-bold text-emerald-100 hover:bg-emerald-500/10">
                {oi + 1 < lab.objectives.length ? "Next task" : "Finish"} <ChevronRight className="h-4 w-4" />
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Trace: follow a lead across log sources ─────────────────────────────────
export function TraceLab({ lab, onDone }: LabProps<"trace">) {
  const [si, setSi] = useState(0);
  const [filter, setFilter] = useState("");
  const [solved, setSolved] = useState(false);
  const [wrong, setWrong] = useState<number | null>(null);
  const [facts, setFacts] = useState<string[]>([]);
  const step = lab.steps[si];
  const done = si === lab.steps.length - 1 && solved;
  useDoneOnce(done, onDone);
  const visible = step.rows.map((r, i) => ({ r, i })).filter(({ r }) => !filter || r.some(c => c.toLowerCase().includes(filter.toLowerCase())));

  function pick(i: number) {
    if (solved) return;
    if (i === step.answer) { setSolved(true); setWrong(null); setFacts(f => [...f, step.learned]); }
    else setWrong(i);
  }
  function next() { setSi(s => s + 1); setSolved(false); setWrong(null); setFilter(""); }

  return (
    <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
      <div className="min-w-0 space-y-3">
        <div className="rounded-xl border border-white/10 bg-[#081120] p-3">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-sky-300">Step {si + 1} of {lab.steps.length} · {step.source}</p>
          <p className="mt-1 text-sm font-semibold text-white">{step.ask}</p>
        </div>
        <div className="overflow-hidden rounded-xl border border-white/10 bg-[#05080e]">
          <div className="flex items-center gap-2 border-b border-white/10 px-3 py-2">
            <Search className="h-4 w-4 text-slate-400" />
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter rows (any value: an IP, a port, a time)"
              aria-label="Filter rows" className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-white outline-none placeholder:text-slate-600" />
            <span className="font-mono text-[10px] text-slate-500">{visible.length}/{step.rows.length}</span>
          </div>
          <div className="max-h-72 overflow-auto">
            <table className="w-full min-w-[34rem] font-mono text-[11.5px]">
              <thead className="sticky top-0 bg-[#111827] text-left text-[10px] uppercase tracking-wider text-slate-400">
                <tr>{step.columns.map(c => <th key={c} className="px-2 py-1.5 font-semibold">{c}</th>)}</tr>
              </thead>
              <tbody>
                {visible.map(({ r, i }) => (
                  <tr key={i} onClick={() => pick(i)}
                    className={cn("cursor-pointer border-t border-white/5 transition",
                      solved && i === step.answer ? "bg-emerald-500/15 text-emerald-100" : wrong === i ? "bg-rose-500/15 text-rose-200" : "text-slate-300 hover:bg-white/5")}>
                    {r.map((c, k) => <td key={k} className="whitespace-nowrap px-2 py-1">{c}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <p role="status" className={cn("min-h-[2.5rem] rounded-lg px-3 py-2 text-sm leading-relaxed", solved ? "bg-emerald-500/10 text-emerald-200" : wrong !== null ? "bg-rose-500/10 text-rose-300" : "text-slate-500")}>
          {solved ? <><Check className="mr-1 inline h-4 w-4" />{step.why}</> : wrong !== null ? "That row does not answer this step. Read the question and the case board again." : "Use the filter, then click the row that answers the step."}
        </p>
        {solved && si < lab.steps.length - 1 && (
          <button onClick={next} className="inline-flex items-center gap-1 rounded-xl border border-sky-300/60 px-4 py-2 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Next log <ChevronRight className="h-4 w-4" /></button>
        )}
      </div>
      <aside className="h-fit rounded-xl border border-amber-300/30 bg-amber-500/5 p-4">
        <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.2em] text-amber-300"><ClipboardList className="h-4 w-4" />Case board</p>
        <p className="mt-2 text-sm text-slate-100"><span className="text-slate-400">Lead: </span>{lab.lead}</p>
        <ul className="mt-2 space-y-1.5">
          {facts.map(f => <motion.li key={f} initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} className="flex gap-2 text-sm text-emerald-200"><Check className="mt-0.5 h-4 w-4 shrink-0" />{f}</motion.li>)}
        </ul>
      </aside>
    </div>
  );
}

// ─── Encap: build a packet layer by layer ────────────────────────────────────
const ENCAP_TINTS = ["#a78bfa", "#60a5fa", "#2dd4bf", "#fbbf24", "#f472b6"];

export function EncapLab({ lab, onDone }: LabProps<"encap">) {
  const [li, setLi] = useState(0);
  const [picked, setPicked] = useState<number[]>([]);
  const [wrong, setWrong] = useState<number | null>(null);
  const [solved, setSolved] = useState(false);
  const done = picked.length === lab.layers.length;
  useDoneOnce(done, onDone);
  const layer = lab.layers[li];

  function choose(i: number) {
    if (solved || !layer) return;
    if (i === layer.answer) { setSolved(true); setWrong(null); setPicked(p => [...p, i]); }
    else setWrong(i);
  }
  function next() { setLi(i => i + 1); setSolved(false); setWrong(null); }

  // completed layers wrap the data: the newest layer is the outermost header
  const built = lab.layers.slice(0, picked.length);
  return (
    <div className="space-y-4">
      <p className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 font-mono text-[12px] text-slate-200"><Network className="mr-1.5 inline h-4 w-4 text-sky-300" />{lab.story}</p>

      {/* The packet as it grows */}
      <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#05080e] p-3">
        <div className="flex min-w-max items-stretch gap-1 font-mono text-[11px]">
          {[...built].reverse().map((l, k) => {
            const idx = built.length - 1 - k;
            const c = ENCAP_TINTS[idx % ENCAP_TINTS.length];
            return (
              <motion.div key={l.id} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }}
                className="rounded-md border px-2 py-1.5" style={{ borderColor: c, background: `${c}1f`, color: c }}>
                <p className="font-bold">{l.layer.split(" ")[0]} hdr</p>
                <p className="text-slate-200">{l.chip ?? l.options[l.answer]}</p>
              </motion.div>
            );
          })}
          <div className="rounded-md border border-slate-500 bg-slate-500/10 px-3 py-1.5 text-slate-200"><p className="font-bold">DATA</p><p>payload</p></div>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">{done ? "Frame complete: ready to leave the network card as bits." : `PDU now: ${built.length ? built[built.length - 1].pdu : "Data"}`}</p>
      </div>

      {layer && !done || (layer && solved) ? (
        <div className="rounded-xl border border-white/10 bg-[#081120] p-3">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-sky-300">{layer.layer} · builds a {layer.pdu}</p>
          <p className="mt-1 text-sm font-semibold text-white">{layer.field}</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {layer.options.map((o, i) => (
              <motion.button key={o} onClick={() => choose(i)} disabled={solved}
                animate={wrong === i ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
                className={cn("rounded-lg border px-3 py-2 text-left font-mono text-[12px] transition enabled:hover:bg-white/5",
                  solved && i === layer.answer ? "border-emerald-400 bg-emerald-500/10 text-emerald-100" : wrong === i ? "border-rose-500 bg-rose-500/10 text-rose-200" : "border-white/15 text-slate-200")}>
                {o}
              </motion.button>
            ))}
          </div>
          <p role="status" className="mt-2 min-h-[1.25rem] text-sm leading-relaxed">
            {solved ? <span className="text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{layer.why}</span>
              : wrong !== null ? <span className="text-rose-300">That value belongs to a different header. Which address or number does this layer use?</span> : null}
          </p>
          {solved && li < lab.layers.length - 1 && (
            <button onClick={next} className="mt-1 inline-flex items-center gap-1 rounded-lg border border-sky-300/60 px-3 py-1.5 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Wrap the next layer <ChevronRight className="h-4 w-4" /></button>
          )}
        </div>
      ) : null}

      {/* The protocol tree, like a packet analyser shows it */}
      {done && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="overflow-hidden rounded-xl border border-white/10 bg-white text-slate-800">
          <p className="bg-[#e5e7eb] px-3 py-1.5 text-[11px] font-semibold text-slate-600">Packet details · frame 1</p>
          <ul className="px-3 py-2 font-mono text-[12px]">
            {[...lab.layers].reverse().map(l => <li key={l.id} className="py-0.5"><span className="text-slate-400">▸ </span>{l.tree}</li>)}
          </ul>
        </motion.div>
      )}
    </div>
  );
}

// ─── Queue: triage a SIEM-style alert queue ──────────────────────────────────
const SEV_TINT: Record<string, string> = { Low: "#94a3b8", Medium: "#fbbf24", High: "#fb923c", Critical: "#f43f5e" };
const TONE: Record<string, string> = { close: "#94a3b8", escalate: "#fb923c", contain: "#f43f5e" };

export function QueueLab({ lab, onDone }: LabProps<"queue">) {
  const [sel, setSel] = useState(lab.alerts[0]?.id ?? "");
  const [handled, setHandled] = useState<Record<string, string>>({}); // alert id -> action id
  const [misses, setMisses] = useState<Set<string>>(new Set());
  const [wrong, setWrong] = useState<string | null>(null);
  const done = Object.keys(handled).length === lab.alerts.length;
  useDoneOnce(done, onDone);
  const alert = lab.alerts.find(a => a.id === sel)!;
  const actionLabel = (id: string) => lab.actions.find(a => a.id === id)?.label ?? id;

  function act(id: string) {
    if (handled[alert.id]) return;
    if (id === alert.answer) {
      setHandled(h => ({ ...h, [alert.id]: id })); setWrong(null);
    } else { setWrong(id); setMisses(m => new Set(m).add(alert.id)); }
  }
  function pick(id: string) { setSel(id); setWrong(null); }
  const nextOpen = lab.alerts.find(a => !handled[a.id] && a.id !== alert.id);

  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-[#060a12]">
      <div className="flex items-center gap-2 border-b border-white/10 bg-[#0e1524] px-3 py-2 text-[11px] font-semibold text-slate-300">
        <span className="h-2 w-2 animate-pulse rounded-full bg-rose-500" />{lab.console}
        <span className="ml-auto font-mono text-slate-400">{Object.keys(handled).length}/{lab.alerts.length} handled</span>
      </div>
      <div className="grid lg:grid-cols-[1.1fr_1fr]">
        {/* Queue */}
        <div className="min-w-0 overflow-x-auto border-b border-white/10 lg:border-b-0 lg:border-r">
          <table className="w-full min-w-[30rem] text-left text-[12px]">
            <thead className="bg-white/[0.03] text-[10px] uppercase tracking-wider text-slate-400">
              <tr><th className="px-2 py-1.5">Time</th><th className="px-2 py-1.5">Sev</th><th className="px-2 py-1.5">Rule</th><th className="px-2 py-1.5">Status</th></tr>
            </thead>
            <tbody>
              {lab.alerts.map(a => (
                <tr key={a.id} onClick={() => pick(a.id)} aria-selected={a.id === sel}
                  className={cn("cursor-pointer border-t border-white/5", a.id === sel ? "bg-sky-500/10" : "hover:bg-white/5")}>
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-slate-400">{a.time}</td>
                  <td className="px-2 py-2"><span className="rounded px-1.5 py-0.5 text-[10px] font-bold" style={{ color: SEV_TINT[a.severity], background: `${SEV_TINT[a.severity]}22` }}>{a.severity}</span></td>
                  <td className="px-2 py-2 text-slate-100">{a.rule}<span className="block font-mono text-[10px] text-slate-500">{a.entity}</span></td>
                  <td className="whitespace-nowrap px-2 py-2 text-[11px]">{handled[a.id] ? <span className="text-emerald-300"><Check className="mr-0.5 inline h-3 w-3" />{actionLabel(handled[a.id])}</span> : <span className="text-slate-500">New</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* Detail */}
        <div className="min-w-0 p-3">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em]" style={{ color: SEV_TINT[alert.severity] }}>{alert.severity} · {alert.time}</p>
          <p className="mt-1 font-semibold text-white">{alert.rule}</p>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-lg border border-white/10 bg-black/30 p-2 font-mono text-[11.5px]">
            {alert.fields.map(f => <React.Fragment key={f.k}><dt className="text-sky-300">{f.k}</dt><dd className="break-all text-slate-200">{f.v}</dd></React.Fragment>)}
          </dl>
          <p className="mt-2 text-sm leading-relaxed text-slate-300">{alert.context}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {lab.actions.map(a => (
              <motion.button key={a.id} onClick={() => act(a.id)} disabled={!!handled[alert.id]}
                animate={wrong === a.id ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
                className={cn("rounded-lg border-2 px-3 py-1.5 text-sm font-bold transition enabled:hover:brightness-125 disabled:opacity-50", handled[alert.id] === a.id && "ring-2 ring-emerald-400")}
                style={{ borderColor: wrong === a.id ? "#f43f5e" : TONE[a.tone], color: TONE[a.tone] }}>
                {a.label}
              </motion.button>
            ))}
          </div>
          <p role="status" className="mt-3 min-h-[2.5rem] text-sm leading-relaxed">
            {handled[alert.id] ? <span className="text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{alert.why}</span>
              : wrong ? <span className="text-rose-300"><X className="mr-1 inline h-4 w-4" />Not the right call for this one. Re-read the fields and the context.</span>
                : <span className="text-slate-500">Read the alert, then choose your action.</span>}
          </p>
          {handled[alert.id] && nextOpen && (
            <button onClick={() => pick(nextOpen.id)} className="mt-1 inline-flex items-center gap-1 rounded-lg border border-sky-300/60 px-3 py-1.5 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Next alert <ChevronRight className="h-4 w-4" /></button>
          )}
          {done && <p className="mt-2 text-sm font-semibold text-emerald-300">Queue clear. Right on the first try: {lab.alerts.length - misses.size} of {lab.alerts.length}.</p>}
        </div>
      </div>
    </div>
  );
}

// ─── Worksheet: work the numbers out of a table ──────────────────────────────
export function WorksheetLab({ lab, onDone }: LabProps<"worksheet">) {
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [ok, setOk] = useState<Set<string>>(new Set());
  const [bad, setBad] = useState<Set<string>>(new Set());
  const [hints, setHints] = useState<Set<string>>(new Set());
  useDoneOnce(ok.size === lab.questions.length, onDone);

  function check(id: string) {
    const q = lab.questions.find(x => x.id === id)!;
    if (q.answer.some(a => norm(a) === norm(answers[id] ?? ""))) { setOk(s => new Set(s).add(id)); setBad(s => { const n = new Set(s); n.delete(id); return n; }); }
    else setBad(s => new Set(s).add(id));
  }

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-xl border border-white/10 bg-[#05080e]">
        <p className="border-b border-white/10 bg-[#0e1524] px-3 py-2 text-[11px] font-semibold text-slate-300">{lab.caption}</p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[32rem] font-mono text-[12px]">
            <thead className="text-left text-[10px] uppercase tracking-wider text-slate-400"><tr>{lab.columns.map(c => <th key={c} className="px-3 py-1.5">{c}</th>)}</tr></thead>
            <tbody>{lab.rows.map((r, i) => <tr key={i} className="border-t border-white/5 text-slate-200">{r.map((c, k) => <td key={k} className="whitespace-nowrap px-3 py-1.5">{c}</td>)}</tr>)}</tbody>
          </table>
        </div>
      </div>
      <ol className="space-y-3">
        {lab.questions.map((q, i) => (
          <li key={q.id} className="rounded-xl border border-white/10 bg-[#081120] p-3">
            <p className="text-sm font-semibold text-white"><span className="mr-2 text-sky-300">{i + 1}.</span>{q.q}</p>
            {ok.has(q.id) ? (
              <p className="mt-2 text-sm leading-relaxed text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{q.why}</p>
            ) : (
              <>
                <div className="mt-2 flex gap-2">
                  <input value={answers[q.id] ?? ""} onChange={e => setAnswers(a => ({ ...a, [q.id]: e.target.value }))} onKeyDown={e => e.key === "Enter" && check(q.id)}
                    aria-label={`Answer ${i + 1}`} placeholder="Your answer"
                    className={cn("min-w-0 flex-1 rounded-lg border bg-black/30 px-3 py-2 font-mono text-sm text-white outline-none", bad.has(q.id) ? "border-rose-500" : "border-white/15 focus:border-sky-400")} />
                  <button onClick={() => check(q.id)} className="rounded-lg border border-sky-300/60 px-3 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Check</button>
                </div>
                {hints.has(q.id) ? <p className="mt-2 text-xs text-amber-200">{q.hint}</p>
                  : <button onClick={() => setHints(h => new Set(h).add(q.id))} className="mt-2 inline-flex items-center gap-1 text-xs text-amber-300 hover:underline"><Lightbulb className="h-3.5 w-3.5" />How do I work it out?</button>}
                {bad.has(q.id) && <p className="mt-1 text-xs text-rose-300">Not quite. Work it from the table again.</p>}
              </>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
