"use client";
/**
 * The analyst's Decoder: a CyberChef-style drawer inside the SOC console, so an encoded value
 * from a log never has to be copied out of the platform (demo feedback 2026-11).
 *
 * <DecoderProvider> owns the drawer. Anything inside it can call useDecoder()?.open(value) to
 * load a value (the log detail panel does, next to fields that look encoded). The recipe is a
 * chain of steps from src/lib/decode/ops.ts, re-run on every change; "Auto" suggests the next
 * step like CyberChef's Magic.
 */
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { Binary, Copy, Plus, Wand2, X, ArrowDownToLine } from "lucide-react";
import { OPS, OP_BY_ID, encodedCommandOf, runRecipe, suggestOp, type OpResult } from "@/lib/decode/ops";
import { cn } from "@/lib/utils";

interface DecoderApi { open: (value?: string) => void }
const DecoderContext = createContext<DecoderApi | null>(null);

/** null outside a provider: callers hide their Decode buttons. */
export function useDecoder(): DecoderApi | null {
  return useContext(DecoderContext);
}

export function DecoderProvider({ children }: { children: ReactNode }) {
  const [openState, setOpenState] = useState(false);
  const [seed, setSeed] = useState<{ value: string; n: number } | null>(null);
  const open = useCallback((value?: string) => {
    setOpenState(true);
    if (value !== undefined) setSeed(s => ({ value, n: (s?.n ?? 0) + 1 }));
  }, []);
  const api = useMemo(() => ({ open }), [open]);
  return (
    <DecoderContext.Provider value={api}>
      {children}
      {openState && <DecoderDrawer seed={seed} onClose={() => setOpenState(false)} />}
    </DecoderContext.Provider>
  );
}

/** The toolbar button that opens an empty Decoder. */
export function DecoderButton({ className }: { className?: string }) {
  const dec = useDecoder();
  if (!dec) return null;
  return (
    <button type="button" onClick={() => dec.open()} title="Decode Base64, URL, hex, gzip, JWT and more without leaving the console"
      className={cn("inline-flex items-center gap-1.5 rounded-md border border-cyber-500/40 bg-cyber-500/10 px-2.5 py-1 text-xs font-semibold text-cyber-200 hover:bg-cyber-500/20", className)}>
      <Binary className="h-3.5 w-3.5" aria-hidden /> Decoder
    </button>
  );
}

function DecoderDrawer({ seed, onClose }: { seed: { value: string; n: number } | null; onClose: () => void }) {
  const ids = useId();
  const [input, setInput] = useState("");
  const [recipe, setRecipe] = useState<string[]>([]);
  const [steps, setSteps] = useState<{ id: string; result: OpResult }[]>([]);
  const [output, setOutput] = useState("");
  const [copied, setCopied] = useState(false);
  const panel = useRef<HTMLDivElement>(null);

  // A value sent from a log field: load it and start the recipe the way an analyst would.
  useEffect(() => {
    if (!seed) return;
    const enc = encodedCommandOf(seed.value);
    const value = enc ?? seed.value;
    setInput(value);
    const first = suggestOp(value);
    setRecipe(first ? [first] : []);
  }, [seed]);

  useEffect(() => {
    let live = true;
    runRecipe(input, recipe).then(r => { if (live) { setSteps(r.steps); setOutput(r.output); } });
    return () => { live = false; };
  }, [input, recipe]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    panel.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const next = suggestOp(output);
  const lastError = steps.find(s => !s.result.ok);
  const notes = steps.map(s => (s.result.ok ? s.result.note : undefined)).filter(Boolean) as string[];

  return (
    <div className="fixed inset-y-0 right-0 z-[900] flex w-full max-w-xl flex-col border-l border-border bg-bg-elevated shadow-2xl"
      role="dialog" aria-modal="false" aria-labelledby={`${ids}-t`} ref={panel} tabIndex={-1}>
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        <Binary className="h-4 w-4 text-cyber-300" aria-hidden />
        <h2 id={`${ids}-t`} className="text-sm font-semibold text-white">Decoder</h2>
        <span className="text-xs text-slate-500">Runs in your browser. Nothing is sent anywhere.</span>
        <button type="button" onClick={onClose} aria-label="Close the decoder" className="ml-auto rounded p-1 text-slate-400 hover:bg-bg-hover hover:text-white">
          <X className="h-4 w-4" aria-hidden />
        </button>
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        <div className="space-y-1">
          <label htmlFor={`${ids}-in`} className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Input</label>
          <textarea id={`${ids}-in`} value={input} onChange={e => setInput(e.target.value)} rows={5} spellCheck={false}
            placeholder="Paste an encoded value: Base64, %2F..., 0x41..., H4sI..., eyJ..."
            className="w-full resize-y rounded-md border border-border bg-bg-panel p-2 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30" />
        </div>

        <div className="space-y-1.5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Recipe</p>
          {recipe.length === 0 && <p className="text-xs text-slate-500">No steps yet. Add one below, or press Auto.</p>}
          <ol className="space-y-1">
            {recipe.map((id, i) => {
              const r = steps[i]?.result;
              return (
                <li key={`${id}-${i}`} className={cn("flex items-center gap-2 rounded-md border px-2 py-1 text-xs",
                  !r ? "border-border text-slate-500" : r.ok ? "border-neon-green/30 text-slate-200" : "border-severity-high/50 text-severity-high")}>
                  <span className="font-mono text-slate-500">{i + 1}</span>
                  <span className="font-semibold">{OP_BY_ID.get(id)?.label}</span>
                  <button type="button" onClick={() => setRecipe(rs => rs.filter((_, j) => j !== i))} aria-label={`Remove step ${i + 1}`}
                    className="ml-auto rounded p-0.5 text-slate-500 hover:text-severity-high"><X className="h-3 w-3" aria-hidden /></button>
                </li>
              );
            })}
          </ol>
          <div className="flex flex-wrap gap-1">
            <button type="button" disabled={!next} onClick={() => next && setRecipe(r => [...r, next])}
              title={next ? `Suggested: ${OP_BY_ID.get(next)?.label}` : "The output looks like plain text"}
              className="inline-flex items-center gap-1 rounded border border-neon-purple/50 bg-neon-purple/10 px-2 py-1 text-[11px] font-semibold text-neon-purple hover:bg-neon-purple/20 disabled:opacity-40">
              <Wand2 className="h-3 w-3" aria-hidden /> Auto{next ? `: ${OP_BY_ID.get(next)?.label}` : ""}
            </button>
            {OPS.map(op => (
              <button key={op.id} type="button" title={op.help} onClick={() => setRecipe(r => [...r, op.id])}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-[11px] text-slate-300 hover:border-cyber-500/50 hover:text-white">
                <Plus className="h-3 w-3" aria-hidden /> {op.label}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-1" aria-live="polite">
          <div className="flex items-center gap-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Output</p>
            <span className="text-[10px] text-slate-500">{output.length.toLocaleString()} chars</span>
            <button type="button" onClick={() => { setInput(output); setRecipe([]); }} disabled={!output || recipe.length === 0}
              title="Make the output the new input" className="ml-auto inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[11px] text-slate-300 hover:text-white disabled:opacity-40">
              <ArrowDownToLine className="h-3 w-3" aria-hidden /> Use as input
            </button>
            <button type="button" disabled={!output} onClick={() => { void navigator.clipboard?.writeText(output).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); }); }}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[11px] text-slate-300 hover:text-white disabled:opacity-40">
              <Copy className="h-3 w-3" aria-hidden /> {copied ? "Copied" : "Copy"}
            </button>
          </div>
          {lastError && !lastError.result.ok && (
            <p className="rounded border border-severity-high/40 bg-severity-high/10 px-2 py-1 text-xs text-severity-high">
              Step {steps.indexOf(lastError) + 1} ({OP_BY_ID.get(lastError.id)?.label}): {lastError.result.error}
            </p>
          )}
          {notes.map((n, i) => <p key={i} className="text-[11px] text-neon-amber">{n}</p>)}
          <pre className="max-h-80 min-h-[6rem] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-[#0b1220] p-2 font-mono text-xs text-slate-100">{output}</pre>
          <p className="text-[11px] text-slate-500">Decoding shows what a value says. It does not make it safe: never run or open a decoded command or link.</p>
        </div>
      </div>
    </div>
  );
}
