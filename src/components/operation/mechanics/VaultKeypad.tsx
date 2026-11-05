"use client";
import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { KeyRound, Lightbulb, Vault } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SanitizedFlagTask } from "@/lib/rooms/sanitize";
import { FieldName } from "@/components/rooms/FieldName";
import { AlreadyCleared, ContinueButton, Verdict, flattenRaw, useMechanic, type MechanicProps } from "../shared";

/**
 * flag → Vault Keypad. Unlimited guesses (the grader never reveals a flag),
 * but each wrong code costs a shield. A right value typed in the wrong shape
 * (a whole address instead of the domain, a URL scheme, a trailing dot) is a
 * format slip, not a wrong finding: it is retried in its bare form and never
 * costs a shield. The hint is decrypted with one Intel token earned in the
 * briefings; with none left it costs a shield instead.
 */

/** The bare form of a value: no scheme, no user part before @, no trailing dot or slash. */
function bareForm(v: string): string {
  let s = v.trim().toLowerCase().replace(/^[a-z]+:\/\//, "");
  if (s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);
  return s.replace(/[./]+$/, "").replace(/^<|>$/g, "");
}
export function VaultKeypad({ roomId, task, isCompleted, onComplete, onMistake, prevLogEvent, intelTokens, spendToken }: MechanicProps<SanitizedFlagTask>) {
  const { submit, record, complete, recordInteraction } = useMechanic(roomId, task.id, isCompleted, onComplete);
  const fields = useMemo(() => (prevLogEvent ? flattenRaw(prevLogEvent.raw as Record<string, unknown>) : []), [prevLogEvent]);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);
  const [wrong, setWrong] = useState(0);
  const [hintOpen, setHintOpen] = useState(false);
  const [opened, setOpened] = useState<{ xp: number; slip: boolean } | null>(null);

  if (isCompleted) return <AlreadyCleared heading="Evidence lock" onContinue={() => complete(0)} />;

  async function tryCode(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim() || busy || opened) return;
    setBusy(true);
    try {
      let r = await submit({ value });
      let slip = false;
      const bare = bareForm(value);
      if (!r.correct && bare && bare !== value.trim().toLowerCase()) {
        r = await submit({ value: bare });
        slip = r.correct;
      }
      record({ type: "flag", value: slip ? bare : value, correct: r.correct });
      if (r.correct) setOpened({ xp: r.xpEarned, slip });
      else { onMistake(); setWrong(w => w + 1); setShake(s => s + 1); }
    } finally {
      setBusy(false);
    }
  }

  function revealHint() {
    if (hintOpen || !task.hint) return;
    if (!spendToken()) onMistake();
    setHintOpen(true);
  }

  return (
    <div className="space-y-5" onClickCapture={recordInteraction}>
      <p className="rounded-xl border border-indigo-400/30 bg-bg-panel/80 px-4 py-3 text-sm leading-relaxed text-slate-200">{task.prompt}</p>

      {fields.length > 0 && (
        <details className="rounded-xl border border-border bg-[#050a12]/90">
          <summary className="cursor-pointer select-none px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-cyber-300">
            Case evidence · {prevLogEvent?.vendor ?? prevLogEvent?.source}
          </summary>
          <div className="max-h-56 overflow-y-auto px-4 pb-3 font-mono text-[11px]">
            {fields.map(f => (
              <div key={f.key} className="flex gap-3 border-b border-white/5 py-1">
                <FieldName name={f.key} />
                <span className="min-w-0 flex-1 break-all text-slate-300">{f.value}</span>
              </div>
            ))}
          </div>
        </details>
      )}

      <motion.form
        key={shake}
        onSubmit={tryCode}
        animate={shake ? { x: [0, -12, 12, -8, 8, 0] } : undefined}
        transition={{ duration: 0.45 }}
        className={cn(
          "mx-auto max-w-md rounded-3xl border-2 p-6 text-center shadow-2xl transition-colors",
          opened ? "border-neon-green/60 bg-neon-green/5" : "border-slate-600 bg-[linear-gradient(160deg,#1e293b,#0b1220)]",
        )}
      >
        <motion.div animate={opened ? { rotate: 180 } : { rotate: 0 }} transition={{ type: "spring", stiffness: 60 }} className="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-full border-4 border-slate-500 bg-slate-800">
          <Vault className={cn("h-7 w-7", opened ? "text-neon-green" : "text-slate-300")} />
        </motion.div>
        <label htmlFor="vault-code" className="block text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-400">
          {opened ? "Vault open" : "Enter the code"}
        </label>
        <input
          id="vault-code"
          value={value}
          onChange={e => setValue(e.target.value)}
          disabled={!!opened}
          autoComplete="off"
          spellCheck={false}
          className="mt-2 w-full rounded-xl border border-slate-600 bg-black/60 px-4 py-3 text-center font-mono text-xl tracking-[0.15em] text-neon-green placeholder:text-slate-700 focus:border-cyber-400 focus:outline-none"
          placeholder="_ _ _ _"
        />
        {!opened && (
          <button disabled={!value.trim() || busy} className="mt-4 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-6 py-2.5 text-sm font-bold text-bg disabled:opacity-40">
            <KeyRound className="h-4 w-4" /> Turn the dial
          </button>
        )}
        {wrong > 0 && !opened && <p role="status" className="mt-3 text-sm text-neon-red">Wrong code ({wrong}). The vault cost you a shield.</p>}
      </motion.form>

      {task.hint && !opened && (
        <div className="mx-auto max-w-md text-center">
          {hintOpen ? (
            <p className="rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-3 py-2 text-left text-sm text-neon-amber">{task.hint}</p>
          ) : (
            <button onClick={revealHint} className="inline-flex items-center gap-2 text-sm text-neon-amber hover:underline">
              <Lightbulb className="h-4 w-4" />
              Decrypt hint ({intelTokens > 0 ? "1 Intel token" : "costs 1 shield"})
            </button>
          )}
        </div>
      )}

      {opened && (
        <>
          <Verdict
            correct
            title="Code accepted"
            xp={opened.xp}
            explanation={opened.slip
              ? `Right finding. The answer field wanted the bare value (${bareForm(value)}), so that is what was accepted: in a ticket, record exactly the value the question asks for.`
              : "Exact match with the evidence. Pulling the precise value from a raw log is what makes a finding defensible."}
          />
          <ContinueButton onClick={() => complete(opened.xp, task.xp)} />
        </>
      )}
    </div>
  );
}
