"use client";
import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Lock, LockOpen } from "lucide-react";
import { cn } from "@/lib/utils";
import { displayOptions, newShuffleSeed } from "@/lib/rooms/shuffle";
import type { SanitizedQuestionTask } from "@/lib/rooms/sanitize";
import { AlreadyCleared, ContinueButton, PersonaAvatar, Verdict, useMechanic, type MechanicProps } from "../shared";

/**
 * question → Lock Terminal. Same two-try contract as QuestionPlayer: a first
 * miss gives a nudge (no reveal), the second try is worth half credit.
 */
export function LockTerminal({ roomId, task, isCompleted, onComplete, onMistake, persona }: MechanicProps<SanitizedQuestionTask>) {
  const { submit, record, complete, recordInteraction } = useMechanic(roomId, task.id, isCompleted, onComplete);
  const options = useMemo(() => displayOptions(task.options, `${newShuffleSeed()}:${task.id}`), [task]);
  const [selected, setSelected] = useState<number | null>(null);
  const [wrongOnce, setWrongOnce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);
  const [result, setResult] = useState<{ correct: boolean; xp: number; answer: number | null; explanation: string } | null>(null);

  if (isCompleted) return <AlreadyCleared heading={task.question} onContinue={() => complete(0)} />;

  async function unlock() {
    if (selected === null || busy) return;
    setBusy(true);
    try {
      const r = await submit({ selectedIndex: selected, attemptNumber: wrongOnce ? 2 : 1 });
      const explanation = typeof r.reveal.explanation === "string" ? r.reveal.explanation : "";
      const answer = typeof r.reveal.answer === "number" ? r.reveal.answer : null;
      if (r.correct) {
        setResult({ correct: true, xp: r.xpEarned, answer: answer ?? selected, explanation });
        record({ type: "question", selected, answer: answer ?? selected, explanation, correct: true });
      } else {
        setShake(s => s + 1);
        if (!wrongOnce) { onMistake(); setWrongOnce(true); setSelected(null); }
        else {
          onMistake(true);
          setResult({ correct: false, xp: 0, answer, explanation });
          record({ type: "question", selected, answer, explanation, correct: false });
        }
      }
    } finally {
      setBusy(false);
    }
  }

  const open = result?.correct;

  return (
    <div className="space-y-5" onClickCapture={recordInteraction}>
      {persona && (
        // An in-world caller frames the question; the line never hints at the answer.
        <div className="flex items-center gap-4 rounded-2xl border border-white/10 bg-bg-panel/70 p-4">
          <PersonaAvatar name={persona.name} photo={persona.photo} size={64} />
          <div className="min-w-0">
            <p className="text-sm font-bold text-white">{persona.name}</p>
            <p className="text-[11px] uppercase tracking-[0.2em] text-slate-400">{persona.role}</p>
            <p className="mt-1.5 text-sm italic leading-relaxed text-slate-200">&ldquo;{persona.line}&rdquo;</p>
          </div>
        </div>
      )}
      <motion.div
        key={shake}
        animate={shake ? { x: [0, -10, 10, -6, 6, 0] } : undefined}
        transition={{ duration: 0.4 }}
        className="rounded-2xl border border-cyber-500/30 bg-[#050a12]/90 p-5 font-mono shadow-glow"
      >
        <div className="mb-4 flex items-center gap-3 text-[11px] uppercase tracking-[0.25em] text-cyber-300">
          {open ? <LockOpen className="h-4 w-4 text-neon-green" /> : <Lock className="h-4 w-4" />}
          <span>{open ? "Terminal unlocked" : "Terminal locked · answer to open"}</span>
          {!result && <span className="ml-auto text-slate-500">{wrongOnce ? "1 attempt left" : "2 attempts"}</span>}
        </div>
        <p className="font-sans text-base leading-relaxed text-slate-100">{task.question}</p>
      </motion.div>

      <div className="grid gap-2.5">
        {options.map(({ label, srcIdx, displayIdx }) => {
          const isAnswer = result && srcIdx === result.answer;
          const isPicked = selected === srcIdx;
          return (
            <button
              key={srcIdx}
              disabled={!!result}
              onClick={() => setSelected(srcIdx)}
              className={cn(
                "group flex items-start gap-3 rounded-xl border px-4 py-3 text-left text-sm transition-all",
                result
                  ? isAnswer
                    ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                    : isPicked ? "border-neon-red/50 bg-neon-red/10 text-neon-red" : "border-border/40 text-slate-500"
                  : isPicked
                    ? "border-cyber-400/70 bg-cyber-500/15 text-white shadow-glow"
                    : "border-border/60 bg-bg-panel/60 text-slate-300 hover:border-cyber-500/50 hover:text-white",
              )}
            >
              <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-md border border-current/40 font-mono text-xs font-bold">
                {String.fromCharCode(65 + displayIdx)}
              </span>
              <span className="leading-relaxed">{label}</span>
            </button>
          );
        })}
      </div>

      {wrongOnce && !result && (
        <p role="status" className="rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-3 py-2 text-sm text-neon-amber">
          Access denied. Re-read the question: what does the evidence actually prove? One more try, half credit.
        </p>
      )}

      {!result && (
        <button
          disabled={selected === null || busy}
          onClick={unlock}
          className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-5 py-2.5 text-sm font-bold text-bg transition hover:brightness-110 disabled:opacity-40"
        >
          <LockOpen className="h-4 w-4" /> {wrongOnce ? "Try again" : "Unlock"}
        </button>
      )}

      {result && (
        <>
          <Verdict correct={result.correct} title={result.correct ? "Unlocked" : "Lock held. Here is why"} xp={result.xp} explanation={result.explanation} />
          <ContinueButton onClick={() => complete(result.correct ? result.xp : 0, result.correct ? task.xp : 0)} />
        </>
      )}
    </div>
  );
}
