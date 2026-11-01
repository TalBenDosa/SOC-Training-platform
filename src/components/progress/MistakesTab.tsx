"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AlertTriangle, Loader2, RotateCcw, XCircle, CheckCircle2, Scale } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import type { ProgressPayload } from "@/lib/progress/selfView";
import type { SelfMistake, SelfMistakesPayload } from "@/app/api/me/mistakes/route";
import { fmtDate, fmtMs } from "./format";
import { EmptyState, SectionTitle } from "./ui";

type Filter = "all" | "unsolved" | "room" | "quiz" | "lesson" | "scenario";

// ─── Spaced review (device-local; a convenience, never a grade) ───────────────
// "Got it" pushes a mistake out by 1 → 3 → 7 → 14 days; "Still unsure" brings it back tomorrow.
const REVIEW_KEY = "soc_mistake_review_v1";
type ReviewState = Record<string, { box: number; due: number }>;
const BOX_DAYS = [1, 3, 7, 14];
function loadReview(): ReviewState {
  try { const raw = localStorage.getItem(REVIEW_KEY); const v = raw ? JSON.parse(raw) : {}; return v && typeof v === "object" ? v as ReviewState : {}; } catch { return {}; }
}
function saveReview(s: ReviewState) { try { localStorage.setItem(REVIEW_KEY, JSON.stringify(s)); } catch { /* storage blocked: review still works for this visit */ } }

export function MistakesTab({ critical }: { critical: ProgressPayload["criticalMisses"] }) {
  const [data, setData] = useState<SelfMistakesPayload | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [reviewing, setReviewing] = useState(false);

  useEffect(() => {
    let alive = true;
    fetch("/api/me/mistakes", { cache: "no-store" })
      .then(async r => { if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error ?? "Couldn't load your mistakes."); return r.json(); })
      .then(d => { if (alive) setData(d); })
      .catch(e => { if (alive) setErr(e instanceof Error ? e.message : "Couldn't load your mistakes."); });
    return () => { alive = false; };
  }, []);

  const areas = useMemo(() => {
    if (!data) return [];
    return data.areas.map(a => ({
      ...a,
      sources: a.sources.filter(s => filter === "all" || filter === "unsolved" || s.kind === filter)
        .map(s => ({ ...s, mistakes: s.mistakes.filter(m => filter !== "unsolved" || m.solved === false) }))
        .filter(s => s.mistakes.length > 0),
    })).filter(a => a.sources.length > 0);
  }, [data, filter]);

  const reviewable = useMemo(() => (data?.areas ?? []).flatMap(a => a.sources.flatMap(s => s.mistakes.filter(m => m.correct !== null).map(m => ({ m, source: s.title, href: s.href })))), [data]);

  const allMissed = [
    ...critical.map(c => ({ key: `${c.source}|${c.title}|${c.at}`, title: c.title, where: c.source === "live" ? "Live feed" : "Team exercise", at: c.at, detail: c.detail, practice: c.practice ? { href: `/rooms/${encodeURIComponent(c.practice.id)}`, title: c.practice.title } : null, technique: c.technique })),
    ...(data?.missedAttacks ?? []).map(m => ({ key: `room|${m.roomId}|${m.at}|${m.prompt}`, title: m.prompt ?? m.roomTitle, where: `Room: ${m.roomTitle}`, at: m.at, detail: "Called a real attack benign on the first try", practice: { href: m.href, title: m.roomTitle }, technique: null })),
  ];

  return (
    <div className="space-y-4">
      <Card className={allMissed.length ? "border-severity-high/40" : undefined}>
        <SectionTitle icon={<AlertTriangle aria-hidden="true" className="h-4 w-4 text-severity-high" />}
          info="The most dangerous mistake for an analyst: a real attack that ended up unreported, closed as benign, or left after opening it. Shown first and on its own.">
          Missed attacks ({allMissed.length})
        </SectionTitle>
        {allMissed.length === 0 ? (
          <p className="mt-2 text-sm text-slate-400">No missed attacks on record. Keep it that way.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {allMissed.slice(0, 12).map(m => (
              <li key={m.key} className="rounded-md border border-severity-high/30 bg-severity-high/5 px-3 py-2.5">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <p className="text-sm font-semibold text-slate-100" dir="auto">{m.title}</p>
                  <span className="text-[11px] text-slate-400">{m.where}{m.at ? ` · ${fmtDate(m.at)}` : ""}</span>
                </div>
                {m.detail && <p className="mt-1 text-[12px] text-slate-300">{m.detail}{m.technique ? ` (${m.technique})` : ""}</p>}
                {m.practice && <Link href={m.practice.href} className="mt-1.5 inline-block text-[11px] font-semibold text-cyber-300 hover:text-cyber-200">Practice: {m.practice.title} →</Link>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      {err && <p role="alert" className="rounded-md border border-severity-high/40 bg-severity-high/5 px-4 py-3 text-sm text-slate-200">{err}</p>}
      {!data && !err && <p className="flex items-center gap-2 text-sm text-slate-400"><Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" /> Loading your mistakes…</p>}

      {data && (data.pattern.fn + data.pattern.fp > 0) && (
        <Card>
          <SectionTitle icon={<Scale aria-hidden="true" className="h-4 w-4 text-neon-amber" />}
            info="From analyst-verdict tasks whose answer you have already seen. A real attack called benign (false negative) and a benign event called an attack (false positive) are different habits, so they are never added together.">
            Your verdict pattern
          </SectionTitle>
          <p className="mt-2 text-sm text-slate-200">
            Real attacks called benign: <strong className="font-mono">{data.pattern.fn}</strong> · Benign events called attacks: <strong className="font-mono">{data.pattern.fp}</strong>
          </p>
          <p className="mt-1 text-[12px] text-slate-400">
            {data.pattern.fn > data.pattern.fp ? "You lean towards closing alerts. Before calling something benign, name the specific evidence that rules the attack out."
              : data.pattern.fp > data.pattern.fn ? "You lean towards escalating. Check for the benign explanation (admin task, known tool, scanner) before calling an attack."
              : "Your misses go both ways. Slow down on the evidence before each verdict."}
          </p>
        </Card>
      )}

      {data && reviewing && <ReviewMode items={reviewable} onExit={() => setReviewing(false)} />}

      {data && !reviewing && (
        data.areas.length === 0 ? (
          <EmptyState title="No mistakes yet" body="Every question you get wrong on the first try lands here with the question, what you answered and, once you have seen it, the right answer." action={<Link href="/rooms" className="text-xs font-semibold text-cyber-300">Start a room →</Link>} />
        ) : (
          <Card padded={false}>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
              <h3 className="text-sm font-semibold text-white">By topic</h3>
              <div className="flex flex-wrap items-center gap-2">
                <label className="flex items-center gap-2 text-[11px] text-slate-400">
                  <span>Show</span>
                  <select id="mistakes-filter" value={filter} onChange={e => setFilter(e.target.value as Filter)} className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-slate-200">
                    <option value="all">All mistakes</option>
                    <option value="unsolved">Not solved yet</option>
                    <option value="room">Rooms</option>
                    <option value="quiz">Quizzes</option>
                    <option value="lesson">Lesson checks</option>
                    <option value="scenario">Scenarios</option>
                  </select>
                </label>
                {reviewable.length > 0 && (
                  <button type="button" onClick={() => setReviewing(true)} className="inline-flex items-center gap-1.5 rounded-md border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 hover:bg-cyber-500/20">
                    <RotateCcw aria-hidden="true" className="h-3.5 w-3.5" /> Review my mistakes
                  </button>
                )}
              </div>
            </div>
            {areas.length === 0 && <p className="px-4 py-6 text-sm text-slate-400">Nothing matches this filter.</p>}
            {areas.map(a => (
              <details key={a.area} className="group border-t border-border/60 first:border-t-0" open={areas.length <= 2}>
                <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-4 py-3 hover:bg-bg-hover">
                  <span className="text-sm font-semibold text-slate-100">{a.label}</span>
                  <span className="text-[11px] text-slate-400">{a.mistakes} mistake{a.mistakes === 1 ? "" : "s"}{a.unsolved ? ` · ${a.unsolved} not solved` : ""}</span>
                </summary>
                <div className="space-y-3 px-4 pb-4">
                  {a.sources.map(s => (
                    <div key={s.kind + s.id}>
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <p className="text-[12px] font-semibold text-slate-300" dir="auto">{s.title}</p>
                        <span className="text-[11px] text-slate-400">{s.firstTryCorrect}/{s.items} right first try</span>
                      </div>
                      <ul className="mt-2 space-y-2">
                        {s.mistakes.map(m => <MistakeCard key={m.key} m={m} href={s.href} />)}
                      </ul>
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </Card>
        )
      )}
    </div>
  );
}

function MistakeCard({ m, href }: { m: SelfMistake; href: string | null }) {
  return (
    <li className={cn("rounded-md border bg-bg px-3 py-2.5", m.verdictError === "fn" ? "border-severity-high/40" : "border-border")}>
      <p className="text-[11px] text-slate-400">
        <XCircle aria-hidden="true" className="mr-1 inline h-3.5 w-3.5 text-severity-critical" />
        {[m.position, m.typeLabel].filter(Boolean).join(" · ")}
      </p>
      {m.prompt && <p className="mt-1 text-[13px] text-slate-100" dir="auto">{m.prompt}</p>}
      <dl className="mt-1.5 grid gap-x-4 gap-y-1 text-[12px] sm:grid-cols-2">
        <div><dt className="inline text-slate-400">You answered: </dt><dd className="inline text-slate-200" dir="auto">{m.chosen ?? "–"}{m.tries ? " (try 1)" : ""}</dd></div>
        <div>
          <dt className="inline text-slate-400">Correct: </dt>
          <dd className="inline" dir="auto">{m.correct !== null ? <span className="text-neon-green">{m.correct}</span> : <span className="text-slate-400">Not shown until you solve it</span>}</dd>
        </div>
      </dl>
      {m.explanation && <p className="mt-1.5 text-[12px] leading-relaxed text-slate-300"><span className="text-slate-400">Why: </span>{m.explanation}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-400">
        {m.solved === true && m.triesToSolve && <span className="text-neon-green"><CheckCircle2 aria-hidden="true" className="mr-0.5 inline h-3 w-3" />Solved on try {m.triesToSolve}</span>}
        {m.solved === false && <span>Not solved yet · {m.tries} tr{m.tries === 1 ? "y" : "ies"}</span>}
        {m.latencyMs !== null && <span>⏱ {fmtMs(m.latencyMs)}</span>}
        {m.at && <span>{fmtDate(m.at)}</span>}
        {href && <Link href={href} className="ml-auto font-semibold text-cyber-300 hover:text-cyber-200">{m.solved === false ? "Try again" : "Open"}</Link>}
      </div>
    </li>
  );
}

function ReviewMode({ items, onExit }: { items: { m: SelfMistake; source: string; href: string | null }[]; onExit: () => void }) {
  const [state, setState] = useState<ReviewState>({});
  const [shown, setShown] = useState(false);
  const [idx, setIdx] = useState(0);
  useEffect(() => { setState(loadReview()); }, []);
  const now = Date.now();
  const due = useMemo(() => items.filter(x => (state[x.m.key]?.due ?? 0) <= now), [items, state, now]);
  const cur = due[idx];
  const grade = (gotIt: boolean) => {
    if (!cur) return;
    const prev = state[cur.m.key]?.box ?? -1;
    const box = gotIt ? Math.min(BOX_DAYS.length - 1, prev + 1) : 0;
    const next = { ...state, [cur.m.key]: { box, due: Date.now() + BOX_DAYS[gotIt ? box : 0] * 86_400_000 } };
    setState(next); saveReview(next); setShown(false);
    setIdx(i => (i >= due.length - 1 ? 0 : i));
  };
  return (
    <Card className="border-cyber-500/40">
      <SectionTitle icon={<RotateCcw aria-hidden="true" className="h-4 w-4 text-cyber-300" />}
        right={<button type="button" onClick={onExit} className="text-[11px] font-semibold text-slate-400 hover:text-slate-200">Back to the list</button>}
        info="Only mistakes whose answer you have already seen. 'Got it' brings a question back after 1, 3, 7 and then 14 days; 'Still unsure' brings it back tomorrow. Kept on this device, no XP.">
        Review my mistakes
      </SectionTitle>
      {!cur ? (
        <p className="mt-3 text-sm text-slate-300">Nothing due right now. Come back tomorrow for the next round.</p>
      ) : (
        <div className="mt-3">
          <p className="text-[11px] text-slate-400">{due.length} due · {cur.source}</p>
          <p className="mt-2 text-sm text-slate-100" dir="auto">{cur.m.prompt ?? "Question"}</p>
          <p className="mt-1 text-[12px] text-slate-400">Last time you answered: <span className="text-slate-300" dir="auto">{cur.m.chosen ?? "–"}</span></p>
          {!shown ? (
            <button type="button" onClick={() => setShown(true)} className="mt-3 rounded-md border border-border bg-bg px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-bg-hover">Show the answer</button>
          ) : (
            <div className="mt-3 rounded-md border border-neon-green/30 bg-neon-green/5 px-3 py-2">
              <p className="text-[13px] text-neon-green" dir="auto">{cur.m.correct}</p>
              {cur.m.explanation && <p className="mt-1 text-[12px] text-slate-300">{cur.m.explanation}</p>}
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={() => grade(true)} className="rounded-md border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-xs font-semibold text-neon-green">Got it</button>
                <button type="button" onClick={() => grade(false)} className="rounded-md border border-border bg-bg px-3 py-1.5 text-xs font-semibold text-slate-200">Still unsure</button>
                {cur.href && <Link href={cur.href} className="ml-auto self-center text-[11px] font-semibold text-cyber-300">Open the source →</Link>}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
