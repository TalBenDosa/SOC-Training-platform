"use client";
import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Check, X, Lock, ShieldAlert, Wifi, AlertTriangle, MonitorSmartphone, FileWarning, Headphones, Activity, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab, EvidenceScreen } from "@/lib/rooms/experience";

// "What does it look like": one realistic screen at a time inside a monitor.
// The learner names what the screen shows; then numbered markers appear on the
// tell-tale parts and the callouts explain them. Teaches, awards nothing.

type Lab = Extract<BriefingLab, { kind: "evidence" }>;
type Mark = (at: string) => React.ReactNode;

/** Numbered marker pinned to a tell-tale part of a screen. */
function Pin({ n }: { n: number }) {
  return (
    <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 400, damping: 14 }}
      className="pointer-events-none absolute -top-2 right-0 z-10 grid h-6 w-6 place-items-center rounded-full bg-rose-500 font-sans text-xs font-black text-white shadow-[0_0_0_3px_rgba(244,63,94,0.35)]">
      {n}
    </motion.span>
  );
}

/** A small SVG line chart; `area` fills under the line, `base` draws a dashed baseline. */
function Chart({ series, stroke, area, base, height = 90 }: { series: number[]; stroke: string; area?: boolean; base?: number; height?: number }) {
  const max = Math.max(...series, base ?? 0) * 1.1 || 1;
  const pts = series.map((v, i) => `${(i / (series.length - 1)) * 300},${height - (v / max) * height}`);
  return (
    <svg viewBox={`0 0 300 ${height}`} className="h-full w-full" preserveAspectRatio="none">
      {area && <polygon points={`0,${height} ${pts.join(" ")} 300,${height}`} fill={stroke} fillOpacity={0.18} />}
      <polyline points={pts.join(" ")} fill="none" stroke={stroke} strokeWidth={2} vectorEffect="non-scaling-stroke" />
      {base !== undefined && <line x1={0} x2={300} y1={height - (base / max) * height} y2={height - (base / max) * height} stroke="#94a3b8" strokeDasharray="4 4" vectorEffect="non-scaling-stroke" />}
    </svg>
  );
}

function Screen({ s, mark }: { s: EvidenceScreen; mark: Mark }) {
  switch (s.type) {
    case "leak":
      return (
        <div className="bg-[#16181d] font-mono text-[12px] text-slate-300">
          <div className="relative flex items-center gap-2 bg-[#22252c] px-3 py-2 text-[13px] font-bold text-emerald-300">{s.site}{mark("site")}</div>
          <div className="px-3 pt-3">
            <p className="relative inline-block break-all pr-6 text-sm font-bold text-white">{s.title}{mark("title")}</p>
            <p className="text-[11px] text-slate-500">{s.meta}</p>
          </div>
          <div className="relative m-3 overflow-x-auto rounded border border-white/10 bg-black/40 p-2">
            {mark("rows")}
            <p className="whitespace-nowrap text-sky-300">{s.header.join(",")}</p>
            {s.rows.map((r, i) => <p key={i} className="whitespace-nowrap">{r.join(",")}</p>)}
            <p className="text-slate-600">...</p>
          </div>
        </div>
      );
    case "integrity":
      return (
        <div className="bg-[#0b1220] p-3 text-[12px] text-slate-300">
          <p className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-amber-300"><FileWarning className="h-4 w-4" />{s.tool}</p>
          <p className="relative mt-2 inline-block break-all pr-6 font-mono text-sm text-white">{s.file}{mark("file")}</p>
          <div className="relative mt-2 space-y-1 rounded border border-white/10 bg-black/30 p-2 font-mono text-[11px]">
            {mark("hashes")}
            <p><span className="text-slate-500">Expected SHA256 </span><span className="break-all text-emerald-300">{s.expected}</span></p>
            <p><span className="text-slate-500">Current SHA256  </span><span className="break-all text-rose-300">{s.current}</span></p>
            <p><span className="text-slate-500">Modified by </span>{s.changedBy} <span className="text-slate-500">at</span> {s.when}</p>
          </div>
          <div className="relative mt-2 rounded border border-white/10 font-mono text-[12px]">
            {mark("change")}
            <p className="bg-rose-500/15 px-2 py-1 text-rose-200">- {s.before}</p>
            <p className="bg-emerald-500/15 px-2 py-1 text-emerald-200">+ {s.after}</p>
          </div>
        </div>
      );
    case "status":
      return (
        <div className="bg-white p-4 text-slate-800">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-lg font-bold">{s.service}</p>
            <span className="relative rounded-full bg-rose-600 px-3 py-1 text-xs font-bold text-white">{s.state}{mark("state")}</span>
          </div>
          <div className="relative mt-3 h-24 rounded border border-slate-200 bg-slate-50 p-1">
            {mark("graph")}
            <Chart series={s.series} stroke="#16a34a" area />
          </div>
          <p className="mt-1 flex justify-between text-[10px] text-slate-400"><span>Availability, last 60 min</span><span>now</span></p>
          <p className="relative mt-2 inline-block rounded bg-rose-50 px-2 py-1 font-mono text-[12px] text-rose-700">{s.errors}{mark("errors")}</p>
        </div>
      );
    case "defaced":
      return (
        <div className="bg-[#e5e7eb]">
          <div className="relative mx-2 my-1.5 flex items-center gap-2 rounded-full bg-white px-3 py-1 text-[12px] text-slate-600"><Lock className="h-3 w-3" />{s.url}{mark("url")}</div>
          <div className="relative grid min-h-[11rem] place-items-center bg-black px-4 py-6 text-center">
            {mark("banner")}
            <div>
              <p className="font-mono text-2xl font-black uppercase tracking-wider text-lime-400 sm:text-3xl">{s.banner}</p>
              <p className="mt-2 font-mono text-[12px] text-lime-200/80">{s.text}</p>
            </div>
          </div>
        </div>
      );
    case "ransom":
      return (
        <div className="relative min-h-[15rem] bg-[radial-gradient(circle_at_30%_20%,#4c0519,#1a0108)] p-3">
          <div className="relative grid w-44 grid-cols-1 gap-1.5 sm:absolute sm:left-3 sm:top-3">
            {mark("files")}
            {s.files.map(f => (
              <span key={f} className="flex items-center gap-1.5 truncate rounded bg-black/30 px-1.5 py-0.5 font-mono text-[10px] text-rose-100"><FileWarning className="h-3 w-3 shrink-0" />{f}</span>
            ))}
          </div>
          <div className="relative mx-auto mt-3 max-w-sm rounded-md border-2 border-rose-500 bg-[#0c0a0a] p-3 shadow-2xl sm:mt-0 sm:ml-48">
            {mark("note")}
            <p className="flex items-center gap-2 font-black uppercase tracking-wide text-rose-400"><Lock className="h-4 w-4" />{s.heading}</p>
            {s.note.map(l => <p key={l} className="mt-1.5 text-[12px] leading-snug text-slate-200">{l}</p>)}
            <p className="relative mt-2 break-all rounded bg-white/5 px-2 py-1 font-mono text-[11px] text-amber-300">{s.wallet}{mark("wallet")}</p>
          </div>
        </div>
      );
    case "traffic":
      return (
        <div className="bg-[#0b1220] p-3 text-slate-300">
          <p className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-sky-300"><Activity className="h-4 w-4" />{s.service} · requests per second</p>
          <div className="relative mt-2 h-28 rounded border border-white/10 bg-black/30 p-1">
            {mark("graph")}
            <Chart series={s.series} stroke="#f43f5e" area base={s.normal} />
          </div>
          <p className="mt-1 text-[10px] text-slate-500">Dashed line: a normal Friday ({s.normal} req/s)</p>
          <div className="relative mt-2 rounded border border-white/10">
            {mark("sources")}
            <p className="grid grid-cols-3 bg-white/5 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400"><span>Source IP</span><span>Country</span><span className="text-right">Req/s</span></p>
            {s.sources.map(r => <p key={r.ip} className="grid grid-cols-3 px-2 py-0.5 font-mono text-[11px]"><span>{r.ip}</span><span>{r.country}</span><span className="text-right">{r.rate}</span></p>)}
          </div>
        </div>
      );
    case "certwarn":
      return (
        <div className="bg-[#f1f3f4]">
          <div className="flex items-center gap-2 bg-[#dee1e6] px-3 py-1.5 text-[11px] text-slate-600">
            <span className="relative inline-flex items-center gap-1 rounded bg-white px-2 py-0.5"><Wifi className="h-3 w-3" />{s.network}{mark("network")}</span>
          </div>
          <div className="relative mx-2 my-1.5 flex items-center gap-2 rounded-full bg-white px-3 py-1 text-[12px] text-rose-600"><AlertTriangle className="h-3 w-3" />Not secure | {s.url}{mark("url")}</div>
          <div className="px-5 py-6 text-slate-700">
            <ShieldAlert className="h-10 w-10 text-rose-600" />
            <p className="mt-3 text-xl font-semibold text-slate-800">Your connection is not private</p>
            <p className="mt-2 text-[13px] leading-relaxed">{s.detail}</p>
            <p className="relative mt-3 inline-block font-mono text-[11px] text-slate-500">{s.error}{mark("error")}</p>
          </div>
        </div>
      );
    case "ticket":
      return (
        <div className="bg-white p-3 text-[12px] text-slate-800">
          <p className="flex items-center gap-2 border-b border-slate-200 pb-2 font-bold"><Headphones className="h-4 w-4 text-sky-600" />Service Desk · Ticket {s.id} · Phone call</p>
          <dl className="mt-2 grid grid-cols-[6.5rem_1fr] gap-y-1.5">
            <dt className="text-slate-500">Caller</dt><dd className="relative">{s.caller}{mark("caller")}</dd>
            <dt className="text-slate-500">Caller ID</dt><dd className="font-mono">{s.callerId}</dd>
            <dt className="text-slate-500">Request</dt><dd className="relative font-semibold">{s.request}{mark("request")}</dd>
            <dt className="text-slate-500">Agent notes</dt><dd className="relative italic text-slate-600">{s.notes}</dd>
          </dl>
          <p className="relative mt-2 rounded bg-amber-50 px-2 py-1 text-amber-800">{s.pressure}{mark("pressure")}</p>
        </div>
      );
    case "siem":
      return (
        <div className="bg-[#0b0f17] p-3 text-[12px] text-slate-300">
          <p className="text-[11px] font-bold uppercase tracking-widest text-emerald-300">{s.product}</p>
          <p className="relative mt-2 break-all rounded border border-white/10 bg-black/40 px-2 py-1.5 pr-6 font-mono text-[11.5px] text-sky-200">{s.query}{mark("query")}</p>
          <div className="relative mt-2 overflow-x-auto rounded border border-white/10">
            {mark("results")}
            <table className="w-full min-w-[26rem] font-mono text-[11px]">
              <thead className="bg-white/5 text-left text-[10px] uppercase text-slate-400"><tr>{s.header.map(h => <th key={h} className="px-2 py-1">{h}</th>)}</tr></thead>
              <tbody>{s.rows.map((r, i) => <tr key={i} className="border-t border-white/5">{r.map((c, k) => <td key={k} className="whitespace-nowrap px-2 py-1">{c}</td>)}</tr>)}</tbody>
            </table>
          </div>
          <p className="relative mt-2 inline-block rounded bg-rose-500/15 px-2 py-1 pr-6 text-[11.5px] font-semibold text-rose-200">Correlation rule fired: {s.rule}{mark("rule")}</p>
        </div>
      );
    case "edrtree":
      return (
        <div className="bg-[#101318] p-3 text-[12px] text-slate-300">
          <p className="flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-red-400"><span>Process tree · {s.host}</span></p>
          <div className="relative mt-2 rounded border border-white/10 bg-black/30 p-2 font-mono text-[11.5px]">
            {mark("tree")}
            {s.nodes.map((n, i) => (
              <p key={i} className={cn("whitespace-nowrap py-0.5", n.bad ? "text-rose-300" : "text-slate-200")} style={{ paddingLeft: n.depth * 18 }}>
                {n.depth > 0 && <span className="text-slate-600">└─ </span>}<span className="font-bold">{n.name}</span> <span className="text-slate-500">{n.detail}</span>
              </p>
            ))}
          </div>
          <p className="relative mt-2 inline-block rounded bg-red-500/15 px-2 py-1 pr-6 text-[11.5px] font-semibold text-red-200">{s.verdict}{mark("verdict")}</p>
        </div>
      );
    case "soarrun":
      return (
        <div className="bg-[#0d1117] p-3 text-[12px] text-slate-300">
          <p className="text-[11px] font-bold uppercase tracking-widest text-violet-300">Playbook run · {s.playbook}</p>
          <p className="relative mt-2 inline-block pr-6 text-slate-400">Trigger: <span className="text-slate-100">{s.trigger}</span>{mark("trigger")}</p>
          <ol className="relative mt-2 space-y-1 rounded border border-white/10 bg-black/30 p-2">
            {mark("steps")}
            {s.steps.map((st, i) => (
              <li key={i} className="flex items-start gap-2 text-[11.5px]">
                <span className={cn("mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full text-[9px] font-bold", st.ok ? "bg-emerald-500/30 text-emerald-200" : "bg-amber-500/30 text-amber-200")}>{st.ok ? "✓" : "!"}</span>
                <span><span className="font-semibold text-slate-100">{st.name}</span> <span className="text-slate-400">{st.result}</span></span>
              </li>
            ))}
          </ol>
        </div>
      );
    case "tip":
      return (
        <div className="bg-[#f8fafc] p-4 text-slate-800">
          <p className="text-[11px] font-bold uppercase tracking-widest text-slate-500">Threat intelligence · indicator lookup</p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <p className="relative break-all pr-6 font-mono text-lg font-bold">{s.indicator}{mark("indicator")}</p>
            <span className="rounded bg-slate-200 px-2 py-0.5 text-[11px] font-semibold">{s.kind}</span>
            <span className="relative rounded bg-rose-600 px-2 py-0.5 pr-6 text-[11px] font-bold text-white">{s.score}{mark("score")}</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">{s.tags.map(t => <span key={t} className="rounded-full border border-slate-300 px-2 py-0.5 text-[11px]">{t}</span>)}</div>
          <ul className="relative mt-3 space-y-1 rounded border border-slate-200 bg-white p-2 text-[12px]">
            {mark("sightings")}
            {s.sightings.map(x => <li key={x}>• {x}</li>)}
          </ul>
        </div>
      );
    case "sms":
      return (
        <div className="grid place-items-center bg-[#0f172a] py-4">
          <div className="w-64 rounded-[2rem] border-4 border-slate-700 bg-white p-3 text-slate-800">
            <p className="relative text-center text-[11px] font-bold text-slate-500">{s.from}{mark("sender")}</p>
            <p className="text-center text-[10px] text-slate-400">{s.time}</p>
            <div className="relative mt-2 rounded-2xl rounded-tl-sm bg-slate-100 px-3 py-2 text-[13px] leading-snug">
              {mark("text")}
              {s.text} <span className="relative break-all text-blue-600 underline">{s.link}{mark("link")}</span>
            </div>
          </div>
        </div>
      );
  }
}

export function EvidenceLab({ lab, onDone }: { lab: Lab; onDone: () => void }) {
  const [idx, setIdx] = useState(0);
  const [solved, setSolved] = useState(false);
  const [wrong, setWrong] = useState<string | null>(null);
  const [fired, setFired] = useState(false);
  const item = lab.items[idx];
  const last = idx === lab.items.length - 1;
  useEffect(() => { if (last && solved && !fired) { setFired(true); onDone(); } }, [last, solved, fired, onDone]);

  const order = item.callouts.map(c => c.at);
  const mark: Mark = at => solved && order.includes(at) ? <Pin n={order.indexOf(at) + 1} /> : null;

  function pick(id: string) {
    if (solved) return;
    if (id === item.answer) { setSolved(true); setWrong(null); } else setWrong(id);
  }
  function next() { setIdx(i => i + 1); setSolved(false); setWrong(null); }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-xs">
        <span className="inline-flex items-center gap-1.5 font-mono uppercase tracking-widest text-sky-300"><MonitorSmartphone className="h-4 w-4" /> Screen {idx + 1} / {lab.items.length}</span>
        <span className="flex gap-1">{lab.items.map((it, i) => <span key={it.id} className={cn("h-1.5 w-6 rounded-full", i < idx || (i === idx && solved) ? "bg-emerald-400" : i === idx ? "bg-sky-400" : "bg-white/10")} />)}</span>
      </div>

      {/* The monitor */}
      <motion.div key={item.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="mx-auto max-w-2xl rounded-2xl border-[6px] border-[#1e2533] bg-[#1e2533] shadow-[0_20px_60px_-20px_rgba(0,0,0,0.9)]">
        <div className="flex items-center gap-1.5 rounded-t-lg bg-[#2a3142] px-3 py-1.5 text-[11px] font-semibold text-slate-300">
          <span className="h-2 w-2 rounded-full bg-rose-400" /><span className="h-2 w-2 rounded-full bg-amber-400" /><span className="h-2 w-2 rounded-full bg-emerald-400" />
          <span className="ml-2 truncate">{item.caption}</span>
        </div>
        <div className="overflow-hidden rounded-b-lg"><Screen s={item.screen} mark={mark} /></div>
      </motion.div>

      {/* What am I looking at? */}
      <div className="rounded-2xl border border-white/10 bg-[#081120] p-3">
        <p className="mb-2 text-sm font-bold text-white">What are you looking at?</p>
        <div className="flex flex-wrap gap-2">
          {lab.choices.map(c => (
            <motion.button key={c.id} onClick={() => pick(c.id)} disabled={solved}
              animate={wrong === c.id ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
              className={cn("rounded-xl border px-3 py-2 text-sm font-semibold transition enabled:hover:bg-white/5",
                solved && c.id === item.answer ? "border-emerald-400 bg-emerald-500/15 text-emerald-100" : wrong === c.id ? "border-rose-500 bg-rose-500/10 text-rose-200" : "border-white/15 text-slate-200")}>
              {c.label}
            </motion.button>
          ))}
        </div>
        {wrong && !solved && <p className="mt-2 text-sm text-rose-300"><X className="mr-1 inline h-4 w-4" />Not that. Look at the screen again: what is the strongest clue?</p>}
        {solved && (
          <motion.ol initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 space-y-1.5">
            <li className="text-sm font-bold text-emerald-300"><Check className="mr-1 inline h-4 w-4" />Right. Here is what gives it away:</li>
            {item.callouts.map((c, i) => (
              <li key={c.at} className="flex gap-2 text-sm leading-relaxed text-slate-200">
                <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-rose-500 text-[11px] font-black text-white">{i + 1}</span>{c.text}
              </li>
            ))}
          </motion.ol>
        )}
        {solved && !last && (
          <button onClick={next} className="mt-3 inline-flex items-center gap-1.5 rounded-xl border border-sky-300/60 px-4 py-2 text-sm font-bold text-sky-100 hover:bg-sky-500/10">
            Next screen <ChevronRight className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
