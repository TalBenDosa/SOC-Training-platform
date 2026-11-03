"use client";
import React, { useEffect, useMemo, useState } from "react";
import { Check, X, Filter, Lightbulb, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";

// A packet capture in a packet-analyser layout: filter bar, packet list,
// protocol tree and payload. Simulated; teaches and awards nothing.

type Lab = Extract<BriefingLab, { kind: "pcap" }>;
type Packet = Lab["packets"][number];

/** Row colours in the spirit of a packet analyser's default colouring rules. */
const ROW: Record<string, string> = {
  dns: "bg-[#1f3550]", http: "bg-[#1e3d2a]", tls: "bg-[#33284d]", tlsv1_3: "bg-[#33284d]", tcp: "bg-[#262b33]",
  udp: "bg-[#20324a]", icmp: "bg-[#4a2a3a]", dhcp: "bg-[#2a3f4f]", ftp: "bg-[#4a3a1e]", "ftp-data": "bg-[#4a3a1e]",
  ssh: "bg-[#2b3340]", smb2: "bg-[#3d3320]", smtp: "bg-[#22403a]", telnet: "bg-[#4f2626]", arp: "bg-[#3a3a22]",
};
const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

/** A small display-filter language: protocol names, ip.addr==X, a quoted
 *  "contains" string, or free text; every term must match. */
function matches(p: Packet, filter: string): boolean {
  const terms = filter.trim().toLowerCase().match(/"[^"]*"|\S+/g) ?? [];
  return terms.every(raw => {
    if (raw === "&&" || raw === "and") return true;
    const t = raw.replace(/^"|"$/g, "");
    const ip = t.match(/^ip\.(?:addr|src|dst)\s*==\s*(.+)$/);
    if (ip) return t.startsWith("ip.src") ? p.src === ip[1] : t.startsWith("ip.dst") ? p.dst === ip[1] : p.src === ip[1] || p.dst === ip[1];
    if (t === "contains" || t === "frame") return true;
    const proto = p.proto.toLowerCase();
    if (/^[a-z0-9_-]+$/.test(t) && (proto === t || proto.startsWith(t + "v") || p.tree.some(l => l.toLowerCase().startsWith(t)))) return true;
    return [p.src, p.dst, p.proto, p.info, ...p.tree, p.data ?? ""].some(f => f.toLowerCase().includes(t));
  });
}

export function PcapLab({ lab, onDone }: { lab: Lab; onDone: () => void }) {
  const [draft, setDraft] = useState("");
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<number>(lab.packets[0]?.no ?? 1);
  const [oi, setOi] = useState(0);
  const [answer, setAnswer] = useState("");
  const [result, setResult] = useState<"ok" | "bad" | null>(null);
  const [hint, setHint] = useState(false);
  const [fired, setFired] = useState(false);
  const done = oi >= lab.objectives.length;
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);

  const shown = useMemo(() => lab.packets.filter(p => !filter || matches(p, filter)), [lab.packets, filter]);
  const pkt = lab.packets.find(p => p.no === sel);
  const obj = lab.objectives[oi];

  function check() {
    if (!obj) return;
    setResult(obj.answer.some(a => norm(a) === norm(answer)) ? "ok" : "bad");
  }
  function next() { setOi(i => i + 1); setAnswer(""); setResult(null); setHint(false); }

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-white/10 bg-[#14171c] shadow-2xl">
        <div className="flex items-center gap-2 bg-[#22262d] px-3 py-1.5 text-[11px] font-semibold text-slate-300">
          <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />{lab.capture}
          <span className="ml-auto font-mono text-[10px] text-slate-500">Displayed: {shown.length} of {lab.packets.length}</span>
        </div>
        {/* Display filter */}
        <form onSubmit={e => { e.preventDefault(); setFilter(draft); }} className="flex items-center gap-2 border-b border-white/10 bg-[#1b1f25] px-2 py-1.5">
          <Filter className="h-3.5 w-3.5 shrink-0 text-emerald-300" />
          <input value={draft} onChange={e => setDraft(e.target.value)} placeholder="Apply a display filter ...  (dns, http, ip.addr==10.0.0.5, &quot;password&quot;)"
            aria-label="Display filter" spellCheck={false}
            className={cn("min-w-0 flex-1 rounded px-2 py-1 font-mono text-[12px] text-slate-100 outline-none placeholder:text-slate-500", draft && shown.length === 0 && filter === draft ? "bg-rose-900/40" : draft ? "bg-emerald-900/30" : "bg-black/30")} />
          <button type="submit" className="rounded border border-white/15 px-2 py-0.5 text-[11px] font-semibold text-slate-200 hover:bg-white/10">Apply</button>
          {filter && <button type="button" onClick={() => { setDraft(""); setFilter(""); }} className="text-[11px] text-slate-400 hover:text-white">Clear</button>}
        </form>
        {/* Packet list */}
        <div className="max-h-56 overflow-auto">
          <table className="w-full min-w-[40rem] font-mono text-[11.5px]">
            <thead className="sticky top-0 bg-[#2a2f37] text-left text-[10px] uppercase tracking-wider text-slate-300">
              <tr><th className="px-2 py-1">No.</th><th className="px-2 py-1">Time</th><th className="px-2 py-1">Source</th><th className="px-2 py-1">Destination</th><th className="px-2 py-1">Protocol</th><th className="px-2 py-1">Length</th><th className="px-2 py-1">Info</th></tr>
            </thead>
            <tbody>
              {shown.map(p => (
                <tr key={p.no} onClick={() => setSel(p.no)} aria-selected={p.no === sel}
                  className={cn("cursor-pointer text-slate-100", p.no === sel ? "bg-[#2563eb] text-white" : (ROW[p.proto.toLowerCase()] ?? "bg-[#262b33]") + " hover:brightness-125")}>
                  <td className="px-2 py-0.5">{p.no}</td><td className="px-2 py-0.5">{p.time}</td><td className="px-2 py-0.5">{p.src}</td><td className="px-2 py-0.5">{p.dst}</td>
                  <td className="px-2 py-0.5">{p.proto}</td><td className="px-2 py-0.5">{p.len}</td><td className="whitespace-nowrap px-2 py-0.5">{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* Details + bytes */}
        {pkt && (
          <div className="grid border-t border-white/10 md:grid-cols-[1.4fr_1fr]">
            <ul className="min-w-0 overflow-x-auto bg-[#181b20] px-3 py-2 font-mono text-[11.5px] text-slate-200">
              <li className="text-slate-400">Frame {pkt.no}: {pkt.len} bytes on wire ({pkt.len * 8} bits)</li>
              {pkt.tree.map((l, i) => <li key={i} className="whitespace-pre py-0.5"><span className="text-slate-500">▸ </span>{l}</li>)}
            </ul>
            <pre className="min-w-0 overflow-auto whitespace-pre-wrap break-all border-t border-white/10 bg-[#101216] px-3 py-2 font-mono text-[11px] text-amber-200/90 md:border-l md:border-t-0">
              {pkt.data ? pkt.data : <span className="text-slate-600">No readable payload: encrypted or header only.</span>}
            </pre>
          </div>
        )}
      </div>

      {/* Objectives */}
      <div className="grid gap-3 lg:grid-cols-[1fr_1.2fr]">
        <ol className="space-y-1.5">
          {lab.objectives.map((o, i) => (
            <li key={o.id} className={cn("flex gap-2 rounded-lg px-2 py-1.5 text-sm", i === oi ? "bg-white/[0.05] text-white" : i < oi ? "text-emerald-300" : "text-slate-500")}>
              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full border border-current text-[10px] font-bold">{i < oi ? <Check className="h-3 w-3" /> : i + 1}</span>{o.task}
            </li>
          ))}
        </ol>
        {obj ? (
          <div className="rounded-xl border border-white/10 bg-[#081120] p-3">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-sky-300">Objective {oi + 1} of {lab.objectives.length}</p>
            <p className="mt-1 text-sm font-semibold text-white">{obj.task}</p>
            {hint ? <p className="mt-2 text-xs text-amber-200">Try the filter: <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono">{obj.hint}</code></p>
              : <button onClick={() => setHint(true)} className="mt-2 inline-flex items-center gap-1 text-xs text-amber-300 hover:underline"><Lightbulb className="h-3.5 w-3.5" />Which filter?</button>}
            {result !== "ok" ? (
              <div className="mt-3 flex gap-2">
                <input value={answer} onChange={e => { setAnswer(e.target.value); setResult(null); }} onKeyDown={e => e.key === "Enter" && check()}
                  placeholder="Your answer" aria-label="Your answer"
                  className={cn("min-w-0 flex-1 rounded-lg border bg-black/30 px-3 py-2 font-mono text-sm text-white outline-none", result === "bad" ? "border-rose-500" : "border-white/15 focus:border-sky-400")} />
                <button onClick={check} className="rounded-lg border border-sky-300/60 px-3 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Check</button>
              </div>
            ) : (
              <>
                <p className="mt-3 text-sm leading-relaxed text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{obj.why}</p>
                <button onClick={next} className="mt-2 inline-flex items-center gap-1 rounded-lg border border-emerald-300/60 px-3 py-1.5 text-sm font-bold text-emerald-100 hover:bg-emerald-500/10">
                  {oi + 1 < lab.objectives.length ? "Next objective" : "Finish"} <ChevronRight className="h-4 w-4" />
                </button>
              </>
            )}
            {result === "bad" && <p className="mt-2 text-xs text-rose-300"><X className="mr-1 inline h-3.5 w-3.5" />Not what the packets show. Filter, select a packet and read its details.</p>}
          </div>
        ) : (
          <p className="h-fit rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3 text-sm font-semibold text-emerald-200"><Check className="mr-1 inline h-4 w-4" />Capture analysed. This is how analysts read traffic: filter, select, read the layers.</p>
        )}
      </div>
    </div>
  );
}
