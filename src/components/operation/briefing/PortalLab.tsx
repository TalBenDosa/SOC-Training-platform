"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { Bell, Bot, Check, ChevronDown, ChevronRight, CircleHelp, FileText, Heart, Lightbulb, ListChecks, Menu, RefreshCw, Search, Settings, Shield, SquareTerminal, Trophy, User, X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";

// A working analyst console: the layout, vocabulary and order of work of the real thing,
// with no logos (docs/ui-reference/real-console-ui.md). The learner is given the job, one
// step at a time, and does it by navigating the console. Looking around is free, as it is
// at work: only a wrong action costs a life, and it says why. A real console has no undo
// prompt for a bad call, so the wrong button does nothing but teach.

type Lab = Extract<BriefingLab, { kind: "portal" }>;
type Page = Lab["pages"][string];
type Record_ = Lab["records"][string];

const TONE: Record<string, string> = { critical: "#a4262c", high: "#d13438", medium: "#f7630c", low: "#c19c00", info: "#8a8886" };
const LIVES = 3;

export function PortalLab({ lab, onDone }: { lab: Lab; onDone: () => void }) {
  const [run, setRun] = useState(0);
  return <PortalRun key={run} lab={lab} onDone={onDone} onRetry={() => setRun(r => r + 1)} />;
}

function PortalRun({ lab, onDone, onRetry }: { lab: Lab; onDone: () => void; onRetry: () => void }) {
  const [pageId, setPageId] = useState(lab.home);
  const [recordId, setRecordId] = useState<string | null>(null);
  const [full, setFull] = useState(false);
  const [logs, setLogs] = useState(false);
  const [tab, setTab] = useState<"overview" | "entities">("overview");
  const [picked, setPicked] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [step, setStep] = useState(0);
  const [lives, setLives] = useState(LIVES);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [hint, setHint] = useState(false);
  const [shake, setShake] = useState(0);

  const cur = lab.steps[step];
  const won = step >= lab.steps.length;
  const lost = lives <= 0;
  const page: Page = lab.pages[pageId];
  const rec: Record_ | null = recordId ? lab.records[recordId] : null;
  const value = (k: string, fallback: string) => values[k] ?? fallback;

  /** Every click in the console lands here. Returns true if the click is allowed to act. */
  function hit(target: string, commit: boolean): boolean {
    if (won || lost) return !commit;
    if (target === cur.target) {
      setNote({ ok: true, text: cur.why });
      setHint(false);
      const next = step + 1;
      setStep(next);
      if (next >= lab.steps.length) onDone();
      return true;
    }
    const trap = lab.traps[target];
    if (trap || commit) {
      setLives(l => l - 1);
      setShake(s => s + 1);
      setNote({ ok: false, text: trap ?? cur.hint });
      return false;
    }
    return true; // looking around is free
  }

  const go = (id: string) => { hit(`menu:${id}`, false); setPageId(id); setRecordId(null); setFull(false); setLogs(false); setMenuOpen(null); setPicked(null); };
  const openRow = (r: NonNullable<Page["table"]>["rows"][number]) => {
    if (!hit(`row:${r.id}`, false)) return;
    if (r.record) { setRecordId(r.record); setFull(false); setLogs(false); setTab("overview"); setPicked(null); }
    else setPicked(r.id);
  };
  const act = (id: string, then?: () => void) => { setMenuOpen(null); if (hit(`action:${id}`, true)) then?.(); };
  const set = (field: string, v: string) => { setMenuOpen(null); if (hit(`set:${field}:${v}`, true)) setValues(s => ({ ...s, [field]: v === "Assign to me" ? "You" : v })); };

  const ui = { lab, page, rec, full, setFull: () => act("full", () => setFull(true)), logs, openLogs: () => act("logs", () => setLogs(true)), closeLogs: () => setLogs(false), tab, setTab, picked, go, openRow, act, set, value, menuOpen, setMenuOpen, pageId, hit, setPicked };

  return (
    <div>
      <div className="mb-3 rounded-xl border border-white/10 bg-black/30 p-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-300">
          <span className="inline-flex items-center gap-0.5" aria-label={`${lives} of ${LIVES} lives left`}>
            {Array.from({ length: LIVES }, (_, i) => <Heart key={i} className={cn("h-4 w-4", i < lives ? "fill-rose-400 text-rose-400" : "text-slate-600")} />)}
          </span>
          <span className="font-semibold text-slate-200">{won ? "Job done" : `Step ${step + 1} of ${lab.steps.length}`}</span>
          <div className="ml-auto flex gap-1" aria-hidden>
            {lab.steps.map((s, i) => <span key={s.id} className={cn("h-1.5 w-5 rounded-full", i < step ? "bg-emerald-400" : i === step ? "bg-white" : "bg-white/15")} />)}
          </div>
        </div>
        {!won && !lost && (
          <>
            <p className="mt-2 text-base font-bold leading-snug text-white">{cur.ask}</p>
            {hint ? <p className="mt-1 text-sm text-amber-200">{cur.hint}</p>
              : <button onClick={() => setHint(true)} className="mt-1 inline-flex items-center gap-1 text-xs text-amber-300 hover:underline"><Lightbulb className="h-3.5 w-3.5" />Where do I look?</button>}
          </>
        )}
      </div>

      {note && !lost && (
        <div role="status" className={cn("mb-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100")}>{note.text}</div>
      )}

      {lost ? (
        <div role="status" className="rounded-2xl border border-rose-400/40 bg-rose-500/10 p-6 text-center">
          <p className="text-lg font-extrabold text-white">Shift over</p>
          <p className="mx-auto mt-1 max-w-lg text-sm leading-relaxed text-slate-100">{note?.text}</p>
          <div className="mx-auto mt-3 max-w-lg rounded-xl border border-white/10 bg-black/30 p-3 text-left">
            <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-amber-300"><Lightbulb className="h-3.5 w-3.5" />What to take from this</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-100">{lab.lesson}</p>
          </div>
          <button autoFocus onClick={onRetry} className="mt-4 rounded-xl bg-white px-5 py-2.5 text-sm font-bold text-[#04121a]">Run it again</button>
        </div>
      ) : (
        <motion.div key={shake} animate={shake ? { x: [0, -6, 6, -3, 3, 0] } : undefined} className="overflow-x-auto rounded-xl border border-white/10">
          {lab.skin === "azure" ? <Azure {...ui} /> : lab.skin === "vsphere" ? <Vsphere {...ui} /> : lab.skin === "entra" ? <Entra {...ui} /> : <Edr {...ui} />}
        </motion.div>
      )}

      {won && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} role="status" className="mt-3 rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-4">
          <p className="flex items-center gap-2 text-sm font-bold text-emerald-200"><Trophy className="h-4 w-4" />Handled like an analyst</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-200">{lab.lesson}</p>
        </motion.div>
      )}
    </div>
  );
}

type Ui = {
  lab: Lab; page: Page; rec: Record_ | null; full: boolean; setFull: () => void; logs: boolean; openLogs: () => void; closeLogs: () => void;
  tab: "overview" | "entities"; setTab: (t: "overview" | "entities") => void; picked: string | null;
  go: (id: string) => void; openRow: (r: NonNullable<Page["table"]>["rows"][number]) => void; act: (id: string, then?: () => void) => void;
  set: (field: string, v: string) => void; value: (k: string, f: string) => string; menuOpen: string | null; setMenuOpen: (m: string | null) => void;
  pageId: string; hit: (t: string, c: boolean) => boolean; setPicked: (p: string | null) => void;
};

/** An Azure-style drop-down in the Severity / Status / Owner strip. */
function AzureDrop({ ui, field, label, value, options, tone }: { ui: Ui; field: string; label: string; value: string; options?: string[]; tone?: string }) {
  const open = ui.menuOpen === field;
  return (
    <div className="relative flex-1 border-r border-[#e1dfdd] last:border-r-0" style={tone ? { borderLeft: `4px solid ${tone}` } : undefined}>
      <button onClick={() => ui.setMenuOpen(open ? null : field)} aria-expanded={open} className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left hover:bg-[#f3f2f1]">
        <span className="min-w-0"><span className="block truncate text-[13px] font-semibold text-[#201f1e]">{value}</span><span className="block text-[11px] text-[#605e5c]">{label}</span></span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0 text-[#605e5c]" />
      </button>
      {open && options && (
        <div className="absolute left-0 top-full z-30 min-w-full rounded-sm border border-[#c8c6c4] bg-white py-1 shadow-lg">
          {options.map(o => <button key={o} onClick={() => ui.set(field, o)} className="block w-full whitespace-nowrap px-3 py-1.5 text-left text-[13px] text-[#201f1e] hover:bg-[#f3f2f1]">{o}</button>)}
        </div>
      )}
    </div>
  );
}

function Grid({ ui, dark }: { ui: Ui; dark?: boolean }) {
  const t = ui.page.table;
  if (!t) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[34rem] text-left text-[12.5px]">
        <thead className={dark ? "text-[11px] text-slate-400" : "text-[12px] text-[#605e5c]"}>
          <tr className={dark ? "border-b border-white/10" : "border-b border-[#edebe9]"}>{t.columns.map(c => <th key={c} className="px-2 py-1.5 font-semibold">{c}</th>)}</tr>
        </thead>
        <tbody>
          {t.rows.map(r => (
            <tr key={r.id} onClick={() => ui.openRow(r)} tabIndex={0} onKeyDown={e => e.key === "Enter" && ui.openRow(r)}
              className={cn("cursor-pointer border-b", dark ? "border-white/5 text-slate-200 hover:bg-white/5" : "border-[#f3f2f1] text-[#323130] hover:bg-[#f3f9fd]", ui.picked === r.id && (dark ? "bg-white/10" : "bg-[#deecf9]"))}>
              {r.cells.map((c, i) => (
                <td key={i} className="px-2 py-1.5 align-top" style={i === 0 && r.tone ? { borderLeft: `3px solid ${TONE[r.tone]}` } : undefined}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Azure: light, blue bar, resource menu, blades ───────────────────────────
function Azure(ui: Ui) {
  const { lab, page, rec } = ui;
  const crumb = rec && ui.full ? [`${lab.resource} | ${page.heading}`, rec.title] : [`${lab.resource} | ${page.heading}`];
  return (
    <div className="min-w-[56rem] bg-white text-[#323130]" style={{ fontFamily: '"Segoe UI", system-ui, sans-serif' }}>
      <div className="flex h-10 items-center gap-3 bg-[#0078d4] px-3 text-white">
        <Menu className="h-4 w-4" /><span className="text-sm font-semibold">{lab.product}</span>
        <div className="mx-auto flex h-7 w-96 items-center gap-2 rounded-sm bg-white/90 px-2 text-xs text-[#605e5c]"><Search className="h-3.5 w-3.5" />Search resources, services, and docs</div>
        <SquareTerminal className="h-4 w-4" /><Bell className="h-4 w-4" /><Settings className="h-4 w-4" /><CircleHelp className="h-4 w-4" />
        <span className="text-xs">analyst@{lab.tenant}</span>
      </div>
      <div className="flex items-center gap-1 px-4 pt-2 text-xs text-[#0078d4]">
        <span>Home</span>
        {crumb.map(c => <React.Fragment key={c}><ChevronRight className="h-3 w-3 text-[#605e5c]" /><span className="truncate">{c}</span></React.Fragment>)}
      </div>

      {rec && ui.full ? <AzureRecord {...ui} rec={rec} /> : (
        <div className="grid min-h-[30rem] grid-cols-[13rem_1fr]">
          <nav aria-label="Resource menu" className="border-r border-[#edebe9] py-2 text-[13px]">
            {lab.menu.map(g => (
              <div key={g.group ?? "top"} className="mb-1">
                {g.group && <p className="px-3 pb-0.5 pt-2 text-[11px] font-semibold text-[#605e5c]">{g.group}</p>}
                {g.items.map(i => (
                  <button key={i.id} onClick={() => ui.go(i.id)} className={cn("block w-full px-3 py-1 text-left hover:bg-[#f3f2f1]", ui.pageId === i.id && "bg-[#edebe9] font-semibold")}>{i.label}</button>
                ))}
              </div>
            ))}
          </nav>
          <div className="min-w-0">
            <div className="flex items-center gap-2 px-4 pt-2">
              <h4 className="text-xl font-semibold text-[#201f1e]">{lab.resource} <span className="font-normal text-[#605e5c]">| {page.heading}</span></h4>
            </div>
            {page.commands && (
              <div className="mt-1 flex gap-4 border-b border-[#edebe9] px-4 py-1.5 text-[13px]">
                <span className="inline-flex items-center gap-1 text-[#0078d4]"><RefreshCw className="h-3.5 w-3.5" />Refresh</span>
                {page.commands.map(c => <button key={c.id} onClick={() => ui.act(c.id)} className="text-[#323130] hover:text-[#0078d4]">{c.label}</button>)}
              </div>
            )}
            <div className="flex min-w-0">
              <div className="min-w-0 flex-1 px-4 py-2">
                {page.tiles && (
                  <div className="mb-2 flex gap-6">
                    {page.tiles.map(t => <div key={t.label}><p className="text-xl font-semibold text-[#201f1e]">{t.value}</p><p className="text-[11px] text-[#605e5c]">{t.label}</p></div>)}
                  </div>
                )}
                {page.filters && (
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <span className="inline-flex w-52 items-center gap-1.5 rounded-sm border border-[#8a8886] px-2 py-1 text-[12px] text-[#605e5c]"><Search className="h-3 w-3" />Search by ID, title, owner</span>
                    {page.filters.map(f => <span key={f} className="rounded-full bg-[#deecf9] px-2.5 py-0.5 text-[12px] text-[#201f1e]">{f}</span>)}
                  </div>
                )}
                {page.note && <p className="mb-2 text-[13px] text-[#605e5c]">{page.note}</p>}
                {page.query && <pre className="mb-2 overflow-x-auto rounded-sm border border-[#c8c6c4] bg-[#faf9f8] p-2 font-mono text-[12px] text-[#201f1e]">{page.query}</pre>}
                <Grid ui={ui} />
              </div>
              {rec && !ui.full && (
                <aside className="w-72 shrink-0 border-l border-[#edebe9] p-3 text-[13px]">
                  <p className="text-[15px] font-semibold text-[#201f1e]">{rec.title}</p>
                  <p className="text-[11px] text-[#605e5c]">Incident ID {rec.id}</p>
                  <div className="my-2 flex rounded-sm border border-[#edebe9]">
                    {rec.strip?.map(s => <AzureDrop key={s.field} ui={ui} field={s.field} label={s.label} value={ui.value(s.field, s.value)} options={s.options} tone={s.tone ? TONE[s.tone] : undefined} />)}
                  </div>
                  {rec.facts.slice(0, 3).map(([k, v]) => <div key={k} className="mb-1.5"><p className="text-[11px] text-[#605e5c]">{k}</p><p className="text-[#201f1e]">{v}</p></div>)}
                  <button onClick={ui.setFull} className="mt-2 w-full rounded-sm bg-[#0078d4] py-1.5 text-[13px] font-semibold text-white hover:bg-[#106ebe]">View full details</button>
                </aside>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AzureRecord(p: Ui & { rec: Record_ }) {
  const { rec, value } = p;
  const open = p.menuOpen === "actions";
  return (
    <div className="pb-3">
      <div className="px-4 pt-1">
        <h4 className="text-xl font-semibold text-[#201f1e]">{rec.title}</h4>
        <p className="text-[12px] text-[#605e5c]">Incident ID {rec.id}</p>
      </div>
      <div className="mt-1 flex gap-4 border-b border-[#edebe9] px-4 py-1.5 text-[13px] text-[#323130]">
        <span className="inline-flex items-center gap-1"><RefreshCw className="h-3.5 w-3.5 text-[#0078d4]" />Refresh</span>
        <button onClick={p.openLogs} className="inline-flex items-center gap-1 hover:text-[#0078d4]"><FileText className="h-3.5 w-3.5 text-[#0078d4]" />Logs</button>
        <button onClick={() => p.act("tasks")} className="inline-flex items-center gap-1 hover:text-[#0078d4]"><ListChecks className="h-3.5 w-3.5 text-[#0078d4]" />Tasks</button>
        <button onClick={() => p.act("activity")} className="inline-flex items-center gap-1 hover:text-[#0078d4]"><FileText className="h-3.5 w-3.5 text-[#0078d4]" />Activity log</button>
      </div>
      <div className="grid min-h-[27rem] grid-cols-[19rem_1fr]">
        <div className="border-r border-[#edebe9] text-[13px]">
          <div className="flex border-b border-[#edebe9]">
            {rec.strip?.map(s => <AzureDrop key={s.field} ui={p} field={s.field} label={s.label} value={value(s.field, s.value)} options={s.options} tone={s.tone ? TONE[s.tone] : undefined} />)}
          </div>
          {value("status", "") === "Closed" && rec.closing && (
            <div className="border-b border-[#edebe9] bg-[#faf9f8] p-3">
              <p className="mb-1 text-[12px] font-semibold text-[#201f1e]">Select classification</p>
              {rec.closing.map(c => <button key={c} onClick={() => p.set("classification", c)} className={cn("mb-1 block w-full rounded-sm border px-2 py-1 text-left text-[12px]", value("classification", "") === c ? "border-[#0078d4] bg-[#deecf9]" : "border-[#c8c6c4] hover:bg-[#f3f2f1]")}>{c}</button>)}
            </div>
          )}
          <div className="p-3">
            {rec.facts.map(([k, v]) => <div key={k} className="mb-2"><p className="text-[12px] text-[#605e5c]">{k}</p><p className="text-[#201f1e]">{v}</p></div>)}
            {rec.evidence && (
              <div className="mb-2">
                <p className="text-[12px] text-[#605e5c]">Evidence</p>
                <div className="mt-0.5 flex gap-5">{rec.evidence.map(([k, v]) => <div key={k}><p className="text-lg font-semibold text-[#201f1e]">{v}</p><p className="text-[11px] text-[#605e5c]">{k}</p></div>)}</div>
              </div>
            )}
            <p className="text-[12px] text-[#605e5c]">Entities ({rec.entities?.length ?? 0})</p>
            {rec.entities?.map(e => <button key={e.id} onClick={() => { p.setTab("entities"); p.act(`entity:${e.id}`); }} className="block text-[#0078d4] hover:underline">{e.label}</button>)}
            {rec.tactics && <><p className="mt-2 text-[12px] text-[#605e5c]">Tactics and techniques</p><p className="text-[#201f1e]">{rec.tactics}</p></>}
          </div>
          <div className="border-t border-[#edebe9] p-3"><button onClick={() => p.act("investigate")} className="rounded-sm bg-[#0078d4] px-4 py-1.5 text-[13px] font-semibold text-white hover:bg-[#106ebe]">Investigate</button></div>
        </div>

        <div className="min-w-0 p-3">
          {p.logs && rec.logs ? (
            <div>
              <div className="mb-1 flex items-center justify-between"><p className="text-[14px] font-semibold text-[#201f1e]">Logs</p><button onClick={p.closeLogs} aria-label="Close Logs" className="text-[#605e5c]"><X className="h-4 w-4" /></button></div>
              <pre className="mb-2 overflow-x-auto rounded-sm border border-[#c8c6c4] bg-[#faf9f8] p-2 font-mono text-[12px] text-[#201f1e]">{rec.logs.query}</pre>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[30rem] text-left text-[12px]">
                  <thead className="text-[#605e5c]"><tr className="border-b border-[#edebe9]"><th className="w-6" />{rec.logs.columns.map(c => <th key={c} className="px-2 py-1 font-semibold">{c}</th>)}</tr></thead>
                  <tbody>
                    {rec.logs.rows.map(r => (
                      <tr key={r.id} className="border-b border-[#f3f2f1]">
                        <td className="px-1"><input type="checkbox" aria-label={`Select row ${r.cells[0]}`} checked={p.picked === r.id} onChange={() => { if (p.hit(`row:${r.id}`, true)) p.setPicked(r.id); }} /></td>
                        {r.cells.map((c, i) => <td key={i} className="px-2 py-1 font-mono">{c}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <button onClick={() => p.act("bookmark")} className="mt-2 rounded-sm border border-[#8a8886] px-3 py-1 text-[12.5px] hover:bg-[#f3f2f1]">Add bookmark to the current incident</button>
            </div>
          ) : (
            <>
              <div className="mb-2 flex items-center justify-between">
                <div className="flex gap-4 text-[13px]" role="tablist">
                  {(["overview", "entities"] as const).map(t => <button key={t} role="tab" aria-selected={p.tab === t} onClick={() => p.setTab(t)} className={cn("pb-1 capitalize", p.tab === t ? "border-b-2 border-[#0078d4] font-semibold text-[#201f1e]" : "text-[#605e5c]")}>{t}</button>)}
                </div>
                <div className="relative">
                  <button onClick={() => p.setMenuOpen(open ? null : "actions")} aria-expanded={open} className="inline-flex items-center gap-1 rounded-sm bg-[#0078d4] px-3 py-1 text-[13px] font-semibold text-white hover:bg-[#106ebe]">Incident actions <ChevronDown className="h-3.5 w-3.5" /></button>
                  {open && (
                    <div className="absolute right-0 top-full z-30 mt-0.5 w-52 rounded-sm border border-[#c8c6c4] bg-white py-1 shadow-lg">
                      {rec.actions?.map(a => <button key={a.id} onClick={() => p.act(a.id)} className="block w-full px-3 py-1.5 text-left text-[13px] text-[#201f1e] hover:bg-[#f3f2f1]">{a.label}</button>)}
                    </div>
                  )}
                </div>
              </div>
              {p.tab === "overview" ? (
                <div>
                  <p className="mb-1 text-[13px] font-semibold text-[#201f1e]">Incident timeline</p>
                  <ul className="mb-3 space-y-1.5">
                    {rec.timeline?.map(t => (
                      <li key={t.time + t.text} className="rounded-sm border-l-4 bg-[#faf9f8] px-2 py-1 text-[12.5px]" style={{ borderColor: TONE[t.tone ?? "info"] }}>
                        <span className="font-mono text-[11px] text-[#605e5c]">{t.time}</span> <span className="text-[#201f1e]">{t.text}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <ul className="space-y-1">
                  {rec.entities?.map(e => (
                    <li key={e.id}>
                      <button onClick={() => p.act(`entity:${e.id}`)} className="flex w-full items-center gap-2 rounded-sm border border-[#edebe9] px-2 py-1.5 text-left text-[13px] hover:bg-[#f3f9fd]">
                        <User className="h-3.5 w-3.5 shrink-0 text-[#0078d4]" /><span className="font-semibold text-[#201f1e]">{e.label}</span><span className="text-[11px] text-[#605e5c]">{e.type}</span>
                        {e.seen && <span className="ml-auto text-[11px] text-[#605e5c]">{e.seen}</span>}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── vSphere-style client: inventory tree, object tabs, event grid, details below ──────
function Vsphere(ui: Ui) {
  const { lab, page, rec } = ui;
  const accent = "#0072a3";
  return (
    <div className="min-w-[56rem] bg-[#fafafa] text-[#313131]" style={{ fontFamily: '"Metropolis", "Segoe UI", system-ui, sans-serif' }}>
      <div className="flex h-10 items-center gap-3 bg-[#0d2c40] px-3 text-white">
        <Menu className="h-4 w-4" /><span className="text-sm font-semibold">{lab.product}</span>
        <div className="mx-auto flex h-7 w-96 items-center gap-2 rounded-sm bg-white/10 px-2 text-xs text-slate-200"><Search className="h-3.5 w-3.5" />Search in all environments</div>
        <RefreshCw className="h-4 w-4" /><CircleHelp className="h-4 w-4" />
        <span className="text-xs">analyst@{lab.tenant.toUpperCase()}</span>
      </div>
      <div className="grid min-h-[30rem] grid-cols-[11rem_1fr]">
        <nav aria-label="Inventory" className="border-r border-[#d7d7d7] bg-white py-2 text-[13px]">
          {lab.menu.map(g => g.items.map(i => (
            <button key={i.id} onClick={() => ui.go(i.id)} style={{ paddingLeft: `${0.5 + (i.depth ?? 0) * 0.8}rem` }}
              className={cn("flex w-full items-center gap-1 py-1 pr-2 text-left hover:bg-[#e8f4fa]", page.node === i.id && "bg-[#d8ecf5] font-semibold")}>
              <ChevronDown className="h-3 w-3 shrink-0 text-[#747474]" /><span className="truncate">{i.label}</span>
            </button>
          )))}
        </nav>
        <div className="min-w-0">
          <div className="border-b border-[#d7d7d7] bg-white px-4 pt-2">
            <div className="flex items-center gap-3">
              <h4 className="text-lg font-semibold text-[#1b1b1b]">{page.object ?? lab.resource}</h4>
              <span className="text-[12px] font-semibold uppercase tracking-wide" style={{ color: accent }}>Actions</span>
            </div>
            {page.tabs && (
              <div role="tablist" className="mt-1 flex gap-5 text-[13px]">
                {page.tabs.map(t => <button key={t.id} role="tab" aria-selected={page.tab === t.label} onClick={() => ui.go(t.id)} className={cn("pb-1.5", page.tab === t.label ? "border-b-2 font-semibold text-[#1b1b1b]" : "text-[#565656] hover:text-[#1b1b1b]")} style={page.tab === t.label ? { borderColor: accent } : undefined}>{t.label}</button>)}
              </div>
            )}
          </div>
          <div className={cn("grid min-w-0", page.sub && "grid-cols-[7.5rem_1fr]")}>
            {page.sub && (
              <div className="border-r border-[#d7d7d7] bg-white py-2 text-[13px]">
                <p className="px-3 pb-1 text-[11px] font-semibold text-[#565656]">Tasks and Events</p>
                {page.sub.map(s => <button key={s.id} onClick={() => ui.go(s.id)} className={cn("block w-full px-3 py-1 text-left hover:bg-[#e8f4fa]", ui.pageId === s.id && "bg-[#d8ecf5] font-semibold")}>{s.label}</button>)}
              </div>
            )}
            <div className="min-w-0 p-3">
              <p className="mb-1 text-[14px] font-semibold text-[#1b1b1b]">{page.heading}</p>
              {page.tiles && <div className="mb-2 flex gap-6">{page.tiles.map(t => <div key={t.label}><p className="text-[11px] text-[#565656]">{t.label}</p><p className="text-sm font-semibold text-[#1b1b1b]">{t.value}</p></div>)}</div>}
              {page.note && <p className="mb-2 rounded-sm border-l-4 border-[#c92100] bg-[#fdf1ef] px-2 py-1 text-[13px] text-[#313131]">{page.note}</p>}
              {page.table && <div className="rounded-sm border border-[#d7d7d7] bg-white [&_td:not(:first-child)]:whitespace-nowrap"><Grid ui={ui} /></div>}
              {rec && (
                <div className="mt-3 rounded-sm border border-[#d7d7d7] bg-white p-3 text-[13px]">
                  <div className="flex items-center gap-3">
                    <p className="text-[14px] font-semibold text-[#1b1b1b]">{rec.title}</p>
                    <div className="ml-auto flex gap-1.5">{rec.actions?.map(a => <button key={a.id} onClick={() => ui.act(a.id)} className="rounded-sm border px-2.5 py-0.5 text-[11.5px] font-semibold uppercase tracking-wide hover:bg-[#e8f4fa]" style={{ borderColor: accent, color: accent }}>{a.label}</button>)}</div>
                  </div>
                  <dl className="mt-2 grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1">
                    {rec.facts.map(([k, v]) => <React.Fragment key={k}><dt className="text-[#565656]">{k}</dt><dd className="font-mono text-[12.5px] text-[#1b1b1b] [overflow-wrap:anywhere]">{v}</dd></React.Fragment>)}
                  </dl>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      <div className="flex items-center gap-4 border-t border-[#d7d7d7] bg-white px-3 py-1 text-[12px] text-[#565656]"><span>Recent Tasks</span><span>Alarms</span></div>
    </div>
  );
}

// ─── Entra-style admin center: left menu, log grid, detail pane with tabs ──────────────
function Entra(ui: Ui) {
  const { lab, page, rec } = ui;
  const [pane, setPane] = useState("basic");
  const facts = rec ? (pane !== "basic" && rec.panes?.[pane]) || rec.facts : [];
  return (
    <div className="min-w-[56rem] bg-white text-[#242424]" style={{ fontFamily: '"Segoe UI", system-ui, sans-serif' }}>
      <div className="flex h-10 items-center gap-3 bg-[#0f548c] px-3 text-white">
        <Menu className="h-4 w-4" /><span className="text-sm font-semibold">{lab.product}</span>
        <div className="mx-auto flex h-7 w-80 items-center gap-2 rounded-sm bg-white/90 px-2 text-xs text-[#616161]"><Search className="h-3.5 w-3.5" />Search resources, services, and docs</div>
        <Settings className="h-4 w-4" /><CircleHelp className="h-4 w-4" />
        <span className="text-xs">analyst@{lab.tenant}</span>
      </div>
      <div className="grid min-h-[30rem] grid-cols-[11.5rem_1fr]">
        <nav aria-label="Admin menu" className="border-r border-[#e0e0e0] bg-[#fafafa] py-2 text-[13px]">
          {lab.menu.map(g => (
            <div key={g.group ?? "top"} className="mb-1">
              {g.group && <p className="px-3 pb-0.5 pt-2 text-[11px] font-semibold text-[#616161]">{g.group}</p>}
              {g.items.map(i => <button key={i.id} onClick={() => ui.go(i.id)} className={cn("block w-full px-3 py-1 text-left hover:bg-[#f0f0f0]", ui.pageId === i.id && "bg-[#ebf3fc] font-semibold text-[#0f6cbd]")}>{i.label}</button>)}
            </div>
          ))}
        </nav>
        <div className="min-w-0 px-4 py-2">
          <h4 className="text-lg font-semibold text-[#242424]">{page.heading}</h4>
          <p className="text-[11px] text-[#616161]">{lab.resource}</p>
          {page.tiles && <div className="my-2 flex gap-6">{page.tiles.map(t => <div key={t.label}><p className="text-xl font-semibold">{t.value}</p><p className="text-[11px] text-[#616161]">{t.label}</p></div>)}</div>}
          {page.filters && <div className="my-2 flex flex-wrap gap-2">{page.filters.map(f => <span key={f} className="rounded-full bg-[#ebf3fc] px-2.5 py-0.5 text-[12px] text-[#242424]">{f}</span>)}</div>}
          {page.note && <p className="my-2 text-[13px] text-[#616161]">{page.note}</p>}
          {page.table && <div className="mt-2 [&_td:not(:first-child)]:whitespace-nowrap"><Grid ui={ui} /></div>}
          {rec && (
            <div className="mt-3 rounded border border-[#e0e0e0] text-[13px]">
              <div className="flex items-center gap-3 border-b border-[#e0e0e0] px-3 py-2">
                <p className="text-[14px] font-semibold">{rec.title}</p>
              </div>
              {rec.panes ? (
                <div role="tablist" className="flex gap-4 border-b border-[#e0e0e0] px-3 pt-1.5">
                  {rec.actions?.map(a => <button key={a.id} role="tab" aria-selected={pane === a.id} onClick={() => { if (ui.hit(`action:${a.id}`, false)) setPane(a.id); }} className={cn("pb-1", pane === a.id ? "border-b-2 border-[#0f6cbd] font-semibold" : "text-[#616161] hover:text-[#242424]")}>{a.label}</button>)}
                </div>
              ) : rec.actions && (
                <div className="flex gap-2 border-b border-[#e0e0e0] px-3 py-1.5">
                  {rec.actions.map(a => <button key={a.id} onClick={() => ui.act(a.id)} className="rounded border border-[#d1d1d1] px-2.5 py-0.5 text-[12.5px] hover:bg-[#f0f0f0]">{a.label}</button>)}
                </div>
              )}
              <dl className="grid grid-cols-[11rem_1fr] gap-x-3 gap-y-1 p-3">
                {facts.map(([k, v]) => <React.Fragment key={k}><dt className="text-[#616161]">{k}</dt><dd className="text-[#242424] [overflow-wrap:anywhere]">{v}</dd></React.Fragment>)}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── EDR: dark, red accent, process tree beside a details panel ──────────────
function Edr(ui: Ui) {
  const { lab, page, rec, value } = ui;
  const node = rec?.tree?.find(n => n.id === ui.picked) ?? rec?.tree?.find(n => n.bad);
  return (
    <div className="min-w-[56rem] bg-[#16181d] text-slate-200" style={{ fontFamily: "system-ui, sans-serif" }}>
      <div className="flex h-10 items-center gap-3 border-b border-white/10 bg-[#1f2228] px-3">
        <Menu className="h-4 w-4 text-slate-300" /><Shield className="h-4 w-4 text-[#e8002d]" /><span className="text-sm font-semibold text-white">{lab.product}</span>
        <div className="mx-auto flex h-7 w-96 items-center gap-2 rounded bg-black/30 px-2 text-xs text-slate-400"><Search className="h-3.5 w-3.5" />Search hosts, hashes, users</div>
        <Bot className="h-4 w-4 text-slate-400" /><Bell className="h-4 w-4 text-slate-400" /><span className="text-xs text-slate-400">{lab.tenant}</span>
      </div>
      <div className="grid min-h-[32rem] grid-cols-[12.5rem_1fr]">
        <nav aria-label="Console menu" className="border-r border-white/10 bg-[#1b1e24] py-2 text-[13px]">
          {lab.menu.map(g => (
            <div key={g.group ?? "top"} className="mb-2">
              {g.group && <p className="px-3 pb-1 pt-1 text-[10px] font-bold uppercase tracking-wider text-slate-500">{g.group}</p>}
              {g.items.map(i => <button key={i.id} onClick={() => ui.go(i.id)} className={cn("block w-full border-l-2 px-3 py-1 text-left hover:bg-white/5", ui.pageId === i.id ? "border-[#e8002d] bg-white/5 font-semibold text-white" : "border-transparent text-slate-300")}>{i.label}</button>)}
            </div>
          ))}
        </nav>
        <div className="min-w-0 p-3">
          {rec ? (
            <div>
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <button onClick={() => ui.go(ui.pageId)} className="text-xs text-slate-400 hover:text-white">{page.heading} /</button>
                <h4 className="text-base font-bold text-white">{rec.title}</h4>
                {rec.strip?.map(s => <EdrDrop key={s.field} ui={ui} field={s.field} label={s.label} value={value(s.field, s.value)} options={s.options} />)}
                <div className="ml-auto flex gap-1.5">
                  {rec.actions?.map(a => <button key={a.id} onClick={() => ui.act(a.id)} className="rounded border border-white/20 px-2.5 py-1 text-[12px] font-semibold text-slate-100 hover:border-[#e8002d] hover:bg-[#e8002d]/20">{a.label}</button>)}
                </div>
              </div>
              <div className={cn("grid gap-3", rec.tree && "grid-cols-[1.15fr_1fr]")}>
                {rec.tree && (
                  <div className="rounded border border-white/10 bg-[#111317] p-3">
                    <p className="mb-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">Process tree</p>
                    {rec.tree.map(n => (
                      <button key={n.id} onClick={() => { if (ui.hit(`tree:${n.id}`, true)) ui.setPicked(n.id); }} style={{ marginLeft: `${n.depth * 18}px` }}
                        className={cn("mb-1.5 block rounded border px-2 py-1 text-left font-mono text-[12px]", n.bad && ui.picked === n.id ? "border-[#e8002d] bg-[#e8002d]/20 text-white" : "border-white/15 bg-white/5 text-slate-200 hover:border-white/40")}>
                        {n.name}<span className="ml-2 text-[10px] text-slate-400">{n.detail}</span>
                      </button>
                    ))}
                  </div>
                )}
                <div className="rounded border border-white/10 bg-[#1b1e24] p-3 text-[12.5px]">
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">Details</p>
                  {[...rec.facts, ...(node?.facts ?? [])].map(([k, v]) => (
                    <button key={k} onClick={() => ui.act(`field:${k}`)} className="mb-1 grid w-full grid-cols-[8.5rem_1fr] gap-2 rounded px-1 py-0.5 text-left hover:bg-white/5">
                      <span className="text-slate-400">{k}</span><span className="font-mono text-slate-100 [overflow-wrap:anywhere]">{v}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div>
              <h4 className="mb-2 text-lg font-bold text-white">{page.heading}</h4>
              {page.tiles && <div className="mb-2 flex gap-6">{page.tiles.map(t => <div key={t.label}><p className="text-xl font-bold text-white">{t.value}</p><p className="text-[11px] text-slate-400">{t.label}</p></div>)}</div>}
              {page.filters && <div className="mb-2 flex flex-wrap gap-1.5">{page.filters.map(f => <span key={f} className="rounded bg-white/10 px-2 py-0.5 text-[11.5px] text-slate-200">{f}</span>)}</div>}
              {page.note && <p className="mb-2 text-[13px] text-slate-400">{page.note}</p>}
              <Grid ui={ui} dark />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EdrDrop({ ui, field, label, value, options }: { ui: Ui; field: string; label: string; value: string; options?: string[] }) {
  const open = ui.menuOpen === field;
  return (
    <div className="relative">
      <button onClick={() => ui.setMenuOpen(open ? null : field)} aria-expanded={open} className="inline-flex items-center gap-1 rounded bg-white/10 px-2 py-0.5 text-[11.5px] text-slate-100 hover:bg-white/20">
        <span className="text-slate-400">{label}:</span> {value} <ChevronDown className="h-3 w-3" />
      </button>
      {open && options && (
        <div className="absolute left-0 top-full z-30 mt-0.5 min-w-full rounded border border-white/20 bg-[#262a31] py-1 shadow-lg">
          {options.map(o => <button key={o} onClick={() => ui.set(field, o)} className="block w-full whitespace-nowrap px-3 py-1 text-left text-[12px] text-slate-100 hover:bg-white/10"><Check className="mr-1 inline h-3 w-3 opacity-0" />{o}</button>)}
        </div>
      )}
    </div>
  );
}
