"use client";
import { Fragment, useId, useState } from "react";
import { KIND_LABEL, type Handoff } from "@/lib/team/handoff";
import { TeamImageThumb, imagesOf } from "./teamImages";

/**
 * The ONE renderer for a hand-off (owner, 2026-11-08: every escalation or case opens with the full
 * detail of what the analyst reported). Every receiver shows the same fields in the same order:
 *
 *   1. who sent it, as what, when      2. the sender's summary, in full (wraps, never truncated)
 *   3. their calls: verdict, severity, requested action, confidence
 *   4. their reasoning (always in the first view)   5. further sections (assessment, findings...)
 *   6. every indicator   7. affected host / user / target   8. request parameters
 *   9. the linked log(s) with their key fields (raw block folded)   10. screenshots
 *   11. what happened after (bounces, comments, logs added)   12. what it builds on (original case, report)
 *
 * Long text folds after a first screenful; nothing the sender wrote is hidden behind a click
 * except the rest of a very long text, the raw log and the related hand-offs.
 */

type Variant = "team" | "sentinel";
const C: Record<Variant, Record<string, string>> = {
  team: {
    root: "space-y-1.5 text-xs text-slate-200",
    meta: "text-[11px] font-semibold uppercase tracking-wider text-slate-400",
    summary: "whitespace-pre-wrap break-words text-sm font-semibold text-slate-100",
    chips: "flex flex-wrap gap-1",
    chip: "rounded border border-border bg-bg-elevated/40 px-1.5 py-0.5 text-[11px] text-slate-100",
    chipK: "text-slate-400",
    k: "text-[11px] font-semibold uppercase tracking-wider text-slate-400",
    text: "whitespace-pre-wrap break-words text-xs text-slate-200",
    muted: "text-[11px] italic text-slate-400",
    ioc: "rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-cyber-200",
    iocT: "text-slate-400",
    dl: "grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[11px]",
    dt: "text-slate-400",
    dd: "break-all font-mono text-slate-200",
    box: "rounded border border-border/60 bg-bg-elevated/30 px-2 py-1",
    btn: "rounded text-[11px] text-cyber-300 underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60",
    sum: "cursor-pointer rounded text-[11px] text-cyber-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60",
    raw: "mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-1.5 font-mono text-[11px] text-slate-300",
    note: "text-[11px] text-slate-300",
    noteK: "font-semibold text-neon-amber",
    rel: "rounded border border-border/60 bg-bg/60 px-2 py-1",
  },
  sentinel: {
    root: "st-ho", meta: "st-ho-meta", summary: "st-ho-summary", chips: "st-ho-chips", chip: "st-ho-chip", chipK: "st-muted",
    k: "st-ho-k", text: "st-ho-text", muted: "st-ho-muted", ioc: "st-ho-ioc", iocT: "st-muted", dl: "st-ho-dl", dt: "st-muted", dd: "st-ho-dd",
    box: "st-ho-box", btn: "st-link st-ho-btn", sum: "st-link st-ho-sum", raw: "st-ho-raw", note: "st-ho-note", noteK: "st-ho-k", rel: "st-ho-box",
  },
};

const FOLD_AT = 600;
const when = (iso: string | null) => (iso ? `${iso.replace("T", " ").slice(0, 16)} UTC` : "");

/** A long text shows its first screenful; the rest is one click away. */
function Fold({ text, cls, btn, at = FOLD_AT }: { text: string; cls: string; btn: string; at?: number }) {
  const [all, setAll] = useState(false);
  const id = useId();
  const long = text.length > at;
  return (
    <>
      <p id={id} className={cls}><bdi>{long && !all ? `${text.slice(0, at).trimEnd()}…` : text}</bdi></p>
      {long && <button type="button" className={btn} aria-expanded={all} aria-controls={id} onClick={() => setAll(a => !a)}>{all ? "Show less" : `Show all (${text.length} characters)`}</button>}
    </>
  );
}

export interface HandoffDetailProps {
  handoff: Handoff;
  /** Needed to show screenshots (they load through the session's image route). */
  sessionId?: string;
  variant?: Variant;
  /** The summary is already the heading of the surrounding card: don't repeat it. */
  hideSummary?: boolean;
  /** Open the related hand-offs (the case behind a request) in the first view. */
  openRelated?: boolean;
  /** Leave out the linked logs (the surrounding view already shows the full log). */
  hideLogs?: boolean;
  /** Nesting depth (a related hand-off renders one level deeper, at most once). */
  depth?: number;
}

export function HandoffDetail({ handoff: h, sessionId, variant = "team", hideSummary = false, openRelated = false, hideLogs = false, depth = 0 }: HandoffDetailProps) {
  const c = C[variant];
  const calls = ([["Verdict", h.verdict], ["Severity", h.severity], ["Asks", h.action], ["Confidence", h.confidence]] as [string, string | undefined][]).filter(([, v]) => !!v) as [string, string][];
  const shots = imagesOf(h.images);
  const facts = [...h.affected, ...h.params];
  return (
    <div className={c.root} data-handoff={h.kind}>
      <p className={c.meta}>{KIND_LABEL[h.kind]} {h.kind === "self_opened" ? "by" : "from"} <bdi>{h.from}</bdi> ({h.fromRole}){h.at ? <> · <time dateTime={h.at}>{when(h.at)}</time></> : null}</p>
      {!hideSummary && <p className={c.summary} data-handoff-summary><bdi>{h.summary}</bdi></p>}
      {calls.length > 0 && (
        <ul className={c.chips} aria-label="The sender's calls">
          {calls.map(([k, v]) => <li key={k} className={c.chip}><span className={c.chipK}>{k}: </span><b>{v}</b></li>)}
        </ul>
      )}
      <div>
        <p className={c.k}>{h.reasoningLabel}</p>
        {h.reasoning ? <Fold text={h.reasoning} cls={c.text} btn={c.btn} /> : <p className={c.muted}>Not written</p>}
      </div>
      {h.sections.map(([k, v]) => (
        <div key={k}>
          <p className={c.k}>{k}</p>
          <Fold text={v} cls={c.text} btn={c.btn} />
        </div>
      ))}
      {h.iocs.length > 0 && (
        <div>
          <p className={c.k}>Indicators ({h.iocs.length})</p>
          <ul className={c.chips} aria-label="Indicators">
            {h.iocs.map(i => <li key={i.value} className={c.ioc}>{i.type && <span className={c.iocT}>{i.type}: </span>}<bdi>{i.value}</bdi></li>)}
          </ul>
        </div>
      )}
      {facts.length > 0 && (
        <dl className={c.dl}>
          {facts.map(([k, v]) => <Fragment key={k}><dt className={c.dt}>{k}</dt><dd className={c.dd}><bdi>{v}</bdi></dd></Fragment>)}
        </dl>
      )}
      {!hideLogs && h.logs.map((l, i) => (
        <div key={`${l.seq ?? i}-${l.label}`} className={c.box}>
          <p className={c.k}>{l.addedBy ? <>Log added by <bdi>{l.addedBy}</bdi></> : h.logs.length > 1 ? "Escalated log" : "Linked log"}{l.seq != null ? ` #${l.seq}` : ""}</p>
          <dl className={c.dl}>
            {l.fields.map(([k, v]) => <Fragment key={k}><dt className={c.dt}>{k}</dt><dd className={c.dd}><bdi>{v}</bdi></dd></Fragment>)}
          </dl>
          {l.raw && (
            <details>
              <summary className={c.sum}>Raw event</summary>
              <pre className={c.raw}>{l.raw}</pre>
            </details>
          )}
        </div>
      ))}
      {shots.length > 0 && sessionId && (
        <div>
          <p className={c.k}>Screenshots ({shots.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {shots.map((img, i) => <TeamImageThumb key={img.path} sessionId={sessionId} image={img} alt={`Screenshot ${i + 1} sent with this ${KIND_LABEL[h.kind].toLowerCase()}`} className="max-h-28" />)}
          </div>
        </div>
      )}
      {shots.length > 0 && !sessionId && <p className={c.muted}>{shots.length} screenshot{shots.length === 1 ? "" : "s"} attached: open the case in the team room to see {shots.length === 1 ? "it" : "them"}.</p>}
      {h.notes.length > 0 && (
        <div>
          <p className={c.k}>After it was sent ({h.notes.length})</p>
          <ul className="space-y-0.5">
            {h.notes.map((n, i) => <li key={i} className={c.note}><span className={c.noteK}>{n.label}</span> (<bdi>{n.by}</bdi>{n.at ? `, ${when(n.at)}` : ""}): <bdi>{n.text}</bdi></li>)}
          </ul>
        </div>
      )}
      {depth === 0 && h.related.map((r, i) => (
        <details key={`${r.kind}-${i}`} open={openRelated} className={c.rel} data-handoff-related>
          <summary className={c.sum}>{KIND_LABEL[r.kind]} from <bdi>{r.from}</bdi>: <bdi>{r.summary}</bdi></summary>
          <div className="mt-1"><HandoffDetail handoff={r} sessionId={sessionId} variant={variant} depth={1} /></div>
        </details>
      ))}
    </div>
  );
}
