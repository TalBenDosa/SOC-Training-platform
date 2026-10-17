"use client";
import { useEffect, useState, useMemo, useRef } from "react";
import { AttachImageButton, PendingImages, uploadTeamImage, useImageAttachments, type TeamImage } from "./teamImages";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowUpRight, ShieldAlert, X } from "lucide-react";
import type { Ev, Ioc } from "@/lib/team/types";
import { asStr, detectIocType, isValidIoc, IOC_HELP, type ActR } from "@/lib/team/format";
import { useServerNow } from "@/lib/team/clock";
import { activeClaims } from "@/lib/team/projections";
import { relatedLogs, entityLabel } from "@/lib/team/correlate";
import { rationaleProblem } from "@/lib/team/escalationCheck";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";

// ── T1 console: pick a log → disposition + structured escalation report ───────
const REQUESTED_ACTIONS = ["investigate", "contain", "monitor", "escalate-to-mgr"];
const SEVERITIES = ["low", "medium", "high", "critical"];

const EMPTY_FORM = { summary: "", observations: "", assessment: "", requested_action: "investigate", severity: "medium" };

export function T1Console({ sessionId, feed, dispositions, events, meId, iocDraft, setIocDraft, nameOf, act, actR, sel, setSel, reportOpen, setReportOpen }: {
  sessionId: string;
  feed: Ev[]; dispositions: Map<string, string>; events: Ev[]; meId: string;
  iocDraft: Ioc[]; setIocDraft: React.Dispatch<React.SetStateAction<Ioc[]>>;
  nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  /** Outcome-returning act — lets the console see a `claim_held` rejection and offer a take-over. */
  actR: ActR;
  // sel + reportOpen live in the parent so the 🚩 button on a LOG (in the feed's
  // DetailPanel) can select that event and open this report modal directly.
  sel: string; setSel: (v: string) => void; reportOpen: boolean; setReportOpen: (v: boolean) => void;
}) {
  const [form, setForm] = useState(EMPTY_FORM);
  // Screenshots that travel with the escalation (EDR view, a query result, a header…).
  const shots = useImageAttachments(3);
  // One draft PER LOG: escalating a new log used to reopen the last log's summary and
  // observations (Tal, 2026-10-08). Switching logs parks the current draft under its log and
  // loads the new log's own draft (empty the first time). Indicators already picked that occur
  // in the new log come along: they were clicked (＋IOC) on that log's fields just before.
  const drafts = useRef(new Map<string, { form: typeof EMPTY_FORM; iocs: Ioc[] }>());
  const draftSel = useRef(sel);
  const formNow = useRef(form); formNow.current = form;
  const iocsNow = useRef(iocDraft); iocsNow.current = iocDraft;
  useEffect(() => {
    const prev = draftSel.current;
    if (prev === sel) return;
    draftSel.current = sel;
    if (prev) drafts.current.set(prev, { form: formNow.current, iocs: iocsNow.current });
    const logText = sel ? JSON.stringify(feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel)?.payload ?? {}).toLowerCase() : "";
    const saved = sel ? drafts.current.get(sel) : undefined;
    const carried = iocsNow.current.filter(i => i.source === "picked" && logText.includes(i.value.toLowerCase()));
    const iocs = [...(saved?.iocs ?? [])];
    for (const i of carried) if (!iocs.some(x => x.value.toLowerCase() === i.value.toLowerCase())) iocs.push(i);
    setForm(saved?.form ?? EMPTY_FORM);
    setIocDraft(iocs);
    setIocText("");
    shots.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs on a log switch only
  }, [sel]);
  const [iocText, setIocText] = useState("");
  const [busy, setBusy] = useState(false);
  const selDisp = sel ? dispositions.get(sel) : undefined;
  // The alert queue is no longer a card here: it is the "Needs triage" view of the
  // SIEM table itself (page.tsx + src/lib/team/alertQueue.ts), with SLA age badges on
  // the SIEM rows — one alert list, not two. C5: ages / claim TTL on the SERVER clock.
  const nowMs = useServerNow(15_000);
  // Selecting an alert (feed, Take next, dropdown) opens its report — count it
  // as an open so a verdict given from this console isn't scored as "unread".
  useEffect(() => { if (sel) void act("event.opened", { event_id: sel, dwell_ms: 0 }); }, [sel, act]);
  const isLowConf = selDisp === "suspicious"; // T1-2: Suspicious → low-confidence lead

  // T1-3: soft-lock claims — the room's ONE claims projection (A3): latest claim per
  // alert, cleared by release/disposition, expired after 5 min on the server clock.
  const claims = useMemo(() => activeClaims(events, nowMs), [events, nowMs]);
  // The projection already applies the server's rule (a later disposition / release /
  // escalation ends the claim), so a re-claim after a TP call shows correctly.
  const claimerOf = (eid: string): { by: string; at: number } | null => claims.get(eid) ?? null;
  const options = feed.map(e => {
    const p = e.payload as { id?: string; description?: unknown; event_type?: unknown }; const id = String(p.id ?? e.seq);
    const c = claimerOf(id); const lock = c ? (c.by === meId ? "🔎 you · " : `🔎 ${nameOf(c.by)} · `) : "";
    return { id, label: `${lock}#${e.seq} ${asStr(p.description) || asStr(p.event_type) || "event"}` };
  });
  const selClaim = sel ? claimerOf(sel) : null;
  // An alert I took is "my alert": pick it up here when nothing is selected (taken
  // from the feed, or after a reload), so the console never sits empty mid-investigation.
  const myClaim = [...claims.entries()].find(([, c]) => c.by === meId)?.[0] ?? null;
  useEffect(() => { if (!sel && myClaim) setSel(myClaim); }, [myClaim]); // eslint-disable-line react-hooks/exhaustive-deps
  // The claim is a 5-minute soft lock. While I still have the alert open here, renew it
  // so the team keeps seeing "Investigating · <me>" through a long investigation.
  const selMine = !!selClaim && selClaim.by === meId;
  const selAt = selClaim?.at ?? 0;
  useEffect(() => {
    if (!selMine || !sel) return;
    const t = setTimeout(() => { void actR("alert.claimed", { event_id: sel }, { handled: ["claim_held"] }); },
      Math.max(5_000, selAt + 4 * 60_000 - nowMs));
    return () => clearTimeout(t);
  }, [selMine, sel, selAt]); // eslint-disable-line react-hooks/exhaustive-deps
  // P0-3: the server rejects a claim on an alert a teammate holds (`claim_held`).
  // `heldFor` covers the race where our view hasn't received their claim yet; a
  // take-over is an explicit, confirmed action that resends with `takeover: true`.
  const [heldFor, setHeldFor] = useState<string | null>(null);
  const [confirmTake, setConfirmTake] = useState<string | null>(null);
  useEffect(() => { setConfirmTake(null); setHeldFor(h => (h && h !== sel ? null : h)); }, [sel]);
  // Once their claim reaches our view the projection shows it — drop the race marker so
  // a later release by them isn't masked by a stale "claimed just now".
  useEffect(() => { if (selClaim) setHeldFor(null); }, [selClaim?.by, selClaim?.at]); // eslint-disable-line react-hooks/exhaustive-deps
  async function claim(takeover = false) {
    if (!sel) return;
    setBusy(true);
    const r = await actR("alert.claimed", takeover ? { event_id: sel, takeover: true } : { event_id: sel }, { handled: ["claim_held"] });
    setBusy(false);
    if (r.ok) { setHeldFor(null); setConfirmTake(null); }
    else if (r.code === "claim_held") setHeldFor(sel);
  }
  async function release() { if (!sel) return; setBusy(true); await act("alert.released", { event_id: sel }); setBusy(false); }
  const ago = (at: number) => { const s = Math.max(0, Math.round((nowMs - at) / 1000)); return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`; };
  // One claim banner for the console + the report modal: who holds it, since when,
  // and a two-step take-over (so taking a teammate's alert is never an accident).
  const heldByOther = !!sel && ((!!selClaim && selClaim.by !== meId) || heldFor === sel);
  const claimBanner = (inModal: boolean) => {
    if (!sel) return null;
    if (heldByOther) {
      const theirs = selClaim && selClaim.by !== meId ? selClaim : null;
      return (
        <div className="mt-2 rounded border border-neon-amber/40 bg-neon-amber/[0.08] px-2 py-1.5 text-[11px]">
          <div className="flex items-center gap-2">
            <span className="text-neon-amber"><span aria-hidden="true">🔒</span> {theirs ? <bdi>{nameOf(theirs.by)}</bdi> : "A teammate"} is working this alert ({theirs ? `claimed ${ago(theirs.at)}` : "claimed just now"}).</span>
            {confirmTake !== sel && <Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={() => setConfirmTake(sel)}>Take over</Button>}
          </div>
          {confirmTake === sel && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              <span className="text-slate-300">Take it over? Agree it in the war room first — they&apos;ll see it moved to you.</span>
              <Button variant="primary" size="sm" disabled={busy} onClick={() => claim(true)}>Confirm take-over</Button>
              <Button variant="outline" size="sm" onClick={() => setConfirmTake(null)}>Cancel</Button>
            </div>
          )}
        </div>
      );
    }
    if (selClaim && selClaim.by === meId) return inModal
      ? <p className="mt-2 text-[11px] text-neon-green">✓ you claimed this alert</p>
      : <div className="mt-2 flex items-center gap-2 text-[11px] text-neon-green"><span>✓ you claimed this alert</span><Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={release}>Release</Button></div>;
    return inModal ? null : <div className="mt-2"><Button variant="outline" size="sm" disabled={busy} onClick={() => claim()}>Take this alert</Button></div>;
  };

  // T1-7: my escalations with live status (sent → acknowledged → bounced/resolved).
  // Status is per ROUND: only what happened to this log after THIS request (and before
  // it was escalated again) counts — a re-escalation after a bounce has its own row.
  const myEsc = useMemo(() => {
    const eidOfEv = (e: Ev) => String((e.payload as { event_id?: string }).event_id);
    return events.filter(e => e.type === "escalation.requested" && e.actor_id === meId).map(e => {
      const p = e.payload as { event_id?: string; summary?: string; what?: string }; const eid = String(p.event_id);
      let status = "sent", reason = "";
      for (const e2 of events) {
        if (e2.seq <= e.seq || eidOfEv(e2) !== eid) continue;
        if (e2.type === "escalation.requested") break;               // next round starts
        if (e2.type === "escalation.resolved") status = "resolved";
        else if (e2.type === "escalation.bounced") { status = "bounced"; reason = asStr((e2.payload as { reason?: string }).reason); }
        else if (e2.type === "escalation.acknowledged" && status === "sent") status = "acknowledged";
      }
      return { seq: e.seq, eid, label: asStr(p.summary) || asStr(p.what) || "escalation", status, reason };
    });
  }, [events, meId]);

  const [iocErr, setIocErr] = useState("");
  function addIoc(value: string, source: "picked" | "manual") {
    const v = value.trim(); if (!v) return;
    // A4: a MANUAL indicator must look like a real IOC; picked-from-log values are trusted.
    if (source === "manual" && !isValidIoc(v)) { setIocErr(`"${v.length > 80 ? v.slice(0, 80) + "…" : v}" isn't a valid indicator (${IOC_HELP}).`); return; }
    setIocErr("");
    setIocDraft(d => d.some(x => x.value.toLowerCase() === v.toLowerCase()) ? d : [...d, { type: detectIocType(v), value: v, source }]);
  }
  // T1-6 quality gate — every condition must hold before Escalate is allowed.
  // The why must cite evidence from the log (2026-10-18 review: escalations said "TI").
  const selPayload = sel ? (feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel)?.payload as Record<string, unknown> | undefined) : undefined;
  const rationaleIssue = rationaleProblem(form.observations, selPayload, iocDraft);
  const gate = {
    // No length minimums (0079): the fields must be filled, not a word count.
    summary: !!form.summary.trim(),
    rationale: rationaleIssue == null,
    ioc: iocDraft.length >= 1,
    severity: !!form.severity,
    // A4: escalate only an attack-ish call — you can't escalate a log you marked benign/FP.
    disposition: selDisp === "true_positive" || selDisp === "suspicious",
  };
  const canEscalate = !!sel && !busy && gate.summary && gate.rationale && gate.ioc && gate.severity && gate.disposition;

  // When the report opens (from the 🚩 on a log OR the dropdown button), take the
  // soft-claim automatically so two Tier-1s don't work the same log — unless a
  // teammate already holds it (then the modal shows a "Take over" banner instead).
  useEffect(() => {
    if (reportOpen && sel && !selClaim) void claim();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportOpen, sel]);

  const [closeNote, setCloseNote] = useState("");
  useEffect(() => { setCloseNote(""); }, [sel]);
  // Read before you close (2026-10-18 review: benign calls made with a 0.5 s average dwell):
  // closing as benign / false positive unlocks once the log has been open READ_FIRST_MS.
  const READ_FIRST_MS = 4000;
  const [openedAt, setOpenedAt] = useState<number>(0);
  const [readTick, setReadTick] = useState(0);
  useEffect(() => { setOpenedAt(sel ? Date.now() : 0); }, [sel]);
  useEffect(() => { if (!sel) return; const t = setTimeout(() => setReadTick(x => x + 1), READ_FIRST_MS + 50); return () => clearTimeout(t); }, [sel]);
  void readTick;
  const readEnough = !!sel && openedAt > 0 && Date.now() - openedAt >= READ_FIRST_MS;
  async function disp(v: string) {
    if (!sel) return;
    setBusy(true);
    const note = (v === "false_positive" || v === "benign") ? closeNote.trim().slice(0, 500) : "";
    const r = await actR("disposition.set", note ? { event_id: sel, verdict: v, note } : { event_id: sel, verdict: v }, { handled: ["claim_held"] });
    if (!r.ok) { setBusy(false); if (r.code === "claim_held") setHeldFor(sel); return; }
    // FP/Benign close at T1 and release any soft claim so a teammate can reuse the row.
    if (v === "false_positive" || v === "benign") await act("alert.released", { event_id: sel });
    // TP / suspicious → you're about to write the escalation: re-take the claim (a
    // disposition ends it server-side) so a teammate can't grab the log mid-report.
    else await actR("alert.claimed", { event_id: sel }, { handled: ["claim_held"] });
    setBusy(false);
  }
  async function escalate() {
    if (!canEscalate) return;
    setBusy(true);
    // Carry the FULL original log with the escalation so Tier-2 investigates the
    // real event (all raw fields), not just T1's words — and independent of feed state.
    const full = feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel)?.payload as Record<string, unknown> | undefined;
    // L8: the escalation payload is capped at 16 KiB server-side — trim an oversized
    // raw block (Tier-2 still has the complete log in the shared feed).
    let snapshot = full;
    if (full && JSON.stringify(full).length > 8000) {
      const rawText = JSON.stringify(full.raw ?? "");
      snapshot = { ...full, raw: rawText.length > 4000 ? `${rawText.slice(0, 4000)}…` : full.raw, snapshot_truncated: true };
    }
    let images: TeamImage[] = [];
    if (shots.items.length) {
      try { images = await Promise.all(shots.items.map(it => uploadTeamImage(sessionId, it))); }
      catch (e) { setBusy(false); shots.setError(e instanceof Error ? e.message : "The screenshots couldn't be uploaded."); return; }
    }
    const fe = full as { hostname?: string; user_email?: string; user?: { email?: string } } | undefined;
    const entity = asStr(fe?.hostname) || asStr(fe?.user_email) || asStr(fe?.user?.email) || "the affected asset";
    const res = await actR("escalation.requested", {
      event_id: sel, summary: form.summary, observations: form.observations, assessment: form.assessment,
      iocs: iocDraft, requested_action: form.requested_action, severity: form.severity,
      confidence: isLowConf ? 0.3 : 0.7, low_confidence: isLowConf || undefined,
      hostname: asStr(fe?.hostname) || undefined, entity, snapshot,
      ...(images.length ? { images } : {}),
      what: form.summary, why: form.observations, // back-compat aliases
    }, { handled: ["claim_held"] });
    const ok = res.ok;
    if (res.code === "claim_held") setHeldFor(sel);
    if (ok) await act("alert.released", { event_id: sel }); // escalated → hand off the claim (the load replay reads the release)
    setBusy(false);
    if (ok) { drafts.current.delete(sel); draftSel.current = ""; setForm(EMPTY_FORM); setIocDraft([]); shots.clear(); setSel(""); setReportOpen(false); }
  }
  // The selected log's payload — powers the modal's log-summary header + the escalate snapshot.
  const selRaw = sel ? feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel) : undefined;
  const selP = selRaw?.payload as { id?: string; description?: unknown; event_type?: unknown; hostname?: unknown; user_email?: unknown; user?: { email?: unknown }; severity?: unknown; source?: unknown } | undefined;
  const selDesc = asStr(selP?.description) || asStr(selP?.event_type) || "event";
  const related = useMemo(() => (selRaw ? relatedLogs(feed, selRaw) : []), [feed, selRaw]);
  const selHost = asStr(selP?.hostname);
  const selUser = asStr(selP?.user_email) || asStr(selP?.user?.email);
  const selSev = asStr(selP?.severity);
  const selSource = asStr(selP?.source);
  const reportRef = useRef<HTMLDivElement>(null);
  useFocusTrap(reportOpen && !!sel, reportRef, { onEscape: () => setReportOpen(false) });
  return (
    <>
    <Card className="border-neon-amber/30 bg-neon-amber/[0.04]">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-neon-amber" /> Tier-1 triage and escalation</h3>
      <ol className="mt-2 grid gap-1 text-[11px] text-slate-300">
        <li><span className="mr-1 rounded bg-cyber-500/20 px-1.5 font-bold text-cyber-300">1</span><b>Take</b> an alert: <span className="text-slate-400">&quot;Take next alert&quot; above the feed, or pick one below. It shows as &quot;Investigating · your name&quot; to the team.</span></li>
        <li><span className="mr-1 rounded bg-cyber-500/20 px-1.5 font-bold text-cyber-300">2</span><b>Investigate</b>: <span className="text-slate-400">open the log, pivot on the host / user, check the IOC, open EDR.</span></li>
        <li><span className="mr-1 rounded bg-cyber-500/20 px-1.5 font-bold text-cyber-300">3</span><b>Close</b> it (not an attack) <b>or escalate</b> it to Tier-2 (attack, or not sure).</li>
      </ol>

      {/* T1-7: my escalations + status tracking (sent/ack/bounced/resolved) */}
      {myEsc.length > 0 && (
        <div className="mt-2 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">My escalations ({myEsc.length})</p>
          {myEsc.slice().reverse().slice(0, 6).map(e => (
            <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-[11px]">
              <span className="min-w-0 flex-1 truncate text-slate-300">{e.label}{e.status === "bounced" && e.reason ? ` — ${e.reason}` : ""}</span>
              <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${e.status === "resolved" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : e.status === "bounced" ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : e.status === "acknowledged" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400"}`}>{e.status}</span>
            </div>
          ))}
        </div>
      )}

      <label className="mt-3 block text-xs">
        <span className="mb-1 block uppercase tracking-wider text-slate-400">Your alert</span>
        <select value={sel} onChange={e => setSel(e.target.value)} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
          <option value="">— select an event —</option>
          {options.map(o => <option key={o.id} value={o.id}>{o.label}{dispositions.get(o.id) ? ` · ${dispositions.get(o.id)}` : ""}</option>)}
        </select>
      </label>
      {/* T1-3: soft-claim so two Tier-1 analysts don't work the same alert (server-enforced, P0-3) */}
      {claimBanner(false)}
      {selRaw && (
        <div className="mt-1.5 flex justify-end">
          <Button variant="outline" size="sm" disabled={busy}
            onClick={() => void act("message.sent", { text: `Take a look at #${selRaw.seq}: ${selDesc}`.slice(0, 400), log_ref: { event_id: sel, seq: selRaw.seq, label: selDesc.slice(0, 160) } })}>
            Share this log in the team chat
          </Button>
        </div>
      )}
      {/* Related activity: the other logs about this host / user / external address (2026-10-18 review:
          the quiet steps of an attack were skipped once one alert of it was found). */}
      {selRaw && related.length > 0 && (
        <div className="mt-2 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.05] p-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">Related activity ({related.length})</p>
          <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
            {related.map(r => {
              const rp = r.e.payload as { description?: unknown; event_type?: unknown; severity?: unknown };
              const d = dispositions.get(r.eid);
              return (
                <li key={r.eid}>
                  <button type="button" onClick={() => setSel(r.eid)} className="flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-left text-[10px] hover:bg-white/5 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyber-400/60">
                    <span className="shrink-0 font-mono text-slate-500">#{r.e.seq}</span>
                    <span className="shrink-0 font-mono uppercase text-slate-400">{asStr(rp.severity) || "info"}</span>
                    <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(rp.description) || asStr(rp.event_type)}</span>
                    <span className="shrink-0 text-slate-500">{r.shared.map(entityLabel).join(", ")}</span>
                    <span className={`shrink-0 font-mono ${d ? "text-neon-green" : "text-neon-amber"}`}>{d ? d.replace("_", " ") : "untriaged"}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {/* T1-2: the decision, as two plain paths: close it, or escalate it. */}
      {sel && (selDisp === "false_positive" || selDisp === "benign") ? (
        <p className="mt-3 rounded-lg border border-neon-green/30 bg-neon-green/5 px-3 py-2 text-xs text-neon-green">
          ✓ Closed as {selDisp === "benign" ? "benign" : "false positive"}. It left the triage queue. Pick the next alert.
        </p>
      ) : (
        <div className="mt-3 grid gap-2">
          <div className="rounded-lg border border-slate-600/60 bg-slate-800/30 p-2.5">
            <p className="text-xs font-semibold text-slate-100">Not an attack? Close the alert</p>
            <input id="t1-close-note" value={closeNote} onChange={e => setCloseNote(e.target.value)} dir="auto" maxLength={500} disabled={!sel}
              placeholder="Closing note (optional): why it's safe"
              className="mt-1.5 w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none disabled:opacity-50" />
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              <Button variant="outline" size="sm" disabled={!sel || busy || !readEnough} onClick={() => disp("false_positive")} title="The rule fired, but it is not malicious">Close as false positive</Button>
              <Button variant="outline" size="sm" disabled={!sel || busy || !readEnough} onClick={() => disp("benign")} title="Expected, normal activity">Close as benign</Button>
            </div>
            {sel && !readEnough && <p className="mt-1 text-[10px] text-slate-500">Read the log first: closing unlocks in a few seconds.</p>}
          </div>
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/[0.06] p-2.5">
            <p className="text-xs font-semibold text-amber-200">Attack, or not sure? Escalate to Tier-2</p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {[["true_positive", "It's an attack (true positive)"], ["suspicious", "Suspicious, needs a deeper look"]].map(([v, label]) => (
                <Button key={v} variant={selDisp === v ? "primary" : "outline"} size="sm" aria-pressed={selDisp === v} disabled={!sel || busy} onClick={() => disp(v)}>{label}</Button>
              ))}
            </div>
            <Button variant="primary" size="sm" className="mt-2 w-full" disabled={!sel} onClick={() => setReportOpen(true)}>
              <ArrowUpRight className="mr-1.5 h-4 w-4" /> Write escalation report{sel ? ` · #${selRaw?.seq}` : ""}
            </Button>
          </div>
          {!sel && <p className="text-[10px] text-slate-500">Take an alert first (&quot;Take next alert&quot;, the feed, or the list above).</p>}
        </div>
      )}
    </Card>

    {/* ── Escalation report modal — opens ON the log (🚩) or via "Write escalation report" ── */}
    {reportOpen && sel && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setReportOpen(false)}>
        <div ref={reportRef} role="dialog" aria-modal="true" aria-labelledby="t1-report-title" tabIndex={-1} className="max-h-[88vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <h2 id="t1-report-title" className="flex items-center gap-2 text-base font-bold text-white"><span aria-hidden="true" className="text-lg leading-none">🚩</span> Escalation report → Tier-2</h2>
            <button onClick={() => setReportOpen(false)} aria-label="Close" className="text-xl leading-none text-slate-400 hover:text-white">&times;</button>
          </div>

          {/* Which log you're reporting on — pulled straight from the flagged event */}
          <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-300/80">Flagged log · #{selRaw?.seq}</p>
            <p className="mt-0.5 text-sm text-slate-200">{selDesc}</p>
            <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
              {selSev && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">severity: {selSev}</span>}
              {selSource && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">{selSource}</span>}
              {selHost && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">host: {selHost}</span>}
              {selUser && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">user: {selUser}</span>}
            </div>
          </div>

          {/* Claim status — surfaced INSIDE the modal so the 🚩 path can't hide a teammate's lock */}
          {claimBanner(true)}

          {/* Disposition — triage before escalate. Set it right here if it isn't yet. */}
          <div className="mt-2">
            {selDisp ? (
              <p className="text-[11px] text-slate-400">Disposition: <span className="font-semibold text-slate-200">{selDisp.replace("_", " ")}</span></p>
            ) : (
              <>
                <p className="text-[11px] text-neon-amber">Set a disposition first (triage → escalate):</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {[["true_positive", "true positive"], ["suspicious", "suspicious"]].map(([v, label]) => (
                    <Button key={v} variant="outline" size="sm" disabled={busy} onClick={() => disp(v)}>{label}</Button>
                  ))}
                </div>
              </>
            )}
          </div>

          <div className="mt-3 space-y-2">
            {isLowConf && <p className="rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px] text-neon-amber">Low-confidence lead — sending to Tier-2 for a second look.</p>}
            <input aria-label="Summary" value={form.summary} onChange={e => setForm(f => ({ ...f, summary: e.target.value }))} placeholder="Summary — one line: what happened + on what" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <textarea aria-label="Observations" value={form.observations} onChange={e => setForm(f => ({ ...f, observations: e.target.value }))} onPaste={shots.onPaste} placeholder="Observations — the process/sequence/evidence (paste a screenshot with Ctrl+V)" rows={3} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            {/* Screenshots as evidence: paste into Observations, drop here, or use the button (up to 3). */}
            <div className="rounded-lg border border-dashed border-border bg-bg px-2 py-1.5" {...shots.dropProps}>
              <div className="flex items-center gap-2">
                <AttachImageButton onPick={f => void shots.add(f)} label="Attach a screenshot to the escalation" />
                <p className="text-[10px] text-slate-400">Screenshots (optional, up to 3): paste, drop, or attach. Tier-2 sees them on the ticket.</p>
              </div>
              {shots.items.length > 0 && <div className="mt-1.5"><PendingImages items={shots.items} onRemove={shots.remove} /></div>}
              {shots.error && <p role="alert" className="mt-1 text-[10px] text-severity-high">{shots.error}</p>}
            </div>
            {/* T1-5: IOCs — pre-seeded from the flagged log; click "+IOC" on raw fields, or type here */}
            <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Indicators (IOCs) — click ＋IOC on the log&apos;s fields, or add below</p>
              {iocDraft.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {iocDraft.map(i => (
                    <span key={i.value} className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyber-300">
                      <span className="text-slate-500">{i.type}:</span>{i.value}
                      <button onClick={() => setIocDraft(d => d.filter(x => x.value !== i.value))} aria-label={`Remove IOC ${i.value}`} className="text-slate-400 hover:text-white"><X className="h-3 w-3" aria-hidden="true" /></button>
                    </span>
                  ))}
                </div>
              )}
              <div className="mt-1 flex gap-1.5">
                <input aria-label="Add an IOC" value={iocText} onChange={e => setIocText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { addIoc(iocText, "manual"); setIocText(""); } }} placeholder="add an IOC (ip / domain / hash / user)…" className="flex-1 rounded border border-border bg-bg px-2 py-1 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                <Button variant="outline" size="sm" onClick={() => { addIoc(iocText, "manual"); setIocText(""); }}>Add</Button>
              </div>
              {iocErr && <p className="mt-1 text-[10px] text-severity-high">{iocErr}</p>}
            </div>
            <input aria-label="Assessment" value={form.assessment} onChange={e => setForm(f => ({ ...f, assessment: e.target.value }))} placeholder="Assessment — what you think this is" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <div className="flex gap-2">
              <select aria-label="Severity" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{SEVERITIES.map(s => <option key={s} value={s}>severity: {s}</option>)}</select>
              <select aria-label="Requested action" value={form.requested_action} onChange={e => setForm(f => ({ ...f, requested_action: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{REQUESTED_ACTIONS.map(a => <option key={a} value={a}>action: {a}</option>)}</select>
            </div>
            {/* T1-6: live checklist for the hard gate — ✓/○ per item + positive "all set" */}
            <div className="text-[10px] leading-relaxed text-slate-500">
              {canEscalate ? (
                <span className="font-semibold text-neon-green">✓ all set — ready to escalate</span>
              ) : (
                <>Before escalating:{" "}
                  {([[gate.disposition, "disposition"], [gate.summary, "summary"], [gate.rationale, "observations with evidence"], [gate.ioc, "≥1 IOC"], [gate.severity, "severity"]] as [boolean, string][]).map(([ok, label]) => (
                    <span key={label} className={ok ? "text-neon-green" : ""}>{ok ? "✓" : "○"} {label}&nbsp;&nbsp;</span>
                  ))}
                  {rationaleIssue && form.observations.trim() && <span className="block text-neon-amber">{rationaleIssue}</span>}
                </>
              )}
            </div>
            <div className="flex gap-2 pt-1">
              <Button variant="outline" size="sm" className="flex-1" onClick={() => setReportOpen(false)}>Cancel</Button>
              <Button variant="primary" size="sm" className="flex-1" disabled={!canEscalate} onClick={escalate}><ArrowUpRight className="mr-1.5 h-4 w-4" /> Escalate to Tier-2</Button>
            </div>
          </div>
        </div>
      </div>
    )}
    </>
  );
}
