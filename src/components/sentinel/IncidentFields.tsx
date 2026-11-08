"use client";
// Owner, Status and Severity: the same strip on the details page and in the grid's preview. As in the
// product each opens a list with Apply and Cancel, nothing changes until Apply, and closing an
// incident happens inside the Status list.
import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronDown, UserRound, Search } from "lucide-react";
import type { ClosingClassification, IncidentState, IncidentStatus, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { CLASSIFICATIONS, STATUSES } from "./helpers";
import { Popover, Select, SevGlyph, StatusIcon } from "./ui";

/** Lowest first, as the product lists them. */
const SEVERITY_ORDER: SentinelSeverity[] = ["Informational", "Low", "Medium", "High"];

function PickFooter({ canApply, onApply, onCancel, busy }: { canApply: boolean; onApply: () => void; onCancel: () => void; busy?: boolean }) {
  return (
    <div className="st-pick-foot">
      <button type="button" className="st-btn primary" disabled={!canApply || busy} onClick={onApply}>Apply</button>
      <button type="button" className="st-btn" onClick={onCancel}>Cancel</button>
    </div>
  );
}

function useApply(onClose: () => void) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const apply = async (fn: () => Promise<string | null>) => {
    setBusy(true); setErr(null);
    const e = await fn();
    setBusy(false);
    if (e) setErr(e); else onClose();
  };
  return { busy, err, apply };
}

interface PickerProps { incident: SentinelIncident; state: IncidentState; anchor: HTMLElement; side: "below" | "right"; onClose: () => void }

function SeverityPicker({ incident, state, anchor, side, onClose }: PickerProps) {
  const { actions } = useSentinel();
  const [pick, setPick] = useState(state.severity);
  const { busy, err, apply } = useApply(onClose);
  return (
    <Popover anchor={anchor} onClose={onClose} width={210} side={side} keepOnTab role="dialog" label="Severity">
      {err && <div className="st-msg err" role="alert">{err}</div>}
      <div role="listbox" aria-label="Severity" className="st-pick-list">
        {SEVERITY_ORDER.map(s => (
          <button key={s} type="button" role="option" aria-selected={pick === s} tabIndex={-1} className="st-opt" onClick={() => setPick(s)}>
            <i className={`st-band ${s}`} style={{ height: 14 }} aria-hidden />{s}
          </button>
        ))}
      </div>
      <PickFooter busy={busy} canApply={pick !== state.severity} onCancel={onClose}
        onApply={() => void apply(() => actions.updateIncident(incident.id, { severity: pick }))} />
    </Popover>
  );
}

function StatusPicker({ incident, state, anchor, side, onClose }: PickerProps) {
  const { actions } = useSentinel();
  const [pick, setPick] = useState<IncidentStatus>(state.status);
  const [classification, setClassification] = useState<ClosingClassification | "">("");
  const [comment, setComment] = useState("");
  const { busy, err, apply } = useApply(onClose);
  const closing = pick === "Closed" && state.status !== "Closed";
  const can = pick !== state.status && (!closing || !!classification);
  const save = () => apply(() => actions.updateIncident(incident.id, closing
    ? { status: "Closed", classification: classification as ClosingClassification, closingComment: comment.trim() }
    : { status: pick }));
  return (
    <Popover anchor={anchor} onClose={onClose} width={320} side={side} keepOnTab role="dialog" label="Status">
      {err && <div className="st-msg err" role="alert">{err}</div>}
      <div role="listbox" aria-label="Status" className="st-pick-list">
        {STATUSES.map(s => (
          <button key={s} type="button" role="option" aria-selected={pick === s} tabIndex={-1} className="st-opt" onClick={() => setPick(s)}>
            <StatusIcon status={s} size={16} />{s}
          </button>
        ))}
      </div>
      {closing && (
        <div className="st-pick-close">
          <Select label="Classification" valueLabel={classification || "Select classification"} value={classification as ClosingClassification} width={296}
            options={CLASSIFICATIONS.map(c => ({ value: c, label: c }))} onChange={setClassification} className="st-input st-row">
            <span className="st-ellipsis st-grow">{classification || "Select classification"}</span><ChevronDown size={14} aria-hidden />
          </Select>
          <label><span className="st-sr">Comment</span>
            <textarea className="st-input st-textarea" rows={6} placeholder="Comment" maxLength={4000} value={comment} onChange={e => setComment(e.target.value)} />
          </label>
        </div>
      )}
      <PickFooter busy={busy} canApply={can} onCancel={onClose} onApply={() => void save()} />
    </Popover>
  );
}

const initials = (n: string) => n.split(/\s+/).map(p => p[0]).slice(0, 2).join("").toUpperCase();

function OwnerPicker({ incident, state, anchor, side, onClose }: PickerProps) {
  const { actions } = useSentinel();
  const [pick, setPick] = useState<string | null>(state.owner);
  const [q, setQ] = useState("");
  const { busy, err, apply } = useApply(onClose);
  const me = actions.me.name;
  const others = useMemo(() => {
    const s = q.trim().toLowerCase();
    return [...new Set(actions.people)].filter(p => p !== me && (!s || p.toLowerCase().includes(s))).sort((a, b) => a.localeCompare(b));
  }, [actions.people, me, q]);
  return (
    <Popover anchor={anchor} onClose={onClose} width={350} side={side} keepOnTab role="dialog" label="Owner">
      {err && <div className="st-msg err" role="alert">{err}</div>}
      <div className="st-pop-pad" style={{ paddingBottom: 4 }}>
        <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">Search users or groups</span>
          <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search users or groups" autoComplete="off" />
        </label>
      </div>
      <div className="st-pick-group">Users</div>
      <div role="listbox" aria-label="Owner" className="st-pick-people">
        <button type="button" role="option" aria-selected={pick === null} tabIndex={-1} className="st-person" onClick={() => setPick(null)}>
          <span className="face plain"><UserRound size={20} aria-hidden /></span><span>Unassign Incident</span>
        </button>
        <button type="button" role="option" aria-label={`Assign to me, ${me}`} aria-selected={pick === me} tabIndex={-1} className="st-person" onClick={() => setPick(me)}>
          <span className="face grey">{initials(me)}</span><span><span className="d">Assign to me</span><span className="d sub">{me}</span></span>
        </button>
        {others.map(p => (
          <button key={p} type="button" role="option" aria-label={p} aria-selected={pick === p} tabIndex={-1} className="st-person" onClick={() => setPick(p)}>
            <span className="face">{initials(p)}</span><span>{p}</span>
          </button>
        ))}
      </div>
      <PickFooter busy={busy} canApply={pick !== state.owner} onCancel={onClose} onApply={() => void apply(() => actions.updateIncident(incident.id, { owner: pick }))} />
    </Popover>
  );
}

type Field = "severity" | "status" | "owner";

/** The strip: Severity, Status, Owner on the page, Owner, Status, Severity in the preview. */
export function FieldBar({ incident, state, order, collapsed, tail }: {
  incident: SentinelIncident; state: IncidentState; order: Field[]; collapsed?: boolean; tail?: ReactNode;
}) {
  const { ended } = useSentinel();
  const [open, setOpen] = useState<{ field: Field; anchor: HTMLElement } | null>(null);
  const close = useCallback(() => setOpen(null), []);
  const refs = useRef<Partial<Record<Field, HTMLButtonElement | null>>>({});
  const owner = state.owner ?? "Unassigned";
  const value: Record<Field, string> = { severity: state.severity, status: state.status, owner };
  const label: Record<Field, string> = { severity: "Severity", status: "Status", owner: "Owner" };
  const glyph = (f: Field, size: number) => (f === "status" ? <StatusIcon status={state.status} size={size} />
    : f === "owner" ? <UserRound size={size} color="#6d28d9" aria-hidden />
      : collapsed ? <SevGlyph value={state.severity} size={size} /> : null);
  const props: PickerProps | null = open ? { incident, state, anchor: open.anchor, side: collapsed ? "right" : "below", onClose: close } : null;
  return (
    <div className={`st-fieldbar${collapsed ? " collapsed" : ""}`}>
      {order.map(f => (
        <button key={f} ref={el => { refs.current[f] = el; }} type="button" className={`st-fieldcell f-${f}`} disabled={ended} aria-haspopup="dialog" aria-expanded={open?.field === f}
          aria-label={`${label[f]}: ${value[f]}`} onClick={e => { const a = e.currentTarget; setOpen(o => (o?.field === f ? null : { field: f, anchor: a })); }}>
          {collapsed ? (
            <>{glyph(f, 20)}<span className="st-ellipsis cval">{value[f]}</span></>
          ) : (
            <>
              {f === "severity" && <i className={`band st-band ${state.severity}`} aria-hidden />}
              <span className="st-grow" style={{ minWidth: 0 }}>
                <span className="val">{glyph(f, 14)}<span className="st-ellipsis">{value[f]}</span></span>
                <span className="lab">{label[f]}</span>
              </span>
              {!ended && <ChevronDown size={14} aria-hidden />}
            </>
          )}
        </button>
      ))}
      {tail}
      {open?.field === "severity" && props && <SeverityPicker {...props} />}
      {open?.field === "status" && props && <StatusPicker {...props} />}
      {open?.field === "owner" && props && <OwnerPicker {...props} />}
    </div>
  );
}
