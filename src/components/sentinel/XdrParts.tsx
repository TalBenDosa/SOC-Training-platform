"use client";
// XDR's own way of drawing an alert and an entity (owner, 2026-11-08: the console keeps its original
// layout, but alerts, entities and the graph must not look one-to-one like Microsoft Sentinel).
// An alert is a card with a severity side stripe, the time on the right and chips for severity,
// product, MITRE tactic and its key entities. Entities are grouped by type under a header with a
// count, one compact row each with a type tile and an alert-count badge. Presentational only.
import { useMemo, type ReactNode } from "react";
import { Bookmark, ShieldAlert, Target } from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelEntity, SentinelSeverity } from "@/lib/sentinel/types";
import { fmtClock, fmtMonthDay, KIND_LABEL, tacticLabel } from "./helpers";
import { entityIcon, MoreMenu, type MenuItem } from "./ui";

/* ------------------------------------------------ chips ------------------------------------------- */

export function SevChip({ value }: { value: SentinelSeverity }) {
  return <span className={`xd-chip sev ${value}`}>{value}</span>;
}

export function ProductChip({ product }: { product: string }) {
  return <span className="xd-chip prod st-ellipsis" title={`Detected by ${product}`}>{product}</span>;
}

export function TacticChips({ tactics, max = 2 }: { tactics: string[]; max?: number }) {
  if (!tactics.length) return null;
  const rest = tactics.length - max;
  return (
    <>
      {tactics.slice(0, max).map(t => <span key={t} className="xd-chip tac" title={`MITRE ATT&CK tactic: ${tacticLabel(t)}`}><Target size={11} aria-hidden />{tacticLabel(t)}</span>)}
      {rest > 0 && <span className="xd-chip tac" title={tactics.slice(max).map(tacticLabel).join(", ")}>+{rest}</span>}
    </>
  );
}

/** A type tile: the entity's icon in a small rounded square, tinted per type family. */
export function EntityTile({ kind, size = 26 }: { kind: EntityKind; size?: number }) {
  const I = entityIcon(kind);
  return <span className={`xd-etile k-${kind}`} style={{ width: size, height: size }} aria-hidden><I size={Math.round(size * .56)} /></span>;
}

export function EntityChip({ entity }: { entity: SentinelEntity }) {
  const I = entityIcon(entity.kind);
  return <span className="xd-echip" title={`${KIND_LABEL[entity.kind]}: ${entity.name}`}><I size={11} aria-hidden /><span className="st-ellipsis">{entity.name}</span></span>;
}

/* ------------------------------------------------ alerts ------------------------------------------ */

const when = (iso: string) => `${fmtMonthDay(iso)}, ${fmtClock(iso)}`;

/**
 * The inside of an alert card: title with the time on the right, then severity, product and tactic
 * chips, then the alert's key entities. The caller wraps it in its own button or block.
 */
export function AlertCardBody({ alert, entities = [], maxEntities = 3, dense }: { alert: SentinelAlert; entities?: SentinelEntity[]; maxEntities?: number; dense?: boolean }) {
  const more = entities.length - maxEntities;
  return (
    <>
      <span className="xd-ac-top">
        <span className="xd-ac-title st-ellipsis" title={alert.name}>{alert.name}</span>
        <time className="xd-ac-time" dateTime={alert.time}>{when(alert.time)}</time>
      </span>
      <span className="xd-ac-chips">
        <SevChip value={alert.severity} />
        <ProductChip product={alert.product} />
        {!dense && <TacticChips tactics={alert.tactics} />}
      </span>
      {entities.length > 0 && (
        <span className="xd-ac-ents">
          {entities.slice(0, maxEntities).map(e => <EntityChip key={e.id} entity={e} />)}
          {more > 0 && <span className="xd-echip more">+{more}</span>}
        </span>
      )}
    </>
  );
}

/** A bookmark, drawn as an alert card would be: accent stripe, author chip, time on the right. */
export function BookmarkCardBody({ name, at, author }: { name: string; at: string; author: string }) {
  return (
    <>
      <span className="xd-ac-top">
        <span className="xd-ac-title st-ellipsis" title={name}>{name}</span>
        <time className="xd-ac-time" dateTime={at}>{when(at)}</time>
      </span>
      <span className="xd-ac-chips">
        <span className="xd-chip bm"><Bookmark size={11} aria-hidden />Bookmark</span>
        <span className="xd-chip prod st-ellipsis">Created by {author}</span>
      </span>
    </>
  );
}

/** The severity-tinted tile an alert's header carries. */
export function AlertTile({ severity, size = 30 }: { severity: SentinelSeverity; size?: number }) {
  return <span className={`xd-atile ${severity}`} style={{ width: size, height: size }} aria-hidden><ShieldAlert size={Math.round(size * .55)} /></span>;
}

/* ----------------------------------------------- entities ----------------------------------------- */

const KIND_ORDER: EntityKind[] = ["account", "host", "ip", "mailbox", "process", "file", "url", "domain", "cloudapp", "azureresource", "registry"];
const PLURAL: Record<EntityKind, string> = {
  account: "Accounts", host: "Hosts", ip: "IP addresses", file: "Files", process: "Processes", url: "URLs", domain: "DNS names",
  mailbox: "Mailboxes", cloudapp: "Cloud applications", azureresource: "Azure resources", registry: "Registry keys",
};

/** How many of the given alerts name each entity. */
export function useAlertCounts(alerts: SentinelAlert[]): Map<string, number> {
  return useMemo(() => {
    const m = new Map<string, number>();
    for (const a of alerts) for (const id of a.entityIds) m.set(id, (m.get(id) ?? 0) + 1);
    return m;
  }, [alerts]);
}

/**
 * Entities grouped by type: a header with the type and its count, then one compact row per entity
 * (type tile, name, alert-count badge, actions). Selecting a row calls onSelect.
 */
export function EntityGroups({ entities, counts, selected, onSelect, menu, empty = "No entity matches." }: {
  entities: SentinelEntity[]; counts: Map<string, number>; selected?: string | null; onSelect: (id: string) => void;
  menu?: (e: SentinelEntity) => MenuItem[]; empty?: ReactNode;
}) {
  const groups = useMemo(() => {
    const by = new Map<EntityKind, SentinelEntity[]>();
    for (const e of entities) by.set(e.kind, [...(by.get(e.kind) ?? []), e]);
    return KIND_ORDER.filter(k => by.has(k)).map(k => ({ kind: k, items: by.get(k) as SentinelEntity[] }));
  }, [entities]);
  if (!entities.length) return <p className="st-muted st-small" style={{ padding: 12 }}>{empty}</p>;
  return (
    <div className="xd-egroups">
      {groups.map(g => (
        <section key={g.kind} className="xd-egroup" aria-label={`${PLURAL[g.kind]} (${g.items.length})`}>
          <h4 className="xd-egroup-head"><span>{PLURAL[g.kind]}</span><span className="xd-count">{g.items.length}</span></h4>
          <ul>
            {g.items.map(e => {
              const n = counts.get(e.id) ?? 0;
              const on = e.id === selected;
              const items = menu?.(e) ?? [];
              return (
                <li key={e.id} className={`xd-erow${on ? " on" : ""}`}>
                  <button type="button" className="xd-erow-main" aria-current={on ? "true" : undefined} title={e.name} onClick={() => onSelect(e.id)}>
                    <EntityTile kind={e.kind} />
                    <span className="xd-ename st-ellipsis">{e.name}</span>
                    {n > 0 && <span className="xd-ebadge" title={`In ${n} ${n === 1 ? "alert" : "alerts"} of this incident`}>{n} {n === 1 ? "alert" : "alerts"}</span>}
                  </button>
                  {menu && <MoreMenu label={`Actions for ${e.name}`} items={items} />}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}

/** A labelled block of an entity or alert panel: a small caps header over its rows. */
export function PaneSection({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="xd-psec">
      <h4 className="xd-psec-head"><span className="st-grow">{title}</span>{aside}</h4>
      {children}
    </section>
  );
}

/** One label and value row of a key-value list. */
export function Kv({ k, children }: { k: string; children: ReactNode }) {
  return <div className="xd-kv"><div className="xd-k">{k}</div><div className="xd-v">{children}</div></div>;
}
