"use client";
// Shared controls of the console. Every popup is position: fixed so scroll areas never clip it,
// and every popup and panel restores focus to what opened it.
import {
  useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState,
  type CSSProperties, type KeyboardEvent as RKeyboardEvent, type ReactNode,
} from "react";
import {
  AppWindow, ArrowDown, ArrowLeft, ArrowUp, ArrowUpDown, Box, CheckCircle2, ChevronDown, Info,
  Cloud, Cpu, FileText, Globe, KeyRound, Link2, Loader, CircleAlert, Mail, Monitor, MoreHorizontal, RefreshCw, Search, User, X,
} from "lucide-react";
import type { EntityKind, IncidentStatus, SentinelSeverity } from "@/lib/sentinel/types";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]';

/* ---------------------------------------------- popover ------------------------------------------- */

export function Popover({ anchor, onClose, children, width, align = "left", side = "below", keepOnTab, role, label, style }: {
  anchor: HTMLElement | null; onClose: () => void; children: ReactNode; width?: number; align?: "left" | "right";
  side?: "below" | "right"; keepOnTab?: boolean; role?: string; label?: string; style?: CSSProperties;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<CSSProperties>({ top: 0, left: 0, visibility: "hidden" });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || !anchor) return;
    const a = anchor.getBoundingClientRect();
    const b = el.getBoundingClientRect();
    const vw = window.innerWidth; const vh = window.innerHeight;
    let left = align === "right" ? a.right - b.width : a.left;
    left = Math.max(4, Math.min(left, vw - b.width - 4));
    let top = a.bottom + 2;
    if (top + b.height > vh - 4) top = Math.max(4, a.top - b.height - 2);
    if (side === "right") { left = Math.min(a.right + 8, vw - b.width - 4); top = Math.max(4, Math.min(a.top, vh - b.height - 4)); }
    setPos({ top, left, visibility: "visible" });
    // Selected option first, then the first control, so arrow keys work at once.
    const first = el.querySelector<HTMLElement>('[aria-selected="true"],[aria-checked="true"]') ?? el.querySelector<HTMLElement>(`input,textarea,select,[role="option"],[role="menuitem"],${FOCUSABLE}`);
    first?.focus({ preventScroll: true });
  }, [anchor, align, side]);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || anchor?.contains(t)) return;
      onClose();
    };
    const onResize = () => onClose();
    document.addEventListener("mousedown", onDown);
    window.addEventListener("resize", onResize);
    return () => { document.removeEventListener("mousedown", onDown); window.removeEventListener("resize", onResize); };
  }, [anchor, onClose]);

  const onKeyDown = (e: RKeyboardEvent) => {
    if (e.key === "Escape") { e.stopPropagation(); e.preventDefault(); onClose(); anchor?.focus(); return; }
    const items = [...(ref.current?.querySelectorAll<HTMLElement>('[role="option"],[role="menuitem"],[role="menuitemcheckbox"]') ?? [])];
    if (!items.length) return;
    const at = items.indexOf(document.activeElement as HTMLElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(at + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(at - 1 + items.length) % items.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
    else if (e.key === "Tab" && !keepOnTab) { onClose(); }
  };

  return (
    <div ref={ref} className="st-popover" role={role} aria-label={label} style={{ ...pos, width, ...style }} onKeyDown={onKeyDown}>
      {children}
    </div>
  );
}

/* ---------------------------------------------- select -------------------------------------------- */

export interface Opt<T extends string = string> { value: T; label: string; icon?: ReactNode }

/** Single choice. `children` draws the closed control, so the same logic serves pills and field cells. */
export function Select<T extends string>({ label, value, valueLabel, options, onChange, disabled, className, children, searchable, width, title }: {
  label: string; value: T; valueLabel?: string; options: Opt<T>[]; onChange: (v: T) => void; disabled?: boolean; className?: string;
  children?: ReactNode; searchable?: boolean; width?: number; title?: string;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => { setOpen(false); setQ(""); }, []);
  const current = options.find(o => o.value === value);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return s ? options.filter(o => o.label.toLowerCase().includes(s)) : options;
  }, [options, q]);
  return (
    <>
      <button
        ref={btn} type="button" className={className} disabled={disabled} title={title}
        aria-haspopup="listbox" aria-expanded={open} aria-label={`${label}: ${valueLabel ?? current?.label ?? value}`}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => { if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); } }}
      >
        {children ?? <><span className="st-ellipsis">{current?.label ?? value}</span><ChevronDown size={12} aria-hidden /></>}
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={width}>
          {searchable && (
            <div className="st-pop-pad">
              <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">Search {label}</span>
                <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" autoComplete="off" />
              </label>
            </div>
          )}
          <div role="listbox" aria-label={label}>
            {shown.map(o => (
              <button key={o.value} type="button" role="option" aria-selected={o.value === value} tabIndex={-1} className="st-opt"
                onClick={() => { close(); btn.current?.focus(); onChange(o.value); }}>
                {o.icon}<span className="st-ellipsis">{o.label}</span>
              </button>
            ))}
            {shown.length === 0 && <p className="st-muted" style={{ padding: "8px 12px" }}>No matches.</p>}
          </div>
        </Popover>
      )}
    </>
  );
}

/** "Severity : All" pill over a list of checkboxes. An empty selection means all. */
export function FilterPill({ label, options, selected, onChange }: {
  label: string; options: string[]; selected: string[]; onChange: (v: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const summary = selected.length === 0 || selected.length === options.length ? "All" : selected.length === 1 ? selected[0] : `${selected.length} selected`;
  const toggle = (v: string) => onChange(selected.includes(v) ? selected.filter(x => x !== v) : [...selected, v]);
  return (
    <>
      <button ref={btn} type="button" className="st-pill" aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        {label} : <b>{summary}</b>
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={240} label={`${label} filter`} role="group">
          <label className="st-opt st-check"><input type="checkbox" checked={selected.length === 0 || selected.length === options.length} onChange={() => onChange([])} />Select all</label>
          {options.map(o => (
            <label key={o} className="st-opt st-check">
              <input type="checkbox" checked={selected.length === 0 || selected.includes(o)}
                onChange={() => toggle2(o, options, selected, onChange, toggle)} />
              <span className="st-ellipsis">{o}</span>
            </label>
          ))}
          {options.length === 0 && <p className="st-muted" style={{ padding: "8px 12px" }}>No values.</p>}
        </Popover>
      )}
    </>
  );
}
function toggle2(o: string, options: string[], selected: string[], onChange: (v: string[]) => void, toggle: (v: string) => void) {
  // From "all", unticking one keeps the rest.
  if (selected.length === 0) onChange(options.filter(x => x !== o));
  else toggle(o);
}

export interface MenuItem { label: string; onSelect: () => void; icon?: ReactNode }

/** A button that opens a menu. Without items there is no button: nothing here is ever dead. */
export function ButtonMenu({ label, items, className, children, align = "left", title }: {
  label: string; items: MenuItem[]; className?: string; children: ReactNode; align?: "left" | "right"; title?: string;
}) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  if (!items.length) return null;
  return (
    <>
      <button ref={btn} type="button" className={className} aria-haspopup="menu" aria-expanded={open} aria-label={label} title={title ?? label}
        onClick={e => { e.stopPropagation(); setOpen(o => !o); }}>
        {children}
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} role="menu" label={label} align={align} width={200}>
          {items.map(it => (
            <button key={it.label} type="button" role="menuitem" tabIndex={-1} className="st-opt"
              onClick={e => { e.stopPropagation(); close(); it.onSelect(); }}>
              {it.icon}<span>{it.label}</span>
            </button>
          ))}
        </Popover>
      )}
    </>
  );
}
export function MoreMenu({ label, items }: { label: string; items: MenuItem[] }) {
  return <ButtonMenu label={label} items={items} className="st-icon-btn" align="right"><MoreHorizontal size={16} aria-hidden /></ButtonMenu>;
}

/* ----------------------------------------------- panel -------------------------------------------- */

/** Open panels, innermost last: Escape closes only the top one. */
const panelStack: symbol[] = [];

export function SlidePanel({ title, subtitle, icon, onClose, width = 480, footer, children, noBody }: {
  title: string; subtitle?: string; icon?: ReactNode; onClose: () => void; width?: number | string; footer?: ReactNode; children: ReactNode; noBody?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const returnTo = useRef<HTMLElement | null>(null);
  useEffect(() => {
    returnTo.current = document.activeElement as HTMLElement | null;
    const panel = ref.current;
    const first = panel?.querySelector<HTMLElement>("[data-autofocus]") ?? panel?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus({ preventScroll: true });
    return () => { returnTo.current?.focus?.({ preventScroll: true }); };
  }, []);
  // On the document: a button that disables itself after a click drops focus to <body>, and Escape
  // must still work. Popups and the query editor keep their own Escape by stopping it first.
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const me = Symbol("panel");
    panelStack.push(me);
    const onEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && panelStack[panelStack.length - 1] === me) closeRef.current();
    };
    document.addEventListener("keydown", onEscape);
    return () => {
      document.removeEventListener("keydown", onEscape);
      panelStack.splice(panelStack.indexOf(me), 1);
    };
  }, []);
  const onKeyDown = (e: RKeyboardEvent) => {
    if (e.key !== "Tab" || !ref.current) return;
    const items = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(el => el.offsetParent !== null || el === document.activeElement);
    if (!items.length) return;
    const first = items[0]; const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  return (
    <>
      <div className="st-scrim" onClick={onClose} aria-hidden />
      <div ref={ref} className="st-panel" role="dialog" aria-modal="true" aria-labelledby={titleId} style={{ width }} onKeyDown={onKeyDown}>
        <div className="st-panel-head">
          {icon}
          <div className="st-grow">
            <h2 id={titleId}>{title}</h2>
            {subtitle && <div className="st-small st-muted">{subtitle}</div>}
          </div>
          <button type="button" className="st-icon-btn" aria-label={`Close ${title}`} onClick={onClose}><X size={18} aria-hidden /></button>
        </div>
        {noBody ? children : <div className="st-panel-body">{children}</div>}
        {footer && <div className="st-panel-foot">{footer}</div>}
      </div>
    </>
  );
}

/* ------------------------------------------------ tabs -------------------------------------------- */

export function Tabs<T extends string>({ label, tabs, value, onChange, className = "st-tabs", tabClass = "st-tab", idBase }: {
  label: string; tabs: { value: T; label: ReactNode; aria?: string }[]; value: T; onChange: (v: T) => void; className?: string; tabClass?: string; idBase?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onKeyDown = (e: RKeyboardEvent) => {
    const at = tabs.findIndex(t => t.value === value);
    let next = -1;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (at + 1) % tabs.length;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (at - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(tabs[next].value);
    ref.current?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus();
  };
  return (
    <div ref={ref} className={className} role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {tabs.map((t, i) => (
        <button key={t.value} type="button" role="tab" id={idBase ? `${idBase}-${t.value}` : undefined} aria-selected={t.value === value}
          aria-label={t.aria} tabIndex={t.value === value || (i === 0 && !tabs.some(x => x.value === value)) ? 0 : -1} className={tabClass} onClick={() => onChange(t.value)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------ marks ------------------------------------------- */

export function Severity({ value, dotted }: { value: SentinelSeverity; dotted?: boolean }) {
  return <span className="st-sev"><i className={`st-band ${value}${dotted ? " dotted" : ""}`} aria-hidden />{value}</span>;
}

const KIND_ICON: Record<EntityKind, typeof User> = {
  account: User, host: Monitor, ip: Globe, file: FileText, process: Cpu, url: Link2, domain: Globe, mailbox: Mail,
  cloudapp: Cloud, azureresource: Box, registry: KeyRound,
};
export const entityIcon = (kind: EntityKind) => KIND_ICON[kind] ?? AppWindow;
export function EntityIcon({ kind, size = 14 }: { kind: EntityKind; size?: number }) {
  const I = entityIcon(kind);
  return <span className="st-ico" aria-hidden><I size={size} /></span>;
}

export function StatusIcon({ status, size = 14 }: { status: IncidentStatus; size?: number }) {
  if (status === "New") return <Loader size={size} color="var(--st-accent)" aria-hidden />;
  if (status === "Active") return <RefreshCw size={size} color="var(--st-medium)" aria-hidden />;
  return <CheckCircle2 size={size} color="var(--st-ok)" aria-hidden />;
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return <div className="st-empty">{icon}<strong>{title}</strong>{children && <div className="st-small">{children}</div>}</div>;
}

/* --------------------------------------------- page chrome ---------------------------------------- */

/**
 * Where a full-page view sits, XDR style: a back button to the list it came from, then the path
 * with slashes. The first item with a click handler is the way back.
 */
export function Crumbs({ items }: { items: { label: string; onClick?: () => void }[] }) {
  const [first, ...rest] = items;
  return (
    <nav className="st-crumb" aria-label="Location">
      {first.onClick
        ? <button type="button" className="xd-backbtn" onClick={first.onClick}><ArrowLeft size={13} aria-hidden />{first.label}</button>
        : <span>{first.label}</span>}
      {rest.map(c => (
        <span key={c.label} className="st-row" style={{ gap: 6 }}>
          <span className="xd-slash" aria-hidden>/</span>
          {c.onClick ? <button type="button" className="st-link" onClick={c.onClick}>{c.label}</button> : <span aria-current="page">{c.label}</span>}
        </span>
      ))}
    </nav>
  );
}

/** The title of a menu page, inside the page beside the menu: icon tile, title, one line on what it is for. */
export function PageHeader({ icon, title, sub, back }: { icon: ReactNode; title: string; sub: string; back?: { label: string; onClick: () => void } }) {
  return (
    <header className="st-blade-head">
      {back && <Crumbs items={[back, { label: title }]} />}
      <div className="st-blade-title">
        <span className="xd-tile" aria-hidden>{icon}</span>
        <div style={{ minWidth: 0 }}>
          <h1 className="st-ellipsis">{title}</h1>
          <div className="sub">{sub}</div>
        </div>
      </div>
    </header>
  );
}

export function Switch({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" role="switch" aria-checked={checked} className="st-switch" onClick={() => onChange(!checked)}>
      <span className="track" aria-hidden><span className="thumb" /></span>{label}
    </button>
  );
}

/** A dropdown of checkboxes for choosing columns: the grid and Logs. */
export function ColumnsButton({ columns, hidden, onToggle, className = "st-cmd", children, side }: {
  columns: { key: string; label: string }[]; hidden: Set<string>; onToggle: (key: string) => void; className?: string; children: ReactNode; side?: "below" | "right";
}) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  return (
    <>
      <button ref={btn} type="button" className={className} aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(o => !o)}>{children}</button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={240} role="group" label="Columns" align="right" side={side === "right" ? "below" : side}>
          {columns.map(c => (
            <label key={c.key} className="st-opt st-check">
              <input type="checkbox" checked={!hidden.has(c.key)} onChange={() => onToggle(c.key)} />
              <span className="st-ellipsis">{c.label}</span>
            </label>
          ))}
        </Popover>
      )}
    </>
  );
}

export function InfoMark({ title }: { title: string }) {
  return <span title={title} className="st-infomark" aria-hidden><Info size={12} /></span>;
}

/** The round glyph the flyout and the collapsed panel put beside a severity. */
export function SevGlyph({ value, size = 14 }: { value: SentinelSeverity; size?: number }) {
  const c = value === "High" ? "var(--st-high)" : value === "Medium" ? "var(--st-medium)" : value === "Low" ? "var(--st-low)" : "var(--st-info)";
  return <CircleAlert size={size} color={c} aria-hidden />;
}

/* ----------------------------------------- sortable tables ---------------------------------------- */

export type SortDir = "asc" | "desc";
export interface SortState<K extends string> { key: K; dir: SortDir }

export function SortTh<K extends string>({ k, sort, onSort, children, style }: {
  k: K; sort: SortState<K>; onSort: (s: SortState<K>) => void; children: ReactNode; style?: CSSProperties;
}) {
  const on = sort.key === k;
  return (
    <th scope="col" style={style} aria-sort={on ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="st-sort" onClick={() => onSort({ key: k, dir: on && sort.dir === "desc" ? "asc" : "desc" })}>
        <span className="st-ellipsis">{children}</span>
        {on ? (sort.dir === "asc" ? <ArrowUp size={12} aria-hidden /> : <ArrowDown size={12} aria-hidden />) : <ArrowUpDown size={12} color="var(--st-text-3)" aria-hidden />}
      </button>
    </th>
  );
}

export function SimplePager({ page, pages, from, to, onPage }: { page: number; pages: number; from: number; to: number; onPage: (p: number) => void }) {
  return (
    <div className="st-pager">
      <button type="button" className="st-pagebtn" disabled={page <= 0} onClick={() => onPage(page - 1)}>&lt; Previous</button>
      <span>{from} - {to}</span>
      <button type="button" className="st-pagebtn" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>Next &gt;</button>
    </div>
  );
}

/** Keyboard for rows that open something: Enter selects, Up and Down move. */
export function rowKeys(onOpen: () => void) {
  return (e: RKeyboardEvent<HTMLElement>) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); (e.currentTarget.nextElementSibling as HTMLElement | null)?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); (e.currentTarget.previousElementSibling as HTMLElement | null)?.focus(); }
  };
}

