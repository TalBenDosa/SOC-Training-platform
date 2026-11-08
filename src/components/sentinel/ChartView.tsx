"use client";
// Result charts in plain SVG. Series colours passed the palette validator (CVD and normal vision),
// in this order. A seventh series folds into Other: a hue is never generated.
import { useEffect, useMemo, useRef, useState } from "react";
import { BarChart3 } from "lucide-react";
import type { KqlChart, KqlColumn, KqlRow } from "@/lib/kql/types";
import { fmtDateTime, fmtCount } from "./helpers";
import { Empty, Select } from "./ui";

export const SERIES = ["#6d28d9", "#c77700", "#00a3a0", "#2f6fb5", "#c8507f", "#4f8a10"];
const OTHER = "#8a8886";
const GRID = "#edebe9";

export type ChartKind = "timechart" | "barchart" | "columnchart" | "piechart";
const KIND_OPTS: { value: ChartKind; label: string }[] = [
  { value: "timechart", label: "Line" }, { value: "columnchart", label: "Column" }, { value: "barchart", label: "Bar" }, { value: "piechart", label: "Pie" },
];

interface Series { name: string; values: number[]; color: string }
interface Model { labels: string[]; times: number[] | null; series: Series[] }

const isNum = (c: KqlColumn) => c.type === "int" || c.type === "long" || c.type === "real";

function foldSeries(all: { name: string; values: number[] }[]): Series[] {
  const sorted = [...all].sort((a, b) => sum(b.values) - sum(a.values));
  const keep = sorted.length > SERIES.length ? sorted.slice(0, SERIES.length - 1) : sorted;
  const out: Series[] = keep.map((s, i) => ({ ...s, color: SERIES[i] }));
  if (sorted.length > SERIES.length) {
    const rest = sorted.slice(SERIES.length - 1);
    out.push({ name: `Other (${rest.length})`, values: rest[0].values.map((_, i) => sum(rest.map(r => r.values[i]))), color: OTHER });
  }
  return out;
}
const sum = (a: number[]) => a.reduce((x, y) => x + y, 0);

export function kindFromResult(chart: KqlChart | undefined): ChartKind | null {
  switch (chart?.kind) {
    case "timechart": case "linechart": case "areachart": return "timechart";
    case "barchart": return "barchart";
    case "columnchart": return "columnchart";
    case "piechart": return "piechart";
    default: return null;
  }
}

/** Series from a result. Null when the rows have no number to draw. */
export function chartModel(columns: KqlColumn[], rows: KqlRow[], kind: ChartKind): Model | null {
  const numbers = columns.filter(isNum);
  if (!numbers.length || !rows.length) return null;
  const timeCol = columns.find(c => c.type === "datetime");
  const textCols = columns.filter(c => c.type === "string");
  if (kind === "timechart" && timeCol) {
    const stamps = [...new Set(rows.map(r => Date.parse(String(r[timeCol.name]))))].filter(Number.isFinite).sort((a, b) => a - b);
    const at = new Map(stamps.map((t, i) => [t, i]));
    const pivot = textCols[0];
    const groups = new Map<string, number[]>();
    for (const r of rows) {
      const i = at.get(Date.parse(String(r[timeCol.name])));
      if (i === undefined) continue;
      if (pivot) {
        const name = String(r[pivot.name] ?? "");
        const v = groups.get(name) ?? new Array(stamps.length).fill(0);
        v[i] += Number(r[numbers[0].name]) || 0;
        groups.set(name, v);
      } else {
        for (const n of numbers) {
          const v = groups.get(n.name) ?? new Array(stamps.length).fill(0);
          v[i] += Number(r[n.name]) || 0;
          groups.set(n.name, v);
        }
      }
    }
    return { labels: stamps.map(t => fmtDateTime(t)), times: stamps, series: foldSeries([...groups].map(([name, values]) => ({ name, values }))) };
  }
  const cat = textCols[0] ?? timeCol ?? columns.find(c => !isNum(c));
  const value = numbers[0];
  const byCat = new Map<string, number>();
  for (const r of rows) {
    const raw = cat ? r[cat.name] : "";
    const key = cat?.type === "datetime" ? fmtDateTime(String(raw)) : String(raw ?? "");
    byCat.set(key, (byCat.get(key) ?? 0) + (Number(r[value.name]) || 0));
  }
  const entries = [...byCat].sort((a, b) => b[1] - a[1]);
  if (kind === "piechart") {
    const named = foldSeries(entries.map(([name, v]) => ({ name, values: [v] })));
    return { labels: [value.name], times: null, series: named };
  }
  const cut = entries.slice(0, 30);
  return { labels: cut.map(e => e[0]), times: null, series: [{ name: value.name, values: cut.map(e => e[1]), color: SERIES[0] }] };
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}
/** Counts get whole-number ticks: 3.75 alerts is not a thing. */
function axisTicks(top: number): number[] {
  const step = top < 1 ? top / 4 : top <= 5 ? 1 : top / 5;
  return Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
}
const compact = (n: number) => (n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${+(n / 1e3).toFixed(1)}K` : String(+n.toFixed(2)));

function useWidth(fallback: number) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: fallback, h: 280 });
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.max(240, e.contentRect.width), h: Math.max(110, e.contentRect.height) }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return { ref, ...size };
}

interface Tip { x: number; y: number; title: string; rows: { name: string; value: number; color: string }[] }

function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div className="st-tip" style={{ left: tip.x, top: tip.y }}>
      <div style={{ fontWeight: 600 }}>{tip.title}</div>
      {tip.rows.map(r => <div key={r.name}><i style={{ background: r.color }} />{r.name}: {fmtCount(r.value)}</div>)}
    </div>
  );
}

function LinePlot({ model, w, h }: { model: Model; w: number; h: number }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const m = { l: 44, r: 12, t: 8, b: 24 };
  const pw = w - m.l - m.r; const ph = h - m.t - m.b;
  const n = model.labels.length;
  const top = niceMax(Math.max(...model.series.flatMap(s => s.values)));
  const times = model.times ?? [];
  const t0 = times[0] ?? 0; const t1 = times[n - 1] ?? 1;
  const x = (i: number) => (n === 1 ? pw / 2 : times.length ? ((times[i] - t0) / Math.max(1, t1 - t0)) * pw : (i / (n - 1)) * pw);
  const y = (v: number) => ph - (v / top) * ph;
  const ticks = axisTicks(top);
  const xTicks = Math.min(6, n);
  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - box.left;
    let best = 0; let dist = Infinity;
    for (let i = 0; i < n; i++) { const d = Math.abs(x(i) - px); if (d < dist) { dist = d; best = i; } }
    setHover(best);
    setTip({
      x: Math.min(m.l + x(best) + 18, w - 200), y: 12, title: model.labels[best],
      rows: model.series.map(s => ({ name: s.name, value: s.values[best], color: s.color })),
    });
  };
  return (
    <>
      <svg width={w} height={h} role="img" aria-label={`Line chart with ${model.series.length} series over ${n} points`}>
        <g transform={`translate(${m.l},${m.t})`}>
          {ticks.map(v => <g key={v}><line x1={0} x2={pw} y1={y(v)} y2={y(v)} stroke={GRID} /><text x={-6} y={y(v) + 4} textAnchor="end">{compact(v)}</text></g>)}
          {Array.from({ length: xTicks }, (_, i) => {
            const idx = xTicks === 1 ? 0 : Math.round((i / (xTicks - 1)) * (n - 1));
            const label = model.labels[idx].replace(/^\d+\/\d+\/\d+, /, "");
            return <text key={i} x={x(idx)} y={ph + 16} textAnchor={i === 0 ? "start" : i === xTicks - 1 ? "end" : "middle"}>{label}</text>;
          })}
          {model.series.map(s => (
            <g key={s.name}>
              <polyline fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"
                points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")} />
              {n <= 40 && s.values.map((v, i) => <circle key={i} cx={x(i)} cy={y(v)} r={hover === i ? 4 : 2.5} fill={s.color} stroke="#fff" strokeWidth={1.5} />)}
            </g>
          ))}
          {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={ph} stroke="#8a8886" />}
          <rect x={0} y={0} width={pw} height={ph} fill="transparent" onPointerMove={onMove} onPointerLeave={() => { setHover(null); setTip(null); }} />
        </g>
      </svg>
      <Tooltip tip={tip} />
    </>
  );
}

function BarPlot({ model, w, h, horizontal }: { model: Model; w: number; h: number; horizontal: boolean }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const s = model.series[0];
  const n = model.labels.length;
  const top = niceMax(Math.max(...s.values));
  const show = (i: number, x: number, y: number) => setTip({ x: Math.min(x + 12, w - 200), y: Math.max(y - 8, 0), title: model.labels[i], rows: [{ name: s.name, value: s.values[i], color: s.color }] });
  if (horizontal) {
    const m = { l: 130, r: 34, t: 4, b: 4 };
    const band = Math.max(16, (h - m.t - m.b) / n);
    const pw = w - m.l - m.r;
    const bar = Math.min(18, band - 4);
    const height = m.t + m.b + band * n;
    return (
      <div style={{ overflow: "auto", height: "100%" }}>
        <svg width={w} height={height} role="img" aria-label={`Bar chart of ${s.name} across ${n} categories`}>
          {s.values.map((v, i) => {
            const len = Math.max(1, (v / top) * pw); const y = m.t + band * i + (band - bar) / 2;
            return (
              <g key={i} onPointerMove={() => show(i, m.l + len, y)} onPointerLeave={() => setTip(null)}>
                <rect x={0} y={m.t + band * i} width={w} height={band} fill="transparent" />
                <text x={m.l - 6} y={y + bar / 2 + 4} textAnchor="end">{model.labels[i].length > 22 ? `${model.labels[i].slice(0, 21)}...` : model.labels[i]}</text>
                <path d={`M${m.l},${y}h${Math.max(0, len - 3)}a3,3 0 0 1 3,3v${bar - 6}a3,3 0 0 1 -3,3h-${Math.max(0, len - 3)}z`} fill={s.color} />
                <text x={m.l + len + 4} y={y + bar / 2 + 4}>{compact(v)}</text>
              </g>
            );
          })}
        </svg>
        <Tooltip tip={tip} />
      </div>
    );
  }
  const m = { l: 44, r: 8, t: 8, b: 44 };
  const pw = w - m.l - m.r; const ph = h - m.t - m.b;
  const band = pw / n; const bar = Math.min(24, band - 2);
  const y = (v: number) => ph - (v / top) * ph;
  const every = Math.ceil(n / Math.max(1, Math.floor(pw / 70)));
  return (
    <>
      <svg width={w} height={h} role="img" aria-label={`Column chart of ${s.name} across ${n} categories`}>
        <g transform={`translate(${m.l},${m.t})`}>
          {axisTicks(top).map(v => <g key={v}><line x1={0} x2={pw} y1={y(v)} y2={y(v)} stroke={GRID} /><text x={-6} y={y(v) + 4} textAnchor="end">{compact(v)}</text></g>)}
          {s.values.map((v, i) => {
            const bx = band * i + (band - bar) / 2; const top2 = y(v); const hgt = Math.max(1, ph - top2);
            return (
              <g key={i} onPointerMove={() => show(i, m.l + bx + bar, m.t + top2)} onPointerLeave={() => setTip(null)}>
                <rect x={band * i} y={0} width={band} height={ph} fill="transparent" />
                <path d={`M${bx},${ph}v-${Math.max(0, hgt - 3)}a3,3 0 0 1 3,-3h${bar - 6}a3,3 0 0 1 3,3v${Math.max(0, hgt - 3)}z`} fill={s.color} />
                {i % every === 0 && <text x={bx + bar / 2} y={ph + 14} textAnchor="middle">{model.labels[i].length > 12 ? `${model.labels[i].slice(0, 11)}...` : model.labels[i]}</text>}
              </g>
            );
          })}
        </g>
      </svg>
      <Tooltip tip={tip} />
    </>
  );
}

function PiePlot({ model, w, h }: { model: Model; w: number; h: number }) {
  const [tip, setTip] = useState<Tip | null>(null);
  const total = sum(model.series.map(s => s.values[0])) || 1;
  const r = Math.min(w, h) / 2 - 10; const inner = r * .58;
  const cx = w / 2; const cy = h / 2;
  let a = -Math.PI / 2;
  const pt = (ang: number, rad: number) => `${cx + rad * Math.cos(ang)},${cy + rad * Math.sin(ang)}`;
  return (
    <>
      <svg width={w} height={h} role="img" aria-label={`Pie chart of ${model.series.length} slices`}>
        {model.series.map(s => {
          const frac = s.values[0] / total;
          const start = a; const end = a + Math.max(frac * Math.PI * 2 - .02, .01); a += frac * Math.PI * 2;
          const large = end - start > Math.PI ? 1 : 0;
          const d = frac >= .999
            ? `M${pt(0, r)}A${r},${r} 0 1 1 ${pt(Math.PI, r)}A${r},${r} 0 1 1 ${pt(0, r)}M${pt(0, inner)}A${inner},${inner} 0 1 0 ${pt(Math.PI, inner)}A${inner},${inner} 0 1 0 ${pt(0, inner)}z`
            : `M${pt(start, r)}A${r},${r} 0 ${large} 1 ${pt(end, r)}L${pt(end, inner)}A${inner},${inner} 0 ${large} 0 ${pt(start, inner)}z`;
          return <path key={s.name} d={d} fill={s.color} fillRule="evenodd"
            onPointerMove={e => { const b = e.currentTarget.ownerSVGElement!.getBoundingClientRect(); setTip({ x: Math.min(e.clientX - b.left + 12, w - 200), y: e.clientY - b.top, title: s.name, rows: [{ name: `${(frac * 100).toFixed(1)}%`, value: s.values[0], color: s.color }] }); }}
            onPointerLeave={() => setTip(null)} />;
        })}
        <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontSize: 16, fontWeight: 600, fill: "#323130" }}>{compact(total)}</text>
      </svg>
      <Tooltip tip={tip} />
    </>
  );
}

export function ChartView({ columns, rows, initial, compact: bare }: { columns: KqlColumn[]; rows: KqlRow[]; initial: ChartKind | null; compact?: boolean }) {
  const hasTime = columns.some(c => c.type === "datetime");
  const [kind, setKind] = useState<ChartKind>(initial ?? (hasTime ? "timechart" : "columnchart"));
  const model = useMemo(() => chartModel(columns, rows, kind), [columns, rows, kind]);
  const { ref, w, h } = useWidth(760);
  if (!model) {
    return <Empty icon={<BarChart3 size={28} aria-hidden />} title="No chart available">The result has no numeric column to plot. Add a summarize, for example: summarize count() by bin(TimeGenerated, 1h)</Empty>;
  }
  return (
    <div className="st-chart" style={bare ? { padding: 0 } : undefined}>
      {!bare && (
        <div className="st-row" style={{ marginBottom: 4 }}>
          <span className="st-small st-muted">Chart type</span>
          <Select label="Chart type" className="st-pill xd-fchip" value={kind} options={KIND_OPTS} onChange={setKind} />
          <div className="st-legend" style={{ marginLeft: 12 }}>
            {model.series.length > 1 && model.series.map(s => <span key={s.name}><i style={{ background: s.color }} />{s.name}</span>)}
          </div>
        </div>
      )}
      <div ref={ref} style={{ position: "relative", flex: "1 1 auto", minHeight: 0 }}>
        {kind === "timechart" && <LinePlot model={model} w={w} h={h} />}
        {kind === "columnchart" && <BarPlot model={model} w={w} h={h} horizontal={false} />}
        {kind === "barchart" && <BarPlot model={model} w={w} h={h} horizontal />}
        {kind === "piechart" && <PiePlot model={model} w={w} h={h} />}
      </div>
    </div>
  );
}
