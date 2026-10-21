"use client";
/**
 * Renders a Mermaid diagram from source text.
 *
 * WHY code-as-diagram instead of image files / generative images: lesson
 * diagrams are technical (TCP handshakes, Kerberos ticket flow, kill chains) and
 * their VALUE is in the exact labels — port numbers, flag names, field names. An
 * AI-generated raster image garbles that text and invents wrong topologies, so a
 * student would learn something false. Mermaid keeps the diagram in version
 * control next to the lesson, renders crisply at any zoom, and can never
 * silently drift from the text it illustrates.
 *
 * mermaid is a large dependency, so it is imported DYNAMICALLY on first render —
 * lessons without a diagram never pay for it.
 *
 * SECURITY: securityLevel "strict" makes mermaid sanitize HTML inside node
 * labels. Diagram source is authored in our data files today, but lesson content
 * can be AI-generated, so this stays strict as defense in depth.
 */
import { useEffect, useRef, useState, type CSSProperties } from "react";

let mermaidReady: Promise<typeof import("mermaid").default> | null = null;

/** Load + configure mermaid once per browser session. */
function getMermaid() {
  if (!mermaidReady) {
    mermaidReady = import("mermaid").then(({ default: mermaid }) => {
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        fontFamily: "ui-sans-serif, system-ui, sans-serif",
        // SVG <text> labels, not HTML in a <foreignObject>. An HTML label is
        // measured once at render and then drawn inside a fixed-size box that
        // clips; when the learner's browser lays the text out slightly wider
        // (zoom, display scaling, a different system font) the last word or line
        // is cut off (learner report 2026-10-19, "can't see the whole sentence").
        // SVG text is measured and wrapped by mermaid itself and is never clipped.
        htmlLabels: false,
        flowchart: { htmlLabels: false },
        // Tuned to the platform's dark SOC palette so diagrams read as part of
        // the lesson rather than a pasted-in white image.
        themeVariables: {
          background: "#080d14",
          primaryColor: "#0d1520",
          primaryTextColor: "#e2e8f0",
          primaryBorderColor: "#38bdf8",
          lineColor: "#64748b",
          secondaryColor: "#131c2b",
          tertiaryColor: "#0d1520",
          noteBkgColor: "#1e293b",
          noteTextColor: "#e2e8f0",
          noteBorderColor: "#475569",
          actorBkg: "#0d1520",
          actorBorder: "#38bdf8",
          actorTextColor: "#e2e8f0",
          signalColor: "#94a3b8",
          signalTextColor: "#cbd5e1",
          labelBoxBkgColor: "#0d1520",
          labelBoxBorderColor: "#38bdf8",
          labelTextColor: "#e2e8f0",
        },
      });
      return mermaid;
    });
  }
  return mermaidReady;
}

let idCounter = 0;

/**
 * The smallest width a diagram may shrink to: 75% of its natural width, so 16px
 * labels never render below ~12px. A diagram wider than the column then scrolls
 * sideways instead of being scaled into unreadable text.
 */
const MIN_SCALE = 0.75;
function minWidthOf(svg: string): number | null {
  const m = /viewBox="[\d.\-]+\s+[\d.\-]+\s+([\d.]+)\s+[\d.]+"/.exec(svg);
  const w = m ? Number(m[1]) : NaN;
  return Number.isFinite(w) && w > 0 ? Math.round(w * MIN_SCALE) : null;
}

export function MermaidDiagram({ chart, caption }: { chart: string; caption?: string }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const idRef = useRef(`mmd-${++idCounter}`);

  useEffect(() => {
    let cancelled = false;
    setSvg(null);
    setFailed(false);

    getMermaid()
      .then(mermaid => mermaid.render(idRef.current, chart.trim()))
      .then(({ svg }) => { if (!cancelled) setSvg(svg); })
      .catch(() => { if (!cancelled) setFailed(true); });

    return () => { cancelled = true; };
  }, [chart]);

  // A broken diagram must never break the lesson — fall back to the source so
  // the student still sees the (readable) structure and we can spot the error.
  if (failed) {
    return (
      <figure className="rounded-lg border border-border bg-bg-elevated overflow-hidden">
        <figcaption className="px-4 py-2 border-b border-border bg-bg-elevated/40 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          Diagram source
        </figcaption>
        <pre className="px-4 py-4 font-mono text-xs text-slate-400 overflow-x-auto whitespace-pre">{chart.trim()}</pre>
      </figure>
    );
  }

  return (
    <figure className="rounded-lg border border-border bg-bg-elevated overflow-hidden">
      <figcaption className="px-4 py-2 border-b border-border bg-bg-elevated/40 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
        {caption ?? "Diagram"}
      </figcaption>
      <div className="overflow-x-auto px-4 py-5">
        {svg
          // Mermaid's own output, produced under securityLevel "strict".
          // "safe center": a diagram wider than the column starts at its left edge
          // (fully scrollable) instead of overflowing on both sides.
          ? <div
              className="mermaid-svg flex [justify-content:safe_center] [&_svg]:max-w-full [&_svg]:h-auto [&_svg]:shrink-0 [&_svg]:min-w-[var(--mmd-min-w)]"
              style={{ "--mmd-min-w": `${minWidthOf(svg) ?? 0}px` } as CSSProperties}
              dangerouslySetInnerHTML={{ __html: svg }}
            />
          : <div className="h-24 animate-pulse rounded bg-bg-elevated/50" />}
      </div>
    </figure>
  );
}
