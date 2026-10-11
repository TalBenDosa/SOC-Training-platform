"use client";
/**
 * Shared theory-content renderer for every reading surface — Learning Path lessons
 * AND Learning Room reading tasks — so a Markdown table, a code block or an ordered
 * list looks identical wherever it appears, and no surface silently prints raw
 * `| pipe | tables |` or literal `- ` bullets again.
 *
 * Supported Markdown: fenced ```code``` (rendered as a terminal-style card, with
 * ```mermaid``` and auto-detected mermaid as diagrams), GitHub pipe tables,
 * ATX headings (##, ###), horizontal rules, ordered/unordered lists with an
 * optional lead-in line, and inline **bold** / *italic* / `code` in every text run.
 *
 * The room reader previously had a much thinner renderer (bold, bullets, headings,
 * hr) which dropped tables and code onto the paragraph path — the source of the
 * "table shown as raw pipes" bug. This module is that renderer's single source of
 * truth; keep new Markdown support here, not copied per surface.
 */
import React from "react";
import { MermaidDiagram } from "@/components/rooms/MermaidDiagram";
import { isMermaidSource } from "@/lib/lessons/mermaid";

// A GitHub-style pipe table: a header row, a `|---|---|` separator, then rows.
function parseMarkdownTable(block: string): { headers: string[]; rows: string[][] } | null {
  const lines = block.split("\n").map(l => l.trim()).filter(Boolean);
  if (lines.length < 2 || !lines[0].includes("|")) return null;
  if (!/^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?$/.test(lines[1])) return null;
  const cells = (l: string) => l.replace(/^\||\|$/g, "").split("|").map(c => c.trim());
  const headers = cells(lines[0]);
  const rows = lines.slice(2).map(cells);
  return { headers, rows };
}

// Inline **bold**, *italic* and `code` in running text, table cells and list items.
// The **bold** alternative is listed first so it wins over the single-* italic rule.
function renderInline(text: string, keyBase: string | number): React.ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*|\*[^*\n]+\*|`[^`]+`)/g).map((part, j) => {
    if (part.startsWith("**") && part.endsWith("**"))
      return <strong key={`${keyBase}-${j}`} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
    if (part.length > 1 && part.startsWith("`") && part.endsWith("`"))
      return <code key={`${keyBase}-${j}`} className="rounded bg-[#111a2e] px-1.5 py-0.5 font-mono text-[12.5px] text-cyan-300">{part.slice(1, -1)}</code>;
    if (part.length > 2 && part.startsWith("*") && part.endsWith("*"))
      return <em key={`${keyBase}-${j}`} className="italic text-slate-200">{part.slice(1, -1)}</em>;
    return <span key={`${keyBase}-${j}`}>{part}</span>;
  });
}

function labelForLang(lang: string): string {
  const l = (lang || "").trim().toLowerCase();
  if (!l || l === "text" || l === "plaintext") return "Example";
  const map: Record<string, string> = {
    spl: "SPL", kql: "KQL", aql: "AQL", eql: "EQL", sql: "SQL",
    ps: "PowerShell", powershell: "PowerShell", bash: "Shell", sh: "Shell",
    cmd: "Command", log: "Log", json: "JSON", yaml: "YAML", yara: "YARA",
    sigma: "Sigma", xml: "XML", http: "HTTP", regex: "Regex",
  };
  return map[l] ?? lang.toUpperCase();
}

function CodeCard({ label, code }: { label: string; code: string }) {
  return (
    <div className="my-4 overflow-hidden rounded-xl border border-slate-700/50 bg-[#0a0f1c] shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-700/40 bg-slate-800/25 px-4 py-2">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400/40" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/40" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/40" />
        </span>
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">{label}</span>
      </div>
      <pre className="overflow-x-auto px-4 py-3.5 font-mono text-[12.5px] leading-relaxed text-slate-200"><code>{code}</code></pre>
    </div>
  );
}

// One fenced ```code``` block → a code card. Mermaid fences render as diagrams.
function renderFencedCode(lang: string, body: string, key: string): React.ReactNode {
  const code = body.replace(/\n+$/, "");
  if (lang === "mermaid" || isMermaidSource(code)) return <MermaidDiagram key={key} chart={code} />;
  return <CodeCard key={key} label={labelForLang(lang)} code={code} />;
}

function renderTextBlocks(text: string, keyPrefix: string): React.ReactNode {
  const blocks = text.split(/\n\n+/);
  return (
    <>
      {blocks.map((block, bi) => {
        const i = `${keyPrefix}-${bi}`;
        const trimmed = block.trim();
        if (!trimmed) return null;

        // Markdown table → real <table>
        const table = parseMarkdownTable(trimmed);
        if (table) {
          return (
            <div key={i} className="overflow-x-auto rounded-lg border border-[#1e2d4a]">
              <table className="w-full text-left text-[13px]">
                <thead>
                  <tr className="border-b border-[#1e2d4a] bg-[#0f1830]">
                    {table.headers.map((h, hi) => (
                      <th key={hi} className="px-3 py-2 font-semibold text-cyan-200 whitespace-nowrap">{renderInline(h, `h${hi}`)}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {table.rows.map((row, ri) => (
                    <tr key={ri} className="border-b border-[#1e2d4a]/50 last:border-0">
                      {row.map((c, ci) => (
                        <td key={ci} className="px-3 py-2 text-slate-300 align-top">{renderInline(c, `r${ri}c${ci}`)}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }

        // Horizontal rule: --- / *** / ___ on its own line.
        if (/^([-*_])\1{2,}$/.test(trimmed)) {
          return <hr key={i} className="border-cyber-500/15" />;
        }

        // ### Sub-heading
        if (trimmed.startsWith("### ") && !trimmed.includes("\n")) {
          return (
            <div key={i} className="flex items-start gap-3 mt-7 mb-1">
              <span className="mt-1 shrink-0 w-[3px] h-5 rounded-full bg-teal-400/70" />
              <h4 className="text-[15px] font-bold text-teal-200 leading-snug">
                {renderInline(trimmed.replace(/^###\s+/, ""), `${i}-h`)}
              </h4>
            </div>
          );
        }

        // ## heading
        if (trimmed.startsWith("## ") && !trimmed.includes("\n")) {
          return (
            <h3 key={i} className="text-[13px] font-bold uppercase tracking-widest text-slate-400 mt-6">
              {renderInline(trimmed.replace(/^##\s+/, ""), `${i}-h`)}
            </h3>
          );
        }

        // # heading (top-level, on its own line)
        const atx = /^(#{1})\s+(.+)$/.exec(trimmed);
        if (atx && !trimmed.includes("\n")) {
          return (
            <h2 key={i} className="text-xl font-bold text-cyan-100 mt-6 first:mt-0">
              {renderInline(atx[2], `${i}-h`)}
            </h2>
          );
        }

        // A **bold line** on its own → a heading (legacy authoring convention).
        if (/^\*\*[^*]+\*\*$/.test(trimmed)) {
          return (
            <h3 key={i} className="text-[15px] font-bold text-cyan-200 mt-6 first:mt-0">
              {trimmed.slice(2, -2)}
            </h3>
          );
        }

        // Bulleted / numbered list — with an optional lead-in line above the items.
        const lines = trimmed.split("\n").map(l => l.trim()).filter(Boolean);
        const firstItem = lines.findIndex(l => /^(?:[-*•]\s+|\d+[.)]\s+)/.test(l));
        if (firstItem !== -1 && lines.slice(firstItem).every(l => /^(?:[-*•]\s+|\d+[.)]\s+)/.test(l))) {
          const leadIn = lines.slice(0, firstItem);
          const items  = lines.slice(firstItem);
          const ordered = /^\d+[.)]\s+/.test(items[0]);
          const ListTag = ordered ? "ol" : "ul";
          return (
            <div key={i} className="space-y-2">
              {leadIn.map((l, li) => (
                <p key={`lead${li}`} className="text-[14px] text-slate-300 leading-[1.8]">
                  {renderInline(l, `l${i}-${li}`)}
                </p>
              ))}
              <ListTag className={`space-y-1.5 pl-5 ${ordered ? "list-decimal" : "list-disc"} marker:text-cyan-400/70`}>
                {items.map((item, ii) => (
                  <li key={ii} className="text-[14px] text-slate-300 leading-[1.8] pl-1">
                    {renderInline(item.replace(/^(?:[-*•]\s+|\d+[.)]\s+)/, ""), `i${i}-${ii}`)}
                  </li>
                ))}
              </ListTag>
            </div>
          );
        }

        // Paragraph — inline **bold**, *italic* and `code`
        return (
          <p key={i} className="text-[14px] text-slate-300 leading-[1.8]">
            {renderInline(trimmed, i)}
          </p>
        );
      })}
    </>
  );
}

/**
 * Render a Markdown string as styled theory content. Fenced code blocks are peeled
 * off first so their inner blank lines / pipes survive the paragraph split.
 */
export function RichText({ content, className }: { content: string; className?: string }) {
  const segments: React.ReactNode[] = [];
  const fenceRe = /```(\w*)\n([\s\S]*?)```/g;
  let last = 0, m: RegExpExecArray | null, seg = 0;
  while ((m = fenceRe.exec(content)) !== null) {
    if (m.index > last) segments.push(<div key={`t${seg}`} className="space-y-4">{renderTextBlocks(content.slice(last, m.index), `t${seg}`)}</div>);
    segments.push(renderFencedCode(m[1], m[2], `c${seg}`));
    last = m.index + m[0].length;
    seg++;
  }
  if (last < content.length) segments.push(<div key={`t${seg}`} className="space-y-4">{renderTextBlocks(content.slice(last), `t${seg}`)}</div>);
  return <div className={className ?? "space-y-4"}>{segments}</div>;
}

export default RichText;
