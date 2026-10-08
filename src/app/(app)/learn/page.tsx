"use client";

import { useState, useEffect, useMemo, useCallback, useId, useRef } from "react";
import Link from "next/link";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { Topbar } from "@/components/nav/Topbar";
// The grid reads the small generated index; a lesson's full content is fetched
// from /api/library/[id] only when it is opened (BUILTIN_LESSONS was ~4.9MB of JS).
import { LIBRARY_INDEX } from "@/data/libraryIndex";
import { libraryEntry, type LibraryEntry } from "@/lib/lessons/libraryEntry";
import { fetchPublishedLessons } from "@/lib/content/publicContent";
import { Search, FileText, ChevronLeft, ChevronRight, CheckCircle2, X, Layers, ArrowRight, BookOpen, ListChecks, Loader2 } from "lucide-react";
import { MermaidDiagram } from "@/components/rooms/MermaidDiagram";
import { MyLearningPlan } from "@/components/plans/MyLearningPlan";
import { AssignedChip } from "@/components/plans/AssignedChip";
import { useAssignedItems } from "@/lib/plans/useAssigned";
import type { AssignedInfo } from "@/lib/plans/assigned";
import { isMermaidSource } from "@/lib/lessons/mermaid";
import { LessonFigure, type LessonImage } from "@/components/lessons/LessonFigure";
import { LessonVideo, type LessonVideoData } from "@/components/lessons/LessonVideo";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Lesson {
  id: string;
  slug: string;
  title: string;
  topic: string;
  difficulty: string;
  kind: "lesson";
  intro: string;
  sections: { heading: string; content: string; codeExample?: string; imageQuery?: string; image?: LessonImage; video?: LessonVideoData }[];
  keyTakeaways: string[];
  // Not shown by this reader, and stripped by /api/library/[id] (it carries the answer key).
  quiz?: { question: string; options: { label: string; value: string }[]; answer: string; explanation: string }[];
  references: string[];
  xp: number;
  estimatedMinutes: number;
  researchUsed?: boolean;
  createdAt?: string;
}

/** A grid card: the index record, plus the full lesson when it is already in hand (org-authored lessons). */
type CardItem = LibraryEntry & { full?: Lesson };

// ─── Helpers ─────────────────────────────────────────────────────────────────

const DIFF_COLORS: Record<string, string> = {
  beginner:     "bg-sky-500/20     text-sky-300     border-sky-500/40",
  intermediate: "bg-yellow-500/20  text-yellow-300  border-yellow-500/40",
  advanced:     "bg-orange-500/20  text-orange-300  border-orange-500/40",
  expert:       "bg-red-500/20     text-red-300     border-red-500/40",
};

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function tagsForLesson(l: { topic: string; title: string; difficulty: string }): string[] {
  const topic = (l.topic + " " + l.title).toLowerCase();
  const tags: string[] = [];
  if (/protocol|network|dns|tcp|smb|http/.test(topic))  tags.push("Network Analysis");
  if (/phish|email|mail|bec/.test(topic))               tags.push("Email Security");
  if (/windows|event.?log|sysmon|registry/.test(topic)) tags.push("Log Analysis");
  if (/threat|intel|hunt|ioc/.test(topic))              tags.push("Threat Intelligence");
  if (/siem|splunk|sentinel|kql|spl/.test(topic))       tags.push("SIEM");
  if (/malware|endpoint|edr|av/.test(topic))            tags.push("Endpoint Security");
  if (/kerberos|active.?dir|ldap|ntlm/.test(topic))     tags.push("Active Directory");
  if (/cloud|aws|azure|s3|iam/.test(topic))             tags.push("Cloud Security");
  if (/vuln|cve|patch|exploit/.test(topic))             tags.push("Vulnerability Mgmt");
  if (/incident|response|forensic/.test(topic))         tags.push("Incident Response");
  tags.push("SOC Analysts");
  if (tags.length < 3) tags.push(capitalize(l.difficulty));
  return tags.slice(0, 5);
}


// ─── Content Renderer ─────────────────────────────────────────────────────────
// Visual hierarchy:
//   H1 = section title (rendered separately, big white text + thick cyan border)
//   H2 = ### sub-heading  (medium teal, thin left accent)
//   H3 = ## fallback      (small cyan, no border)
//   P  = paragraph        (slate-300, 14px, leading-relaxed)

// A GitHub-style pipe table: a header row, a `|---|---|` separator, then rows.
// Previously unsupported, so SLA matrices and field-comparison tables were
// written as ASCII inside code blocks; now they render as real tables.
function parseMarkdownTable(block: string): { headers: string[]; rows: string[][] } | null {
  const lines = block.split("\n").map(l => l.trim()).filter(Boolean);
  if (lines.length < 2 || !lines[0].includes("|")) return null;
  if (!/^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?$/.test(lines[1])) return null;
  const cells = (l: string) => l.replace(/^\||\|$/g, "").split("|").map(c => c.trim());
  const headers = cells(lines[0]);
  const rows = lines.slice(2).map(cells);
  return { headers, rows };
}

function renderInline(text: string, keyBase: string | number) {
  // Handles **bold**, *italic* and `inline code` in running text, table cells and list items.
  // The **bold** alternative is listed first so it wins over the single-* italic rule.
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

// Shared "code/example" card: a subtle terminal-window header (muted window dots
// + a type label) over legible monospace. Replaces the old glowing-green <pre> so
// snippets read clearly as worked examples. Kept byte-for-byte in sync with the
// route reader (learn/[slug]/[lesson]/page.tsx) so both surfaces look identical.
function labelForLang(lang: string) {
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
function renderFencedCode(lang: string, body: string, key: string) {
  const code = body.replace(/\n+$/, "");
  if (lang === "mermaid" || isMermaidSource(code)) return <MermaidDiagram key={key} chart={code} />;
  return <CodeCard key={key} label={labelForLang(lang)} code={code} />;
}

function renderContent(text: string) {
  // First peel off fenced code blocks so their inner blank lines / pipes survive
  // the \n\n paragraph split below. Text between fences is rendered as normal blocks.
  const segments: React.ReactNode[] = [];
  const fenceRe = /```(\w*)\n([\s\S]*?)```/g;
  let last = 0, m: RegExpExecArray | null, seg = 0;
  while ((m = fenceRe.exec(text)) !== null) {
    if (m.index > last) segments.push(<div key={`t${seg}`} className="space-y-4">{renderTextBlocks(text.slice(last, m.index), `t${seg}`)}</div>);
    segments.push(renderFencedCode(m[1], m[2], `c${seg}`));
    last = m.index + m[0].length;
    seg++;
  }
  if (last < text.length) segments.push(<div key={`t${seg}`} className="space-y-4">{renderTextBlocks(text.slice(last), `t${seg}`)}</div>);
  return <div className="space-y-4">{segments}</div>;
}

function renderTextBlocks(text: string, keyPrefix: string) {
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

        // H2 — ### Sub-heading: clearly subordinate to section title
        if (trimmed.startsWith("### ")) {
          return (
            <div key={i} className="flex items-start gap-3 mt-7 mb-1">
              <span className="mt-1 shrink-0 w-[3px] h-5 rounded-full bg-teal-400/70" />
              <h4 className="text-[15px] font-bold text-teal-200 leading-snug">
                {trimmed.replace(/^### /, "")}
              </h4>
            </div>
          );
        }

        // H3 — ## heading (fallback)
        if (trimmed.startsWith("## ")) {
          return (
            <h3 key={i} className="text-[13px] font-bold uppercase tracking-widest text-slate-400 mt-6">
              {trimmed.replace(/^## /, "")}
            </h3>
          );
        }

        // Bulleted / numbered list — with an optional lead-in line above the items.
        // The route reader (learn/[slug]/[lesson]) has always rendered these; this
        // branch exists so the modal reader does not silently print literal "- ".
        const lines = trimmed.split("\n").map(l => l.trim()).filter(Boolean);
        const firstItem = lines.findIndex(l => /^(?:[-*]\s+|\d+[.)]\s+)/.test(l));
        if (firstItem !== -1 && lines.slice(firstItem).every(l => /^(?:[-*]\s+|\d+[.)]\s+)/.test(l))) {
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
                    {renderInline(item.replace(/^(?:[-*]\s+|\d+[.)]\s+)/, ""), `i${i}-${ii}`)}
                  </li>
                ))}
              </ListTag>
            </div>
          );
        }

        // Paragraph — inline **bold** and `code` support
        return (
          <p key={i} className="text-[14px] text-slate-300 leading-[1.8]">
            {renderInline(trimmed, i)}
          </p>
        );
      })}
    </>
  );
}

// ─── Lesson Card ──────────────────────────────────────────────────────────────

function LessonCard({ lesson, onClick, onIntent, assigned }: { lesson: CardItem; onClick: () => void; onIntent: () => void; assigned?: AssignedInfo }) {
  const diffCls = DIFF_COLORS[lesson.difficulty] ?? DIFF_COLORS.intermediate;
  const tags     = tagsForLesson(lesson);
  const pages    = lesson.sectionCount + 1; // intro + sections
  const isExpanded = pages >= 8;               // deepened lessons carry extended depth

  return (
    <button
      onClick={onClick}
      // Start fetching the lesson as soon as the reader shows intent, so it is
      // usually already loaded by the time they click.
      onMouseEnter={onIntent}
      onFocus={onIntent}
      className="group text-left w-full rounded-2xl border border-[#1e2d4a] bg-[#0d1322] p-5 hover:border-cyan-500/40 hover:bg-[#0f1830] transition-all duration-200 flex flex-col gap-3"
    >
      {/* title + badge */}
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-bold leading-snug line-clamp-3 transition-colors text-white group-hover:text-cyan-100">
          {lesson.title}
        </h3>
        <div className="flex flex-col items-end gap-1 shrink-0 mt-0.5">
          <span className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase whitespace-nowrap ${diffCls}`}>
            {capitalize(lesson.difficulty)}
          </span>
          <AssignedChip info={assigned} className="whitespace-nowrap" />
          {isExpanded && (
            <span className="flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold uppercase whitespace-nowrap text-emerald-300">
              <Layers className="h-3 w-3" />
              Expanded
            </span>
          )}
        </div>
      </div>

      {/* description */}
      {lesson.blurb && (
        <p className="text-[13px] text-slate-400 leading-relaxed line-clamp-4">
          {lesson.blurb}
        </p>
      )}

      {/* tags */}
      <div className="flex flex-wrap gap-1.5">
        {tags.map(tag => (
          <span key={tag} className="rounded-full border border-[#2a3555] bg-[#111828] px-2.5 py-0.5 text-[11px] text-slate-400">
            {tag}
          </span>
        ))}
      </div>

      {/* stats */}
      <div className="flex items-center gap-4 text-[12px] text-slate-400 border-t border-[#1e2d4a] pt-3">
        <span className="flex items-center gap-1.5">
          <FileText className="h-3.5 w-3.5" />
          {pages} pages
        </span>
      </div>
    </button>
  );
}

// ─── Section Page Content (combined slide + text) ────────────────────────────

function SectionPageContent({
  section,
}: {
  lesson:  Lesson;
  section: { heading: string; content: string; codeExample?: string; imageQuery?: string; image?: LessonImage; video?: LessonVideoData };
}) {
  return (
    <div className="space-y-6">

      {/* ── Section heading ────────────────────────────────────── */}
      <div className="pb-5 border-b border-[#1e2d4a]">
        <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/70 block mb-2">
          Section
        </span>
        <h1 className="text-[22px] font-bold text-white leading-snug">{section.heading}</h1>
      </div>

      {/* ── Authored figure ────────────────────────────────────────
          Above the body text so the student sees the thing being described
          before reading the description. Shared with the /learn/[slug]/[lesson]
          reader via LessonFigure — see that file for why. */}
      {section.image && <LessonFigure image={section.image} />}

      {/* ── Authored explainer video (same-origin, curated) ─────────
          Shown above the body like the figure — the video covers the lesson,
          so it is attached to the first section only. Shared LessonVideo so this
          modal and the /learn/[slug]/[lesson] reader cannot drift. */}
      {section.video && <LessonVideo video={section.video} />}

      {/* ── Body text ──────────────────────────────────────────── */}
      {renderContent(section.content)}

      {/* ── Code example / diagram ─────────────────────────────────
          This modal reader used to stop at section.content, silently
          dropping codeExample — which 98 of the platform's 115 lesson
          sections carry. The other reader
          (learn/[slug]/[lesson]/page.tsx) rendered it, so the same
          lesson taught different material depending on which route you
          reached it through: every SPL/KQL query and comparison table
          was invisible here.

          Mermaid source is detected and rendered as an actual diagram
          rather than dumped as code — MermaidDiagram already existed but
          was wired only into rooms, so a diagram in a lesson displayed
          as raw `flowchart TD` text. */}
      {section.codeExample && (
        isMermaidSource(section.codeExample)
          ? <MermaidDiagram chart={section.codeExample} />
          : <CodeCard label="Example" code={section.codeExample} />
      )}

    </div>
  );
}

// ─── Paginated Lesson Reader ───────────────────────────────────────────────────

function LessonModal({ lesson, onClose }: { lesson: Lesson; onClose: () => void }) {
  const [page, setPage]             = useState(0);

  // A closing summary page is shown whenever the lesson carries key takeaways,
  // which also
  // gives the final page real substance instead of ending mid-section.
  const hasSummary = (lesson.keyTakeaways?.length ?? 0) > 0;

  // Page layout:  0 = intro,  1..N = sections,  N+1 = summary (if any)
  const totalPages = 1 + lesson.sections.length + (hasSummary ? 1 : 0);

  const goTo   = useCallback((p: number) => setPage(Math.max(0, Math.min(p, totalPages - 1))), [totalPages]);
  const onNext = () => goTo(page + 1);
  const onPrev = () => goTo(page - 1);

  // Keyboard nav
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") onNext();
      if (e.key === "ArrowLeft")  onPrev();
      if (e.key === "Escape")     onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  });

  const diffCls = DIFF_COLORS[lesson.difficulty] ?? DIFF_COLORS.intermediate;
  const progress = ((page + 1) / totalPages) * 100;

  // Current content
  const isIntro   = page === 0;
  const isSummary = hasSummary && page === totalPages - 1;
  const section   = !isIntro && !isSummary ? lesson.sections[page - 1] : null;

  // Modal dialog semantics + focus trap (Tab cycles inside, focus returns to the
  // lesson card on close). Escape is still handled by the keydown handler above.
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(true, dialogRef);

  // Every page change starts the reader at the top of the new page (the old modal kept
  // the previous page's scroll offset, so "Next" often landed mid-way down a section).
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => { scrollRef.current?.scrollTo({ top: 0 }); }, [page]);

  // Sidebar outline: intro, every section, then the wrap-up page.
  const outline = [
    "Introduction",
    ...lesson.sections.map((s) => s.heading),
    ...(hasSummary ? ["Key Takeaways"] : []),
  ];

  return (
    // Full-screen reader: the lesson owns the whole viewport (no centred card with
    // a fixed max width), a section outline on wide screens, and one scroll area.
    <div className="fixed inset-0 z-50 bg-[#070b14]">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="flex h-full w-full flex-col"
      >

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="relative shrink-0 border-b border-[#1e2d4a] bg-[#0b0f1e]">
          <div className="flex items-center justify-between gap-3 px-4 py-2.5 sm:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
                <FileText className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <h2 id={titleId} className="truncate text-sm font-bold text-white sm:text-[15px]">{lesson.title}</h2>
                <p className="text-[11px] text-slate-400">
                  Page {page + 1} of {totalPages}
                </p>
              </div>
            </div>
            <div className="ml-3 flex shrink-0 items-center gap-2">
              <span className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase ${diffCls}`}>
                {capitalize(lesson.difficulty)}
              </span>
              <button onClick={onClose} aria-label="Close lesson" className="rounded-lg border border-slate-700 bg-slate-800 p-1.5 text-slate-400 transition-colors hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
          {/* Progress along the top edge */}
          <div className="h-[3px] w-full bg-[#1a2035]" aria-hidden="true">
            <div className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>
        </div>

        {/* ── Body: outline + content ────────────────────────────────────── */}
        <div className="flex min-h-0 flex-1">
          <nav aria-label="Lesson sections" className="hidden w-72 shrink-0 overflow-y-auto border-r border-[#1e2d4a] bg-[#0b0f1e]/60 p-3 lg:block">
            <ol className="space-y-0.5">
              {outline.map((label, i) => {
                const current = i === page;
                const done = i < page;
                return (
                  <li key={i}>
                    <button
                      onClick={() => goTo(i)}
                      aria-current={current ? "step" : undefined}
                      className={`flex w-full items-start gap-2.5 rounded-md px-2.5 py-2 text-left text-[13px] leading-snug transition-colors ${
                        current ? "bg-cyan-500/10 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                      }`}
                    >
                      <span className={`mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px] font-bold ${
                        current ? "bg-cyan-500 text-[#070b14]" : done ? "bg-emerald-500/15 text-emerald-300" : "bg-slate-800 text-slate-400"
                      }`}>
                        {done ? <CheckCircle2 className="h-3 w-3" aria-hidden="true" /> : i + 1}
                      </span>
                      <span>{label}{done && <span className="sr-only"> (read)</span>}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </nav>

          <div ref={scrollRef} className="min-w-0 flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-[920px] px-5 py-8 sm:px-8 lg:py-10 [&_p]:text-[15.5px] [&_li]:text-[15.5px]">

              {/* Intro page */}
              {isIntro && (
                <div className="space-y-6">
                  {/* H1 — Main topic title */}
                  <div className="pb-5 border-b border-[#1e2d4a]">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/70 block mb-2">
                      Introduction
                    </span>
                    <h1 className="text-[22px] font-bold text-white leading-snug">
                      {lesson.title}
                    </h1>
                  </div>

                  {renderContent(lesson.intro)}

                  {/* ── "In this lesson" agenda ──────────────────────────────────
                      The intro is a single framing paragraph, so on a full-height
                      page it left a large empty area below it. This outline fills
                      the page with genuinely useful content — the student sees the
                      path ahead and can jump straight to any section. */}
                  {lesson.sections.length > 0 && (
                    <div className="rounded-xl border border-[#1e2d4a] bg-[#0d1322] p-5">
                      <h3 className="mb-4 flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-cyan-500/70">
                        <ListChecks className="h-3.5 w-3.5" /> In this lesson
                      </h3>
                      <ol className="space-y-2.5">
                        {lesson.sections.map((s, i) => (
                          <li key={i}>
                            <button
                              onClick={() => goTo(i + 1)}
                              className="group flex w-full items-start gap-3 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-white/5"
                            >
                              <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-cyan-500/30 bg-cyan-500/10 text-[11px] font-bold text-cyan-300">
                                {i + 1}
                              </span>
                              <span className="text-[14px] leading-snug text-slate-300 group-hover:text-cyan-200">
                                {s.heading}
                              </span>
                            </button>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              )}

              {/* Section page */}
              {section && (
                <SectionPageContent lesson={lesson} section={section} />
              )}

              {/* Summary page: key takeaways. Reference URLs are kept in the data as provenance, not shown to students. */}
              {isSummary && (
                <div className="space-y-6">
                  <div className="pb-5 border-b border-[#1e2d4a]">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/70 block mb-2">
                      Wrap-up
                    </span>
                    <h1 className="text-[22px] font-bold text-white leading-snug">Key Takeaways</h1>
                  </div>

                  {(lesson.keyTakeaways?.length ?? 0) > 0 && (
                    <ul className="space-y-3">
                      {lesson.keyTakeaways.map((t, i) => (
                        <li key={i} className="flex items-start gap-3">
                          <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" />
                          <span className="text-[15px] leading-relaxed text-slate-200">{t}</span>
                        </li>
                      ))}
                    </ul>
                  )}

                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Footer nav ─────────────────────────────────────────────────── */}
        <div className="shrink-0 border-t border-[#1e2d4a] bg-[#0b0f1e]">
          <div className="flex">
          {/* spacer under the outline so the buttons line up with the reading column */}
          <div className="hidden w-72 shrink-0 lg:block" aria-hidden="true" />
          <div className="mx-auto flex w-full max-w-[920px] items-center justify-between gap-3 px-5 py-3 sm:px-8">
            <button
              onClick={onPrev}
              disabled={page === 0}
              className="flex items-center gap-1.5 rounded-xl border border-[#2a3555] bg-[#0d1322] px-4 py-2 text-[13px] font-semibold text-slate-300 transition-all hover:border-slate-500 hover:text-white disabled:cursor-not-allowed disabled:opacity-30"
            >
              <ChevronLeft className="h-4 w-4" /> Previous
            </button>

            <span className="text-[12px] tabular-nums text-slate-400">{page + 1} / {totalPages}</span>

            <button
              onClick={page === totalPages - 1 ? onClose : onNext}
              className="flex items-center gap-1.5 rounded-xl bg-cyan-600 px-5 py-2 text-[13px] font-semibold text-white transition-all hover:bg-cyan-500"
            >
              {page === totalPages - 1 ? "Finish" : "Next"}
              {page !== totalPages - 1 && <ChevronRight className="h-4 w-4" />}
            </button>
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}


// ─── Loading state for an on-demand lesson ─────────────────────────────────────

function LessonLoading({ title, failed, onRetry, onCancel }: { title: string; failed: boolean; onRetry: () => void; onCancel: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#070b14]/80 px-4">
      <div role={failed ? "alertdialog" : "status"} aria-live="polite" aria-label={failed ? "Lesson failed to load" : "Loading lesson"}
        className="w-full max-w-sm rounded-2xl border border-[#1e2d4a] bg-[#0d1322] p-6 text-center">
        {failed ? (
          <>
            <p className="text-sm font-semibold text-white">Couldn&apos;t open this lesson</p>
            <p className="mt-1 text-[13px] text-slate-400">{title}</p>
            <p className="mt-3 text-[12px] text-slate-400">Check your connection and try again.</p>
            <div className="mt-5 flex justify-center gap-2">
              <button onClick={onCancel} className="rounded-xl border border-slate-700 px-4 py-2 text-[13px] text-slate-300 hover:text-white">Close</button>
              <button onClick={onRetry} className="rounded-xl bg-cyan-600 px-4 py-2 text-[13px] font-semibold text-white hover:bg-cyan-500">Try again</button>
            </div>
          </>
        ) : (
          <>
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-cyan-400" aria-hidden="true" />
            <p className="mt-3 text-sm font-semibold text-white">Opening lesson</p>
            <p className="mt-1 text-[13px] text-slate-400 line-clamp-2">{title}</p>
            <button onClick={onCancel} className="mt-4 text-[12px] text-slate-400 underline hover:text-slate-200">Cancel</button>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function LearnPage() {
  const [lessons,    setLessons]    = useState<CardItem[]>([]);
  const [search,     setSearch]     = useState("");
  const [level,      setLevel]      = useState("all");
  const [openLesson, setOpenLesson] = useState<Lesson | null>(null);
  const [mounted,    setMounted]    = useState(false);
  // On-demand loading of a built-in lesson's full content.
  const [pending,    setPending]    = useState<CardItem | null>(null);
  const [loadFailed, setLoadFailed] = useState<CardItem | null>(null);
  const fullCache = useRef(new Map<string, Promise<Lesson>>());
  const pendingRef = useRef<string | null>(null);
  // "Assigned" chips for org-authored library lessons that sit in a plan.
  const assigned = useAssignedItems();

  // Admin-published lessons now live in the durable content_lessons table
  // (migration 0019), not per-browser localStorage — this is what makes them
  // actually visible to real students for the first time. deleted_lesson_ids
  // (hiding a BUILT-IN lesson) stays local for now — a lower-stakes,
  // reversible moderation toggle, not authored content that can be lost.
  async function loadLessons() {
    let deletedSet = new Set<string>();
    try {
      const deleted: string[] = JSON.parse(localStorage.getItem("deleted_lesson_ids") ?? "[]");
      deletedSet = new Set(deleted);
    } catch { /* storage blocked */ }

    const saved = await fetchPublishedLessons<Lesson>();
    const savedIds = new Set(saved.map(l => l.id));
    const builtins: CardItem[] = LIBRARY_INDEX
      .filter(l => !savedIds.has(l.id) && !deletedSet.has(l.id));
    // Org-authored lessons arrive complete, so their card carries the full lesson.
    const all: CardItem[] = [...saved.map(l => ({ ...libraryEntry(l), full: l })), ...builtins];
    setLessons(all);
    // Deep link (?open=<lessonId>) — used by Learning Path lessons that point
    // to related Library lessons while they are in preparation.
    try {
      const openId = new URLSearchParams(window.location.search).get("open");
      const hit = openId ? all.find(l => l.id === openId) : undefined;
      if (hit) openItem(hit);
    } catch { /* no window / malformed URL */ }
  }

  /** The full lesson for a card: in hand already, or one cached fetch per lesson. */
  function loadFull(item: CardItem): Promise<Lesson> {
    if (item.full) return Promise.resolve(item.full);
    let p = fullCache.current.get(item.id);
    if (!p) {
      p = fetch(`/api/library/${encodeURIComponent(item.id)}`).then(async r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return (await r.json()) as Lesson;
      });
      // A failed load must not stick: drop it so the next attempt refetches.
      p.catch(() => fullCache.current.delete(item.id));
      fullCache.current.set(item.id, p);
    }
    return p;
  }

  function prefetch(item: CardItem) {
    loadFull(item).catch(() => { /* surfaced if they actually open it */ });
  }

  function openItem(item: CardItem) {
    setLoadFailed(null);
    if (item.full) { setOpenLesson(item.full); return; }
    pendingRef.current = item.id;
    setPending(item);
    loadFull(item)
      .then(full => { if (pendingRef.current === item.id) setOpenLesson(full); })
      .catch(() => { if (pendingRef.current === item.id) setLoadFailed(item); })
      .finally(() => { if (pendingRef.current === item.id) { pendingRef.current = null; setPending(null); } });
  }

  function cancelPending() {
    pendingRef.current = null;
    setPending(null);
    setLoadFailed(null);
  }

  useEffect(() => {
    setMounted(true);
    loadLessons();
    // Re-sync deleted_lesson_ids across tabs on the same device (the
    // durable-content half no longer needs this — a fresh mount re-fetches it).
    const onStorage = () => loadLessons();
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return lessons.filter(l => {
      if (level !== "all" && l.difficulty !== level) return false;
      if (q && !l.title.toLowerCase().includes(q) && !l.topic.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [lessons, search, level]);

  return (
    <div className="min-h-screen bg-[#0b0f1e]">
      <Topbar title="Learning Path" subtitle="Explore cybersecurity knowledge through interactive lessons" />

      <div className="container mx-auto max-w-[1400px] px-6 py-8">

        {/* Plans set by the learner's organisation — renders nothing for solo learners. */}
        <div className="mb-8 empty:hidden">
          <MyLearningPlan />
        </div>

        {/* ── Source-of-truth signpost ──────────────────────────────────
            This page (the Lesson Library) is reference/exploration
            material with no mastery gate. The graded, sequenced curriculum —
            the one that scores you, enforces prerequisites, and tracks real
            competence — is Learning Rooms. Say so plainly so a beginner who
            lands here first doesn't mistake the reading library for the course. */}
        <Link
          href="/rooms"
          className="group mb-8 flex items-center gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/5 px-4 py-3 transition-colors hover:border-cyan-500/50 hover:bg-cyan-500/10"
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
            <Layers className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-semibold text-cyan-100">
              This is a reference &amp; exploration library — read freely, in any order.
            </p>
            <p className="text-[12px] text-slate-400 leading-relaxed">
              The graded curriculum that scores you, unlocks by prerequisite, and tracks your progress to analyst is{" "}
              <span className="font-semibold text-cyan-200">Learning Rooms</span>. Start there for the real path.
            </p>
          </div>
          <ArrowRight className="h-4 w-4 shrink-0 text-cyan-400 transition-transform group-hover:translate-x-0.5" />
        </Link>

        {/* ── Lesson library (flat reference collection) ── */}
        <div className="mb-4 flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">Lesson Library</h2>
          <span className="text-[11px] text-slate-500">— browse any topic on its own; not ordered</span>
        </div>

        {/* ── Search + filter ─────────────────────────── */}
        <div className="mb-8 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
            <input
              type="text"
              placeholder="Search lessons..."
              aria-label="Search lessons"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full rounded-xl border border-[#2a3555] bg-[#0d1322] py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
          </div>
          <div className="relative">
            <select
              value={level}
              onChange={e => setLevel(e.target.value)}
              aria-label="Filter by difficulty level"
              className="appearance-none rounded-xl border border-[#2a3555] bg-[#0d1322] pl-4 pr-10 py-2.5 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/60 cursor-pointer min-w-[160px]"
            >
              <option value="all">All Levels</option>
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
              <option value="expert">Expert</option>
            </select>
            <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 rotate-90 pointer-events-none" />
          </div>
        </div>

        {!mounted ? null : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <FileText className="h-12 w-12 text-slate-500 mb-4" />
            <p className="text-base font-semibold text-slate-400">
              {lessons.length === 0 ? "No lessons yet" : "No lessons match your filters"}
            </p>
            <p className="mt-1 text-sm text-slate-400">
              {lessons.length === 0
                ? "Go to Admin → Lesson Management to generate lessons"
                : <button onClick={() => { setSearch(""); setLevel("all"); }} className="text-cyan-400 hover:text-cyan-300 underline">Clear filters</button>
              }
            </p>
          </div>
        ) : (
          <>
            <p className="mb-4 text-[12px] text-slate-400">{filtered.length} item{filtered.length !== 1 ? "s" : ""}</p>
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {filtered.map(l => (
                <LessonCard key={l.id} lesson={l} onClick={() => openItem(l)} onIntent={() => prefetch(l)} assigned={assigned[`lesson:${l.id}`]} />
              ))}
            </div>
          </>
        )}

      </div>

      {openLesson && <LessonModal lesson={openLesson} onClose={() => setOpenLesson(null)} />}

      {/* Opening a lesson that isn't loaded yet: a brief, cancellable loading
          state, or a retry if the fetch failed. Usually skipped entirely because
          hovering or focusing the card already started the fetch. */}
      {!openLesson && (pending || loadFailed) && (
        <LessonLoading
          title={(pending ?? loadFailed)!.title}
          failed={!!loadFailed}
          onRetry={() => loadFailed && openItem(loadFailed)}
          onCancel={cancelPending}
        />
      )}
    </div>
  );
}
