/**
 * Lesson markdown → HTML (AI-generated and org-authored lesson bodies).
 *
 * SECURITY: the text is UNTRUSTED. HTML-significant characters are escaped FIRST
 * (& and <), before any markdown replacement, so an injected tag stays inert
 * text; every tag emitted afterwards is our own whitelisted formatting markup.
 * Fenced ```code``` blocks are lifted out into placeholders first (so their
 * pipes / blank lines survive the replacements) and re-inserted at the end.
 *
 * Moved out of the lesson page (QA phase 6): the placeholder was written with
 * literal NUL bytes but restored with a regex looking for SPACES, so every code
 * block rendered as "\uFFFDCB0\uFFFD" — and the NUL bytes made the file look binary
 * to code search, hiding its dangerouslySetInnerHTML sink from audits.
 */
export function labelForLang(lang: string) {
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

export function lessonMarkdownToHtml(text: string): string {
  const codeBlocks: string[] = [];
  const staged = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, lang: string, body: string) => {
    const esc = body.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/\n+$/, "");
    const label = labelForLang(lang);
    const card =
      `<div class="my-4 overflow-hidden rounded-xl border border-slate-700/50 bg-[#0a0f1c] shadow-sm">` +
        `<div class="flex items-center justify-between border-b border-slate-700/40 bg-slate-800/25 px-4 py-2">` +
          `<span class="flex gap-1.5">` +
            `<span class="inline-block h-2.5 w-2.5 rounded-full bg-red-400/40"></span>` +
            `<span class="inline-block h-2.5 w-2.5 rounded-full bg-amber-400/40"></span>` +
            `<span class="inline-block h-2.5 w-2.5 rounded-full bg-emerald-400/40"></span>` +
          `</span>` +
          `<span class="font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">${label}</span>` +
        `</div>` +
        `<pre class="overflow-x-auto px-4 py-3.5 font-mono text-[12.5px] leading-relaxed text-slate-200"><code>${esc}</code></pre>` +
      `</div>`;
    const i = codeBlocks.push(card) - 1;
    return `\u0000CB${i}\u0000`;
  });
  const html = staged
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    // GFM tables → <table>. Runs after HTML-escaping so cell content is safe;
    // the tags emitted here are our own whitelisted markup. A block is a run of
    // lines that start and end with "|", whose 2nd line is a "| --- |" separator.
    .replace(/(?:^\|.*\|[ \t]*\n?)+/gm, (block: string) => {
      const lines = block.trim().split("\n");
      if (lines.length < 2 || !/^\|[ \t:|\-]+\|[ \t]*$/.test(lines[1])) return block;
      const cells = (r: string) => r.trim().replace(/^\|/, "").replace(/\|[ \t]*$/, "").split("|").map(c => c.trim());
      const th = cells(lines[0]).map(c => `<th class="border border-[#1e2d4a] bg-[#0f1830] px-3 py-1.5 text-left font-semibold text-cyan-200">${c}</th>`).join("");
      const rows = lines.slice(2).map(r => `<tr>${cells(r).map(c => `<td class="border border-[#1e2d4a] px-3 py-1.5 align-top text-slate-300">${c}</td>`).join("")}</tr>`).join("");
      return `<table class="my-4 w-full border-collapse text-sm"><thead><tr>${th}</tr></thead><tbody>${rows}</tbody></table>`;
    })
    .replace(/^### (.+)$/gm, '<h3 class="mt-5 mb-2 text-base font-bold text-white">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="mt-6 mb-3 text-lg font-bold text-white">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="mt-6 mb-3 text-xl font-bold text-white">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="rounded bg-bg px-1.5 py-0.5 font-mono text-xs text-cyber-300">$1</code>')
    .replace(/^> (.+)$/gm, '<blockquote class="border-l-4 border-cyber-500/40 pl-4 italic text-slate-400 my-3">$1</blockquote>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-slate-300 my-1">$1</li>')
    .replace(/(<li[^>]*>.*<\/li>\n?)+/g, m => `<ul class="my-3 space-y-1">${m}</ul>`)
    .replace(/\n\n/g, '</p><p class="my-3 text-slate-300 leading-relaxed">')
    .replace(/^(?!<[hbuclpt])/, '<p class="my-3 text-slate-300 leading-relaxed">')
    .replace(/$(?<![>])/, '</p>');
  // Swap the fenced-code placeholders back for their rendered <pre> blocks.
  const finalHtml = html.replace(/\u0000CB(\d+)\u0000/g, (_m, i) => codeBlocks[+i] ?? "");
  return finalHtml;
}
