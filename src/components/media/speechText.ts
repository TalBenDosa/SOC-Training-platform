/**
 * Turns reading content (the platform's markdown dialect) into plain text that
 * sounds right when read aloud by the Web Speech API (feedback FB-009).
 *
 * Code blocks are not read character-by-character — a synthesiser reciting a
 * KQL query or a JSON log is noise — they're replaced by a short spoken cue.
 * Tables are read row by row, formatting marks are dropped, links keep their
 * text. Pure, so it can be unit-tested without a browser.
 */
export function toSpeechText(markdown: string): string {
  if (!markdown) return "";
  let t = markdown.replace(/\r\n?/g, "\n");

  // Fenced code blocks (``` or ~~~) → a short cue.
  t = t.replace(/(```|~~~)[^\n]*\n[\s\S]*?(?:\1|$)/g, "\n(Code example shown on screen.)\n");
  // HTML tags / comments.
  t = t.replace(/<!--[\s\S]*?-->/g, " ").replace(/<\/?[a-zA-Z][^>]*>/g, " ");
  // Images keep their alt text; links keep their label.
  t = t.replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1");
  t = t.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
  // Table separator rows vanish; remaining table rows read as comma lists.
  t = t.replace(/^\s*\|?[\s:|-]*-{2,}[\s:|-]*\|?\s*$/gm, "");
  t = t.replace(/^\s*\|(.*)\|\s*$/gm, (_m, row: string) =>
    row.split("|").map(c => c.trim()).filter(Boolean).join(", ") + ".");
  // Headings, blockquotes, list markers, horizontal rules.
  t = t.replace(/^\s{0,3}#{1,6}\s+(.*)$/gm, "$1.");
  t = t.replace(/^\s*>\s?/gm, "");
  t = t.replace(/^\s*(?:[-*+•]|\d+[.)])\s+/gm, "");
  t = t.replace(/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/gm, "");
  // Inline code keeps its content; emphasis marks go.
  t = t.replace(/`([^`]+)`/g, "$1");
  t = t.replace(/(\*\*|__)(.+?)\1/g, "$2").replace(/(\*|_)(\S(?:.*?\S)?)\1/g, "$2");
  t = t.replace(/~~(.+?)~~/g, "$1");
  // Arrows and a few symbols that synthesisers mangle.
  t = t.replace(/\s*(?:→|->|=>)\s*/g, " to ").replace(/\s*(?:←|<-)\s*/g, " from ");
  // Collapse whitespace; keep paragraph breaks as sentence breaks.
  t = t.replace(/\.\s*\.(?=\s|$)/g, ".").replace(/[ \t]+/g, " ").replace(/\n{2,}/g, "\n").trim();
  return t;
}

/**
 * Split text into utterance-sized chunks. Chrome silently stops speaking a
 * single utterance after ~15 seconds, so long readings are queued as a series
 * of sentence-grouped chunks instead of one long utterance.
 */
export function chunkForSpeech(text: string, maxLen = 220): string[] {
  const sentences = text
    .split(/\n+/)
    .flatMap(p => p.match(/[^.!?]+(?:[.!?]+|$)/g) ?? [])
    .map(s => s.trim())
    .filter(Boolean);
  const chunks: string[] = [];
  let cur = "";
  for (const s of sentences) {
    if (s.length > maxLen) {
      if (cur) { chunks.push(cur); cur = ""; }
      // Hard-wrap an overlong sentence on word boundaries.
      let rest = s;
      while (rest.length > maxLen) {
        const cut = rest.lastIndexOf(" ", maxLen);
        const at = cut > maxLen / 2 ? cut : maxLen;
        chunks.push(rest.slice(0, at).trim());
        rest = rest.slice(at).trim();
      }
      cur = rest;
      continue;
    }
    if ((cur + " " + s).trim().length > maxLen) { chunks.push(cur); cur = s; }
    else cur = (cur ? cur + " " : "") + s;
  }
  if (cur) chunks.push(cur);
  return chunks;
}
