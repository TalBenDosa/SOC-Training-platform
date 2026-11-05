import React from "react";

/**
 * Inline emphasis for task text: **bold**, *italic* and `code`. Readings go through the
 * full Markdown renderer, but scenarios, questions and explanations are plain strings, so
 * their markers used to show as raw asterisks. Line breaks in the string are kept.
 */
const TOKEN = /(\*\*[^*\n]+\*\*|\*[^*\s][^*\n]*\*|`[^`\n]+`)/g;

export function InlineMd({ text }: { text: string | null | undefined }) {
  if (!text) return null;
  return (
    <>
      {text.split(TOKEN).map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**") && part.length > 4) return <strong key={i} className="font-semibold text-white">{part.slice(2, -2)}</strong>;
        if (part.startsWith("`") && part.endsWith("`") && part.length > 2) return <code key={i} className="rounded bg-white/10 px-1 font-mono text-[0.9em]">{part.slice(1, -1)}</code>;
        if (part.startsWith("*") && part.endsWith("*") && part.length > 2) return <em key={i}>{part.slice(1, -1)}</em>;
        return part.split("\n").map((line, k) => <React.Fragment key={`${i}-${k}`}>{k > 0 && <br />}{line}</React.Fragment>);
      })}
    </>
  );
}
