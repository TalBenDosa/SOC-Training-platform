/**
 * Is a lesson's `codeExample` a Mermaid diagram rather than a query or table?
 *
 * Lesson sections have one pre-formatted slot, `codeExample`, and it carries
 * two different kinds of thing: SPL/KQL queries and comparison tables (which
 * belong in a <pre>), and Mermaid diagram source (which should be rendered).
 * Both lesson readers call this to decide.
 *
 * The test is anchored to the diagram-type keyword Mermaid requires on its
 * first non-empty line, rather than searching the whole string — an SPL query
 * with the word "graph" in a comment, or a table describing a "timeline",
 * must not be mistaken for a diagram and swallowed by the renderer.
 */
export function isMermaidSource(src: string): boolean {
  const first = src.split("\n").map(l => l.trim()).find(Boolean) ?? "";
  return /^(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram(-v2)?|erDiagram|journey|gantt|pie|mindmap|timeline|quadrantChart|requirementDiagram|gitGraph)\b/
    .test(first);
}
