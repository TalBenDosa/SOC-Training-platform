/**
 * Shared "KQL in 90 seconds" primer.
 *
 * Coverage-audit finding A-02: eleven `query_fill` tasks ask the student to write
 * KQL, but sit in networking / Windows / identity rooms whose prerequisite chain
 * never passes through a KQL-teaching room (sentinel-fundamentals / defender-xdr).
 * Rather than gate those rooms behind a SIEM room — which would invert the
 * curriculum (you would have to learn Sentinel before TCP/IP) — we anchor the
 * knowledge locally by prepending this primer to each such task's `context`, so the
 * syntax the task needs is always shown before the task is asked.
 *
 * Keep it factual and tight: it must teach exactly the KQL those templates require
 * (pipe model, where / summarize / dcount / project / join, time filters).
 */
export const KQL_PRIMER =
  "**KQL in 90 seconds** — Kusto Query Language (KQL) is the query language Microsoft " +
  "Sentinel and Defender XDR use to search log tables. A query names a table and pipes " +
  "(`|`) its rows left-to-right through operators:\n\n" +
  "- `where` filters rows by a condition — e.g. `where SPFResult == \"Fail\"`. Use `==` / `!=` " +
  "for an exact match, `has` for a whole word, `contains` for a substring, `startswith` / `endswith` for edges.\n" +
  "- `summarize` aggregates — e.g. `summarize attempts = count(), targets = dcount(TargetAccount) by SourceIP`. " +
  "`count()` counts rows; `dcount()` counts DISTINCT values (that is how you catch \"one source, many targets\" " +
  "when the raw failure count per account is low).\n" +
  "- `project` keeps only the columns you name; `sort by <col> desc` orders; `join` correlates two tables on a shared key.\n" +
  "- Time is a column (usually `TimeGenerated`); `where TimeGenerated > ago(1h)` limits to the last hour.\n\n" +
  "So a detection query is just: pick the table → `where` down to the suspicious pattern → optionally " +
  "`summarize ... by` the entity and threshold it. Fill the blanks below with the exact field values that " +
  "isolate the pattern described.\n\n";
