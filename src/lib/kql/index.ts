import { KqlFail, LIMITS, lineCol, resetBudget } from "./errors";
import { execute, queryFiltersTime } from "./exec";
import { parseKql } from "./parser";
import type { KqlEnv, KqlResult, KqlRow } from "./types";

export { kqlCompletions } from "./completions";
export { tokenizeKql, type KqlToken, type KqlTokenClass } from "./tokenize";
export { KqlTimespan, formatKqlValue } from "./values";
export type { KqlChart, KqlColumn, KqlCompletion, KqlEnv, KqlError, KqlResult, KqlRow, KqlTable, KqlType } from "./types";

const DEFAULT_MAX_ROWS = 30000;

/** Runs a query over in-memory tables. Pure and synchronous, and never throws: every failure is a KqlError result. */
export function runKql(query: string, env: KqlEnv): KqlResult {
  try {
    resetBudget();
    if (query.length > LIMITS.maxQueryLength) {
      throw new KqlFail("Query text size exceeds the maximum safe limit.", 0);
    }
    const parsed = parseKql(query);
    if (parsed.statements.length === 0) {
      throw new KqlFail("The query is empty.", 0);
    }
    const { table, chart, warnings } = execute(parsed, env);
    const maxRows = env.maxRows ?? DEFAULT_MAX_ROWS;
    const truncated = table.rows.length > maxRows;
    const rows: KqlRow[] = truncated ? table.rows.slice(0, maxRows) : table.rows;
    return { ok: true, columns: table.columns, rows, truncated, chart, warnings };
  } catch (e) {
    if (e instanceof KqlFail) {
      return { ok: false, error: { message: e.message, ...lineCol(query, e.pos) } };
    }
    if (e instanceof RangeError) {
      return { ok: false, error: { message: "Query syntax depth exceeds the maximum safe limit.", line: 1, column: 1 } };
    }
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, error: { message: `The query could not be run: ${message}`, line: 1, column: 1 } };
  }
}

/** True when the query sets its own time window, which is when the portal shows "Set in query". */
export function kqlSetsTimeRange(query: string): boolean {
  try {
    return queryFiltersTime(parseKql(query));
  } catch {
    return false;
  }
}
