/** Kusto scalar column types, as Log Analytics names them. */
export type KqlType = "string" | "int" | "long" | "real" | "bool" | "datetime" | "timespan" | "dynamic" | "guid";

export interface KqlColumn { name: string; type: KqlType }

export type KqlRow = Record<string, unknown>;

export interface KqlTable { name: string; columns: KqlColumn[]; rows: KqlRow[] }

export interface KqlEnv {
  /** Tables by exact name. Table names are case-sensitive, as in Log Analytics. */
  tables: Record<string, KqlTable>;
  /** The value of now(). The simulated clock, never Date.now() inside the engine. */
  now: Date;
  /** The Time range picker. Applied to TimeGenerated of every table that has it, unless the query itself filters on TimeGenerated. */
  timeRange?: { from: Date; to: Date };
  /** Row cap on results, as in the portal. Default 30000. */
  maxRows?: number;
}

export interface KqlError {
  /** Short, in the style of Log Analytics, such as "'wher' is not a recognized operator". */
  message: string;
  /** 1-based position of the offending token. */
  line: number;
  column: number;
}

export interface KqlChart { kind: "timechart" | "barchart" | "columnchart" | "piechart" | "linechart" | "areachart" | "table" }

export type KqlResult =
  | { ok: true; columns: KqlColumn[]; rows: KqlRow[]; truncated: boolean; chart?: KqlChart; warnings: string[] }
  | { ok: false; error: KqlError };

export interface KqlCompletion { label: string; kind: "table" | "column" | "operator" | "function" | "keyword"; insert: string; detail?: string }
