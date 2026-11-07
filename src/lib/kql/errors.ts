/** Internal failure carrying a source offset. Converted to KqlError at the runKql boundary. */
export class KqlFail extends Error {
  pos: number;
  /** Set on unresolved table references, which `union isfuzzy=true` downgrades to warnings. */
  readonly unresolvedTable?: string;
  constructor(message: string, pos = 0, unresolvedTable?: string) {
    super(message);
    this.pos = pos;
    this.unresolvedTable = unresolvedTable;
  }
}

/** Raised when a query exceeds the work budget. Never reaches the caller as an exception. */
export class KqlLimitFail extends KqlFail {}

export function lineCol(src: string, pos: number): { line: number; column: number } {
  const p = Math.max(0, Math.min(pos, src.length));
  let line = 1;
  let last = -1;
  for (let i = 0; i < p; i++) {
    if (src.charCodeAt(i) === 10) {
      line++;
      last = i;
    }
  }
  return { line, column: p - last };
}

/**
 * Work accounting. The engine is synchronous and runs on the UI thread, so every
 * loop that scales with data or with the query charges this budget. A query that
 * runs out stops with an error instead of freezing the tab.
 */
export const LIMITS = {
  /** Abstract work units, roughly one row-expression node or one regex thread step. Measured at about 2s at worst. */
  budget: 150_000_000,
  /** Row cap for any intermediate result: join, mv-expand, union, range. */
  maxIntermediateRows: 1_000_000,
  /** Longest string an expression may build. Stops strcat doubling. */
  maxStringLength: 4_000_000,
  /** Longest array an expression may build. Stops array_concat doubling. */
  maxArrayLength: 1_000_000,
  /** Query text size, in characters. */
  maxQueryLength: 200_000,
  /** Parser nesting depth. */
  maxDepth: 150,
};

let remaining = LIMITS.budget;

export function resetBudget(budget: number = LIMITS.budget): void {
  remaining = budget;
}

export function charge(units = 1): void {
  remaining -= units;
  if (remaining < 0) {
    throw new KqlLimitFail("The query exceeded the resource limits of this console. Narrow it with a where clause, a smaller time range or fewer joined rows.");
  }
}

export function checkRows(count: number, pos = 0): void {
  if (count > LIMITS.maxIntermediateRows) {
    throw new KqlLimitFail(`The query produced more than ${LIMITS.maxIntermediateRows} rows in an intermediate step. Filter the input before this operator.`, pos);
  }
}

export function tooLarge(): KqlLimitFail {
  return new KqlLimitFail("The query built a value larger than the limit of this console.");
}

export function checkString(s: string): string {
  if (s.length > LIMITS.maxStringLength) throw tooLarge();
  return s;
}

/** Bounded edit distance for near-match suggestions. */
export function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 4 || a.length > 128 || b.length > 128) return 99;
  let prev: number[] = [];
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    const cur: number[] = [i];
    for (let j = 1; j <= b.length; j++) {
      const sub = prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1);
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, sub);
    }
    prev = cur;
  }
  return prev[b.length];
}

export function nearest(name: string, candidates: Iterable<string>): string | undefined {
  const lower = name.toLowerCase();
  let best: string | undefined;
  let bestScore = 99;
  for (const c of candidates) {
    const score = c.toLowerCase() === lower ? 0 : editDistance(lower, c.toLowerCase());
    if (score < bestScore) {
      bestScore = score;
      best = c;
    }
  }
  const allowed = Math.max(2, Math.floor(name.length / 3));
  return bestScore <= allowed ? best : undefined;
}

export function didYouMean(name: string, candidates: Iterable<string>): string {
  const hit = nearest(name, candidates);
  return hit && hit !== name ? ` Did you mean '${hit}'?` : "";
}

/** Appends a suggestion to a message that ends in a quoted name. */
export function withHint(message: string, name: string, candidates: Iterable<string>): string {
  const hint = didYouMean(name, candidates);
  return hint ? `${message}.${hint}` : message;
}
