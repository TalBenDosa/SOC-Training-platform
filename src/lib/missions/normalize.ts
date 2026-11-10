/**
 * Normalisers for typed answers: the reason a learner who writes 198.51.100[.]77,
 * "1,400 MB" or "08:52 UTC" is not failed on spelling. Pure and shared by the
 * grader and the notebook (which shows each indicator defanged and typed).
 */
import type { FieldFormat, IocType } from "./types";

/** hxxp, [.], (.), {.}, [dot], [:]  ->  the live form, for comparison only. */
export function refang(s: string): string {
  return s.trim()
    .replace(/^hxxp/i, "http")
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*@\s*\]|\[at\]/gi, "@");
}

/** The safe form for display in the notebook: 198.51.100[.]77, hxxps://site[.]example/path. Hashes, files and hosts stay as typed. */
export function defang(type: IocType, raw: string): string {
  const v = refang(raw);
  if (type === "url") {
    const m = /^(https?)(:\/\/)([^/]+)(.*)$/i.exec(v);
    if (m) return m[1].replace(/tt/i, "xx") + m[2] + m[3].replace(/\./g, "[.]") + m[4];
    return v.replace(/\./g, "[.]");
  }
  if (type === "ip" || type === "domain") return v.replace(/\.(?=[^.]*$)/, "[.]");
  if (type === "email") return v.replace("@", "[@]").replace(/\.(?=[^.]*$)/, "[.]");
  return v;
}

export function looseText(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ").replace(/^["'`]|["'`]$/g, "");
}

function stripSlashDot(s: string): string {
  return s.replace(/\.$/, "").replace(/\/+$/, "");
}

const UNITS: Record<string, number> = {
  b: 1, byte: 1, bytes: 1,
  kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12,
  kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3,
};

/** "1,400", "1.4 GB", "1400MB" -> number of base units (bytes when a unit is given). */
export function parseNumber(raw: string): number | null {
  const m = /^\s*([+-]?[\d,]*\.?\d+)\s*([a-z]+)?\s*$/i.exec(raw.replace(/_/g, ""));
  if (!m) return null;
  const n = Number(m[1].replace(/,/g, ""));
  if (!Number.isFinite(n)) return null;
  if (!m[2]) return n;
  const mult = UNITS[m[2].toLowerCase()];
  return mult ? n * mult : null;
}

/**
 * Minutes since midnight (for a time of day) or since the epoch (for a date-time),
 * from "08:52", "08:52:31", "8:52 UTC", "2026-04-14 08:52", "2026-04-14T08:52:31Z".
 * A value with a date is compared with dates; a bare time only with bare times.
 */
export function parseUtc(raw: string): { kind: "time" | "datetime"; minutes: number } | null {
  const s = raw.trim().replace(/\s*(utc|z|gmt)$/i, "").replace(/z$/i, "");
  const dt = /^(\d{4})-(\d{2})-(\d{2})[ t](\d{1,2}):(\d{2})(?::(\d{2}))?$/i.exec(s);
  if (dt) {
    const ms = Date.UTC(+dt[1], +dt[2] - 1, +dt[3], +dt[4], +dt[5], +(dt[6] ?? 0));
    return Number.isFinite(ms) ? { kind: "datetime", minutes: Math.floor(ms / 60000) } : null;
  }
  const t = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
  if (t && +t[1] < 24 && +t[2] < 60) return { kind: "time", minutes: +t[1] * 60 + +t[2] };
  return null;
}

/** Normalised comparison key for a scalar format (not set/choice/number/utc, which compare by value). */
export function normalizeAs(format: Exclude<FieldFormat, "set">, raw: string): string {
  switch (format) {
    case "ip": return refang(raw).replace(/^\[|\]$/g, "").replace(/:\d+$/, "").toLowerCase();
    case "domain": return stripSlashDot(refang(raw).toLowerCase().replace(/^https?:\/\//, ""));
    case "url": return stripSlashDot(refang(raw).toLowerCase());
    case "email": return refang(raw).toLowerCase().replace(/^<|>$/g, "");
    case "hash": return raw.trim().toLowerCase();
    case "host": return raw.trim().toLowerCase().replace(/\.$/, "");
    case "account": return raw.trim().toLowerCase().replace(/^.*\\/, "");
    case "choice": return raw.trim();
    default: return looseText(raw);
  }
}

/** Splits a typed list on commas, semicolons and new lines. */
export function splitList(raw: string): string[] {
  return raw.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
}

/** Recognises what a typed indicator is, for the notebook's type chip and for grading. */
export function detectIocType(raw: string): IocType | null {
  const v = refang(raw);
  if (/^[a-f0-9]{64}$/i.test(v)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(v)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(v)) return "md5";
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(v)) return "ip";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return "url";
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "email";
  if (/\.(exe|dll|html?|js|vbs|ps1|bat|cmd|lnk|iso|zip|docm|xlsm|hta|msi|scr|bin)$/i.test(v)) return "filename";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)) return "domain";
  if (/^[a-z0-9-]+$/i.test(v) && /\d/.test(v) && v.includes("-")) return "host";
  return null;
}

/** Comparison key of an indicator, by its type. */
export function iocKey(type: IocType, raw: string): string {
  switch (type) {
    case "ip": return normalizeAs("ip", raw);
    case "domain": return normalizeAs("domain", raw);
    case "url": return normalizeAs("url", raw);
    case "email": return normalizeAs("email", raw);
    case "sha256": case "sha1": case "md5": return normalizeAs("hash", raw);
    case "host": return normalizeAs("host", raw);
    case "account": return normalizeAs("account", raw);
    case "filename": return raw.trim().toLowerCase();
  }
}
