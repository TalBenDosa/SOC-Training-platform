/**
 * No log may carry a well-known placeholder hash (scenario review 2026-10-01): the
 * phishing attachment marked "Malicious" was SHA-256("123") and another one the
 * empty-file hash — an analyst who looks either up finds a harmless text / empty
 * file, the log contradicting itself. Telemetry data only; lessons may quote these
 * hashes as teaching examples.
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const WORDS = ["", "123", "1234", "12345", "123456", "password", "test", "abc", "hello", "foo", "bar", "admin", "malware", "virus", "a", "1"];
const PLACEHOLDERS = new Set(WORDS.flatMap(w => ["sha256", "sha1", "md5"].map(alg => crypto.createHash(alg).update(w).digest("hex"))));

const ROOTS = ["src/lib/sim", "src/app/(app)/dashboard", "src/data/companyEvents"].map(r => path.join(process.cwd(), r));
function files(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) files(p, out);
    else if (/\.(ts|tsx|json)$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

describe("telemetry hashes", () => {
  it("no log uses the hash of an empty / trivial string", () => {
    const hits: string[] = [];
    for (const f of ROOTS.flatMap(r => files(r))) {
      const text = fs.readFileSync(f, "utf8");
      for (const m of text.matchAll(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi)) {
        if (PLACEHOLDERS.has(m[0].toLowerCase())) hits.push(`${path.relative(process.cwd(), f)}: ${m[0]}`);
      }
    }
    expect(hits).toEqual([]);
  });
});
