/**
 * The set of source files that carry scenario / telemetry content, shared by
 * every content gate so they all scan the same tree. Three scripts used to
 * carry their own copy of this list and walker, and a new content directory
 * would have had to be added to each.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Directories (relative to the repo root) that hold content to validate. */
export const CONTENT_DIRS = ["src/data", "src/lib/sim", "src/app/(app)/dashboard"];

/** Every .ts/.tsx file under `dir`, recursively. Missing dirs yield nothing. */
export function walkTsFiles(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkTsFiles(full, acc);
    else if (/\.tsx?$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

/** All content source files, absolute paths. */
export function contentFiles(root = REPO_ROOT) {
  return CONTENT_DIRS.flatMap(d => walkTsFiles(path.join(root, d)));
}
