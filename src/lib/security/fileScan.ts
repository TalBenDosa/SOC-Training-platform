/**
 * fileScan.ts — server-side CONTENT inspection for uploaded org media.
 *
 * The upload route already sniffs magic bytes and allowlists PDF/PPTX/MP4/WebM
 * (see api/org/media/route.ts). Magic bytes prove the FORMAT but say nothing
 * about a malicious PAYLOAD inside a format-valid file — a macro-laden PPTX or a
 * PDF that runs JavaScript on open is the realistic "upload a clean-looking file,
 * infect whoever downloads it" path. This adds a self-contained content gate (no
 * external AV service required) that rejects the highest-signal active-content
 * markers before a file can be published to students.
 *
 * This is a heuristic hardening layer, NOT a full anti-virus: a determined
 * payload hidden inside a compressed PDF object stream, or a novel macro-free
 * exploit, can still pass. Pair with a real AV/VirusTotal scan for defence in
 * depth. Only trusted org-staff can upload (requireOrgAdmin), so this raises the
 * bar against a compromised-staff-account or mistaken upload.
 */

export interface ScanResult {
  ok: boolean;
  /** English reason, safe to surface to the uploader when ok === false. */
  reason?: string;
}

// Zip-bomb / malformed-OPC guards for the PPTX (zip) path.
const MAX_ZIP_ENTRIES = 5000;
const MAX_ZIP_UNCOMPRESSED = 300 * 1024 * 1024; // 300MB expanded ceiling

/**
 * Inspect a PPTX (OPC zip): reject VBA macros, confirm it is a real
 * presentation package (not an arbitrary zip that merely starts with PK), and
 * guard against a decompression bomb.
 */
export async function inspectPptx(bytes: Uint8Array): Promise<ScanResult> {
  const JSZip = (await import("jszip")).default;
  let zip: InstanceType<typeof JSZip>;
  try {
    zip = await JSZip.loadAsync(bytes);
  } catch {
    return { ok: false, reason: "File is not a valid Office document (could not read the package)." };
  }

  const names = Object.keys(zip.files);
  if (names.length > MAX_ZIP_ENTRIES) {
    return { ok: false, reason: "File rejected: archive has too many entries (possible zip bomb)." };
  }

  let totalUncompressed = 0;
  for (const name of names) {
    const f = zip.files[name] as unknown as { _data?: { uncompressedSize?: number } };
    totalUncompressed += f?._data?.uncompressedSize ?? 0;
    if (totalUncompressed > MAX_ZIP_UNCOMPRESSED) {
      return { ok: false, reason: "File rejected: uncompressed size is implausibly large (possible zip bomb)." };
    }
  }

  // Macro-enabled Office content ships a vbaProject.bin part. A .pptx (as opposed
  // to a macro-enabled .pptm) must never contain one — its presence is the single
  // strongest "this Office file can run code on open" signal.
  if (names.some((n) => /(^|\/)vba(project)?\.bin$/i.test(n) || /\.pptm$/i.test(n))) {
    return { ok: false, reason: "File rejected: it contains VBA macros. Upload a macro-free .pptx." };
  }

  // Confirm real OPC presentation structure — not an arbitrary zip renamed .pptx.
  const hasContentTypes = names.some((n) => n === "[Content_Types].xml");
  const hasPresentation = names.some((n) => /^ppt\/presentation\.xml$/i.test(n));
  if (!hasContentTypes || !hasPresentation) {
    return { ok: false, reason: "File rejected: not a valid PowerPoint presentation package." };
  }

  return { ok: true };
}

// Active-content markers that make a PDF execute or launch something on open.
// /OpenAction and /AA alone are common in benign PDFs (go-to-page), so they are
// deliberately NOT on the reject list; these four are high-signal for a
// weaponised document.
const PDF_ACTIVE_MARKERS = ["/JavaScript", "/JS", "/Launch", "/EmbeddedFile"];

/**
 * Inspect a PDF for embedded scripts / launch actions / embedded files. Scans
 * the raw bytes as latin1 (PDF keywords are ASCII); this catches markers present
 * in the uncompressed document catalog — the common case — but cannot see inside
 * a FlateDecode-compressed object stream (a known limitation; use a real AV for
 * that).
 */
export function inspectPdf(bytes: Uint8Array): ScanResult {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  }
  const hit = PDF_ACTIVE_MARKERS.find((m) => s.includes(m));
  if (hit) {
    return { ok: false, reason: `File rejected: the PDF contains active content (${hit}) that can run on open.` };
  }
  return { ok: true };
}

/** Dispatch content inspection by detected kind. Video is not macro/script-bearing. */
export async function inspectDocContent(
  kind: "pdf" | "pptx" | "video",
  bytes: Uint8Array,
): Promise<ScanResult> {
  if (kind === "pdf") return inspectPdf(bytes);
  if (kind === "pptx") return inspectPptx(bytes);
  return { ok: true };
}
