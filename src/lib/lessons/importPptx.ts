/**
 * importPptx.ts — Client-side utility to extract slide text from a .pptx file
 * A .pptx file is a ZIP archive containing XML files — we unzip with jszip
 * and extract all <a:t>...</a:t> text nodes from each slide's XML.
 */

export interface ExtractedSlide {
  title: string;
  text:  string;
}

export interface PptxImportResult {
  slides:      ExtractedSlide[];
  pptxBase64:  string;   // full file stored so viewer can render the real design
}

/**
 * Extract all visible text AND store the raw base64 of the .pptx file.
 */
export async function extractSlidesFromPptx(
  buffer: ArrayBuffer,
): Promise<PptxImportResult> {
  // Dynamic import so jszip isn't bundled on every page
  const JSZip = (await import("jszip")).default;

  let zip: InstanceType<typeof JSZip>;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    throw new Error("File is not a valid .pptx (ZIP parse failed)");
  }

  // Find all ppt/slides/slideN.xml files
  const slideEntries = Object.keys(zip.files)
    .filter(name => /^ppt\/slides\/slide\d+\.xml$/i.test(name))
    .sort((a, b) => {
      const na = parseInt(a.match(/\d+/)?.[0] ?? "0", 10);
      const nb = parseInt(b.match(/\d+/)?.[0] ?? "0", 10);
      return na - nb;
    });

  if (slideEntries.length === 0) {
    throw new Error("No slides found in presentation");
  }

  const MAX_SLIDES = 30;
  const slides: ExtractedSlide[] = [];

  for (const fileName of slideEntries.slice(0, MAX_SLIDES)) {
    const xml    = await zip.files[fileName].async("string");
    const texts  = extractTextNodes(xml);

    if (texts.length === 0) continue;   // skip blank slides

    const title  = texts[0];
    const body   = texts.slice(1).join("\n").trim();

    slides.push({ title, text: body });
  }

  if (slides.length === 0) {
    throw new Error("Presentation appears to be empty (no text found)");
  }

  // Encode the original file to base64 so the viewer can render real design
  const uint8 = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < uint8.length; i++) binary += String.fromCharCode(uint8[i]);
  const pptxBase64 = btoa(binary);

  return { slides, pptxBase64 };
}

/**
 * Extract all text content from <a:t> nodes in a slide's XML.
 * PowerPoint stores all visible text in DrawingML <a:t> leaf elements.
 * Returns an array of non-empty strings in document order.
 */
function extractTextNodes(xml: string): string[] {
  // Match <a:t>...</a:t> — text may contain entities like &amp; &lt; etc.
  const tagRe = /<a:t(?:\s[^>]*)?>([\s\S]*?)<\/a:t>/g;
  const results: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = tagRe.exec(xml)) !== null) {
    const raw = match[1]
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .trim();
    if (raw) results.push(raw);
  }

  // Merge consecutive fragments that belong to the same run
  // (PowerPoint sometimes splits a single word across multiple <a:t> nodes)
  const merged: string[] = [];
  let prev = "";
  for (const t of results) {
    if (prev && !prev.endsWith(" ") && !t.startsWith(" ") && prev.length < 80) {
      prev += t;
    } else {
      if (prev) merged.push(prev);
      prev = t;
    }
  }
  if (prev) merged.push(prev);

  return merged;
}
