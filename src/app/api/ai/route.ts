import { NextResponse } from "next/server";

/**
 * AI Co-Analyst endpoint.
 *
 * In production this proxies to the Claude API (Anthropic SDK) with prompt caching
 * on the long system prompt + alert context. The system prompt is intentionally
 * grounded so the model only reasons about the synthetic SOC data.
 *
 * For now we ship a stub that returns a structured response so the UI can iterate
 * end-to-end without needing API keys configured.
 */
export const runtime = "nodejs";

const SYSTEM_PROMPT = `You are HACK THE SOC's Co-Analyst.

Role: senior SOC analyst mentor. The trainee is a Tier-1 / Tier-2 analyst.
Ground rules:
- Only reason about the alerts, telemetry, and IOCs from the active scenario.
- Always map findings to MITRE ATT&CK (tactic + technique IDs).
- Recommend concrete next pivots (a query, an action, a tool to use).
- Be concise. Use bullets. No marketing fluff.
- Never claim to have taken an action. You are advisory only.`;

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const { message } = body as { message?: string };
  if (!message) return NextResponse.json({ error: "Missing 'message'" }, { status: 400 });

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return NextResponse.json({
      reply: stubReply(message),
      grounded: false,
      note: "ANTHROPIC_API_KEY not configured — returning stub. See src/app/api/ai/route.ts.",
    });
  }

  // Live Anthropic call — uncomment once @anthropic-ai/sdk is installed.
  /*
  const Anthropic = (await import("@anthropic-ai/sdk")).default;
  const client = new Anthropic({ apiKey });
  const resp = await client.messages.create({
    model: process.env.ANTHROPIC_MODEL ?? "claude-opus-4-7",
    max_tokens: 1024,
    system: [{ type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } }],
    messages: [{ role: "user", content: message }],
  });
  const text = resp.content.map(c => (c.type === "text" ? c.text : "")).join("");
  return NextResponse.json({ reply: text, grounded: true });
  */

  return NextResponse.json({ reply: stubReply(message), grounded: false });
}

function stubReply(q: string): string {
  return `I'd normally call Claude here. Quick note on your question: "${q.slice(0, 140)}".\n\n` +
    `Recommended pivots:\n` +
    `1. Confirm parent process and command line in raw EDR telemetry.\n` +
    `2. Search the SHA256 fleet-wide.\n` +
    `3. Map to MITRE; if T1059.001, hunt for sibling Office→script-interpreter spawns over 7d.\n` +
    `4. If verdict trends true-positive, isolate via EDR and rotate creds.`;
}
