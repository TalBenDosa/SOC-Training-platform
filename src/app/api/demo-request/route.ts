import "server-only";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { asObject } from "@/lib/http/body";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { sendEmail } from "@/lib/email/sendEmail";
import { demoRecipients, demoRequestEmail, validateDemoRequest } from "@/lib/demo/demoRequest";

/**
 * POST /api/demo-request: a visitor of the public /demo page asks for a demo.
 *
 * Public by design (listed in the middleware's PUBLIC_API_PREFIXES): nobody is signed in yet. What protects it:
 *  - the middleware refuses a cross-site write (CSRF) before this runs, and rate-limits every API call;
 *  - its own budgets: 5 requests an hour per address, 3 a day per email, 60 a day for the whole platform,
 *    so it can neither flood the owner's inbox nor burn the email provider's quota;
 *  - a honeypot field answered as success without sending, so a bot learns nothing;
 *  - every field validated and length-capped, single-line fields stripped of line breaks, the email escaped
 *    (src/lib/demo/demoRequest.ts).
 * Nothing is stored. The request becomes one email to DEMO_REQUEST_TO (server env, never in the code) with the
 * requester as Reply-To. The requester's address is never logged.
 */

export const runtime = "nodejs";

const IP_LIMIT = { max: 5, windowMs: 60 * 60_000 };
const EMAIL_LIMIT = { max: 3, windowMs: 24 * 60 * 60_000 };
const DAILY_BUDGET = { max: 60, windowMs: 24 * 60 * 60_000 };

// Same trusted-source rule as src/middleware.ts: x-real-ip is set by the platform; the right-most
// x-forwarded-for hop only when it is absent.
function clientIp(req: NextRequest): string {
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  const xff = req.headers.get("x-forwarded-for");
  if (xff) { const hops = xff.split(","); return hops[hops.length - 1].trim(); }
  return "unknown";
}

const busy = () => NextResponse.json({ ok: false, error: "Too many requests. Please try again later." }, { status: 429 });

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = asObject(await req.json());
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request." }, { status: 400 });
  }
  const v = validateDemoRequest(body);
  if (!v.ok) return NextResponse.json({ ok: false, error: v.error, field: v.field }, { status: 400 });

  if (!(await checkRateLimit(`demo-ip:${clientIp(req)}`, IP_LIMIT.max, IP_LIMIT.windowMs)).ok) return busy();
  // A bot that filled the hidden field is told it worked, and nothing is sent.
  if (v.bot) return NextResponse.json({ ok: true });
  if (!(await checkRateLimit(`demo-email:${v.value.email}`, EMAIL_LIMIT.max, EMAIL_LIMIT.windowMs)).ok) return busy();
  if (!(await checkRateLimit("demo-daily", DAILY_BUDGET.max, DAILY_BUDGET.windowMs)).ok) return busy();

  const to = demoRecipients(process.env.DEMO_REQUEST_TO);
  if (!to.length) {
    console.error("[demo-request] DEMO_REQUEST_TO is not set: a demo request could not be delivered");
    return NextResponse.json({ ok: false, error: "Demo requests are not open right now. Please try again later." }, { status: 503 });
  }
  const mail = demoRequestEmail(v.value, new Date());
  const sent = await sendEmail({ to, subject: mail.subject, html: mail.html, text: mail.text, replyTo: v.value.email });
  if (!sent.ok) {
    return NextResponse.json({ ok: false, error: "We couldn't send your request just now. Please try again in a few minutes." }, { status: 502 });
  }
  return NextResponse.json({ ok: true });
}
