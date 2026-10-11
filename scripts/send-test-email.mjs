// Send (or preview) a test invite email.
//   node scripts/send-test-email.mjs [to-address]
// Renders the real org-welcome template, writes a preview HTML next to it, and —
// if RESEND_API_KEY is set — actually sends via Resend. Without a key it only
// writes the preview and reports that sending was skipped (never pretends).
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Inline copy of the template (kept in sync with src/lib/email/templates.ts) so
// this stays a dependency-free .mjs. If you change the template, update both.
const BRAND = "#0891b2";
const shell = (title, body) => `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
  <div style="max-width:560px;margin:0 auto;padding:24px;">
    <div style="background:#0b1220;border-radius:12px 12px 0 0;padding:20px 28px;">
      <span style="font-family:'Courier New',monospace;font-weight:bold;letter-spacing:2px;color:#fff;font-size:16px;">HACK<span style="color:#22d3ee;"> THE </span>SOC</span>
    </div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-top:0;border-radius:0 0 12px 12px;padding:28px;">
      <h1 style="margin:0 0 14px;font-size:20px;">${title}</h1>${body}
      <p style="margin:28px 0 0;font-size:12px;color:#94a3b8;">SOC Analyst Training Platform</p>
    </div></div></body></html>`;
const button = (h, l) => `<a href="${h}" style="display:inline-block;background:${BRAND};color:#fff;text-decoration:none;font-weight:bold;font-size:14px;padding:12px 20px;border-radius:8px;">${l}</a>`;
const linkBox = h => `<div style="margin:10px 0;padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-family:'Courier New',monospace;font-size:12px;word-break:break-all;color:#334155;">${h}</div>`;
function orgWelcomeEmail({ orgName, classLink, adminLink }) {
  const adminBlock = adminLink
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">First, set up your own admin account:</p><p style="margin:0 0 4px;">${button(adminLink, "Create your admin account")}</p>${linkBox(adminLink)}<hr style="border:0;border-top:1px solid #e2e8f0;margin:22px 0;">`
    : "";
  const html = shell(`Your ${orgName} environment is ready`,
    `${adminBlock}<p style="margin:0 0 8px;font-size:14px;line-height:1.6;"><strong>Class invite link</strong> — share this with your students. Anyone who opens it creates an account inside your college's environment:</p><p style="margin:0 0 4px;">${button(classLink, "Open the class invite link")}</p>${linkBox(classLink)}<p style="margin:18px 0 0;font-size:13px;color:#475569;line-height:1.6;">Each student's data is isolated to your organisation. You can manage your class any time from the "Manage Class" area after signing in.</p>`);
  const text = `Your ${orgName} environment is ready.\n\n${adminLink ? `Create your admin account: ${adminLink}\n\n` : ""}Class invite link:\n${classLink}`;
  return { subject: `Your ${orgName} environment on HACK THE SOC is ready`, html, text };
}

const TO = process.argv[2] || "tal14997@gmail.com";
const SITE = "https://soc-training-platform-jade.vercel.app";
const mail = orgWelcomeEmail({
  orgName: "Sapir College (TEST)",
  classLink: `${SITE}/join?token=demo-class-link`,
  adminLink: `${SITE}/join?token=demo-admin-link`,
});

const preview = join(dirname(fileURLToPath(import.meta.url)), "..", "email-preview.html");
writeFileSync(preview, mail.html);
console.log(`Preview written: ${preview}`);
console.log(`Subject: ${mail.subject}`);

const KEY = process.env.RESEND_API_KEY;
const FROM = process.env.EMAIL_FROM || "HACK THE SOC <onboarding@resend.dev>";
if (!KEY) {
  console.log(`\nSKIP: RESEND_API_KEY is not set — no email was sent.`);
  console.log(`To actually send to ${TO}: set RESEND_API_KEY (and EMAIL_FROM) and re-run this script.`);
  process.exit(0);
}
const res = await fetch("https://api.resend.com/emails", {
  method: "POST",
  headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
  body: JSON.stringify({ from: FROM, to: [TO], subject: mail.subject, html: mail.html, text: mail.text }),
});
console.log(res.ok ? `\n✅ SENT to ${TO}` : `\n❌ FAILED ${res.status}: ${await res.text()}`);
process.exit(res.ok ? 0 : 1);
