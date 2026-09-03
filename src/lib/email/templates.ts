/**
 * Transactional email templates (inline-styled HTML — email clients strip
 * <style>, so everything is on the element). Kept provider-agnostic: they return
 * { subject, html, text } for sendEmail().
 */

const BRAND = "#0891b2"; // cyber-600, readable on white

function shell(title: string, bodyHtml: string): string {
  return `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
  <div style="max-width:560px;margin:0 auto;padding:24px;">
    <div style="background:#0b1220;border-radius:12px 12px 0 0;padding:20px 28px;">
      <span style="font-family:'Courier New',monospace;font-weight:bold;letter-spacing:2px;color:#fff;font-size:16px;">HACK<span style="color:#22d3ee;"> THE </span>SOC</span>
    </div>
    <div style="background:#ffffff;border:1px solid #e2e8f0;border-top:0;border-radius:0 0 12px 12px;padding:28px;">
      <h1 style="margin:0 0 14px;font-size:20px;color:#0f172a;">${title}</h1>
      ${bodyHtml}
      <p style="margin:28px 0 0;font-size:12px;color:#94a3b8;">SOC Analyst Training Platform</p>
    </div>
  </div></body></html>`;
}

function button(href: string, label: string): string {
  return `<a href="${href}" style="display:inline-block;background:${BRAND};color:#ffffff;text-decoration:none;font-weight:bold;font-size:14px;padding:12px 20px;border-radius:8px;">${label}</a>`;
}

function linkBox(href: string): string {
  return `<div style="margin:10px 0;padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-family:'Courier New',monospace;font-size:12px;word-break:break-all;color:#334155;">${href}</div>`;
}

/** A prominent monospace code chip — for the class affiliation code. */
function codeChip(code: string): string {
  return `<div style="margin:10px 0;padding:14px 18px;background:#f0f9ff;border:1px solid ${BRAND};border-radius:10px;text-align:center;font-family:'Courier New',monospace;font-size:24px;font-weight:bold;letter-spacing:6px;color:#0369a1;">${code}</div>`;
}

/** Sent to a college's admin when their environment is provisioned. */
export function orgWelcomeEmail(args: { orgName: string; adminLink?: string | null; classCode?: string | null }): {
  subject: string; html: string; text: string;
} {
  const { orgName, adminLink, classCode } = args;
  const adminBlock = adminLink
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">First, set up your own admin account:</p>
       <p style="margin:0 0 4px;">${button(adminLink, "Create your admin account")}</p>
       ${linkBox(adminLink)}<hr style="border:0;border-top:1px solid #e2e8f0;margin:22px 0;">`
    : "";
  // A starter class code, when one is minted with the invite. It is valid 24h —
  // stated plainly, because the invite link itself lasts 14 days, so an admin
  // who registers later must generate a fresh one from Manage Class.
  const codeBlock = classCode
    ? `<p style="margin:18px 0 6px;font-size:14px;line-height:1.6;"><strong>Your first class code</strong> — share it with your students so they can register today:</p>
       ${codeChip(classCode)}
       <p style="margin:6px 0 0;font-size:12px;color:#64748b;line-height:1.5;">This code is valid for <strong>24 hours</strong>. Generate a fresh one anytime from your "Manage Class" area — a new code always replaces the old one.</p>`
    : `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;"><strong>How students join:</strong> from your "Manage Class" area, generate your class's <strong>affiliation code</strong> (valid 24 hours — generate a fresh one each day) and share it with your students.</p>`;
  const html = shell(
    `Your ${orgName} environment is ready`,
    `${adminBlock}
     ${codeBlock}
     <p style="margin:18px 0 0;font-size:13px;color:#475569;line-height:1.6;">Students register with their email + the code — there is no other way in, so nobody outside your class can enrol. Each student's data is isolated to your organisation, and their enrolment is valid for 100 days before they re-enter a current code.</p>`,
  );
  const text = `Your ${orgName} environment is ready.

${adminLink ? `Create your admin account: ${adminLink}

` : ""}${classCode
    ? `Your first class code (share with students, valid 24 hours): ${classCode}
Generate a fresh one anytime from "Manage Class".

`
    : `How students join: from "Manage Class", generate your class's affiliation code (valid 24 hours) and share it.

`}Students register with their email + the code — there is no other way in.`;
  return { subject: `Your ${orgName} environment on HACK THE SOC is ready`, html, text };
}

/**
 * Sent when a user requests a password reset. The link carries a stateless
 * Supabase recovery token_hash and points straight at /update-password on the
 * origin the request came from — so it does NOT depend on the Supabase project's
 * Site URL / redirect allowlist, and (unlike PKCE) works when opened on a
 * different device than the one that asked. Sent via our own Resend sender.
 */
export function passwordResetEmail(args: { resetLink: string }): {
  subject: string; html: string; text: string;
} {
  const { resetLink } = args;
  const html = shell(
    "Reset your password",
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">We received a request to reset the password for your HACK THE SOC account. Click below to choose a new one:</p>
     <p style="margin:0 0 4px;">${button(resetLink, "Set a new password")}</p>
     ${linkBox(resetLink)}
     <p style="margin:18px 0 0;font-size:12px;color:#64748b;line-height:1.5;">This link is valid for a limited time and can be used once. If you didn't request this, you can safely ignore this email — your password won't change.</p>`,
  );
  const text = `Reset your HACK THE SOC password.

Set a new password: ${resetLink}

This link is valid for a limited time and can be used once. If you didn't request this, ignore this email — your password won't change.`;
  return { subject: "Reset your HACK THE SOC password", html, text };
}

/** Sent to an individual invitee (roster / CSV enrollment). */
export function studentInviteEmail(args: { orgName: string; joinLink: string }): {
  subject: string; html: string; text: string;
} {
  const { orgName, joinLink } = args;
  const html = shell(
    `You've been invited to ${orgName}`,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">Your course is using HACK THE SOC to train as a SOC analyst. Click below to create your account and get started:</p>
     <p style="margin:0 0 4px;">${button(joinLink, "Accept invitation")}</p>
     ${linkBox(joinLink)}`,
  );
  const text = `You've been invited to ${orgName} on HACK THE SOC.\n\nAccept your invitation and create your account:\n${joinLink}`;
  return { subject: `You're invited to ${orgName} on HACK THE SOC`, html, text };
}

/**
 * Sent to a learner who started but has been idle for a while.
 *
 * Written to be short and non-guilting: skills decay, here's the one thing to
 * pick up. It names the specific next room rather than saying "come back",
 * because a concrete next action is the thing that actually converts — and it
 * says how long it takes, so the ask feels small.
 */
export function lapsedNudgeEmail(args: {
  name: string;
  daysAway: number;
  resumeLink: string;
  nextRoomTitle?: string | null;
  nextRoomMinutes?: number | null;
}): { subject: string; html: string; text: string } {
  const { name, daysAway, resumeLink, nextRoomTitle, nextRoomMinutes } = args;

  const nextBlock = nextRoomTitle
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">Your next room is <strong>${nextRoomTitle}</strong>${
        nextRoomMinutes ? ` — about ${nextRoomMinutes} minutes` : ""
      }.</p>`
    : `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">Pick up wherever you left off — your progress is exactly where you left it.</p>`;

  const html = shell(
    `Still with us, ${name}?`,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">It's been about ${daysAway} days. Detection skills fade fast when they're not used — a short session now is worth more than a long one later.</p>
     ${nextBlock}
     <p style="margin:0 0 4px;">${button(resumeLink, "Pick up where you left off")}</p>
     ${linkBox(resumeLink)}
     <p style="margin:18px 0 0;font-size:12px;color:#94a3b8;line-height:1.6;">Not training right now? No problem — you can ignore this, and your progress stays saved.</p>`,
  );

  const text = `Still with us, ${name}?\n\nIt's been about ${daysAway} days. Detection skills fade fast when they're not used.\n\n${
    nextRoomTitle ? `Your next room: ${nextRoomTitle}${nextRoomMinutes ? ` (~${nextRoomMinutes} min)` : ""}\n\n` : ""
  }Pick up where you left off:\n${resumeLink}\n\nNot training right now? You can ignore this — your progress stays saved.`;

  return { subject: `Your SOC training is waiting — ${daysAway} days idle`, html, text };
}
