/**
 * Transactional email templates (inline-styled HTML — email clients strip
 * <style>, so everything is on the element). Kept provider-agnostic: they return
 * { subject, html, text } for sendEmail().
 */

import { PLATFORM_NAME } from "@/lib/brand/brand";

const BRAND = "#0891b2"; // cyber-600, readable on white
const HEADER_BG = "#0b1220"; // bg-elevated

/**
 * Who the email comes from (white label, src/lib/brand): the platform, or a white-label
 * organization's own name and logo. Every template takes an optional `brand`; without one
 * the email is the platform's.
 */
export interface EmailBrand {
  productName: string;
  whiteLabel: boolean;
  /** Absolute https URL of the organization's logo for the header (white label only). */
  logoUrl: string | null;
  /** Accent colour for buttons, #rrggbb (null = the platform's). */
  color?: string | null;
  /** Header band colour, #rrggbb (the tenant theme's surface; null = the platform's). */
  background?: string | null;
}

export const PLATFORM_EMAIL_BRAND: EmailBrand = { productName: PLATFORM_NAME, whiteLabel: false, logoUrl: null };

/**
 * Escape text for an HTML email body. EVERY interpolated value goes through it
 * (SEC-14): display names, org names and room titles are user- or admin-written,
 * and a name like `<a href="https://x">Verify</a>` rendered as a link in our mail.
 * The shared helpers below escape their own arguments.
 */
function esc(s: string): string {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function header(brand: EmailBrand): string {
  if (!brand.whiteLabel) {
    return `<span style="font-family:'Courier New',monospace;font-weight:bold;letter-spacing:2px;color:#fff;font-size:16px;">HACK<span style="color:#22d3ee;"> THE </span>SOC</span>`;
  }
  const logo = brand.logoUrl && /^https:\/\/\S+$/.test(brand.logoUrl)
    ? `<img src="${esc(brand.logoUrl)}" alt="" height="32" style="height:32px;max-width:180px;vertical-align:middle;margin-right:10px;">`
    : "";
  return `${logo}<span style="font-weight:bold;color:#fff;font-size:17px;vertical-align:middle;">${esc(brand.productName)}</span>`;
}

function shell(title: string, bodyHtml: string, brand: EmailBrand = PLATFORM_EMAIL_BRAND): string {
  return `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
  <div style="max-width:560px;margin:0 auto;padding:24px;">
    <div style="background:${brand.background && /^#[0-9a-fA-F]{6}$/.test(brand.background) ? brand.background : HEADER_BG};border-radius:12px 12px 0 0;padding:20px 28px;">
      ${header(brand)}
    </div>
    <div style="background:#ffffff;border:1px solid #e2e8f0;border-top:0;border-radius:0 0 12px 12px;padding:28px;">
      <h1 style="margin:0 0 14px;font-size:20px;color:#0f172a;">${esc(title)}</h1>
      ${bodyHtml}
      <p style="margin:28px 0 0;font-size:12px;color:#94a3b8;">SOC Analyst Training Platform</p>
    </div>
  </div></body></html>`;
}

function button(href: string, label: string, color: string | null = null): string {
  const bg = color && /^#[0-9a-fA-F]{6}$/.test(color) ? color : BRAND;
  return `<a href="${esc(href)}" style="display:inline-block;background:${bg};color:#ffffff;text-decoration:none;font-weight:bold;font-size:14px;padding:12px 20px;border-radius:8px;">${esc(label)}</a>`;
}

function linkBox(href: string): string {
  return `<div style="margin:10px 0;padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-family:'Courier New',monospace;font-size:12px;word-break:break-all;color:#334155;">${esc(href)}</div>`;
}

/** A prominent monospace code chip — for the class affiliation code. */
function codeChip(code: string): string {
  return `<div style="margin:10px 0;padding:14px 18px;background:#f0f9ff;border:1px solid ${BRAND};border-radius:10px;text-align:center;font-family:'Courier New',monospace;font-size:24px;font-weight:bold;letter-spacing:6px;color:#0369a1;">${esc(code)}</div>`;
}

/** Sent to a college's admin when their environment is provisioned. */
export function orgWelcomeEmail(args: { orgName: string; adminLink?: string | null; classCode?: string | null; brand?: EmailBrand }): {
  subject: string; html: string; text: string;
} {
  const { orgName, adminLink, classCode } = args;
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;
  const adminBlock = adminLink
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">First, set up your own admin account:</p>
       <p style="margin:0 0 4px;">${button(adminLink, "Create your admin account", brand.color)}</p>
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
    brand,
  );
  const text = `Your ${orgName} environment is ready.

${adminLink ? `Create your admin account: ${adminLink}

` : ""}${classCode
    ? `Your first class code (share with students, valid 24 hours): ${classCode}
Generate a fresh one anytime from "Manage Class".

`
    : `How students join: from "Manage Class", generate your class's affiliation code (valid 24 hours) and share it.

`}Students register with their email + the code — there is no other way in.`;
  return { subject: brand.whiteLabel ? `Your ${orgName} environment is ready` : `Your ${orgName} environment on ${PLATFORM_NAME} is ready`, html, text };
}

/**
 * Sent when a user requests a password reset. The link carries a stateless
 * Supabase recovery token_hash and points straight at /update-password on the
 * origin the request came from — so it does NOT depend on the Supabase project's
 * Site URL / redirect allowlist, and (unlike PKCE) works when opened on a
 * different device than the one that asked. Sent via our own Resend sender.
 */
export function passwordResetEmail(args: { resetLink: string; brand?: EmailBrand }): {
  subject: string; html: string; text: string;
} {
  const { resetLink } = args;
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;
  const name = brand.productName;
  const html = shell(
    "Reset your password",
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">We received a request to reset the password for your ${esc(name)} account. Click below to choose a new one:</p>
     <p style="margin:0 0 4px;">${button(resetLink, "Set a new password", brand.color)}</p>
     ${linkBox(resetLink)}
     <p style="margin:18px 0 0;font-size:12px;color:#64748b;line-height:1.5;">This link is valid for a limited time and can be used once. If you didn't request this, you can safely ignore this email — your password won't change.</p>`,
    brand,
  );
  const text = `Reset your ${name} password.

Set a new password: ${resetLink}

This link is valid for a limited time and can be used once. If you didn't request this, ignore this email — your password won't change.`;
  return { subject: `Reset your ${name} password`, html, text };
}

/**
 * Sent by the platform admin to a college admin/instructor who has an account
 * but hasn't been signing in. Same stateless recovery link as the password
 * reset (token_hash → /update-password, works on any device): they set a
 * password and land in their dashboard.
 */
export function accountAccessEmail(args: { orgName: string; link: string; brand?: EmailBrand }): {
  subject: string; html: string; text: string;
} {
  const { orgName, link } = args;
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;
  const title = brand.whiteLabel ? `Sign in to ${orgName}` : `Sign in to ${orgName} on ${PLATFORM_NAME}`;
  const html = shell(
    title,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">Your admin account for <strong>${esc(orgName)}</strong> is ready and waiting. Click below to set your password and sign in — from there you can manage your class and generate today&#39;s class code for students.</p>
     <p style="margin:0 0 4px;">${button(link, "Set a password and sign in", brand.color)}</p>
     ${linkBox(link)}
     <p style="margin:18px 0 0;font-size:12px;color:#64748b;line-height:1.5;">This link is valid for a limited time and can be used once. If it has expired, ask for a new one or use "Forgot password" on the sign-in page.</p>`,
    brand,
  );
  const text = `${title}.

Set a password and sign in: ${link}

This link is valid for a limited time and can be used once. If it has expired, use "Forgot password" on the sign-in page.`;
  return { subject: title, html, text };
}

/** Sent to an individual invitee (roster / CSV enrollment). */
export function studentInviteEmail(args: { orgName: string; joinLink: string; brand?: EmailBrand }): {
  subject: string; html: string; text: string;
} {
  const { orgName, joinLink } = args;
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;
  const lead = brand.whiteLabel
    ? `Your course uses ${esc(brand.productName)} to train you as a SOC analyst.`
    : `Your course is using ${PLATFORM_NAME} to train as a SOC analyst.`;
  const html = shell(
    `You've been invited to ${orgName}`,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">${lead} Click below to create your account and get started:</p>
     <p style="margin:0 0 4px;">${button(joinLink, "Accept invitation", brand.color)}</p>
     ${linkBox(joinLink)}`,
    brand,
  );
  const where = brand.whiteLabel ? "" : ` on ${PLATFORM_NAME}`;
  const text = `You've been invited to ${orgName}${where}.\n\nAccept your invitation and create your account:\n${joinLink}`;
  return { subject: `You're invited to ${orgName}${where}`, html, text };
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
  brand?: EmailBrand;
}): { subject: string; html: string; text: string } {
  const { name, daysAway, resumeLink, nextRoomTitle, nextRoomMinutes } = args;
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;

  const nextBlock = nextRoomTitle
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">Your next room is <strong>${esc(nextRoomTitle)}</strong>${
        nextRoomMinutes ? ` — about ${nextRoomMinutes} minutes` : ""
      }.</p>`
    : `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">Pick up wherever you left off — your progress is exactly where you left it.</p>`;

  const html = shell(
    `Still with us, ${name}?`,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">It's been about ${daysAway} days. Detection skills fade fast when they're not used — a short session now is worth more than a long one later.</p>
     ${nextBlock}
     <p style="margin:0 0 4px;">${button(resumeLink, "Pick up where you left off", brand.color)}</p>
     ${linkBox(resumeLink)}
     <p style="margin:18px 0 0;font-size:12px;color:#94a3b8;line-height:1.6;">Not training right now? No problem — you can ignore this, and your progress stays saved.</p>`,
    brand,
  );

  const text = `Still with us, ${name}?\n\nIt's been about ${daysAway} days. Detection skills fade fast when they're not used.\n\n${
    nextRoomTitle ? `Your next room: ${nextRoomTitle}${nextRoomMinutes ? ` (~${nextRoomMinutes} min)` : ""}\n\n` : ""
  }Pick up where you left off:\n${resumeLink}\n\nNot training right now? You can ignore this — your progress stays saved.`;

  return { subject: `Your SOC training is waiting — ${daysAway} days idle`, html, text };
}

/** One line of plain text: control characters out, whitespace collapsed, clipped. */
function oneLine(s: string | null | undefined, max: number): string {
  // eslint-disable-next-line no-control-regex
  const t = (s ?? "").replace(/[\u0000-\u001F\u007F]+/g, " ").replace(/\s{2,}/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export type PlanEmailKind = "plan_assigned" | "plan_updated" | "personal_plan";

/**
 * Sent (only when the manager ticks "Also email recipients") alongside the
 * in-app notification for a learning plan. Deliberately minimal:
 *  - the SUBJECT is fixed text (plus the org's name, which the platform admin
 *    set at provisioning) — never org-admin free text;
 *  - the plan title appears only in the escaped body, clipped to 80 chars;
 *  - no item titles or notes — the plan card in the app is the source of truth.
 */
export function planNotificationEmail(args: { kind: PlanEmailKind; planTitle: string; orgName?: string | null; link: string; brand?: EmailBrand }): {
  subject: string; html: string; text: string;
} {
  const brand = args.brand ?? PLATFORM_EMAIL_BRAND;
  const org = oneLine(args.orgName, 60);
  const plan = oneLine(args.planTitle, 80);
  const subject = args.kind === "plan_assigned"
    ? (org ? `New learning plan from ${org}` : "You have a new learning plan")
    : args.kind === "plan_updated"
      ? "Your learning plan was updated"
      : "Your personal priorities were updated";
  const lead = args.kind === "plan_assigned"
    ? "You've been assigned a new learning plan"
    : args.kind === "plan_updated"
      ? "New items were added to your learning plan"
      : "Your training administrator updated your personal priorities";
  const named = args.kind !== "personal_plan" && plan;
  const html = shell(
    subject,
    `<p style="margin:0 0 12px;font-size:14px;line-height:1.6;">${esc(lead)}${named ? `: <strong>${esc(plan)}</strong>` : ""}.</p>
     <p style="margin:0 0 4px;">${button(args.link, "Open my learning plan", brand.color)}</p>
     <p style="margin:18px 0 0;font-size:12px;color:#64748b;line-height:1.5;">You're receiving this because your training administrator${org ? ` at ${esc(org)}` : ""} assigned you work on ${esc(brand.productName)}. You'll also find it under the bell in the app.</p>`,
    brand,
  );
  const text = `${lead}${named ? `: ${plan}` : ""}.\n\nOpen your learning plan: ${args.link}\n\nYou're receiving this because your training administrator${org ? ` at ${org}` : ""} assigned you work on ${brand.productName}.`;
  return { subject, html, text };
}
