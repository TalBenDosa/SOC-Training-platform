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

/** Sent to a college's admin when their environment is provisioned. */
export function orgWelcomeEmail(args: { orgName: string; classLink: string; adminLink?: string | null }): {
  subject: string; html: string; text: string;
} {
  const { orgName, classLink, adminLink } = args;
  const adminBlock = adminLink
    ? `<p style="margin:0 0 8px;font-size:14px;line-height:1.6;">First, set up your own admin account:</p>
       <p style="margin:0 0 4px;">${button(adminLink, "Create your admin account")}</p>
       ${linkBox(adminLink)}<hr style="border:0;border-top:1px solid #e2e8f0;margin:22px 0;">`
    : "";
  const html = shell(
    `Your ${orgName} environment is ready`,
    `${adminBlock}
     <p style="margin:0 0 8px;font-size:14px;line-height:1.6;"><strong>Class invite link</strong> — share this with your students. Anyone who opens it creates an account inside your college's environment:</p>
     <p style="margin:0 0 4px;">${button(classLink, "Open the class invite link")}</p>
     ${linkBox(classLink)}
     <p style="margin:18px 0 0;font-size:13px;color:#475569;line-height:1.6;">Each student's data is isolated to your organisation. You can manage your class any time from the "Manage Class" area after signing in.</p>`,
  );
  const text = `Your ${orgName} environment is ready.\n\n${adminLink ? `Create your admin account: ${adminLink}\n\n` : ""}Class invite link to share with students:\n${classLink}\n\nAnyone who opens it creates an account inside your college's environment.`;
  return { subject: `Your ${orgName} environment on HACK THE SOC is ready`, html, text };
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
