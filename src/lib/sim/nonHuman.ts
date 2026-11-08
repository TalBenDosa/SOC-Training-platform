/**
 * ONE rule for "this account is not a person" (Sdema review K7, 2026-11-08). The story
 * re-homing (attackStories.ts instantiateStory: who a story happens to) and the named-organization
 * swap (team/tenant.ts applyTenant: who the people are) used two different lists, so `it.admin` was
 * a service account to one and a victim to the other. A non-human account never becomes a victim,
 * never stands in for one, and keeps its (generic) name when its domain changes.
 *
 * Non-human: service and pipeline principals (svc-*, ci-*, *.svc, sql, dc, backup, sync, deploy,
 * monitor, scanner, krbtgt), role and shared mailboxes (admin@, it.admin, helpdesk, servicedesk,
 * security@, soc.t2, dba, finance-team, accounts-payable, notifications), decoys (canary,
 * honeytoken), devices and rooms (printer, kiosk, badge, boardroom). A person's own tiered admin
 * account (admin.vandenberg) is still that person.
 */
const NON_HUMAN_RE = new RegExp([
  String.raw`^(?:svc|ci|sa)[-._]`,
  String.raw`[-._]svc(?:@|$)`,
  String.raw`^(?:admin|administrator|root|noreply|no-reply|notifications?|system|helpdesk|servicedesk|devops|dba|backup|scanner|printer|kiosk|finance|accounts|security|secops|soc)(?:@|$)`,
  String.raw`^(?:soc|security|secops|system)[-._]`,
  String.raw`^it[-._](?:admin|ops|helpdesk|support|deploy)(?:[-._@]|$)`,
  String.raw`(?:^|[-._])admin(?:@|$)`,
  String.raw`(?:^|[-._])(?:service|svc|device|badge|printer|scanner|kiosk|backup|bkp|sync|bot|replication|repl|deploy|monitor|monitoring|daemon|automation|scan|sql|mssql|dc|krbtgt|healthcheck|canary|honeytoken|dba|helpdesk|servicedesk|desk\d*|shift|team|payable|operations|notifications|boardroom\d*|mtr)(?:[-._@\d]|$)`,
].join("|"), "i");

/** True when an account (mail address, UPN or bare local part) is not a person. */
export function isNonHumanAccount(account: string | undefined | null): boolean {
  if (!account) return false;
  const a = account.trim();
  return NON_HUMAN_RE.test(a) || NON_HUMAN_RE.test(a.split("@")[0]);
}

/**
 * A person a story can be re-homed onto: a mail-style identity (local@domain) that is not a service,
 * role or decoy account. A user_email without "@" (an anonymous chat session id such as
 * assist-enduser-7731, a device id, a bare service name) is never re-homed.
 */
export function isRehomeablePerson(account: string | undefined | null): account is string {
  return !!account && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(account) && !isNonHumanAccount(account);
}
