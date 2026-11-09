import type { BriefingLab, RoomExperience } from "./types";

// "Operation Single Sign-Off" for the "okta-identity-fundamentals" room.
// Script: docs/campaign/91-okta-identity-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Quayside Capital (fictional), not the graded tasks' GlobalLogis records.
// Signature mechanic: a portal on the entra skin laid out as an identity provider's admin
// console, with a System Log in real eventType values, worked out from one sign-in to a
// token and a second account, and a spotdiff of two sign-on policies.
// Game mix: defuse + portal + spotdiff.
// Lab data differs from the graded tasks: a spray (many accounts, one try each), never a burst
// on one account. The second factor is SMS, never an approved or denied push. The persistence
// is an API token and a weakened policy rule, never a group self-add. Hosting network is
// Northpier Hosting Ltd on 203.0.113.58, never Tarnava Hosting or 198.51.100.44. The rate-limit lab
// counts locked accounts, not a confirmed password. Nobody is named n.abara, c.lee or j.ortiz.

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const DOMAIN = "quaysidecapital.example";
const addr = (user: string) => `${user}@${DOMAIN}`;

const VANCE: [string, string][] = [
  ["actor.id", "00u3hx7QzV1mKp0Y5d7"],
  ["actor.type", "User"],
  ["actor.alternateId", addr("e.vance")],
  ["actor.displayName", "Ellis Vance"],
];
const KERR: [string, string][] = [
  ["actor.id", "00u9tb2LwR6nDs4C8e1"],
  ["actor.type", "User"],
  ["actor.alternateId", addr("t.kerr")],
  ["actor.displayName", "Tobias Kerr"],
];
const OFFICE: [string, string][] = [
  ["client.ipAddress", "198.51.100.20"],
  ["client.userAgent.browser", "EDGE"],
  ["client.userAgent.os", "Windows 11"],
  ["client.geographicalContext.city", "Bristol"],
  ["client.geographicalContext.country", "United Kingdom"],
  ["securityContext.asNumber", "64505"],
  ["securityContext.asOrg", "Harbour Fibre Ltd"],
  ["securityContext.isp", "Harbour Fibre Ltd"],
  ["securityContext.isProxy", "false"],
];
const NIGHT: [string, string][] = [
  ["client.ipAddress", "203.0.113.58"],
  ["client.userAgent.browser", "CHROME"],
  ["client.userAgent.os", "Windows 10"],
  ["client.geographicalContext.city", "Rotterdam"],
  ["client.geographicalContext.country", "Netherlands"],
  ["securityContext.asNumber", "64503"],
  ["securityContext.asOrg", "Northpier Hosting Ltd"],
  ["securityContext.isp", "Northpier Hosting Ltd"],
  ["securityContext.domain", "northpier-hosting.example"],
  ["securityContext.isProxy", "false"],
];
const TABS = [{ id: "basic", label: "Event" }, { id: "actor", label: "Actor" }, { id: "client", label: "Client" }, { id: "outcome", label: "Outcome" }, { id: "target", label: "Target" }];

/** One System Log event with the same five detail tabs. */
function logEvent(id: string, eventType: string, displayMessage: string, published: string, actor: [string, string][], client: [string, string][], outcome: [string, string][], target: [string, string][]) {
  return {
    id,
    title: "Event detail",
    actions: TABS,
    facts: [["eventType", eventType], ["displayMessage", displayMessage], ["published", published], ["severity", "INFO"]] as [string, string][],
    panes: { actor, client, outcome, target: target.length ? target : [["target", "No target on this event"]] as [string, string][] },
  };
}

const LOG_COLUMNS = ["Time (UTC)", "Actor", "Event info", "eventType", "Result", "Client IP"];

const SYSTEM_LOG_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "Work the System Log",
  prompt: "Thursday 07:10, the last working day of the month. The SIEM flagged a sign-in for e.vance at 23:37 last night, and Treasury signs off the big payments at noon. Ngaire Holm opens the admin console and slides you the keyboard. Work outward from that one sign-in, and close what is still open.",
  product: "Identity admin console",
  resource: "Quayside Capital",
  tenant: DOMAIN,
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Dashboard" }] },
    { group: "Directory", items: [{ id: "people", label: "People" }, { id: "groups", label: "Groups" }] },
    { group: "Security", items: [{ id: "policies", label: "Sign-on policies" }, { id: "networks", label: "Network zones" }, { id: "tokens", label: "API tokens" }] },
    { group: "Reports", items: [{ id: "syslog", label: "System Log" }, { id: "bysource", label: "Saved search: 203.0.113.58" }] },
  ],
  pages: {
    overview: { heading: "Dashboard", tiles: [{ label: "People", value: "340" }, { label: "Groups", value: "62" }, { label: "Applications", value: "38" }], note: `Org ${DOMAIN}. Every sign-in, admin action and policy change in this org lands in the System Log.` },
    people: {
      heading: "People",
      table: {
        columns: ["Person", "Username", "Title", "Status"],
        rows: [
          { id: "u-vance", cells: ["Ellis Vance", addr("e.vance"), "IT Operations Lead", "Active"], record: "u-vance" },
          { id: "u-sorel", cells: ["Imogen Sorel", addr("i.sorel"), "IAM Engineer", "Active"], record: "u-sorel" },
          { id: "u-kerr", cells: ["Tobias Kerr", addr("t.kerr"), "Vendor consultant", "Active"], record: "u-kerr" },
          { id: "u-holm", cells: ["Ngaire Holm", addr("n.holm"), "IAM Security Analyst", "Active"], record: "u-holm" },
        ],
      },
    },
    groups: {
      heading: "Groups",
      table: {
        columns: ["Group", "Group ID", "People", "Source"],
        rows: [
          { id: "g-treasury", cells: ["Treasury-Approvers", "00g2fv8KsT3yNq6R1h4", "6", "Directory"] },
          { id: "g-vendors", cells: ["Vendors", "00g7mc1XpB9wJe2L5a8", "23", "Directory"] },
          { id: "g-itops", cells: ["IT-Operations", "00g4rd6HnZ0uGk7V3c9", "11", "Directory"] },
        ],
      },
    },
    policies: {
      heading: "Sign-on policies",
      table: {
        columns: ["Rule", "Status", "Require MFA", "Last modified"],
        rows: [
          { id: "pr-1", cells: ["Vendor network", "Active", "No", "Yesterday 23:44"] },
          { id: "pr-2", cells: ["Office network", "Active", "Yes", "12 Oct"] },
          { id: "pr-3", cells: ["Catch-all", "Active", "Yes", "12 Oct"] },
        ],
      },
    },
    networks: {
      heading: "Network zones",
      table: {
        columns: ["Zone", "Gateway IPs", "Status", "Last modified"],
        rows: [
          { id: "z-office", cells: ["Quayside-Office", "198.51.100.20/32", "Active", "12 Oct"] },
          { id: "z-vendor", cells: ["Vendor-Partners", "198.51.100.96/28, 203.0.113.58/32", "Active", "Yesterday 23:42"] },
          { id: "z-hr", cells: ["HR-Vendor", "198.51.100.144/29", "Active", "2025-02-11"] },
          { id: "z-cust", cells: ["Custody-Bank", "198.51.100.160/29", "Active", "2025-06-03"] },
        ],
      },
    },
    tokens: {
      heading: "API tokens",
      note: "A token acts with the rights of the admin who created it, and using it involves no sign-on policy and no second factor. It expires after 30 days without use.",
      table: {
        columns: ["Token name", "Created by", "Created", "Last used", "Network"],
        rows: [
          { id: "t-hr", cells: ["scim-hr-feed", "i.sorel", "2025-02-11", "Today 06:00", "Zone: HR-Vendor"], record: "t-hr" },
          { id: "t-cust", cells: ["custody-sync", "i.sorel", "2025-06-03", "Today 06:30", "Zone: Custody-Bank"], record: "t-cust" },
          { id: "t-new", cells: ["custody-sync-2", "e.vance", "Yesterday 23:51", "Today 02:17", "Any IP"], record: "t-new", tone: "high" },
        ],
      },
    },
    syslog: {
      heading: "System Log",
      filters: [`actor.alternateId eq "${addr("e.vance")}"`, "Showing: sign-in events only", "Last 24 hours", "Sort: oldest first"],
      table: {
        columns: LOG_COLUMNS,
        rows: [
          { id: "b-eval", cells: ["Wed 08:11:40", "Ellis Vance", "Evaluation of sign-on policy", "policy.evaluate_sign_on", "CHALLENGE", "198.51.100.20"], record: "b-eval" },
          { id: "b-mfa", cells: ["Wed 08:12:03", "Ellis Vance", "Authentication of user via MFA", "user.authentication.auth_via_mfa", "SUCCESS", "198.51.100.20"], record: "b-mfa" },
          { id: "b-sess", cells: ["Wed 08:12:04", "Ellis Vance", "User login to Okta", "user.session.start", "SUCCESS", "198.51.100.20"], record: "b-sess" },
          { id: "a-eval", cells: ["Wed 23:37:53", "Ellis Vance", "Evaluation of sign-on policy", "policy.evaluate_sign_on", "CHALLENGE", "203.0.113.58"], record: "a-eval", tone: "medium" },
          { id: "a-sms", cells: ["Wed 23:37:53", "Ellis Vance", "Send second factor auth SMS", "system.sms.send_factor_verify_message", "SUCCESS", "203.0.113.58"], record: "a-sms" },
          { id: "a-mfa", cells: ["Wed 23:38:21", "Ellis Vance", "Authentication of user via MFA", "user.authentication.auth_via_mfa", "SUCCESS", "203.0.113.58"], record: "a-mfa" },
          { id: "a-sess", cells: ["Wed 23:38:22", "Ellis Vance", "User login to Okta", "user.session.start", "SUCCESS", "203.0.113.58"], record: "a-sess" },
        ],
      },
    },
    bysource: {
      heading: "System Log",
      filters: ['client.ipAddress eq "203.0.113.58"', "Last 24 hours", "Sort: oldest first"],
      table: {
        columns: LOG_COLUMNS,
        rows: [
          { id: "s-eval", cells: ["Wed 23:37:53", "Ellis Vance", "Evaluation of sign-on policy", "policy.evaluate_sign_on", "CHALLENGE", "203.0.113.58"], record: "a-eval" },
          { id: "s-sms", cells: ["Wed 23:37:53", "Ellis Vance", "Send second factor auth SMS", "system.sms.send_factor_verify_message", "SUCCESS", "203.0.113.58"], record: "a-sms" },
          { id: "s-mfa", cells: ["Wed 23:38:21", "Ellis Vance", "Authentication of user via MFA", "user.authentication.auth_via_mfa", "SUCCESS", "203.0.113.58"], record: "a-mfa" },
          { id: "s-sess", cells: ["Wed 23:38:22", "Ellis Vance", "User login to Okta", "user.session.start", "SUCCESS", "203.0.113.58"], record: "a-sess" },
          { id: "s-admin", cells: ["Wed 23:39:40", "Ellis Vance", "User accessing Okta admin app", "user.session.access_admin_app", "SUCCESS", "203.0.113.58"], record: "s-admin" },
          { id: "s-zone", cells: ["Wed 23:42:16", "Ellis Vance", "Update network zone", "zone.update", "SUCCESS", "203.0.113.58"], record: "s-zone" },
          { id: "s-rule", cells: ["Wed 23:44:05", "Ellis Vance", "Update policy rule", "policy.rule.update", "SUCCESS", "203.0.113.58"], record: "s-rule" },
          { id: "s-token", cells: ["Wed 23:51:33", "Ellis Vance", "Create API token", "system.api_token.create", "SUCCESS", "203.0.113.58"], record: "s-token" },
          { id: "s-app", cells: ["Wed 23:53:10", "Ellis Vance", "Add user to application membership", "application.user_membership.add", "SUCCESS", "203.0.113.58"], record: "s-app" },
          { id: "s-kerr", cells: ["Thu 00:06:47", "Tobias Kerr", "Evaluation of sign-on policy", "policy.evaluate_sign_on", "ALLOW", "203.0.113.58"], record: "s-kerr" },
          { id: "s-kerrs", cells: ["Thu 00:06:47", "Tobias Kerr", "User login to Okta", "user.session.start", "SUCCESS", "203.0.113.58"], record: "s-kerrs" },
        ],
      },
    },
  },
  records: {
    "b-eval": logEvent("b-eval", "policy.evaluate_sign_on", "Evaluation of sign-on policy", "Wed 08:11:40", VANCE, OFFICE, [["outcome.result", "CHALLENGE"], ["outcome.reason", "Sign-on policy evaluation resulted in CHALLENGE"], ["transaction.id", "TxH4d9Pn"]], [["target.0.type", "PolicyEntity"], ["target.0.displayName", "Quayside global session policy"], ["target.1.type", "PolicyRule"], ["target.1.displayName", "Catch-all"]]),
    "b-mfa": logEvent("b-mfa", "user.authentication.auth_via_mfa", "Authentication of user via MFA", "Wed 08:12:03", VANCE, OFFICE, [["outcome.result", "SUCCESS"], ["transaction.id", "TxH4d9Pn"]], [["target.0.type", "AuthenticatorEnrollment"], ["target.0.displayName", "Phone"]]),
    "b-sess": logEvent("b-sess", "user.session.start", "User login to Okta", "Wed 08:12:04", VANCE, OFFICE, [["outcome.result", "SUCCESS"], ["transaction.id", "TxH4d9Pn"]], []),
    "a-eval": logEvent("a-eval", "policy.evaluate_sign_on", "Evaluation of sign-on policy", "Wed 23:37:53", VANCE, NIGHT, [["outcome.result", "CHALLENGE"], ["outcome.reason", "Sign-on policy evaluation resulted in CHALLENGE"], ["transaction.id", "TxW7k2Jc"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], [["target.0.type", "PolicyEntity"], ["target.0.displayName", "Quayside global session policy"], ["target.1.type", "PolicyRule"], ["target.1.displayName", "Catch-all"]]),
    "a-sms": logEvent("a-sms", "system.sms.send_factor_verify_message", "Send second factor auth SMS", "Wed 23:37:53", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["transaction.id", "TxW7k2Jc"]], []),
    "a-mfa": logEvent("a-mfa", "user.authentication.auth_via_mfa", "Authentication of user via MFA", "Wed 23:38:21", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["transaction.id", "TxW7k2Jc"], ["debugContext.debugData.factor", "SMS_FACTOR"]], [["target.0.type", "AuthenticatorEnrollment"], ["target.0.displayName", "Phone"]]),
    "a-sess": logEvent("a-sess", "user.session.start", "User login to Okta", "Wed 23:38:22", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["transaction.id", "TxW7k2Jc"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], []),
    "s-admin": logEvent("s-admin", "user.session.access_admin_app", "User accessing Okta admin app", "Wed 23:39:40", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], []),
    "s-zone": logEvent("s-zone", "zone.update", "Update network zone", "Wed 23:42:16", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], [["target.0.displayName", "Vendor-Partners"]]),
    "s-rule": logEvent("s-rule", "policy.rule.update", "Update policy rule", "Wed 23:44:05", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], [["target.0.type", "PolicyRule"], ["target.0.displayName", "Vendor network"], ["target.0.id", "0pr8sk3DfV1nHq6T2w5"]]),
    "s-token": logEvent("s-token", "system.api_token.create", "Create API token", "Wed 23:51:33", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], [["target.0.type", "Token"], ["target.0.displayName", "custody-sync-2"], ["target.0.id", "00T6bn4GhW2xMr9K0y3"]]),
    "s-app": logEvent("s-app", "application.user_membership.add", "Add user to application membership", "Wed 23:53:10", VANCE, NIGHT, [["outcome.result", "SUCCESS"], ["authenticationContext.externalSessionId", "trsG5vQ1mYbZ8sLn"]], [["target.0.type", "AppUser"], ["target.0.displayName", "Tobias Kerr"], ["target.1.type", "AppInstance"], ["target.1.displayName", "Settlement Portal"], ["target.1.id", "0oa5py7CzN8vLt1R4j6"]]),
    "s-kerr": logEvent("s-kerr", "policy.evaluate_sign_on", "Evaluation of sign-on policy", "Thu 00:06:47", KERR, NIGHT, [["outcome.result", "ALLOW"], ["transaction.id", "TxM3q8Vf"]], [["target.0.type", "PolicyEntity"], ["target.0.displayName", "Quayside global session policy"], ["target.1.type", "PolicyRule"], ["target.1.displayName", "Vendor network"]]),
    "s-kerrs": logEvent("s-kerrs", "user.session.start", "User login to Okta", "Thu 00:06:47", KERR, NIGHT, [["outcome.result", "SUCCESS"], ["transaction.id", "TxM3q8Vf"]], []),
    "t-new": { id: "t-new", title: "custody-sync-2", facts: [["Token ID", "00T6bn4GhW2xMr9K0y3"], ["Created by", "e.vance, Org Administrator"], ["Acts with", "The creator's admin rights"], ["Network", "Any IP"], ["Last used", "Today 02:17"]], actions: [{ id: "revoke-new", label: "Revoke" }] },
    "t-cust": { id: "t-cust", title: "custody-sync", facts: [["Created by", "i.sorel"], ["Change record", "CHG-3382"], ["Network", "Zone: Custody-Bank"], ["Used for", "Nightly custody statements"]], actions: [{ id: "revoke-cust", label: "Revoke" }] },
    "t-hr": { id: "t-hr", title: "scim-hr-feed", facts: [["Created by", "i.sorel"], ["Change record", "CHG-3107"], ["Network", "Zone: HR-Vendor"], ["Used for", "Joiners and leavers from HR"]], actions: [{ id: "revoke-hr", label: "Revoke" }] },
    "u-vance": { id: "u-vance", title: "Ellis Vance", facts: [["Username", addr("e.vance")], ["Title", "IT Operations Lead"], ["Admin role", "Org Administrator"], ["Enrolled factor", "Phone (SMS)"], ["IT desk note", "Ellis rang at 07:02: no mobile signal since about 23:20 last night"]], actions: [{ id: "clear-vance", label: "Clear user sessions" }, { id: "resetpw-vance", label: "Reset password" }] },
    "u-sorel": { id: "u-sorel", title: "Imogen Sorel", facts: [["Username", addr("i.sorel")], ["Title", "IAM Engineer"], ["Last sign-in", "Today 06:55 from 198.51.100.20"]] },
    "u-kerr": { id: "u-kerr", title: "Tobias Kerr", facts: [["Username", addr("t.kerr")], ["Title", "Vendor consultant"], ["Groups", "Vendors"], ["Contract", "Ended in June"], ["Last sign-in", "Today 00:06 from 203.0.113.58"]] },
    "u-holm": { id: "u-holm", title: "Ngaire Holm", facts: [["Username", addr("n.holm")], ["Title", "IAM Security Analyst"]] },
  },
  steps: [
    { id: "log", ask: "Start where every event in this org is written.", hint: "Reports, at the bottom of the menu.", target: "menu:syslog", why: "One log for the whole org. The filter is already on e.vance's sign-in events, so you can see the account's normal morning next to last night." },
    { id: "open", ask: "Open the sign-in the SIEM flagged: 23:37, the first event from that address.", hint: "Read the Time and Client IP columns.", target: "row:a-eval", why: "The list shows the result, not the reason. Everything you need is in the event's tabs." },
    { id: "net", ask: "Before anything else, find out what kind of network that request came from.", hint: "One of the tabs across the event.", target: "action:client", why: "Northpier Hosting Ltd, a hosting company's range in Rotterdam. Ellis's sign-in that morning came from Harbour Fibre, the office line. The network doesn't fit the person." },
    { id: "out", ask: "Now find out how far this attempt got.", hint: "Result is one field. The tab next door has its partner.", target: "action:outcome", why: "CHALLENGE, reason 'Sign-on policy evaluation resulted in CHALLENGE'. The policy only asks for a factor once the password is accepted, so the password was right. The morning sign-in shows the same pair, which is how an ordinary SMS sign-in begins." },
    { id: "mfa", ask: "Follow the same transaction. Open the event that shows whether the second factor passed.", hint: "Look down the eventType column, a few rows later, for MFA.", target: "row:a-mfa", why: "SUCCESS, 28 seconds after the SMS went out. target.0.displayName says Phone, debugData says SMS_FACTOR. Ellis says the phone has had no signal since 23:20, and a code goes wherever the number goes." },
    { id: "pivot", ask: "This view shows sign-ins only. Look at everything that address did.", hint: "There's a saved search under Reports.", target: "menu:bysource", why: "Filtering on the source shows all that address touched, whichever account it used. Same address, same session ID, minutes apart: that's one timeline." },
    { id: "rule", ask: "Open the change to the policy you compared this morning.", hint: "The leading segment of eventType is the category you want.", target: "row:s-rule", why: "Six minutes after the session opened: policy.rule.update on Vendor network, and zone.update just before it. Open the Target tab if you want the rule's ID. The log gives you who, when and from where." },
    { id: "token", ask: "Something here will outlive any session. Open it.", hint: "A system event, not a user one, though a user made it.", target: "row:s-token", why: "system.api_token.create, named custody-sync-2 to sit quietly beside the real feed. The actor is a person, so this is an admin's act, not Okta's own housekeeping." },
    { id: "kerr", ask: "Work out what the policy change was for. Open the sign-in it let through.", hint: "A different actor, after midnight. The event that shows the rule.", target: "row:s-kerr", why: "t.kerr, a vendor whose contract ended in June, from the same address. ALLOW straight away on rule Vendor network, with no challenge. That's a second account in hand, and it was added to the Settlement Portal at 23:53." },
    { id: "tokens", ask: "Time to contain. Start with what no sign-out will touch.", hint: "Security, in the menu.", target: "menu:tokens", why: "Tokens have their own page because they live outside any session." },
    { id: "pick", ask: "Open the token from last night.", hint: "Check who created it and when.", target: "row:t-new", why: "Any IP, used at 02:17 this morning, with Ellis's Org Administrator rights." },
    { id: "revoke", ask: "Cancel it.", hint: "The button on the token's page.", target: "action:revoke-new", why: "Revoked, and logged as system.api_token.revoke. Clearing sessions alone would have left this working." },
    { id: "people", ask: "Now the live session. Go to the people list.", hint: "Directory, near the top.", target: "menu:people", why: "A session is held per person, so it's closed from the person's page." },
    { id: "ellis", ask: "Open the account that made the changes.", hint: "The actor on every admin event you just read.", target: "row:u-vance", why: "Org Administrator, SMS as the only factor, and a note from the IT desk that fits the timing." },
    { id: "clear", ask: "End what that account has open.", hint: "The buttons on the person's page.", target: "action:clear-vance", why: "Sessions cleared. Ngaire takes it from here: Ellis's password and factor, t.kerr's session and Portal seat, the rule and the zone, all before noon." },
  ],
  traps: {
    "action:revoke-cust": "That token has a change record, its own network zone and a job: custody statements. Revoking it breaks month-end and removes nothing the intruder holds.",
    "action:revoke-hr": "That token has a change record and its own network zone, and it feeds joiners and leavers from HR. It isn't part of this.",
    "action:resetpw-vance": "A new password doesn't close a session that's already open. Close what's open first, then change the password.",
  },
  lesson: "A sign-in is where the trail starts, not where it ends. The tabs tell you what kind of network it was and how far it got, the address ties the night together across accounts, and every admin event has an actor and a target to read. Containment follows what you found: a token, a session and a second account are three separate things to close.",
};

export const OKTA_IDENTITY_FUNDAMENTALS: RoomExperience = {
  roomId: "okta-identity-fundamentals",
  codename: "Operation Single Sign-Off",
  theme: "singlesignoff",
  handler: { name: "Ngaire Holm", role: "IAM Security Analyst, Quayside Capital" },
  briefing: [
    "Quayside Capital. A fund manager on the harbour front, with one sign-in in front of every app its people use, the Settlement Portal included.",
    "At month-end a large payment needs two people to sign off. Both of them arrive through the same identity provider.",
    "Ngaire Holm reads that provider's System Log every day, and warns that a query carried over from another platform will come back empty and look like good news.",
    "Learn how this log is written, how far a sign-in really got, who changed what, and what to close before noon.",
  ],
  mission: "Learn the System Log's own fields, trace a spray to the account it found, read the network and the factor, compare two sign-on policies, then work the log from one sign-in to everything it touched.",
  estimate: "~55 min",
  look: { primary: "#6fc3df", secondary: "#f2cc8f", warn: "#e76f51" },
  scene: "facilitysinglesignoff",
  layout: "facility",
  stations: [
    {
      id: "syslog",
      label: "The System Log",
      topic: "What Okta is · the eventType taxonomy · actor and target · outcome.result and outcome.reason",
      tagline: "How far did it get?",
      building: "archive",
      taskIds: ["oktaf-r1", "oktaf-r2", "oktaf-r3", "oktaf-q1"],
    },
    {
      id: "source",
      label: "Behind the Attempt",
      topic: "securityContext network signals · factor enrollment and factor types",
      tagline: "Who is on the other end?",
      building: "lab",
      taskIds: ["oktaf-r4", "oktaf-r5", "oktaf-q2"],
    },
    {
      id: "policies",
      label: "Two Policies",
      topic: "Okta against Entra ID · sign-on policy rules · reading one event in full",
      tagline: "What changed, and what was lost?",
      building: "vault",
      taskIds: ["oktaf-r6", "oktaf-la1"],
    },
    {
      id: "trail",
      label: "The Admin Trail",
      topic: "Rate limiting and system events · user, group and policy changes",
      tagline: "Who did it, and to what?",
      building: "control",
      taskIds: ["oktaf-r7", "oktaf-r8", "oktaf-q3"],
    },
    {
      id: "signoff",
      label: "Single Sign-Off",
      topic: "Reading a privilege change to the end · triage order · classifying the incident",
      tagline: "Finish the chain",
      building: "ticket",
      taskIds: ["oktaf-la2", "oktaf-m1", "oktaf-o1", "oktaf-f1", "oktaf-q4", "oktaf-q5"],
      boss: true,
    },
  ],
  personas: {
    "oktaf-q1": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Someone else's closure note. Read it before you agree with it." },
    "oktaf-q2": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Two second factors. Tell me why they aren't equal." },
    "oktaf-la1": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Another firm's ticket, one event. Take your time over it." },
    "oktaf-q3": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "A new event landed in that ticket. What do you make of it?" },
    "oktaf-la2": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Same ticket, a few minutes on. Read every field." },
    "oktaf-m1": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Sort these out and most of the log reads itself." },
    "oktaf-o1": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Next time the flag goes up, what's your order of work?" },
    "oktaf-f1": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "One value from that event. I need it for the next check." },
    "oktaf-q4": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "Two tickets, two identity providers, one morning." },
    "oktaf-q5": { name: "Ngaire Holm", role: "IAM Security Analyst", line: "One more ticket. Give it a single, accurate name." },
  },
  briefings: {
    // ── Reading 1: what Okta is, and silent filters ──
    "oktaf-r1": [
      {
        kind: "sort",
        title: "Will This Filter Find Anything?",
        prompt: "Quayside's SOC inherited a folder of saved searches from a firm that ran Entra ID. Ngaire Holm wants to know which ones work on this org's data before anyone trusts them. Sort each filter by what it would do against the Okta data in the SIEM.",
        primer: {
          title: "One org, one log, its own field names",
          points: [
            "An **identity provider (IdP)** answers who someone is and what they may reach. Okta bundles three things: a directory of users and groups (Universal Directory), single sign-on (SSO) into many apps, and a policy engine that decides when to ask for more proof.",
            "One customer's whole Okta presence is called an **org**, and its activity record is the **System Log**. What kind of thing happened is held in one field, `eventType`.",
            "The fields to know are `eventType`, `actor`, `target`, `outcome.result`, `outcome.reason` and `securityContext`. In a SIEM they usually carry an `okta.` prefix.",
            "A SIEM filter on a field the data doesn't have is not an error. It simply matches no rows.",
          ],
          example: {
            label: "Worked example: wrong source, clean-looking result",
            lines: [
              "`EventID:4625` run over Linux `auth.log` data returns 0 rows.",
              "Linux logs have no EventID field, so that zero says nothing about failed logons on those hosts.",
            ],
          },
        },
        buckets: [{ id: "hits", label: "Matches Okta events" }, { id: "silent", label: "Matches nothing, with no error" }],
        items: [
          { id: "a", text: 'okta.eventType: "user.account.lock"', bucket: "hits", why: "eventType is the field every event in this log carries." },
          { id: "b", text: 'UserPrincipalName: "r.sandhu@quaysidecapital.example"', bucket: "silent", why: "That's Entra's name for the account. Here the same value sits in actor.alternateId." },
          { id: "c", text: 'okta.outcome.reason: "LOCKED_OUT"', bucket: "hits", why: "outcome.reason is one of the richest fields in this log." },
          { id: "d", text: 'AppDisplayName: "Settlement Portal"', bucket: "silent", why: "An Entra sign-in field. This log names an app in target, on events about that app." },
          { id: "e", text: 'RiskLevelDuringSignIn: "high"', bucket: "silent", why: "An Entra sign-in field. Okta's risk signals have their own names and event types." },
          { id: "f", text: 'okta.securityContext.asOrg: "Harbour Fibre Ltd"', bucket: "hits", why: "securityContext describes the network behind a request." },
          { id: "g", text: 'AuthenticationRequirement: "multiFactorAuthentication"', bucket: "silent", why: "Another Entra sign-in field, so this saved search would look perfectly healthy and return nothing." },
          { id: "h", text: 'okta.actor.alternateId: "r.sandhu@quaysidecapital.example"', bucket: "hits", why: "alternateId is the readable identifier for whoever acted, usually an email address." },
        ],
      },
    ],
    // ── Reading 2: taxonomy, actor and target ──
    "oktaf-r2": [
      {
        kind: "anatomy",
        title: "Read One System Log Event",
        prompt: "Tuesday afternoon at Quayside: an ordinary change, and a good one to learn on. Imogen Sorel gave a new treasury analyst read access. Scan each key field.",
        source: "System Log · event detail",
        fields: [
          { key: "okta.eventType", value: "group.user_membership.add", label: "What happened", note: "The machine-readable name, built as object.verb. This is the field a detection rule should use." },
          { key: "okta.displayMessage", value: "Add user to group membership", label: "The human caption", note: "Written for someone scanning the log. Several eventType values can share a caption, so it's no basis for a rule." },
          { key: "okta.outcome.result", value: "SUCCESS" },
          { key: "okta.actor.alternateId", value: "i.sorel@quaysidecapital.example", label: "Who did it", note: "actor is the identity that performed the action, here the admin making the change." },
          { key: "okta.actor.type", value: "User", label: "What kind of actor", note: "User is a person or account. SystemPrincipal is the platform itself, with no person behind it." },
          { key: "okta.target.0.alternateId", value: "r.sandhu@quaysidecapital.example", label: "First target", note: "target is an array, because one action can touch several objects. On a membership change, target.0 is the user." },
          { key: "okta.target.0.id", value: "00u5kd2RwM8fPz3N6q1", label: "The user's ID", note: "Okta IDs show their type at the start: user IDs begin 00u." },
          { key: "okta.target.1.type", value: "UserGroup", label: "Second target", note: "On a membership change, target.1 is the group the user joined." },
          { key: "okta.target.1.displayName", value: "Treasury-Readers" },
          { key: "okta.target.1.id", value: "00g8wj5TcH1sQb7X4m2", label: "The group's ID", note: "Group IDs begin 00g. This ID is what you carry to the next check, because display names can be changed and reused." },
          { key: "okta.transaction.id", value: "TxB2n6Rd", label: "What ties events together", note: "Events from the same request share this value, so you can follow one transaction across several rows." },
        ],
        summary: "Imogen Sorel (actor) added r.sandhu (target.0) to Treasury-Readers (target.1). Read who acted and what was touched as two separate questions, every time.",
      },
      {
        kind: "sort",
        title: "Which Category Would Catch It?",
        prompt: "Ngaire Holm wants a handful of detections, each watching a whole category and not one exact event. Put each thing that happened at Quayside under the wildcard that would catch it.",
        primer: {
          title: "eventType reads left to right",
          points: [
            "`eventType` is built as object.verb, or object.subobject.verb.",
            "The leading segment is the broad category: user, group, application, policy, system and so on. The trailing segment is the action.",
            "A rule on a category ending in `.*` also catches actions you haven't seen yet, which is why the pattern is worth more than a list.",
          ],
          example: {
            label: "Worked example: user.account.lock",
            lines: [
              "`user` is the category, `account` the sub-object, `lock` the action.",
              "A rule on `user.account.*` would also catch `user.account.unlock`, without anyone listing it.",
            ],
          },
        },
        buckets: [
          { id: "app", label: "application.user_membership.*" },
          { id: "life", label: "user.lifecycle.*" },
          { id: "token", label: "system.api_token.*" },
          { id: "pol", label: "policy.lifecycle.*" },
        ],
        items: [
          { id: "a", text: "A leaver's account is switched off", bucket: "life", why: "user.lifecycle.deactivate: an account's state changed." },
          { id: "b", text: "A contractor is suspended for a month", bucket: "life", why: "user.lifecycle.suspend: the same category, a different last word." },
          { id: "c", text: "An analyst is given the Settlement Portal", bucket: "app", why: "application.user_membership.add: someone gained an app." },
          { id: "d", text: "A leaver loses the Settlement Portal", bucket: "app", why: "application.user_membership.remove: same object, opposite verb." },
          { id: "e", text: "A new credential for a script appears", bucket: "token", why: "system.api_token.create: the leading segment is system even when a person pressed the button, so read actor too." },
          { id: "f", text: "A script's credential is cancelled", bucket: "token", why: "system.api_token.revoke." },
          { id: "g", text: "A whole policy is switched off", bucket: "pol", why: "policy.lifecycle.deactivate: the policy itself changed state." },
          { id: "h", text: "A policy's settings are edited", bucket: "pol", why: "policy.lifecycle.update." },
        ],
      },
    ],
    // ── Reading 3: outcome.reason. The decisive signal, on a spray ──
    "oktaf-r3": [
      {
        kind: "trace",
        title: "How Far Did It Get?",
        prompt: "Tuesday night a source worked down Quayside's staff list, one try per account, about one every three minutes. Nearly every row says FAILURE. Ngaire Holm wants to know whether any of them should worry you.",
        primer: {
          title: "Result says what. Reason says how far",
          points: [
            "`outcome.result` covers one step: SUCCESS, FAILURE, ALLOW, DENY, SKIPPED or CHALLENGE. `outcome.reason` is where the detail lives.",
            "A sign-in moves in stages: password, then a second factor if policy asks for one, then a session.",
            "`INVALID_CREDENTIALS`: the credentials weren't accepted. `LOCKED_OUT`: too many failures, so the account is locked.",
            "A right password is not logged as a failure. The sign-on policy runs next: `policy.evaluate_sign_on` with result `CHALLENGE` (reason `Sign-on policy evaluation resulted in CHALLENGE`) means the password stage is passed and policy now wants a second factor.",
            "To confirm it, look at what Okta logged next under the same `transaction.id` or `externalSessionId`: a challenge going out, then the factor's result.",
          ],
          example: {
            label: "Worked example: passport control",
            lines: [
              "A border desk sends a traveller on to a second check. The officer only does that after the passport has checked out.",
              "The traveller may never get in, and you still learn the passport was good. Read which desk wrote the line, not only whether the traveller got through.",
            ],
          },
        },
        lead: "A source at 203.0.113.58, Tuesday from 22:41, one try per account",
        steps: [
          {
            id: "who",
            ask: "Eight tries, one per account. Find the one where the password was right.",
            source: "System Log · client.ipAddress eq 203.0.113.58",
            columns: ["published", "actor.alternateId", "eventType", "outcome.result", "outcome.reason"],
            rows: [
              ["22:41:12", "a.rosen", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["22:43:40", "b.lindqvist", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["22:46:05", "c.duarte", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["22:49:31", "d.achebe", "user.session.start", "FAILURE", "LOCKED_OUT"],
              ["22:52:17", "e.vance", "policy.evaluate_sign_on", "CHALLENGE", "Sign-on policy evaluation resulted in CHALLENGE"],
              ["22:54:02", "f.novak", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["22:56:48", "g.sato", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["22:58:10", "h.ibsen", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
            ],
            answer: 4,
            why: "The sign-on policy answers CHALLENGE only after the password stage, so e.vance's password was right. d.achebe's LOCKED_OUT tells you the account was already locked, which proves nothing about the password tried.",
            learned: "e.vance: password accepted at 22:52:17",
          },
          {
            id: "prove",
            ask: "Back it up. Find the event that shows a second-factor challenge really went out for that attempt.",
            source: "System Log · around 22:52",
            columns: ["published", "eventType", "actor.alternateId", "outcome.result", "transaction.id"],
            rows: [
              ["22:52:17", "policy.evaluate_sign_on", "e.vance", "CHALLENGE", "TxQ7m2Lk"],
              ["22:52:18", "system.sms.send_factor_verify_message", "e.vance", "SUCCESS", "TxQ7m2Lk"],
              ["22:53:02", "system.sms.send_factor_verify_message", "j.adeyemi", "SUCCESS", "Tx8bN4pW"],
              ["22:54:02", "user.session.start", "f.novak", "FAILURE", "TxC2r9Vd"],
            ],
            answer: 1,
            why: "Same transaction.id, one second after the CHALLENGE: the SMS went to Ellis's number. The SMS row below it is another person's ordinary sign-in on another transaction. Always match on the transaction, not only on the time.",
            learned: "Same transaction: SMS sent to e.vance's number",
          },
          {
            id: "next",
            ask: "The run went on after 23:00. Find the next account whose password the source now holds.",
            source: "System Log · client.ipAddress eq 203.0.113.58",
            columns: ["published", "actor.alternateId", "eventType", "outcome.result", "outcome.reason"],
            rows: [
              ["23:01:22", "l.marsh", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["23:03:51", "m.okoye", "policy.evaluate_sign_on", "CHALLENGE", "Sign-on policy evaluation resulted in CHALLENGE"],
              ["23:06:14", "n.pereira", "user.session.start", "FAILURE", "LOCKED_OUT"],
              ["23:08:37", "o.frey", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
              ["23:11:05", "p.stroud", "user.session.start", "FAILURE", "INVALID_CREDENTIALS"],
            ],
            answer: 1,
            why: "m.okoye is the second. Neither account has a session from this address tonight, and both passwords are in someone else's hands. Those are two separate facts.",
            learned: "m.okoye: password accepted at 23:03:51",
          },
        ],
      },
      {
        kind: "sort",
        title: "What Does the Source Now Hold?",
        prompt: "Ngaire Holm keeps three columns on the case board for every account a source touches. These are from other cases this year. Put each account's evidence in the column it supports.",
        buckets: [
          { id: "none", label: "Nothing proved" },
          { id: "pass", label: "Holds the password" },
          { id: "sess", label: "Holds a live session" },
        ],
        items: [
          { id: "a", text: "One try, reason INVALID_CREDENTIALS, then silence", bucket: "none", why: "The attempt stopped at the first stage. Nothing here says the source learned anything." },
          { id: "b", text: "Reason LOCKED_OUT after a run of failures", bucket: "none", why: "Locked means too many failures. It doesn't tell you any attempt was right." },
          { id: "c", text: "Sign-on policy CHALLENGE, an SMS sent, the code never entered", bucket: "pass", why: "The second factor held and nothing opened, and the SMS only went out because the password was accepted." },
          { id: "d", text: "Sign-on policy CHALLENGE on a contractor account, then two silent days", bucket: "pass", why: "Silence afterwards doesn't take the password back. It only means nobody has used it yet." },
          { id: "e", text: "CHALLENGE, then auth_via_mfa SUCCESS, then user.session.start SUCCESS and admin activity", bucket: "sess", why: "Every stage passed, and the activity after it shows the session being used." },
          { id: "f", text: "user.session.start SUCCESS under a rule needing no second factor, then app access", bucket: "sess", why: "You won't see a CHALLENGE here, because no policy asked for a factor. The password alone was enough." },
        ],
      },
    ],
    // ── Reading 4: securityContext ──
    "oktaf-r4": [
      {
        kind: "queue",
        title: "Whose Network Is This?",
        prompt: "Wednesday's identity alerts at Quayside. Ngaire Holm asks you to read the network behind each one before anything else. Open each alert, read its fields, and make the call.",
        primer: {
          title: "securityContext describes the network, not the person",
          points: [
            "`asNumber` and `asOrg` name the network block a request came from and who owns it. `isp` and `domain` confirm and refine that.",
            "Staff normally arrive from home broadband, a mobile carrier or an office line. Hosting and data-centre ranges are where servers live.",
            "`isProxy` is Okta's own view of whether a known proxy or anonymiser was used. It's one more clue, and it depends on what Okta knows about.",
            "`client.geographicalContext` is a separate thing: a guess at location from the IP. Location and type of network are two different signals.",
            "This works on failed attempts too, so check it first. It needs no successful sign-in.",
          ],
          example: {
            label: "Worked example: a hotel in Lisbon",
            lines: [
              "asOrg `Seaview Hospitality Ltd`, city Lisbon, for a user who is at a conference in Lisbon.",
              "Odd city, ordinary kind of network, and a calendar that fits. It reads as a person on a guest Wi-Fi.",
            ],
          },
        },
        console: "SIEM · Identity alerts",
        actions: [
          { id: "close", label: "Close: fits the person", tone: "close" },
          { id: "esc", label: "Escalate: check this source", tone: "escalate" },
        ],
        alerts: [
          {
            id: "a1",
            time: "07:48",
            severity: "Low",
            rule: "Sign-in from new country",
            entity: "r.sandhu@quaysidecapital.example",
            fields: [{ k: "securityContext.asOrg", v: "Seaboard Mobile BV" }, { k: "securityContext.isp", v: "Seaboard Mobile BV" }, { k: "securityContext.isProxy", v: "false" }, { k: "client.geographicalContext.city", v: "Antwerp" }, { k: "outcome.result", v: "SUCCESS" }],
            context: "HR calendar: Rafi Sandhu is on leave in Belgium this week.",
            answer: "close",
            why: "A mobile carrier, in the country the calendar says. The alert fired on geography, and the network is what a person on holiday uses.",
          },
          {
            id: "a2",
            time: "08:15",
            severity: "Medium",
            rule: "Sign-in failures, single account",
            entity: "c.duarte@quaysidecapital.example",
            fields: [{ k: "securityContext.asOrg", v: "Northpier Hosting Ltd" }, { k: "securityContext.asNumber", v: "64503" }, { k: "securityContext.isProxy", v: "false" }, { k: "client.geographicalContext.city", v: "Bristol" }, { k: "outcome.reason", v: "INVALID_CREDENTIALS" }],
            context: "Bristol is the user's home city.",
            answer: "esc",
            why: "Right city, wrong kind of network. A hosting range is where servers run, so someone sitting at a server is making these attempts, and asOrg told you that in one field.",
          },
          {
            id: "a3",
            time: "09:02",
            severity: "Medium",
            rule: "Sign-in through proxy",
            entity: "k.lund@quaysidecapital.example",
            fields: [{ k: "client.ipAddress", v: "198.51.100.20" }, { k: "securityContext.asOrg", v: "Harbour Fibre Ltd" }, { k: "securityContext.isProxy", v: "true" }, { k: "client.geographicalContext.city", v: "Bristol" }, { k: "outcome.result", v: "SUCCESS" }],
            context: "198.51.100.20 is Quayside's own office egress, behind the company web proxy.",
            answer: "close",
            why: "The flag is true, and the address is your own office. Ordinary corporate egress can trip it, so check the flag against what you know about the address.",
          },
          {
            id: "a4",
            time: "10:37",
            severity: "Medium",
            rule: "Multiple failed sign-ins",
            entity: "f.novak@quaysidecapital.example",
            fields: [{ k: "securityContext.asOrg", v: "Greywake Datacentres GmbH" }, { k: "securityContext.domain", v: "greywake-dc.example" }, { k: "securityContext.isProxy", v: "false" }, { k: "client.geographicalContext.city", v: "Frankfurt" }, { k: "outcome.result", v: "FAILURE" }],
            context: "Nobody at Quayside works in Frankfurt, and the firm has no servers with this provider.",
            answer: "esc",
            why: "Before you read a single outcome.reason, the source tells you this is unlikely to be the user mistyping a password. A data-centre range with no business link to the firm is worth checking.",
          },
          {
            id: "a5",
            time: "12:20",
            severity: "Low",
            rule: "Sign-in from new ISP",
            entity: "j.adeyemi@quaysidecapital.example",
            fields: [{ k: "securityContext.asOrg", v: "Anchor Broadband Ltd" }, { k: "securityContext.isp", v: "Anchor Broadband Ltd" }, { k: "securityContext.isProxy", v: "false" }, { k: "client.geographicalContext.city", v: "Bath" }, { k: "outcome.result", v: "SUCCESS" }],
            context: "Joss Adeyemi moved house last month and works from home on Wednesdays.",
            answer: "close",
            why: "Home broadband, a nearby town, and a reason for the change. New doesn't mean bad when the kind of network is what a person would use.",
          },
        ],
      },
    ],
    // ── Reading 5: factors ──
    "oktaf-r5": [
      {
        kind: "inspect",
        title: "Read the Authenticator Register",
        prompt: "Ngaire Holm pulls Quayside's authenticator register and a sample MFA event. Open each line to see what it is and how it fails. One account in this story is still on the weakest row.",
        artifact: "Security · Authenticators, with one sample event",
        items: [
          { id: "push", text: "Okta Verify (push): 271 enrolled", tag: "One tap", tone: "info", note: "The app gets an approve or deny prompt for a sign-in. Nothing to read or type, so someone who already has the password can keep asking until a person taps." },
          { id: "otp", text: "Okta Verify (one-time passcode): 58 enrolled", tag: "Typed code", tone: "info", note: "The same app shows a short-lived code the user types in, which is handy where push can't reach. A code can be typed into the wrong page as easily as the right one." },
          { id: "fido", text: "FIDO2 (WebAuthn): 31 enrolled", tag: "Phishing-resistant", tone: "trust", note: "A security key or a built-in authenticator like Touch ID. Its signature is tied by cryptography to the real site's address, so it gives a look-alike site nothing to use." },
          { id: "sms", text: "Phone (SMS or voice): 9 enrolled, including e.vance", tag: "Weakest", tone: "warn", note: "A phone number can be moved to another SIM with no mistake by the user at all. The code then goes wherever the number went." },
          { id: "enroll", text: "user.mfa.factor.activate, target AuthenticatorEnrollment", tag: "Enrollment", tone: "info", note: "A factor must be enrolled before it can be used, and the log records that lifecycle. A new enrollment on an account is worth reading in its own right." },
          { id: "name", text: "target.0.displayName: Phone", tag: "Which factor", tone: "info", note: "On an MFA event this names the enrolled factor involved, so you can say exactly which one a challenge or a result refers to." },
          { id: "ip", text: "client.ipAddress: 203.0.113.58", tag: "Whose address", tone: "warn", note: "On a challenge this is the requester's address, not the phone that received the prompt. Don't read it as the user's device." },
        ],
      },
    ],
    // ── Reading 6: the second signature, then the vocabulary ──
    "oktaf-r6": [
      {
        kind: "spotdiff",
        title: "Approved Policy, Live Policy",
        prompt: "Before Thursday's noon sign-off Ngaire Holm compares the live sign-on policy with the copy approved in October. Find every line that weakens what the policy demands, and leave harmless edits alone.",
        primer: {
          title: "How to read a sign-on policy rule",
          points: [
            "A rule is a set of conditions (who, from where) and what it then demands. Rules are checked in order, and the first match decides.",
            "Okta's **sign-on and authentication policies** do the job Entra's Conditional Access does, with their own rules and their own log events.",
            "For each changed line ask three things: does the rule now reach more people, demand less, or last longer?",
            "Weakening rarely deletes a rule. It changes one value and leaves the name alone.",
            "Owners and descriptions are labels. They change nothing that's enforced.",
          ],
          example: {
            label: "Worked example: a door rule",
            lines: [
              "`IF badge is Contractor, THEN escort required: Yes`.",
              "Change Yes to No and the rule keeps its name while the door gets weaker. Change the note beside it to `Reviewed` and nothing about the door has moved.",
            ],
          },
        },
        goodTitle: "Approved copy · CHG-4417 · 12 Oct",
        suspectTitle: "Live policy · last event: policy.rule.update",
        good: [
          "Policy: Quayside global session policy",
          "Rule 1: Vendor network",
          "  Applies to: Vendors",
          "  Exclude group: Treasury-Approvers",
          "  IF IP is in zone: Vendor-Partners",
          "  THEN require MFA: Yes",
          "  Session idle timeout: 2 hours",
          "  Owner: i.sorel",
          "Rule 2: Office network",
          "  IF IP is in zone: Quayside-Office",
          "  THEN require MFA: Yes",
          "  Description: Staff on site",
          "Rule 3: Catch-all",
          "  THEN require MFA: Yes",
        ],
        suspect: [
          "Policy: Quayside global session policy",
          "Rule 1: Vendor network",
          "  Applies to: Vendors",
          "  Exclude group: (none)",
          "  IF IP is in zone: Vendor-Partners",
          "  THEN require MFA: No",
          "  Session idle timeout: 12 hours",
          "  Owner: IAM team",
          "Rule 2: Office network",
          "  IF IP is in zone: Quayside-Office",
          "  THEN require MFA: Yes",
          "  Description: Staff on the office network",
          "Rule 3: Catch-all",
          "  THEN require MFA: Yes",
        ],
        diffs: [
          { line: 3, why: "The exclusion kept Treasury-Approvers away from this rule. With it gone, the rule reaches more people, and those are the people who sign off payments." },
          { line: 5, why: "From this zone a password is now enough. That's the line that matters most, and the rule's name gives no hint of it." },
          { line: 6, why: "An idle session now lasts six times longer, so an unattended or stolen session stays useful for most of a day." },
        ],
        decoys: [
          { line: 7, why: "The owner label moved to a team name. It enforces nothing." },
          { line: 11, why: "A reworded description. Rule 2 demands exactly what it did." },
        ],
        lesson: "Rule name, order and status all survived, so nothing looked broken. Compare what a rule reaches, what it demands and how long it lasts. Three small edits turned a guarded door into a side door.",
        hud: "Tap the lines that weaken the policy",
        sameLine: "That line matches the approved copy.",
        winTitle: "Every weakening found",
        howTo: ["Compare the live policy with the approved copy, line by line.", "Tap each line that weakens what the policy demands.", "Tapping a harmless or identical line costs a life."],
      },
      {
        kind: "match",
        title: "Same Job, Different Name",
        prompt: "A colleague joining from an Entra shop asks Ngaire Holm where things live here. Match each Entra term with what does that job in Okta.",
        primer: {
          title: "An Entra habit on an Okta log",
          points: [
            "The two platforms often have a different word for the same part, so the word you search for depends on which IdP issued the log.",
          ],
          example: {
            label: "Worked example: tenant and org",
            lines: ["Entra calls the customer's whole environment a **tenant**. Okta calls it an **org**. Same idea, and searching for the wrong word finds nothing."],
          },
        },
        pairs: [
          { id: "ca", left: "Conditional Access", right: "Sign-on and authentication policies", why: "Both decide when to demand more proof, with different rule syntax and different log events." },
          { id: "idp", left: "Identity Protection", right: "ThreatInsight and Okta's risk scoring", why: "Both score risk, and each uses its own fields, logic and event names." },
          { id: "dir", left: "Entra's directory, tied into the Microsoft stack", right: "Universal Directory", why: "Universal Directory is platform-neutral. It can stand alone or sync from Active Directory, Google Workspace or an HR system." },
          { id: "upn", left: "UserPrincipalName", right: "actor.alternateId", why: "Both hold the readable account name, usually an email address." },
          { id: "ip", left: "IPAddress on a sign-in", right: "client.ipAddress", why: "Same idea, and client.ipAddress is the field name to filter on here." },
        ],
      },
    ],
    // ── la1 warm-up: name what was lost ──
    "oktaf-la1": [
      {
        kind: "defuse",
        title: "What Did They Actually Get?",
        prompt: "The month-end duty desk has four small cases on it before the clock runs out. For each one, work out what is actually in the wrong hands, then cut the action that cancels it.",
        primer: {
          title: "Name what was lost, then cancel that",
          points: [
            "Before acting, ask what the other side now holds: a credential, a session or a right.",
            "Each has its own off switch. A token is revoked, a session is cleared, a membership is removed.",
            "Closing one doesn't close another, because none of them depends on the rest.",
            "After you cancel it, read what it was used for. Containment and scoping go together.",
          ],
          example: {
            label: "Worked example: a courier's master key",
            lines: [
              "A courier loses the master key to the post room. The lost thing is the key, so the lock gets changed, and then the door log gets read.",
              "The lock is the off switch for that key.",
            ],
          },
        },
        device: "Month-end duty desk",
        seconds: 100,
        rounds: [
          {
            id: "token",
            state: "A reporting script's API token is in clear text in a build log on the wiki. The System Log shows no calls with it so far.",
            wires: [
              { id: "wiki", label: "Delete the line from the wiki page" },
              { id: "revoke", label: "Revoke the token, then read what it called" },
              { id: "owner", label: "Reset the script owner's password" },
            ],
            cut: "revoke",
            hint: "What exactly could someone copy from that page?",
            why: "The token is what was exposed, and deleting the text doesn't un-copy it. Its owner's password has no effect on a token already issued.",
          },
          {
            id: "session",
            state: "A fund accountant's unlocked laptop was taken on a train, with the browser still signed in to the SSO portal.",
            wires: [
              { id: "clear", label: "Clear the user's sessions, then read what they did" },
              { id: "disk", label: "Rely on the laptop's disk encryption" },
              { id: "group", label: "Remove the user from every group" },
            ],
            cut: "clear",
            hint: "The thief doesn't need to sign in. Why not?",
            why: "A live session is what was taken. Disk encryption protects a machine that's off, not one that's unlocked. Clearing the session ends it without stripping an innocent user's access.",
          },
          {
            id: "seat",
            state: "A leaver's account is still in Treasury-Approvers, because the HR feed missed it and group.user_membership.remove never fired.",
            wires: [
              { id: "mfa", label: "Require MFA on Treasury-Approvers" },
              { id: "pw", label: "Reset the leaver's password" },
              { id: "remove", label: "Remove the membership, then check the group's recent activity" },
            ],
            cut: "remove",
            hint: "Is the problem how this account gets in, or what it can do?",
            why: "The excess is a right, so the right gets removed. A new password or a stronger gate leaves an ex-employee as an approver.",
          },
          {
            id: "all",
            state: "A consultant's account has three live things at once: an open session, an API token it created, and a seat on the Settlement Portal.",
            wires: [
              { id: "sess", label: "Clear the session: a token dies with its creator's sign-out" },
              { id: "seatonly", label: "Remove the seat: a token can't reach an app it isn't assigned to" },
              { id: "all", label: "Close all three together, then read what each one did" },
            ],
            cut: "all",
            hint: "Which of these three needs any of the others in order to work?",
            why: "None does. A token works with no session, and a seat waits for the next sign-in. Three separate ways back in get closed together, then scoped.",
          },
        ],
        lesson: "Name what was actually lost, then cancel that exact thing and read what it was used for. A token, a session and a membership each have their own off switch, and closing one leaves the others working.",
      },
    ],
    // ── Reading 7: system events ──
    "oktaf-r7": [
      {
        kind: "worksheet",
        title: "Count What Had Already Happened",
        prompt: "Later that Tuesday the source sped up, and Okta logged its own reaction. Ngaire Holm hands you the rows. Work out what the limiter's arrival did and didn't change.",
        primer: {
          title: "When Okta reports on itself",
          points: [
            "Leading `system.` means Okta's own platform event. Some are its own infrastructure acting, with `actor.type` SystemPrincipal. Others, like `system.api_token.create`, record what an admin did, so read the actor.",
            "`system.org.rate_limit.warning` means traffic on an endpoint is nearing its limit. `system.org.rate_limit.violation` means the limit was passed and requests are being rejected.",
            "Limits are per org and per endpoint, not per source IP.",
            "A rate-limit event often shows `outcome.result` SUCCESS: the limiter did its job. That word is about the limiter.",
            "An API token is a powerful, often long-lived credential that needs no interactive MFA once issued, so an unexpected one is a persistence signal.",
          ],
          example: {
            label: "Worked example: a car park barrier",
            lines: [
              "The barrier drops when the car park reaches 200 cars. Car 201 waits outside.",
              "To know what's in the car park you still count the 200. The barrier only speaks for what comes next.",
            ],
          },
        },
        caption: "System Log · Tuesday · 23:20 to 23:24 · /api/v1/authn traffic",
        columns: ["published", "eventType", "actor.type", "actor", "URI"],
        rows: [
          ["23:20:04", "user.account.lock", "User", "q.tan", "/api/v1/authn"],
          ["23:20:39", "user.account.lock", "User", "r.boyle", "/api/v1/authn"],
          ["23:21:12", "user.account.lock", "User", "s.ilves", "/api/v1/authn"],
          ["23:21:48", "user.account.lock", "User", "t.marin", "/api/v1/authn"],
          ["23:22:20", "system.org.rate_limit.warning", "SystemPrincipal", "Okta system", "/api/v1/authn"],
          ["23:22:31", "user.account.lock", "User", "u.hale", "/api/v1/authn"],
          ["23:23:02", "system.org.rate_limit.violation", "SystemPrincipal", "Okta system", "/api/v1/authn"],
        ],
        questions: [
          { id: "locked", q: "How many accounts were already locked when the violation event fired?", hint: "Count the user.account.lock rows above it.", answer: ["5", "five"], why: "Five, and all five stay locked until they are unlocked, which logs user.account.unlock. The limiter reacts to volume from here on." },
          { id: "warn", q: "How many accounts were locked after the warning event?", hint: "A warning is only a warning. Look just below it.", answer: ["1", "one"], why: "One. u.hale locked eleven seconds after the warning, because a warning rejects nothing." },
          { id: "actor", q: "How many rows have Okta's own infrastructure as the actor?", hint: "Read the actor.type column.", answer: ["2", "two"], why: "The two rate-limit rows. No person or application account acted there, which is why actor.type matters." },
        ],
      },
    ],
    // ── Reading 8: actor and target, then the signature console ──
    "oktaf-r8": [
      {
        kind: "sort",
        title: "Routine, or Review Now?",
        prompt: "Ngaire Holm reads every admin event as two questions: who acted, and what was touched. These rows are from Quayside's last quarter. Sort them.",
        primer: {
          title: "Read actor and target as two questions",
          points: [
            "`actor` performed the action. `target` is what it was done to, and the array can hold several objects, such as a user and a group.",
            "Sign-ins are rarely where abuse shows. It shows in `user.*`, `group.user_membership.*` and `policy.rule.*` events that come after.",
            "The same eventType can be routine or serious. The pair of identities and the facts around it decide.",
            "When actor and target are one identity and that identity gained rights, it gave them to itself. Compare the IDs, not the display names.",
            "When they differ and nothing explains the change, ask whether the actor's own account is in someone else's hands.",
          ],
          example: {
            label: "Worked example: a due password change",
            lines: [
              "`user.account.update_password`, actor `d.lowe`, target `d.lowe`, from the office, on the day the password fell due.",
              "Same identity on both sides, and no rights were gained. Routine. The same pair on `user.account.privilege.grant` would be a very different finding.",
            ],
          },
        },
        buckets: [{ id: "ok", label: "Routine administration" }, { id: "review", label: "Review now" }],
        items: [
          { id: "a", text: "group.user_membership.add · actor i.sorel · target new starter, group Finance-Readers · ticket HR-2291", bucket: "ok", why: "An admin, a standard group and a ticket: this is what the event looks like when it's normal." },
          { id: "b", text: "user.account.privilege.grant · actor t.brandt · target.0 t.brandt · 02:40 · no ticket", bucket: "review", why: "Same identity on both sides, and it gained an admin right. That's a change to read in full, whatever the account's history." },
          { id: "c", text: "group.user_membership.remove · actor i.sorel · target leaver · group Treasury-Readers · HR feed", bucket: "ok", why: "Removing a leaver is the system working. Read the verb as well as the object." },
          { id: "d", text: "group.user_membership.add · actor a.rosen · target svc-reporting · group IT-Operations · no ticket", bucket: "review", why: "A low-privilege service account moved into an IT group by someone with no reason to do it. The actor is a question too." },
          { id: "e", text: "group.user_membership.add · actor b.lindqvist (Facilities) · target l.marsh · group Treasury-Readers · no ticket · actor's session on a hosting ASN", bucket: "review", why: "Facilities has no reason to hand out Treasury access, and the actor's own session sits on a hosting network. The target did nothing here: the actor's account is the concern." },
          { id: "f", text: "policy.rule.update · actor i.sorel · target Office network · 11:05 · CHG-4502", bucket: "ok", why: "Policy changes are rare, so each deserves a look. This one has a change record, in working hours, from the person who owns it." },
          { id: "g", text: "user.mfa.factor.activate · actor r.sandhu · target r.sandhu · from home · ticket for a new phone", bucket: "ok", why: "Same identity, and nothing gained. Actor equals target is only a warning when rights moved." },
        ],
      },
      SYSTEM_LOG_LAB,
    ],
  },
};
