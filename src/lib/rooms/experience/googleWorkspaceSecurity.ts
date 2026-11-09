import type { BriefingLab, RoomExperience } from "./types";

// "Operation Shared Drive" for the "google-workspace-security" room.
// Script: docs/campaign/68-google-workspace-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Larkspur Studios (fictional animation studio), not the graded tasks' MedCore Health records.
// Signature mechanic: a Workspace-style admin console on the entra skin, played twice in one
// incident. "Read the Mail Trail" works the Gmail and login logs; "Contained, or Just Quiet?"
// follows a token through the OAuth and Admin logs, revokes it, blocks it by client ID and ends at
// the proof. The order of a full response is taught on a separate incident, a forwarding setting.
// Plus two spotdiffs: two grants of two apps with the same name, and two sharing states.
// Arcade mix: codebreak + portal + spotdiff.
// Event names and parameters in the console are the native Reports API ones (login_success,
// suspicious_login, change_user_access, change_document_visibility, RESET_SIGNIN_COOKIES,
// REVOKE_3LO_TOKEN, ADD_TO_BLOCKED_OAUTH2_APPS, originating_app_id, Has delegate). The room's own
// flattened gws.* fields carry only real Reports API parameters (token app_name, client_id,
// client_type, scope; admin USER_EMAIL) and appear only where the console says they are the SIEM
// export. Governance facts (access setting, verification, publisher, offline access) are Admin
// console lookups, never log fields: the token audit log records none of them.
// Lab data differs from the graded tasks: a composer's hijacked mailbox in a cue sheet thread with
// a link, never a supplier's invoice thread (q1); Reel Review with drive.readonly and
// contacts.readonly, never FormFlow Sync with drive and calendar (la1); 212 downloads in 7
// minutes from 203.0.113.58, never 340 in 11 from Amsterdam (la2); containment by
// RESET_SIGNIN_COOKIES and a forced change at next login, never a CHANGE_PASSWORD closure (q2, q4);
// a sharing change from people_within_domain_with_link to people_with_link with an outside dub
// vendor, never private to anyone-with-the-link followed by an unknown IP (q3); the queue's quiet
// grant is calendar.freebusy on Shift Planner, never drive.file on a writing app (ac1); the time
// drill answers 12, 24 and 289 minutes, never 16 (f1).

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const FAKE_ID = "881634027715-k2n7d4s9f1c8v6b3m5x0.apps.googleusercontent.com";
const REAL_ID = "402817365520-t8q1w4e7r2y9u3i6o0p5.apps.googleusercontent.com";

const MAIL_TABS = [{ id: "basic", label: "Basic info" }, { id: "auth", label: "Authentication" }, { id: "link", label: "Links" }, { id: "delegate", label: "Delegate" }];

const MAIL_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "Read the Mail Trail",
  prompt: "Tuesday, 09:05. A film blog has posted 12 frames from reel 6 of The Lantern Keeper, and the production files sit behind j.aldana's account. Mei-Ling Castro opens the Admin console and slides you the keyboard. Find out how anyone reached j.aldana: the mail first, then the sign-ins.",
  product: "Admin console",
  resource: "Larkspur Studios",
  tenant: "larkspur.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Home" }, { id: "users", label: "Users" }] },
    { group: "Audit and investigation", items: [{ id: "gmail", label: "Gmail log events" }, { id: "login", label: "Login log events" }] },
  ],
  pages: {
    overview: { heading: "Home", tiles: [{ label: "Users", value: "240" }, { label: "Shared drives", value: "38" }, { label: "Apps with audit logs", value: "9" }], note: "Domain larkspur.example. Domain is Google's word for the organisation. Users, security policy and app access are all managed here, and each app writes its own log." },
    gmail: {
      heading: "Gmail log events",
      filters: ["Owner: j.aldana", "Last 48 hours"],
      note: "The Authentication tab shows each message's results as the SIEM export stores them.",
      table: {
        columns: ["Date", "Event", "Owner", "From (Header address)", "Subject", "Spam classification"],
        rows: [
          { id: "g-news", cells: ["Mon 09:00:11", "Receive", "j.aldana", "newsletter@frameworks.example", "Frameworks weekly", "Clean"], record: "g-news" },
          { id: "g-spoof", cells: ["Mon 11:06:18", "Receive", "j.aldana", "accounts@larkspur.example", "Payroll portal update", "Phishing"], record: "g-spoof", tone: "medium" },
          { id: "g-send", cells: ["Mon 15:02:44", "Send", "j.aldana", "j.aldana@larkspur.example", "Cast call sheet, week 46", "-"], record: "g-send" },
          { id: "g-cue", cells: ["Mon 16:12:05", "Receive", "j.aldana", "n.vale@valemusic.example", "Re: Reel 6 cue sheet", "Clean"], record: "g-cue" },
          { id: "g-click", cells: ["Mon 16:13:22", "Link click", "j.aldana", "n.vale@valemusic.example", "Re: Reel 6 cue sheet", "-"], record: "g-click" },
        ],
      },
    },
    login: {
      heading: "Login log events",
      filters: ["Last 48 hours"],
      table: {
        columns: ["Date", "Event name", "User", "Login type", "Challenge method", "IP address"],
        rows: [
          { id: "l-cb", cells: ["Sun 23:14:37", "suspicious_login", "c.brandt", "-", "-", "203.0.113.70"], record: "l-cb", tone: "medium" },
          { id: "l-si", cells: ["Mon 07:58:20", "login_failure", "s.ito", "google_password", "password", "198.51.100.20"] },
          { id: "l-ver", cells: ["Mon 08:41:02", "login_verification", "j.aldana", "google_password", "google_prompt", "198.51.100.20"], record: "l-ver" },
          { id: "l-ja", cells: ["Mon 08:41:09", "login_success", "j.aldana", "google_password", "password, google_prompt", "198.51.100.20"], record: "l-ja" },
          { id: "l-out", cells: ["Mon 18:37:44", "logout", "j.aldana", "-", "-", "198.51.100.20"] },
        ],
      },
    },
    users: {
      heading: "Users",
      table: {
        columns: ["Name", "Email", "Job title", "2-Step Verification"],
        rows: [
          { id: "u-ja", cells: ["Jonas Aldana", "j.aldana@larkspur.example", "Line Producer", "Enrolled"], record: "u-ja" },
          { id: "u-lm", cells: ["Lena Marsh", "l.marsh@larkspur.example", "Production Assistant", "Enrolled"], record: "u-lm" },
          { id: "u-cb", cells: ["Cora Brandt", "c.brandt@larkspur.example", "Post Coordinator", "Enrolled"], record: "u-cb" },
        ],
      },
    },
  },
  records: {
    "g-news": { id: "g-news", title: "Event details", actions: MAIL_TABS, facts: [["Event", "Receive"], ["From (Header address)", "newsletter@frameworks.example"], ["Subject", "Frameworks weekly"]], panes: { auth: [["gws.spf_result", "PASS"], ["gws.dkim_result", "PASS"], ["gws.dkim_domain", "frameworks.example"], ["gws.dmarc_result", "PASS"], ["gws.dmarc_policy", "none"], ["gws.classification", "inbox"]], link: [["Links", "Unsubscribe only"]], delegate: [["Has delegate", "false"]] } },
    "g-spoof": { id: "g-spoof", title: "Event details", actions: MAIL_TABS, facts: [["Event", "Receive"], ["From (Header address)", "accounts@larkspur.example"], ["From (Envelope)", "bounce@mailer-41.example"], ["Subject", "Payroll portal update"], ["IP address", "203.0.113.144"]], panes: { auth: [["gws.spf_result", "PASS"], ["SPF domain", "mailer-41.example"], ["gws.dkim_result", "NONE"], ["gws.dkim_domain", "none"], ["gws.dmarc_result", "FAIL"], ["gws.dmarc_policy", "quarantine"], ["gws.classification", "quarantined"], ["gws.spam_score", "8.7"]], link: [["Target link URL", "https://payroll-larkspur.example/login"], ["Clicked", "No: the message never reached the inbox"]], delegate: [["Has delegate", "false"]] } },
    "g-send": { id: "g-send", title: "Event details", actions: MAIL_TABS, facts: [["Event", "Send"], ["Owner", "j.aldana@larkspur.example"], ["Subject", "Cast call sheet, week 46"], ["IP address", "198.51.100.20"]], panes: { auth: [["Result", "Outbound message: checked by the receiving side"]], link: [["Links", "None"]], delegate: [["Has delegate", "true"], ["Delegate", "l.marsh@larkspur.example"], ["Owner", "j.aldana@larkspur.example"], ["Mailbox delegation since", "2024-09-02"]] } },
    "g-cue": { id: "g-cue", title: "Event details", actions: MAIL_TABS, facts: [["Event", "Receive"], ["From (Header address)", "n.vale@valemusic.example"], ["Subject", "Re: Reel 6 cue sheet"], ["Message ID", "<b7c1e4a9@mail.valemusic.example>"], ["IP address", "198.51.100.77"], ["Has attachment", "false"]], panes: { auth: [["gws.spf_result", "PASS"], ["gws.dkim_result", "PASS"], ["gws.dkim_domain", "valemusic.example"], ["gws.dmarc_result", "PASS"], ["gws.dmarc_policy", "reject"], ["gws.classification", "inbox"], ["gws.spam_score", "0.2"]], link: [["Target link URL", "https://cue-review.example/reel6"], ["Link domain", "cue-review.example"], ["First seen in this domain", "Mon 16:12"], ["Thread history", "14 messages from n.vale since March"], ["Sender history", "PDF attachments every time, never a link"]], delegate: [["Has delegate", "false"]] } },
    "g-click": { id: "g-click", title: "Event details", actions: MAIL_TABS, facts: [["Event", "Link click"], ["Owner", "j.aldana@larkspur.example"], ["Target link URL", "https://cue-review.example/reel6"], ["IP address", "198.51.100.20"]], panes: { auth: [["Result", "See the Receive event for this message"]], link: [["Link domain", "cue-review.example"]], delegate: [["Has delegate", "false"]] } },
    "l-cb": { id: "l-cb", title: "Event details", facts: [["Event name", "suspicious_login"], ["affected_email_address", "c.brandt@larkspur.example"], ["login_timestamp", "Sun 23:14:37"], ["IP address", "203.0.113.70"], ["Mei-Ling's note", "Lisbon hotel. Confirmed by Cora on the phone: a trip that was on the calendar"]] },
    "l-ver": { id: "l-ver", title: "Event details", facts: [["Event name", "login_verification"], ["login_type", "google_password"], ["login_challenge_method", "google_prompt"], ["is_second_factor", "true"], ["login_challenge_status", "Challenge Passed."]] },
    "l-ja": { id: "l-ja", title: "Event details", facts: [["Event name", "login_success"], ["User", "j.aldana@larkspur.example"], ["login_type", "google_password"], ["login_challenge_method", "password, google_prompt"], ["is_suspicious", "false"], ["IP address", "198.51.100.20"]] },
    "u-ja": { id: "u-ja", title: "Jonas Aldana", actions: [{ id: "basic", label: "User details" }, { id: "sec", label: "Security" }, { id: "apps", label: "Connected applications" }], facts: [["Email", "j.aldana@larkspur.example"], ["Job title", "Line Producer"], ["Mailbox delegates", "l.marsh@larkspur.example"]], panes: { sec: [["2-Step Verification", "Enrolled: Google prompt"], ["Password last changed", "2026-08-19"], ["Last sign-in", "Mon 08:41"]], apps: [["Reel Review", `Authorized 2025-03-03, client ${REAL_ID.slice(0, 12)}`], ["Reel Review (second entry)", `Authorized Mon 16:14, client ${FAKE_ID.slice(0, 12)}`]] } },
    "u-lm": { id: "u-lm", title: "Lena Marsh", facts: [["Email", "l.marsh@larkspur.example"], ["Job title", "Production Assistant to J. Aldana"], ["Delegate of", "j.aldana@larkspur.example"]], actions: [{ id: "undelegate", label: "Remove mailbox delegation" }] },
    "u-cb": { id: "u-cb", title: "Cora Brandt", facts: [["Email", "c.brandt@larkspur.example"], ["Job title", "Post Coordinator"], ["Last sign-in", "Mon 09:12"]], actions: [{ id: "suspendcb", label: "Suspend user" }] },
  },
  steps: [
    { id: "log", ask: "Mail first. Open the log where Gmail records what happened to each message.", hint: "Audit and investigation, in the menu on the left.", target: "menu:gmail", why: "Each Workspace app has its own audit log. There is no one shared feed to search, so you start by choosing the log." },
    { id: "spoof", ask: "One message never reached the inbox. Open it.", hint: "Read the Spam classification column: only one row isn't Clean.", target: "row:g-spoof", why: "It claims to come from Larkspur's own domain, but the envelope sender and the IP address say otherwise." },
    { id: "spoofauth", ask: "See how the three checks scored it.", hint: "The detail tabs across the top of the pane.", target: "action:auth", why: "SPF passed, but only for mailer-41.example: SPF checks the envelope domain, not the From address you see. There's no DKIM signature. DMARC asks whether a passing check lines up with the From domain, larkspur.example, and nothing does, so DMARC FAIL, and the domain's policy says quarantine. This is the job the checks are built for: a domain name used by someone it never authorised." },
    { id: "cue", ask: "Now the message j.aldana clicked through on Monday afternoon. Open the row where it arrived.", hint: "The Receive event just before the Link click.", target: "row:g-cue", why: "A reply from Nadia Vale, the film's composer, in a thread that has run since March. No attachment, one link." },
    { id: "cueauth", ask: "Run the same reading on this one.", hint: "The Authentication tab again.", target: "action:auth", why: "PASS, PASS, PASS, with gws.dkim_domain matching the sender, and even a reject policy. So valemusic.example's own servers really sent this. A low spam score adds nothing either: mail from a taken-over mailbox looks like that person's normal mail. The checks say which infrastructure sent it, never who is at the keyboard." },
    { id: "cuelink", ask: "The checks can't judge this message. Find what can.", hint: "Sender history, the thread, and the link itself.", target: "action:link", why: "14 messages with PDF attachments and never a link, then a link to a domain first seen that same minute. A clean authentication result moves the question to sender history, thread context and the link. This mailbox has been taken over." },
    { id: "send", ask: "One more thing looks odd: j.aldana was in the edit suite at 15:02, and yet a Send sits in the log. Open it.", hint: "The only Send event on the page.", target: "row:g-send", why: "The Owner column says whose mailbox it is. It doesn't always say whose hands were on it." },
    { id: "delegate", ask: "Find out who really sent it.", hint: "There's a tab for it.", target: "action:delegate", why: "Has delegate is true, and Delegate names l.marsh, j.aldana's assistant, set up in 2024. Read the actor against the object: owner and actor aren't always the same person, and here the difference is routine." },
    { id: "login", ask: "Now the sign-ins. Did anyone get into j.aldana's account after that link?", hint: "Login log events, in the same group.", target: "menu:login", why: "login_success, login_failure, suspicious_login: this log records authentication, and nothing else." },
    { id: "lastlogin", ask: "Open j.aldana's last successful sign-in.", hint: "A login_success event for j.aldana.", target: "row:l-ja", why: "08:41, from the office, password plus Google prompt, is_suspicious false, and then nothing until logout. There is no sign-in at 16:13. The suspicious_login on the page is c.brandt's, and it's a different story." },
    { id: "users", ask: "So no intruder signed in, and yet the link led somewhere. Go to the account itself.", hint: "Users, near the top of the menu.", target: "menu:users", why: "If a log of sign-ins shows nothing, check what the account has handed out." },
    { id: "who", ask: "Open j.aldana.", hint: "The Line Producer.", target: "row:u-ja", why: "2-Step Verification is enrolled and the password is months old. The account looks healthy." },
    { id: "apps", ask: "Check what this account has given access to.", hint: "The tab that lists applications.", target: "action:apps", why: "Reel Review appears twice, and the second entry was authorized one minute after the click, with a different client number. No password was typed and no prompt was answered. On a consent screen the user delegates access to an app, so nothing is left for 2-Step Verification to challenge, and no malware runs for an endpoint tool to see." },
  ],
  traps: {
    "action:undelegate": "Has delegate on its own isn't a finding. l.marsh has held this delegation since 2024 and it's how the producer's office runs. Removing it breaks real work and proves nothing.",
    "action:suspendcb": "c.brandt's suspicious_login was a hotel in Lisbon, confirmed by phone. A flagged sign-in is a question, and that one has its answer.",
  },
  lesson: "SPF, DKIM and DMARC say whether a domain authorised a message, so a hijacked mailbox passes all three. Judge those messages by sender history, thread and link. And when the login log shows nothing at all, that isn't an all clear: consent grants never pass through a sign-in.",
};

const TOKEN_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "Contained, or Just Quiet?",
  prompt: "Tuesday, 14:10. Wes Ruiz in IT signed j.aldana out of every session at 11:38, closed the alert and wrote 'contained' on the ticket. At 13:55 the blog posted a new frame. Mei-Ling wants to know what that action didn't touch. Follow the second Reel Review, stop it, and show how you'd prove it stopped.",
  product: "Admin console",
  resource: "Larkspur Studios",
  tenant: "larkspur.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Home" }, { id: "users", label: "Users" }] },
    { group: "Security", items: [{ id: "alerts", label: "Alert center" }, { id: "apps", label: "App access control" }] },
    { group: "Audit and investigation", items: [{ id: "oauth", label: "OAuth log events" }, { id: "drive", label: "Drive log events" }, { id: "admin", label: "Admin log events" }] },
  ],
  pages: {
    overview: { heading: "Home", tiles: [{ label: "Users", value: "240" }, { label: "Shared drives", value: "38" }, { label: "Trusted apps", value: "12" }], note: "Domain larkspur.example." },
    alerts: {
      heading: "Alert center",
      table: {
        columns: ["Date", "Alert type", "Severity", "Affected user", "Status"],
        rows: [
          { id: "al-1", cells: ["Mon 16:15", "Activity Rule", "High", "j.aldana", "Closed by w.ruiz, Tue 11:40"], record: "al-1", tone: "high" },
          { id: "al-2", cells: ["Sun 23:15", "Suspicious login blocked", "Medium", "c.brandt", "Closed by m.castro, Mon 09:30"], tone: "medium" },
        ],
      },
    },
    oauth: {
      heading: "OAuth log events",
      filters: ["App name: Reel Review", "Last 7 days"],
      note: "Showing 4 of 268 rows.",
      table: {
        columns: ["Date", "Event name", "App name", "Client ID", "User", "IP address"],
        rows: [
          { id: "t-auth", cells: ["Mon 16:14:31", "authorize", "Reel Review", FAKE_ID.slice(0, 12), "j.aldana", "198.51.100.20"], record: "t-auth" },
          { id: "t-a1", cells: ["Mon 16:52:10", "activity", "Reel Review", FAKE_ID.slice(0, 12), "j.aldana", "203.0.113.58"], record: "t-a1" },
          { id: "t-real", cells: ["Tue 09:15:20", "activity", "Reel Review", REAL_ID.slice(0, 12), "s.ito", "198.51.100.20"], record: "t-real" },
          { id: "t-act", cells: ["Tue 13:48:02", "activity", "Reel Review", FAKE_ID.slice(0, 12), "j.aldana", "203.0.113.58"], record: "t-act", tone: "high" },
        ],
      },
    },
    admin: {
      heading: "Admin log events",
      filters: ["Last 30 days"],
      table: {
        columns: ["Date", "Event name", "Actor", "Target"],
        rows: [
          { id: "a-cookies", cells: ["Tue 11:38:05", "RESET_SIGNIN_COOKIES", "w.ruiz", "j.aldana"], record: "a-cookies" },
          { id: "a-role", cells: ["Oct 20 14:31:09", "ASSIGN_ROLE", "m.castro", "w.ruiz"], record: "a-role" },
          { id: "a-prev", cells: ["Oct 14 10:06:44", "REVOKE_3LO_TOKEN", "m.castro", "v.lindqvist"], record: "a-prev" },
          { id: "a-block", cells: ["Oct 14 10:07:31", "ADD_TO_BLOCKED_OAUTH2_APPS", "m.castro", "Clip Trimmer"], record: "a-block" },
        ],
      },
    },
    users: {
      heading: "Users",
      table: {
        columns: ["Name", "Email", "Job title", "2-Step Verification"],
        rows: [
          { id: "u-ja", cells: ["Jonas Aldana", "j.aldana@larkspur.example", "Line Producer", "Enrolled"], record: "u-ja" },
          { id: "u-si", cells: ["Sora Ito", "s.ito@larkspur.example", "Story Artist", "Enrolled"] },
          { id: "u-wr", cells: ["Wes Ruiz", "w.ruiz@larkspur.example", "IT Support", "Enrolled"] },
        ],
      },
    },
    apps: {
      heading: "App access control",
      note: "Apps are matched by client ID. The display name is whatever the app's developer typed.",
      table: {
        columns: ["App name", "Type", "Client ID", "Access", "Verified", "Users"],
        rows: [
          { id: "app-r1", cells: ["Reel Review", "Web application", REAL_ID.slice(0, 12), "Trusted", "Yes", "31"], record: "app-r1" },
          { id: "app-r2", cells: ["Reel Review", "Web application", FAKE_ID.slice(0, 12), "Not configured", "No", "1"], record: "app-r2" },
          { id: "app-clip", cells: ["Clip Trimmer", "Web application", "731884402196", "Blocked", "No", "0"] },
          { id: "app-shift", cells: ["Shift Planner", "Web application", "560219847733", "Trusted", "Yes", "88"] },
        ],
      },
    },
    drive: {
      heading: "Drive log events",
      filters: ["Actor: j.aldana or shared drive LK Final Animatics", "Last 48 hours"],
      tiles: [{ label: "download events under j.aldana, Mon 21:04 to 21:11", value: "212" }],
      note: "Showing 6 of 240 rows. Originating app ID is the Google Cloud project number of the app behind an action, and it's empty when a person did it directly.",
      table: {
        columns: ["Date", "Event name", "Item name", "User", "IP address", "Originating app ID"],
        rows: [
          { id: "d-own", cells: ["Mon 10:14:33", "download", "LK_budget_wk45.xlsx", "j.aldana", "198.51.100.20", "-"], record: "d-own" },
          { id: "d-vis", cells: ["Mon 12:20:09", "change_document_visibility", "LK_R06_animatic_v9.mov", "c.brandt", "198.51.100.20", "-"], record: "d-vis" },
          { id: "d-usr", cells: ["Mon 12:22:41", "change_user_access", "LK_R06_animatic_v9.mov", "c.brandt", "198.51.100.20", "-"], record: "d-usr" },
          { id: "d-1", cells: ["Mon 21:04:12", "download", "LK_R06_animatic_v9.mov", "j.aldana", "203.0.113.58", "881634027715"], record: "d-1", tone: "high" },
          { id: "d-2", cells: ["Mon 21:04:13", "download", "LK_R06_boards_final.pdf", "j.aldana", "203.0.113.58", "881634027715"], record: "d-1", tone: "high" },
          { id: "d-3", cells: ["Mon 21:11:03", "download", "LK_R07_animatic_v4.mov", "j.aldana", "203.0.113.58", "881634027715"], record: "d-1", tone: "high" },
        ],
      },
    },
  },
  records: {
    "al-1": { id: "al-1", title: "Alert details", facts: [["gws.alert.center.type", "Activity Rule"], ["Rule name", "Sensitive-scope grant by unlisted app"], ["gws.alert.center.id", "7f2c91d0-41ea-4b6e-a0d3-9e15c0b7a214"], ["Affected user", "j.aldana@larkspur.example"], ["Closing note", "w.ruiz: user signed out everywhere, contained"]] },
    "t-auth": { id: "t-auth", title: "Event details", actions: [{ id: "basic", label: "Basic info" }, { id: "scopes", label: "Scopes" }, { id: "siem", label: "SIEM export" }], facts: [["Event name", "authorize"], ["app_name", "Reel Review"], ["client_id", FAKE_ID], ["client_type", "WEB"], ["User", "j.aldana@larkspur.example"], ["IP address", "198.51.100.20"]], panes: { scopes: [["https://www.googleapis.com/auth/drive.readonly", "See and download all your Google Drive files"], ["https://www.googleapis.com/auth/contacts.readonly", "See and download your contacts"]], siem: [["gws.event.type", "token"], ["gws.event.name", "authorize"], ["gws.actor.email", "j.aldana@larkspur.example"], ["gws.token.app_name", "Reel Review"], ["gws.token.client_id", FAKE_ID], ["gws.token.client_type", "WEB"], ["gws.token.scope", "[https://www.googleapis.com/auth/drive.readonly, https://www.googleapis.com/auth/contacts.readonly]"]] } },
    "t-a1": { id: "t-a1", title: "Event details", facts: [["Event name", "activity"], ["app_name", "Reel Review"], ["client_id", FAKE_ID], ["api_name", "drive"], ["method_name", "drive.files.list"], ["IP address", "203.0.113.58"]] },
    "t-real": { id: "t-real", title: "Event details", facts: [["Event name", "activity"], ["app_name", "Reel Review"], ["client_id", REAL_ID], ["api_name", "drive"], ["method_name", "drive.files.get"], ["IP address", "198.51.100.20"]] },
    "t-act": { id: "t-act", title: "Event details", facts: [["Event name", "activity"], ["app_name", "Reel Review"], ["client_id", FAKE_ID], ["api_name", "drive"], ["method_name", "drive.files.get"], ["num_response_bytes", "48211904"], ["IP address", "203.0.113.58"]] },
    "a-cookies": { id: "a-cookies", title: "Event details", actions: [{ id: "basic", label: "Basic info" }, { id: "siem", label: "SIEM export" }], facts: [["Event name", "RESET_SIGNIN_COOKIES"], ["Actor", "w.ruiz@larkspur.example"], ["USER_EMAIL", "j.aldana@larkspur.example"], ["IP address", "198.51.100.20"]], panes: { siem: [["gws.event.type", "admin"], ["gws.event.name", "RESET_SIGNIN_COOKIES"], ["gws.actor.email", "w.ruiz@larkspur.example"], ["gws.admin.user.email", "j.aldana@larkspur.example"]] } },
    "a-role": { id: "a-role", title: "Event details", facts: [["Event name", "ASSIGN_ROLE"], ["Actor", "m.castro@larkspur.example"], ["USER_EMAIL", "w.ruiz@larkspur.example"], ["ROLE_NAME", "User Management Admin"], ["ORG_UNIT_NAME", "/"]] },
    "a-prev": { id: "a-prev", title: "Event details", facts: [["Event name", "REVOKE_3LO_TOKEN"], ["Actor", "m.castro@larkspur.example"], ["USER_EMAIL", "v.lindqvist@larkspur.example"], ["APP_ID", "731884402196"], ["Next admin event", "ADD_TO_BLOCKED_OAUTH2_APPS, 731884402196, one minute later"], ["Case", "Clip Trimmer, last month"]] },
    "a-block": { id: "a-block", title: "Event details", facts: [["Event name", "ADD_TO_BLOCKED_OAUTH2_APPS"], ["Actor", "m.castro@larkspur.example"], ["OAUTH2_APP_NAME", "Clip Trimmer"], ["OAUTH2_APP_ID", "731884402196"], ["ORG_UNIT_NAME", "/"]] },
    "u-ja": { id: "u-ja", title: "Jonas Aldana", facts: [["Email", "j.aldana@larkspur.example"], ["Job title", "Line Producer"], ["Connected app 1", `Reel Review, client ${REAL_ID.slice(0, 12)}, authorized 2025-03-03`], ["Connected app 2", `Reel Review, client ${FAKE_ID.slice(0, 12)}, authorized Mon 16:14`]], actions: [{ id: "revokereal", label: `Revoke client ${REAL_ID.slice(0, 12)}` }, { id: "revokefake", label: `Revoke client ${FAKE_ID.slice(0, 12)}` }, { id: "reset", label: "Reset password" }] },
    "app-r1": { id: "app-r1", title: "Reel Review", facts: [["Client ID", REAL_ID], ["Access", "Trusted"], ["Publisher", "Inkstone Software Ltd"], ["Requested scopes", "https://www.googleapis.com/auth/drive.appdata"]], actions: [{ id: "blockreal", label: "Change access to Blocked" }] },
    "app-r2": { id: "app-r2", title: "Reel Review", facts: [["Client ID", FAKE_ID], ["Access", "Not configured"], ["Publisher", "Not verified"], ["Requested scopes", "https://www.googleapis.com/auth/drive.readonly, https://www.googleapis.com/auth/contacts.readonly"]], actions: [{ id: "block", label: "Change access to Blocked" }, { id: "trust", label: "Change access to Trusted" }] },
    "d-own": { id: "d-own", title: "Event details", facts: [["Event name", "download"], ["doc_title", "LK_budget_wk45.xlsx"], ["User", "j.aldana@larkspur.example"], ["IP address", "198.51.100.20"], ["originating_app_id", "none"]] },
    "d-vis": { id: "d-vis", title: "Event details", facts: [["Event name", "change_document_visibility"], ["doc_title", "LK_R06_animatic_v9.mov"], ["old_value", "people_within_domain_with_link"], ["new_value", "people_with_link"], ["visibility_change", "external"], ["Mei-Ling's note", "c.brandt's change for the dub vendor. Closed again today. One view under it, from the vendor's office"]] },
    "d-usr": { id: "d-usr", title: "Event details", facts: [["Event name", "change_user_access"], ["doc_title", "LK_R06_animatic_v9.mov"], ["target_user", "intake@polyglotdub.example"], ["old_value", "none"], ["new_value", "can_view"], ["visibility_change", "external"]] },
    "d-1": { id: "d-1", title: "Event details", facts: [["Event name", "download"], ["doc_type", "video"], ["owner", "LK Final Animatics"], ["owner_is_shared_drive", "true"], ["User", "j.aldana@larkspur.example"], ["IP address", "203.0.113.58 (hosting provider)"], ["originating_app_id", "881634027715"], ["SIEM count: download, same originating_app_id, 21:04 to 21:11", "212 events"]] },
  },
  steps: [
    { id: "log", ask: "The link led to a consent screen, so start with the log of app grants.", hint: "Audit and investigation, in the menu on the left.", target: "menu:oauth", why: "In SIEM terms this is gws.event.type token: authorize is a new grant, and activity is an app using one." },
    { id: "grant", ask: "Open the grant that followed the link click.", hint: "An authorize event, Monday afternoon. Check the date.", target: "row:t-auth", why: "client_id stays the same for every later use of this grant, so it's the value to pivot on. The app_name is only a label." },
    { id: "scopes", ask: "Read exactly what was granted.", hint: "The tabs across the top of the pane.", target: "action:scopes", why: "drive.readonly reads everything j.aldana can open, shared drives included. For a tool that only needs its own review notes, that's far too much. Read the scope list before anything else." },
    { id: "act", ask: "The alert was closed at 11:40. Has this client ID gone quiet since?", hint: "activity events. Compare the Client ID column, because s.ito uses the other Reel Review.", target: "row:t-act", why: "13:48, two hours after 'contained', from a hosting provider and not from any Larkspur device. An offline grant gives the app's servers a refresh token, so nobody needs to be signed in. Whether a grant is being used, and from where, is always the next question." },
    { id: "admin", ask: "Check what Wes's action really did. Find where it's recorded.", hint: "Admin log events.", target: "menu:admin", why: "Don't take the ticket's word for it. A containment step leaves its own record." },
    { id: "cookies", ask: "Open the action on the ticket.", hint: "The one with j.aldana as the target, today.", target: "row:a-cookies", why: "RESET_SIGNIN_COOKIES ends the browser sessions. The app never used one of those." },
    { id: "field", ask: "Read the whole record your SIEM stores for this action. What does it say it did to app grants?", hint: "The view your SIEM stores.", target: "action:siem", why: "Nothing. RESET_SIGNIN_COOKIES carries one parameter, the user's email: it ends browser sessions and touches no grant. A revoked grant writes its own REVOKE_3LO_TOKEN row, and there is none for j.aldana. Wes acted, and every grant is still in place, so the ticket is open, whatever it says." },
    { id: "users", ask: "End it. Grants are removed per user, so go to the account.", hint: "Users, near the top of the menu.", target: "menu:users", why: "The app is still reading, and revoking erases none of the audit history." },
    { id: "who", ask: "Open j.aldana.", hint: "The Line Producer.", target: "row:u-ja", why: "Two grants with one name. Only the numbers tell them apart." },
    { id: "revoke", ask: "Revoke the grant behind this incident, and only that one.", hint: "Match the client number from the OAuth log.", target: "action:revokefake", why: "Only this removes the token: 881634027715 can't refresh any more. The Admin log records it as REVOKE_3LO_TOKEN." },
    { id: "apps", ask: "Revoking ends this grant, but anyone else at Larkspur could still click Allow. Go to where apps are controlled.", hint: "App access control, under Security.", target: "menu:apps", why: "Revoking cleans up one user. Blocking closes the door for the whole domain." },
    { id: "app", ask: "Open the entry for the app you just revoked.", hint: "Two rows share a name. Read the Client ID.", target: "row:app-r2", why: "Access Not configured means no admin ever decided anything about it. Not verified means Google never reviewed it. Neither one stopped the app from working." },
    { id: "block", ask: "Stop this client ID from being authorized again.", hint: "The access buttons on the app's entry.", target: "action:block", why: "Blocked, by client ID. The name stays free for the real Reel Review, and the story team doesn't lose a tool." },
    { id: "prove", ask: "Don't assume those two clicks worked. See what proof looks like: open how last month's case was closed.", hint: "Admin log events: the REVOKE_3LO_TOKEN row.", target: "row:a-prev", why: "Last month Mei-Ling closed the Clip Trimmer case with two rows here: REVOKE_3LO_TOKEN and, a minute later, ADD_TO_BLOCKED_OAUTH2_APPS. Your two actions must show up the same way, and only then is containment a fact." },
  ],
  traps: {
    "action:reset": "Not a containment step here. This token holds Drive and Contacts scopes, and only Gmail-scoped refresh tokens stop on a password change. Revoke the specific grant.",
    "action:revokereal": "That client ID is the sanctioned Reel Review the story team works in. Same name, different app: the client ID identifies a grant.",
    "action:blockreal": "That's the sanctioned app, Trusted since 2025, with 31 users. Blocking by name stops the story team and leaves the real problem alone. Match the client ID.",
    "action:trust": "Trusted tells the whole domain that this app has been approved. Nothing in this entry has earned that.",
  },
  lesson: "A sign-out or a password change is not the end of an app grant, so read the record of what each action really did. Identify an app by client ID, because its name proves nothing. A case is closed by evidence, not by a word on a ticket.",
};

export const GOOGLE_WORKSPACE_SECURITY: RoomExperience = {
  roomId: "google-workspace-security",
  codename: "Operation Shared Drive",
  theme: "shareddrive",
  handler: { name: "Mei-Ling Castro", role: "Workspace Security Admin, Larkspur Studios" },
  briefing: [
    "Larkspur Studios. 240 people, one Google Workspace domain, and six weeks until The Lantern Keeper reaches cinemas.",
    "Every frame of the film lives on shared drives, and this morning twelve of them turned up on a film blog.",
    "Mei-Ling Castro runs Workspace security, and the sign-in log says nobody got in. So how did the frames get out?",
    "Learn Workspace's own logs, find a grant nobody noticed, and make sure that 'contained' really means contained.",
  ],
  mission: "Read Workspace's audit logs in their own words, trace a clean-looking email, compare two grants of two apps with one name, spot a widened file, stop a live token and prove it stopped, then close the graded case.",
  estimate: "~60 min",
  look: { primary: "#9d8cff", secondary: "#ffd166", warn: "#ff6b6b" },
  scene: "facilityshareddrive",
  layout: "facility",
  story: {
    intro: { title: "Twelve Frames", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-intro-c4fec027.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-intro-73862cb7.jpg" },
    afterStation: {
      console: { title: "Nobody Signed In", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-ch2-d34d21b6.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-ch2-52ab9539.jpg" },
      consent: { title: "Contained", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-ch3-cfe8a55c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-ch3-7d978d6c.jpg" },
      finalcut: { title: "Final Cut", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-finale-075cb822.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/google-workspace-security/shareddrive-finale-1a52540c.jpg" },
    },
  },
  stations: [
    {
      id: "console",
      label: "The Admin Console",
      topic: "Workspace in the SOC · gws.event.type and gws.event.name · SPF, DKIM and DMARC in Gmail's fields",
      tagline: "One console, a log for every app",
      building: "control",
      taskIds: ["gwsf-r1", "gwsf-r2", "gwsf-r3", "gwsf-q1"],
    },
    {
      id: "consent",
      label: "The Consent Screen",
      topic: "OAuth scopes · offline and online tokens · app access setting and verification in the Admin console",
      tagline: "Nobody signed in",
      building: "office",
      taskIds: ["gwsf-r4", "gwsf-la1"],
    },
    {
      id: "drive",
      label: "The Shared Drive",
      topic: "The Drive audit · sharing changes · download bursts · the Admin audit log",
      tagline: "Contained, or just quiet?",
      building: "vault",
      taskIds: ["gwsf-r5", "gwsf-la2", "gwsf-r6", "gwsf-q2"],
    },
    {
      id: "suites",
      label: "Two Suites",
      topic: "Alert Center · Workspace against Microsoft 365 · telling a sanctioned grant from a bad one",
      tagline: "Same job, different words",
      building: "lab",
      taskIds: ["gwsf-r7", "gwsf-r8", "gwsf-ac1", "gwsf-m1"],
    },
    {
      id: "finalcut",
      label: "Final Cut",
      topic: "The full response to a malicious grant · timing the attack · proving the case is closed",
      tagline: "Is it really over?",
      building: "ticket",
      taskIds: ["gwsf-o1", "gwsf-f1", "gwsf-q3", "gwsf-q4"],
      boss: true,
    },
  ],
  personas: {
    "gwsf-q1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Three fields, one thread. Tell me what they prove." },
    "gwsf-la1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Read this grant for me, field by field." },
    "gwsf-la2": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Walk me through this burst." },
    "gwsf-q2": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Before anyone touches this ticket, read the record." },
    "gwsf-ac1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Another user, another app. Your call." },
    "gwsf-m1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "The new hire comes from a Microsoft shop. Line it up for them." },
    "gwsf-o1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "It's confirmed. What happens, and in what order?" },
    "gwsf-f1": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Give me the number for the timeline." },
    "gwsf-q3": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "Legal asks how this compares with the Microsoft side. What do I say?" },
    "gwsf-q4": { name: "Mei-Ling Castro", role: "Workspace Security Admin", line: "One line for the case file. What is this?" },
  },
  briefings: {
    // ── Reading 1: what carries over ──
    "gwsf-r1": [
      {
        kind: "sort",
        title: "Carries Over, or Learn It Again?",
        prompt: "Larkspur has just hired an analyst from a Microsoft 365 shop. Mei-Ling wants a one-page note on what that experience is worth here. Sort each card: does it carry over to Workspace, or does it have to be learned again?",
        buckets: [{ id: "carry", label: "Carries over" }, { id: "learn", label: "Learn it again" }],
        items: [
          { id: "a", text: "A file opened up to anyone holding a link is a risk worth an alert", bucket: "carry", why: "Sharing risk is the same on any suite. Only the event that records it changes." },
          { id: "b", text: "Searching the logs for an Operation field", bucket: "learn", why: "Operation belongs to Microsoft's Unified Audit Log. Workspace has no such field." },
          { id: "c", text: "One account pulling hundreds of files in minutes deserves a closer look", bucket: "carry", why: "Collection looks like collection on either suite." },
          { id: "d", text: "A sharing change is recorded as change_document_visibility", bucket: "learn", why: "That name exists only in Workspace's Drive log." },
          { id: "e", text: "An unknown publisher asking for wide access is a warning sign", bucket: "carry", why: "The judgement transfers. The way each suite writes that access doesn't." },
          { id: "f", text: "Reading a permission written as https://www.googleapis.com/auth/contacts.readonly", bucket: "learn", why: "Google's scope strings are a vocabulary of their own." },
          { id: "g", text: "An admin switching off 2-Step Verification needs explaining", bucket: "carry", why: "A weakened control matters everywhere." },
          { id: "h", text: "Expecting every app's activity to sit in one shared log", bucket: "learn", why: "Workspace gives each app its own audit trail, all managed from one Admin console. Google calls the organisation the domain." },
        ],
      },
    ],
    // ── Reading 2: which log, which action ──
    "gwsf-r2": [
      {
        kind: "codebreak",
        title: "Name the Log, Name the Event",
        prompt: "Mei-Ling won't let anyone query until they can say two things: which log, and which action in that log. Each clue is something that happened at Larkspur this week. Crack the word you'd filter on.",
        tries: 6,
        rounds: [
          { id: "l", clue: "Which log (gws.event.type)? A story artist signs in from home.", answer: "login", why: "Sign-in activity lives in the login log: login_success, login_failure, suspicious_login." },
          { id: "a", clue: "Which log? An admin changes 2-Step Verification policy for the Story team.", answer: "admin", why: "Console configuration changes are the admin log, and each change has a precise name." },
          { id: "m", clue: "Which log? A render-floor tablet drops out of device management.", answer: "mobile", why: "Device management has a category of its own. A SIEM usually pulls several of these feeds in parallel." },
          { id: "t", clue: "Which log? An outside app reads a producer's contacts through the API.", answer: "token", why: "OAuth app authorization and API use both sit in the token log." },
          { id: "z", clue: "Which event name, inside that log? A user clicks Allow and an app gets a new grant.", answer: "authorize", why: "authorize records the grant itself, once." },
          { id: "c", clue: "Which event name, inside that log? The app uses the grant it already holds.", answer: "activity", why: "activity records each use. An analyst needs both: what was given, and what was done with it." },
        ],
        lesson: "Two fields work together: gws.event.type says which log, and gws.event.name says which action inside it. Choose the log first, because an event name only means something in its own category.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Workspace Event",
        prompt: "Before you use the console, read one native event field by field. s.ito shared a dub script with the vendor on Monday. This is the record, in the shape the Reports API hands it over.",
        source: "Reports API · applicationName=drive",
        fields: [
          { key: "id.applicationName", value: "drive", label: "Which log", note: "A SIEM usually stores this feed under gws.event.type. Drive reads and edits arrive with type access, and permission changes with type acl_change." },
          { key: "events[0].type", value: "acl_change" },
          { key: "events[0].name", value: "change_user_access", label: "Which action", note: "Your SIEM calls this gws.event.name. Compare one flat Operation field in Microsoft's log: here 'which log' and 'which action' are kept apart." },
          { key: "actor.email", value: "s.ito@larkspur.example", label: "Who did it", note: "Usually stored as gws.actor.email." },
          { key: "ipAddress", value: "198.51.100.20", label: "From where" },
          { key: "events[0].parameters.doc_title", value: "LK_R02_dub_script.docx", label: "On what" },
          { key: "events[0].parameters.target_user", value: "intake@polyglotdub.example", label: "Affecting whom", note: "The other half of the story. Always read the actor against the object." },
          { key: "events[0].parameters.old_value", value: "none" },
          { key: "events[0].parameters.new_value", value: "can_view", note: "The role before and after." },
          { key: "events[0].parameters.visibility_change", value: "external", note: "external means the file moved from inside the domain to outside it." },
        ],
        summary: "A person inside Larkspur gave an outside address view access to one document, from the office. Always judge the actor against the object. An admin resetting someone else's password is one finding, and an account quietly changing its own settings is a very different one.",
      },
    ],
    // ── Reading 3: signature console, part one ──
    "gwsf-r3": [MAIL_LAB],
    // ── Reading 4: scopes, offline tokens, governance ──
    "gwsf-r4": [
      {
        kind: "spotdiff",
        title: "Same Name, Different App",
        prompt: "Reel Review appears twice on j.aldana's account. The left copy shows the studio's sanctioned review tool, taken from s.ito's grant. The right copy came from the click. Compare them line by line and tap each line that tells you this isn't the same app.",
        goodTitle: "Sanctioned grant · s.ito · token authorize",
        suspectTitle: "Monday's grant · j.aldana · token authorize",
        good: [
          "@timestamp: 2025-03-03T10:22:08Z",
          "gws.event.type: token",
          "gws.event.name: authorize",
          "gws.actor.email: s.ito@larkspur.example",
          "gws.token.app_name: Reel Review",
          `gws.token.client_id: ${REAL_ID}`,
          "gws.token.client_type: WEB",
          "gws.token.scope: [https://www.googleapis.com/auth/drive.appdata, openid]",
          "event.outcome: success",
          "Admin console, App access control: Trusted",
          "Admin console, consent screen: verified by Google",
          "Admin console, publisher: Inkstone Software Ltd",
          "Admin console, connected apps: offline access (refresh token)",
        ],
        suspect: [
          "@timestamp: 2026-11-02T16:14:31Z",
          "gws.event.type: token",
          "gws.event.name: authorize",
          "gws.actor.email: j.aldana@larkspur.example",
          "gws.token.app_name: Reel Review",
          `gws.token.client_id: ${FAKE_ID}`,
          "gws.token.client_type: WEB",
          "gws.token.scope: [https://www.googleapis.com/auth/drive.readonly, https://www.googleapis.com/auth/contacts.readonly]",
          "event.outcome: success",
          "Admin console, App access control: Unconfigured",
          "Admin console, consent screen: not verified",
          "Admin console, publisher: none named",
          "Admin console, connected apps: offline access (refresh token)",
        ],
        diffs: [
          { line: 5, why: "client_id is the durable identity of an app: it stays the same for every future use of a grant. Two values means two apps, whatever the name says. app_name is free text the developer typed." },
          { line: 7, why: "Scope is the blast radius. drive.appdata reaches only the app's own hidden folder. drive.readonly reads every file the user can open. For scale: drive.file reaches only files the app created or the user opened with it, and plain drive is the whole Drive, read and write. https://mail.google.com/ is the whole mailbox." },
          { line: 9, why: "The token event carries no governance facts, so you look the client_id up under Security, API controls. Trusted means an admin approved this app. Unconfigured means nobody decided anything, and the default user-consent policy simply didn't stop it. It's not a reviewed decision, and it doesn't limit what the app can do." },
          { line: 10, why: "Verified means Google reviewed the app's consent screen. Not verified means no review happened. That isn't a finding of malice, and it doesn't block a single API call." },
          { line: 11, why: "A named company you can hold to account, or nobody at all. Publisher is about the app's governance, not about what the user did." },
        ],
        decoys: [
          { line: 0, why: "The two grants were made on different days, and that says nothing about the app. Anyone can authorize a good app today." },
          { line: 3, why: "Different users authorize apps all the time. This line is about who clicked. You're comparing the apps." },
        ],
        hud: "Tap the lines that show these are two different apps",
        sameLine: "That line is identical in both grants, so it can't separate them. Note what's on it: offline, for example, is on both, because sanctioned apps hold refresh tokens too.",
        howTo: ["Compare the two grants line by line.", "Tap a line on the right when it shows these are different apps.", "A line that's the same on both, or that only tells you who and when, costs a life."],
        winTitle: "Two apps, one name",
        lesson: "The act of consenting looks the same for a good app and a bad one, and so can the name and the offline flag. What separates them is the client_id and scope breadth in the log, then the access setting, verification and publisher you look up in the Admin console, read together. After a bad grant, the next question is whether the token has been used, and from where.",
      },
      {
        kind: "worksheet",
        title: "What Survives a Password Change?",
        prompt: "IT's reflex is to reset the password. Mei-Ling puts four grants from a staff audit on the table and asks what that reset would really do to each one.",
        caption: "Token audit scopes · access type from the user's connected-apps entry in the Admin console (the token log does not record it)",
        columns: ["App", "gws.token.scope", "Connected apps: access"],
        rows: [
          ["Mailroom Digest", "https://mail.google.com/", "offline"],
          ["Crew Directory", "https://www.googleapis.com/auth/contacts.readonly", "offline"],
          ["Sheet Stitcher", "https://www.googleapis.com/auth/spreadsheets", "offline"],
          ["Quick Look", "https://www.googleapis.com/auth/presentations.readonly", "online"],
        ],
        questions: [
          { id: "gmail", q: "The user changes their password. Which offline grant stops working because of it?", hint: "Google documents one exception, and it's about one service's scopes.", answer: ["Mailroom Digest", "Mailroom"], why: "Google documents that a refresh token stops working on a password change when it contains Gmail scopes. That's the only tie between the two." },
          { id: "other", q: "Does Crew Directory keep its access after that password change? (yes/no)", hint: "Contacts isn't Gmail.", answer: ["yes"], why: "An offline token is a credential of its own. A non-Gmail scope isn't tied to the password, so the app's servers keep refreshing it." },
          { id: "online", q: "Which app can't get a new token once the user is gone?", hint: "Read the third column.", answer: ["Quick Look", "QuickLook"], why: "An online access token works until it expires, and then the app can't refresh it without the user. Offline means a refresh token: the app works with the user absent, for as long as the grant stands." },
          { id: "fix", q: "What single word describes the action that reliably ends Sheet Stitcher's access?", hint: "Not reset. Something done to the grant itself.", answer: ["revoke", "revoking", "revocation"], why: "Even when a reset happens to kill a Gmail token, it's never a containment plan. The specific grant has to be revoked." },
        ],
      },
    ],
    // ── Reading 5: Drive sharing and download volume ──
    "gwsf-r5": [
      {
        kind: "spotdiff",
        title: "Two Sharing States",
        prompt: "Could the frames have left by the front door? Mei-Ling pulls the reel 6 animatic's access snapshot from Friday and today's. Tap each line that widens who can reach the file. Internal housekeeping doesn't count.",
        goodTitle: "Access snapshot · Friday",
        suspectTitle: "Access snapshot · today",
        good: [
          "doc_title: LK_R06_animatic_v9.mov",
          "doc_id: 1Qm8vTz4kLp2Xc7RnYb0sHd5Fa3Ue9Wj",
          "owner: LK Final Animatics (shared drive)",
          "owner_is_shared_drive: true",
          "last_edit: Thu 17:40 by s.ito",
          "visibility: people_within_domain_with_link",
          "link role: can_view",
          "viewers can download: no",
          "member: j.aldana@larkspur.example  organizer",
          "member: s.ito@larkspur.example  can_comment",
          "member: outside the domain: none",
          "label: Confidential",
        ],
        suspect: [
          "doc_title: LK_R06_animatic_v9.mov",
          "doc_id: 1Qm8vTz4kLp2Xc7RnYb0sHd5Fa3Ue9Wj",
          "owner: LK Final Animatics (shared drive)",
          "owner_is_shared_drive: true",
          "last_edit: Mon 11:15 by s.ito",
          "visibility: people_with_link",
          "link role: can_view",
          "viewers can download: yes",
          "member: j.aldana@larkspur.example  organizer",
          "member: s.ito@larkspur.example  can_edit",
          "member: outside the domain: intake@polyglotdub.example  can_view",
          "label: Confidential",
        ],
        diffs: [
          { line: 5, why: "people_with_link: the file now opens for whoever holds the URL, and a URL gets forwarded and leaked. The Drive log writes this as change_document_visibility with visibility_change external." },
          { line: 7, why: "A viewer who can download keeps a copy for good, and no later change takes it back." },
          { line: 10, why: "A named outside address was added: change_user_access, with target_user naming it. A vendor, on purpose, but it's still a file that left the domain." },
        ],
        decoys: [
          { line: 4, why: "Someone edited the file. That's work, not access." },
          { line: 9, why: "An internal member's role moved, and it's Larkspur staff either way. Worth noticing, but it doesn't widen who can reach the file." },
        ],
        hud: "Tap the lines that widen who can reach this file",
        sameLine: "That line is the same on both days. Compare the two copies again.",
        howTo: ["Compare Friday's snapshot with today's, line by line.", "Tap each line on the right that widens who can reach the file.", "A line that hasn't changed, or changes nothing about access, costs a life."],
        winTitle: "Every wider door found",
        lesson: "c.brandt opened this file on Monday for the dub vendor and left it open. It was a real exposure, and Mei-Ling has closed it. Now ask who used it: a sharing change tells you about access, and the Drive log's view and download events tell you what happened next.",
      },
      {
        kind: "worksheet",
        title: "Whose Downloads?",
        prompt: "One big number proves nothing. These four bursts come from Mei-Ling's notes on last month's Drive reviews at Larkspur. Work out what was behind each one.",
        caption: "Drive audit · four bursts from last month",
        columns: ["User", "Event name", "Events", "Window", "IP address", "originating_app_id"],
        rows: [
          ["r.okafor", "sync_item_content", "418", "2 h", "198.51.100.20, studio office", "-"],
          ["s.ito", "download", "64", "25 min", "198.51.100.20, studio office", "-"],
          ["c.brandt", "download", "150", "40 min", "198.51.100.21, render floor", "-"],
          ["v.lindqvist", "download", "90", "6 min", "203.0.113.91, hosting provider", "731884402196"],
        ],
        questions: [
          { id: "app", q: "Which user's burst ran on an app's servers and not on a person's machine?", hint: "Two columns tell you: the last two.", answer: ["v.lindqvist", "lindqvist"], why: "An app's project number and a hosting provider's IP. v.lindqvist's name is on the rows, and v.lindqvist's browser had no part in them. The user column names whose token it was." },
          { id: "rate", q: "How many events per minute was that?", hint: "Events divided by minutes.", answer: ["15"], why: "90 in 6 minutes. One download is nothing, and volume and pattern are what count." },
          { id: "field", q: "The Drive rows give only originating_app_id, 731884402196, and no app name. Which token log field do you match it against to find the grant behind the burst?", hint: "The OAuth value that starts with the same digits.", answer: ["client_id", "gws.token.client_id", "client id", "clientid"], why: "originating_app_id is the app's Google Cloud project number, and an OAuth client_id starts with that number (731884402196-....apps.googleusercontent.com). Matching the two ties the collection to an earlier authorize event, and that event's app_name names the app. Always make that match on a burst." },
          { id: "first", q: "That burst was the Clip Trimmer app, and its grant was still live when Mei-Ling found it. What came first: list the files, or end the grant? (list/end)", hint: "Is the app still reading while you make your list?", answer: ["end", "end the grant"], why: "Every minute of listing is another minute of files leaving. Ending the grant erases none of the audit history, so the list can wait. Blocking the hosting IP wouldn't do it either: the app's calls go to Google's servers, not through Larkspur's firewall." },
          { id: "again", q: "With the grant gone, anyone at Larkspur could still authorize the same app. What identifies it on the blocked list: its name or its client ID?", hint: "Which value stays constant, and which can a developer type freely?", answer: ["client id", "client_id", "clientid", "the client id"], why: "The client ID is what the app can't change. Blocking it stops anyone in the domain authorizing that app again." },
          { id: "big", q: "r.okafor has the biggest number on the page. Does it need escalating? (yes/no)", hint: "Who, from where, and with what?", answer: ["no"], why: "A new laptop syncing from the office, run as the user, with no third-party app behind it. Big and innocent looks like this." },
        ],
      },
    ],
    // ── Reading 6: signature console, part two ──
    "gwsf-r6": [
      TOKEN_LAB,
      {
        kind: "sequence",
        title: "Order of Work",
        prompt: "A different case from Mei-Ling's files. Last spring the login log showed email_forwarding_out_of_domain on b.haas's mailbox in Accounts: every message was being copied to an outside address. All four jobs below were right. Tap them in the order Mei-Ling did them.",
        items: [
          { id: "scope", text: "Work through the Gmail log and list every message that went out", note: "Slow, careful work, and now it can take the time it needs: nothing more is leaving, and the log keeps its history." },
          { id: "harden", text: "Turn off automatic forwarding outside the domain for the whole organisation", note: "The lasting fix. It changes how everyone works, so it gets a proper decision once the incident itself is over." },
          { id: "contain", text: "Remove the forwarding address from the mailbox", note: "Mail is leaving right now, so this can't wait for anything else. Removing the setting erases none of the audit history." },
          { id: "verify", text: "Check the records: the setting is gone and no new message has gone out", note: "A click isn't proof. Until the records agree, you only believe it stopped." },
        ],
        order: ["contain", "verify", "scope", "harden"],
        doneNote: "Stop the harm, prove it stopped, measure the damage, then fix what allowed it. Measuring first leaves the leak running while you count, and a policy debate in the middle of an incident helps nobody.",
      },
    ],
    // ── Reading 7: Alert Center ──
    "gwsf-r7": [
      {
        kind: "sort",
        title: "Alert or Raw Log?",
        prompt: "Wes closed Monday's alert from the alert page alone. Mei-Ling wants a rule for the team: what can Alert Center tell you, and what do you only get by pivoting into the audit logs? Sort each thing you'd need on a case.",
        buckets: [{ id: "alert", label: "Alert Center gives you this" }, { id: "raw", label: "Only the raw audit logs have this" }],
        items: [
          { id: "a", text: "Which named pattern fired (gws.alert.center.type)", bucket: "alert", why: "That's its job: a named, pre-correlated item, so nobody has to scan raw events to notice it." },
          { id: "b", text: "A unique id for tracking the alert (gws.alert.center.id)", bucket: "alert", why: "Handy for the ticket, and no use for scoping." },
          { id: "c", text: "That a leaked password matched a known breach list", bucket: "alert", why: "One of the built-in alert types: leaked password, suspicious sign-in, suspicious email spikes and more." },
          { id: "d", text: "The exact scope list of a grant", bucket: "raw", why: "It's in the token authorize event. You need it to judge the blast radius." },
          { id: "e", text: "The client ID to revoke and block", bucket: "raw", why: "The value you act on comes from the raw event." },
          { id: "f", text: "The IP address behind every API call an app made", bucket: "raw", why: "activity events, one per use." },
          { id: "g", text: "A file-by-file list of what a token downloaded", bucket: "raw", why: "Drive log events. An alert tells you to look, not what was taken." },
        ],
      },
    ],
    // ── Reading 8: two suites ──
    "gwsf-r8": [
      {
        kind: "worksheet",
        title: "Two Suites, One Desk",
        prompt: "Larkspur's parent company runs Microsoft 365, and a shared SOC watches both. Mei-Ling's desk card shows the same job in both vocabularies. Use it to answer what the new analyst asks.",
        caption: "Desk card · same job, two suites",
        columns: ["Job", "Google Workspace", "Microsoft 365"],
        rows: [
          ["Mail", "Gmail: gws.dmarc_result in Gmail's own log events", "Exchange Online: mail-flow fields, Operation-centric audit"],
          ["Files", "Drive: gws.drive.visibility, gws.event.name", "SharePoint and OneDrive: SharingCapability, Operation"],
          ["Open link", "change_document_visibility to people_with_link", "An anyone link on SharePoint or OneDrive"],
          ["Administration", "Admin console: one place, identity and suite settings together", "Microsoft 365 admin center plus Entra ID: separate consoles"],
          ["App grants", "Token audit: gws.token.scope, contacts.readonly", "Entra logs: Microsoft Graph permissions, Contacts.Read"],
          ["Built-in alerts", "Alert Center: gws.alert.center.type", "Defender alerts over Entra and M365 telemetry"],
        ],
        questions: [
          { id: "two", q: "Which suite splits identity administration and suite administration into separate consoles: Workspace or Microsoft?", hint: "Read the Administration row.", answer: ["Microsoft", "Microsoft 365", "M365"], why: "Workspace keeps settings like 2-Step Verification enforcement and suite settings in one console and one log category." },
          { id: "same", q: "contacts.readonly and Contacts.Read look alike. Can you judge one by reading the other's documentation? (yes/no)", hint: "Two vocabularies.", answer: ["no"], why: "The risk pattern is shared, but the permission strings aren't interchangeable. Learn each platform's own names before judging how broad a grant is." },
          { id: "first", q: "A query for Operation returns nothing on an unfamiliar tenant. Which pair of fields do you try once you've confirmed it's Workspace? Give the first.", hint: "Which log comes before which action.", answer: ["gws.event.type", "event.type"], why: "Confirm which suite issues the logs before the first query. Most cross-suite mistakes start there." },
        ],
      },
    ],
    // ── Drill before the verdict ──
    "gwsf-ac1": [
      {
        kind: "queue",
        title: "Grant Review",
        prompt: "The rule fires on every new third-party grant, and every Monday Mei-Ling reviews what it caught. A benign true positive means the rule was right and the activity is real but legitimate. A false positive means the rule misfired. Open each one, read the fields together, and decide.",
        console: "Token audit · New grants this week",
        actions: [
          { id: "btp", label: "Benign true positive: close, cite the approval", tone: "close" },
          { id: "fp", label: "False positive: send to tuning", tone: "contain" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          { id: "shift", time: "Mon 09:12", severity: "Low", rule: "New third-party grant", entity: "l.marsh",
            fields: [{ k: "gws.event.name", v: "authorize" }, { k: "gws.token.app_name", v: "Shift Planner" }, { k: "gws.token.scope", v: "https://www.googleapis.com/auth/calendar.freebusy" }, { k: "gws.token.client_type", v: "WEB" }, { k: "Admin console: App access control", v: "Trusted" }, { k: "Admin console: consent screen", v: "verified" }, { k: "Admin console: publisher", v: "Tern Labs Ltd" }, { k: "Admin console: connected apps", v: "offline access" }],
            context: "A scheduling tool used by 88 people.", answer: "btp", why: "A real grant, so the rule did its job. It sees free and busy times, nothing else. An admin approved it, Google verified it and the publisher is named. Offline on a small, sanctioned grant isn't a finding." },
          { id: "grab", time: "Mon 11:40", severity: "Medium", rule: "New third-party grant", entity: "t.bello",
            fields: [{ k: "gws.event.name", v: "authorize" }, { k: "gws.token.app_name", v: "Frame Grabber Free" }, { k: "gws.token.scope", v: "https://mail.google.com/" }, { k: "gws.token.client_type", v: "WEB" }, { k: "Admin console: App access control", v: "Unconfigured" }, { k: "Admin console: consent screen", v: "not verified" }, { k: "Admin console: publisher", v: "none named" }, { k: "Admin console: connected apps", v: "offline access" }],
            context: "A screenshot tool, by its description.", answer: "esc", why: "A screenshot tool has no reason to read, send and delete all of someone's mail. And the Admin console has nothing to vouch for it: unconfigured, not verified, no publisher." },
          { id: "stamp", time: "Tue 08:30", severity: "Low", rule: "New third-party grant", entity: "c.brandt",
            fields: [{ k: "gws.event.name", v: "authorize" }, { k: "gws.token.app_name", v: "Docket Stamp" }, { k: "gws.token.scope", v: "https://www.googleapis.com/auth/spreadsheets" }, { k: "gws.token.client_type", v: "WEB" }, { k: "Admin console: App access control", v: "Unconfigured" }, { k: "Admin console: consent screen", v: "verified" }, { k: "Admin console: publisher", v: "Docket Tools GmbH" }, { k: "Admin console: connected apps", v: "offline access" }],
            context: "A delivery-note tool from a named company, new at Larkspur.", answer: "esc", why: "Verified isn't the same as approved. Google reviewed the listing, but no admin has decided this tool may read and change every spreadsheet. Not an attack, but somebody has to make that decision." },
          { id: "queue", time: "Tue 10:05", severity: "Low", rule: "New third-party grant", entity: "r.okafor",
            fields: [{ k: "gws.event.name", v: "authorize" }, { k: "gws.token.app_name", v: "Render Queue Viewer" }, { k: "gws.token.scope", v: "https://www.googleapis.com/auth/drive.metadata.readonly" }, { k: "gws.token.client_type", v: "WEB" }, { k: "Admin console: App access control", v: "Trusted" }, { k: "Admin console: consent screen", v: "verified" }, { k: "Admin console: publisher", v: "Inkstone Software Ltd" }, { k: "Admin console: connected apps", v: "online access" }],
            context: "From the same vendor as the studio's review tool.", answer: "btp", why: "A real grant again, and an approved one. File names and dates only, no content, an online token, and an approved, known vendor." },
          { id: "tidy", time: "Tue 11:20", severity: "Low", rule: "New third-party grant", entity: "s.ito",
            fields: [{ k: "gws.event.name", v: "revoke" }, { k: "gws.token.app_name", v: "Old Colour Picker" }, { k: "gws.token.scope", v: "https://www.googleapis.com/auth/drive.file" }, { k: "gws.token.client_type", v: "WEB" }, { k: "Admin console: App access control", v: "Unconfigured" }, { k: "Admin console: consent screen", v: "verified" }, { k: "Admin console: publisher", v: "Huebox Ltd" }],
            context: "s.ito was tidying up connected apps.", answer: "fp", why: "Read gws.event.name: revoke. Nothing was granted here. The rule matches every token event when it should match authorize, so the rule is wrong, not the user. It goes to tuning." },
        ],
      },
    ],
    // ── Drill before the flag ──
    "gwsf-f1": [
      {
        kind: "worksheet",
        title: "Foothold to Collection",
        prompt: "Attack speed goes in every report: how long from the consent grant to the first file taken? Count complete minutes, and drop any leftover seconds.",
        caption: "Case notes · grant and first app-attributed download",
        columns: ["App", "authorize event", "First download"],
        rows: [
          ["Clip Trimmer", "09:14:48", "09:27:05"],
          ["Sticker Packer", "13:40:10", "14:05:02"],
          ["Reel Review", "16:14:31", "21:04:12"],
        ],
        questions: [
          { id: "a", q: "Clip Trimmer: how many complete minutes?", hint: "Don't just subtract the minutes. A full 13 minutes after the grant would be 09:27:48.", answer: ["12"], why: "12 minutes 17 seconds. Subtracting only the minute digits says 13, which is wrong: the clock hadn't reached 09:27:48." },
          { id: "b", q: "Sticker Packer: how many complete minutes?", hint: "It crosses the hour.", answer: ["24"], why: "24 minutes 52 seconds. The leftover seconds are dropped, not rounded up." },
          { id: "c", q: "Reel Review: how many complete minutes?", hint: "Four hours is 240 minutes. Then count on from 20:14:31.", answer: ["289"], why: "4 hours 49 minutes 41 seconds, so 289 complete minutes. It waited for the evening, when nobody was around to watch." },
        ],
      },
    ],
    // ── Drill before the last question: the boss task's decisive signal ──
    "gwsf-q4": [
      {
        kind: "worksheet",
        title: "Did the Fix Take?",
        prompt: "Before the case file closes, Mei-Ling audits four older tickets, all marked closed, against what the Admin log and the token log really say. A word on a ticket proves nothing. Read the records.",
        caption: "Ticket audit · containment records against later token activity",
        columns: ["Ticket", "Admin log event", "Grant still in connected apps?", "On the blocked list?", "Token activity afterwards"],
        rows: [
          ["LS-201", "RESET_SIGNIN_COOKIES", "Yes", "No", "41 calls"],
          ["LS-204", "REVOKE_3LO_TOKEN", "No", "Yes", "None"],
          ["LS-209", "CHANGE_PASSWORD_ON_NEXT_LOGIN", "Yes", "No", "12 calls"],
          ["LS-212", "REVOKE_3LO_TOKEN", "No", "No", "None, then a new authorize event two days later"],
        ],
        questions: [
          { id: "ok", q: "Which one ticket is truly closed?", hint: "The token is gone, the door is shut, and nothing came after.", answer: ["LS-204"], why: "The grant was revoked, the client ID is blocked and the token log has gone silent. Three records agree." },
          { id: "cal", q: "LS-209's grant held only a Sheets scope. Did making the user change password end it? (yes/no)", hint: "Read the last column, then remember which scopes a password change touches.", answer: ["no"], why: "The grant is still on the user's connected apps and the log shows 12 more calls. The action was real, but it never reached the grant." },
          { id: "label", q: "LS-201 and LS-209 both say closed. Should they be reopened? (yes/no)", hint: "Is the access still in place?", answer: ["yes"], why: "Something was done, so it's tempting to call it finished. If the token still works, the attacker's access is intact and the case stays open." },
          { id: "miss", q: "What was skipped on LS-212 that let the app come back? One word.", hint: "Look at the fourth column.", answer: ["block", "blocklist", "blocking", "blocked"], why: "Revoking ended one grant, but the client ID stayed authorizable, so one more click brought it back." },
        ],
      },
    ],
  },
};
