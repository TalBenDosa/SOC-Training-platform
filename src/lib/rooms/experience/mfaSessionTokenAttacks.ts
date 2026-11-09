import type { RoomExperience } from "./types";

// "Operation Stolen Session" for the "mfa-session-token-attacks" room.
// Script: docs/campaign/108-mfa-session-token-attacks.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Kingsmere Private Hospital (fictional), not the graded tasks' Castellan Risk Partners records.
// Mentor: Hyun-woo Salazar, Identity Threat Hunter.
// Signature: After MFA Passed. An Entra-style portal over sign-in logs where one session ID sits
// in two places, and a pathway pair: one walks the AiTM relay, the copied cookie and the replay,
// the other walks a copied token into the controls until Token Protection stops it.
// Game mix: pathway + portal + tune. Other labs: anatomy, sort, worksheet, sequence, queue, locks.
//
// New task order (the room's own order put fatigue first and left ac1 and o1 away from their
// topics; "The Cookie" has to teach the cookie):
//   r1 r4 o1 | r5 la1 | r2 q1 r3 q2 ac1 | r6 q3 r7 | r8 q4 f1
// No flag or question refers to a task number, so nothing else depends on the order.
//
// Lab data differs from the graded tasks. No d.okafor, r.aldana, Chicago, Amsterdam, Denver,
// 141.98.11.203, 91.108.4.33 or 3d8a6f21. The relay lab uses a QR code and a typed OATH code and
// ends at a mailbox; o1 uses a link and a push and ends in persistence, which only the portal's
// audit row shows. The portal's replay comes 38 minutes after a sign-in that came from the proxy
// itself, in a browser on a phone; la1 has 11 minutes after an office sign-in. Push data never
// uses the pair of 11 denials in 12 minutes (q1), and q2's approval event appears only as a labelled
// row and primer line, never asked. The close-out queue teaches the verdict words on enrolment,
// rota and travel alerts, never a denied push (ac1). The consent item asks for a rota app's file
// access, not a mailbox (q3). The locks lab applies "does the attack cross that gate?" to four
// other pairs and never pairs Token Protection with fatigue (q4).

const MAEVE = "m.tierney@kingsmerehospital.example";
const SESSION_RELAY = "c71e04ab-9f3d-4a28-b6c5-2e80d1f7a913";
const SESSION_LAPTOP = "5ad2f9b0-7c16-4e3a-8d41-b03c6e92f4d7";
const SESSION_PHONE = "e08b3c56-12d4-49f7-a6be-7d91c4a05e28";
const SESSION_MONDAY = "2b7f6e19-a0c4-4d58-93e1-c6d8107fb2a4";
const LAPTOP_ID = "9be2c041-6d7a-4f13-a8c5-31e07db4f662";
const PHONE_ID = "77c0a3de-48b1-4e92-b7f6-0c95e2d1a384";
const SIGNIN_TABS = [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "dev", label: "Device info" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }];

const FRESH_MFA: [string, string][] = [["Step 1 method", "Password"], ["Step 1 succeeded", "True"], ["Step 1 result detail", "Correct password"], ["Step 2 method", "OATH verification code"], ["Step 2 succeeded", "True"], ["Step 2 result detail", "MFA successfully completed"]];
const CLAIM_MFA: [string, string][] = [["Step 1 method", "Previously satisfied"], ["Step 1 succeeded", "True"], ["Step 1 result detail", "MFA requirement satisfied by claim in the token"], ["Requirement", "Multifactor authentication"]];
const POLICY: [string, string][] = [["Policy name", "KPH All users require MFA"], ["Grant controls", "Require multifactor authentication"], ["Result", "Success"]];

/** One sign-in record, shaped like the admin center's detail pane. */
function signIn(r: {
  id: string; date: string; app: string; resource: string; client: string; session: string; token: string; incoming: string;
  ip: string; asn: string; place: string; deviceId: string; browser: string; os: string; compliant: string; managed: string; join: string; auth: [string, string][];
}) {
  const facts: [string, string][] = [
    ["Date", r.date], ["Request ID", r.id], ["Status", "Success"], ["User", "Maeve Tierney"], ["Username", MAEVE], ["Application", r.app], ["Resource", r.resource], ["Client app", r.client],
    ["Token issuer type", "Azure AD"], ["Incoming token type", r.incoming], ["Authentication Protocol", "none"], ["Authentication requirement", "Multifactor authentication"], ["Session ID", r.session], ["Unique token identifier", r.token],
  ];
  return {
    id: r.id,
    title: `Activity details: ${r.date}`,
    facts,
    actions: SIGNIN_TABS,
    panes: {
      loc: [["IP address", r.ip], ["Autonomous system number", r.asn], ["Location", r.place]] as [string, string][],
      dev: [["Device ID", r.deviceId], ["Browser", r.browser], ["Operating system", r.os], ["Compliant", r.compliant], ["Managed", r.managed], ["Join type", r.join]] as [string, string][],
      auth: r.auth,
      capol: POLICY,
    },
  };
}

export const MFA_SESSION_TOKEN_ATTACKS: RoomExperience = {
  roomId: "mfa-session-token-attacks",
  codename: "Operation Stolen Session",
  theme: "stolensession",
  handler: { name: "Hyun-woo Salazar", role: "Identity Threat Hunter, Kingsmere Private Hospital" },
  briefing: [
    "Kingsmere Private Hospital. 92 beds, four operating theatres, and one tenant that everyone from the surgeons to the kitchen signs in to.",
    "At 09:40 on Tuesday, Maeve Tierney's mailbox asked Accounts to change an implant supplier's bank details. Maeve, the Theatre Manager, was in Theatre 2 at 09:40.",
    "MFA passed. Risk reads none. Conditional Access reads success. Identity Threat Hunter Hyun-woo Salazar wants to know who was really in that session.",
    "Follow the cookie, prove where it went, find who else was targeted, and work out what would have stopped it.",
  ],
  mission: "Find what MFA leaves behind, walk a relay from QR code to mailbox, prove one session sat in two places, tune a rule for push storms, sort token evidence by layer, find a sign-in nobody issued, then show which control acts on which attack.",
  estimate: "~65 min",
  look: { primary: "#e8b36a", secondary: "#8fd3ff", warn: "#ff4f6d" },
  scene: "facilitystolensession",
  layout: "facility",
  stations: [
    {
      id: "cookie",
      label: "The Cookie",
      topic: "The one idea behind MFA bypass · five techniques · AiTM reverse-proxy phishing · T1539 and T1550.004",
      tagline: "MFA passed. Then what?",
      building: "reception",
      taskIds: ["mfast-r1", "mfast-r4", "mfast-o1"],
    },
    {
      id: "twoplaces",
      label: "Two Places",
      topic: "Reading Entra ID sign-in logs side by side · sessionId · risk and Conditional Access on a replay",
      tagline: "One session, one browser. Supposedly.",
      building: "wing",
      taskIds: ["mfast-r5", "mfast-la1"],
    },
    {
      id: "push",
      label: "The Push",
      topic: "MFA fatigue (T1621) · Okta System Log fields · detection rules · number matching · benign denials",
      tagline: "The same crew tries the night shift",
      building: "emergency",
      taskIds: ["mfast-r2", "mfast-q1", "mfast-r3", "mfast-q2", "mfast-ac1"],
    },
    {
      id: "othertokens",
      label: "Other Tokens",
      topic: "Windows OS tokens (T1134.001) · OAuth consent grants (T1528) · Golden SAML (T1606.002)",
      tagline: "Same word, different layer",
      building: "vault",
      taskIds: ["mfast-r6", "mfast-q3", "mfast-r7"],
    },
    {
      id: "aftermfa",
      label: "After MFA Passed",
      topic: "The defence ladder: number matching, Conditional Access, Token Protection, FIDO2, session lifetime",
      tagline: "What would have stopped it?",
      building: "control",
      taskIds: ["mfast-r8", "mfast-q4", "mfast-f1"],
      boss: true,
    },
  ],
  personas: {
    "mfast-o1": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "The board wants this as a timeline. Put it in order." },
    "mfast-la1": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "Different company, same desk. Tell me what you can prove." },
    "mfast-q1": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "The duty manager asks why this one got a phone call. What do you say?" },
    "mfast-q2": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "Give me the fields you'd quote in the ticket." },
    "mfast-ac1": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "It fired, so it's yours. Work it and tell me how it closes." },
    "mfast-q3": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "Somebody else filled in this ticket. Tell me what you make of it." },
    "mfast-q4": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "The board asks what's still open. One answer, please." },
    "mfast-f1": { name: "Hyun-woo Salazar", role: "Identity Threat Hunter", line: "One ID for the case file, then we're done." },
  },
  briefings: {
    // ── Reading 1: what MFA leaves behind ──
    "mfast-r1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Session Cookie",
        prompt: "Tuesday, 11:05. Before anyone opens a log, Hyun-woo Salazar signs in to a test account in a clean browser and opens the developer tools: 'This is what a sign-in leaves behind.' Scan each attribute of the cookie.",
        primer: {
          fold: true,
          title: "What MFA actually produces",
          points: [
            "**MFA** (multi-factor authentication) asks for more than one kind of proof: a password plus a code, a push or a key.",
            "The asking happens at one moment, the sign-in. What comes out of that moment is an artifact: a session cookie, an access token or a signed SAML assertion.",
            "A **session cookie** is a value the browser hands back on each visit, so that nobody signs in again on every page.",
            "A **bearer credential** works for whoever presents it, the way cash does.",
          ],
          example: {
            label: "The same shape at a car park",
            lines: [
              "The attendant checks a staff card once and hands over a paper exit token.",
              "At the exit, the barrier reads the token. It never asks for the card.",
              "From then on, the only question anyone asks is whether the token is valid.",
            ],
          },
        },
        source: "Browser developer tools · Application · Cookies · test sign-in",
        fields: [
          { key: "Name", value: "ESTSAUTHPERSISTENT", label: "Which cookie", note: "Microsoft Entra's session cookie when the user chooses Stay signed in. Without that choice it's ESTSAUTH, and it ends with the browser session." },
          { key: "Value", value: "1.AQsAq7f...k2Zw (about 1,900 characters)", label: "The content", note: "Opaque to the browser. The sign-in service reads it on each visit." },
          { key: "Domain", value: ".login.microsoftonline.com", note: "The browser sends the cookie to this host only." },
          { key: "Path", value: "/" },
          { key: "Expires", value: "2027-02-08T11:02:41Z", label: "Lifetime", note: "A persistent cookie stays on disk and survives a browser restart." },
          { key: "Secure", value: "true", note: "Sent over HTTPS only." },
          { key: "HttpOnly", value: "true", note: "Scripts on the page can't read it. It still travels in the Set-Cookie response header." },
          { key: "SameSite", value: "None", note: "Sent on cross-site requests too, which sign-in redirects need." },
        ],
        summary: "Read the list again for what isn't there: no phone, no fingerprint, no address the browser must come from. The prompt ended at sign-in, and this value is what the service reads from then on. It's a bearer credential, so a copy works like the original. Copying it and using it are two moves, and ATT&CK gives them two IDs, which the next labs walk through.",
      },
      {
        kind: "sort",
        title: "Tricked, Stolen or No Login at All?",
        prompt: "Hyun-woo keeps a board of the ways people get past MFA without cracking a password. Eight cards from past incidents at other hospitals: bin each one by how MFA was beaten.",
        primer: {
          fold: true,
          title: "Five techniques, one gate",
          points: [
            "**T1621**, Multi-Factor Authentication Request Generation: the attacker has a password and wears a person down with prompts.",
            "**T1539**, Steal Web Session Cookie, then **T1550.004**, Web Session Cookie: the sign-in runs properly and the cookie is taken and reused.",
            "**T1134.001**, Token Impersonation/Theft: a Windows security token is copied on a host.",
            "**T1528**, Steal Application Access Token: an app ends up holding tokens of its own.",
            "**T1606.002**, SAML Tokens: a signed assertion is forged with a stolen key.",
          ],
          example: {
            label: "Three ways round a hotel front desk",
            lines: [
              "The clerk is talked into handing over a key card: the human was tricked.",
              "A genuine key card is lifted from a guest's pocket: the artifact was stolen.",
              "Someone with the master encoder cuts a new card: nobody went near the desk at all.",
            ],
          },
        },
        buckets: [{ id: "tricked", label: "A person was tricked into approving" }, { id: "stolen", label: "A genuine session was taken after sign-in" }, { id: "nologin", label: "No fresh sign-in was needed at all" }],
        items: [
          { id: "c1", text: "38 prompts overnight to an anaesthetist's phone, and at 04:10 one Approve", bucket: "tricked", why: "T1621. The attacker never held the second factor: a tired person supplied it." },
          { id: "c2", text: "A caller claiming to be IT says 'just approve the next one so we can fix this'", bucket: "tricked", why: "Still T1621: a phone call added to the prompts, and the approval still comes from a person." },
          { id: "c3", text: "A lookalike host forwards a real sign-in and keeps a copy of the reply", bucket: "stolen", why: "T1539. The sign-in itself was correct. The taking happened afterwards." },
          { id: "c4", text: "That copied cookie is loaded into a browser on another continent", bucket: "stolen", why: "T1550.004: the use of what T1539 took. Two IDs, two moments." },
          { id: "c5", text: "A 'potato' tool coerces a SYSTEM service on a ward server and copies its token", bucket: "nologin", why: "T1134.001. A Windows token, duplicated on the host. No identity provider took part." },
          { id: "c6", text: "A signing key stolen from a federation server signs an assertion for an admin", bucket: "nologin", why: "T1606.002. The proof of sign-in was written from scratch, offline." },
          { id: "c7", text: "An app granted access in March is still reading files in June, after two password changes", bucket: "nologin", why: "T1528, Steal Application Access Token. The app uses its own tokens, so no sign-in happens each time." },
          { id: "c8", text: "A registrar taps Approve on the first prompt, at 02:00, half asleep", bucket: "tricked", why: "T1621 at its cheapest: one prompt, one reflex. Nothing was taken from the phone." },
        ],
      },
    ],
    // ── Reading 4: AiTM ──
    "mfast-r4": [
      {
        kind: "pathway",
        title: "Follow the Relay",
        prompt: "Tuesday, 11:30. Maeve still has the rota swap form: a PDF with a QR code, scanned on a personal phone at 08:52. She typed her password and a six-digit code, and everything worked. Walk what happened, hop by hop, from the QR code to the mailbox.",
        primer: {
          fold: true,
          title: "How a relay works",
          points: [
            "**Adversary-in-the-middle (AiTM)**: the attacker's server sits between a victim and the real service, passes traffic both ways and records it.",
            "A **reverse proxy** takes a client's requests and forwards them to a server behind it. TLS ends at the proxy, so it reads everything.",
            "Public kits of this kind include Evilginx, Tycoon 2FA and EvilProxy.",
            "An **OATH code** is the six-digit code in an authenticator app that changes every 30 seconds.",
          ],
          example: {
            label: "A reverse proxy doing honest work",
            lines: [
              "A ticket site runs behind a load balancer that ends TLS.",
              "The padlock in the browser belongs to the load balancer's certificate.",
              "Every request and reply, cookies included, passes through it as readable text.",
              "Give that position to an attacker, on a hostname of their choosing, and you have this lab.",
            ],
          },
        },
        goal: "Take the session from the QR code to the mailbox",
        nodes: [
          { id: "lure", label: "Rota swap PDF", sub: "QR code", x: 12, y: 22 },
          { id: "fake", label: "Saved copy of a login page", x: 30, y: 62 },
          { id: "proxy", label: "rota.kingsmere-staff.example", sub: "198.51.100.23", x: 32, y: 26 },
          { id: "entra", label: "Real sign-in service", sub: "Microsoft Entra ID", x: 54, y: 16 },
          { id: "cookie", label: "Set-Cookie response", sub: "ESTSAUTHPERSISTENT", x: 78, y: 20 },
          { id: "maeve", label: "Maeve's phone", x: 90, y: 50 },
          { id: "capture", label: "The proxy's own log", x: 60, y: 46 },
          { id: "attacker", label: "Another browser", sub: "203.0.113.140", x: 44, y: 80 },
          { id: "prompt", label: "A new MFA prompt", x: 20, y: 88 },
          { id: "exo", label: "Maeve's mailbox", sub: "Exchange Online", x: 72, y: 82 },
        ],
        edges: [["lure", "fake"], ["lure", "proxy"], ["proxy", "entra"], ["proxy", "attacker"], ["entra", "cookie"], ["cookie", "maeve"], ["cookie", "capture"], ["capture", "attacker"], ["attacker", "prompt"], ["attacker", "exo"]],
        route: ["lure", "proxy", "entra", "cookie", "capture", "attacker", "exo"],
        notes: {
          lure: "A form in a PDF, with a QR code. Scanning it moves the sign-in from a managed laptop to a personal phone.",
          proxy: "This host isn't a copy of a page. Each request goes on to the real service and each reply comes back through here, so what Maeve saw was the real page, live.",
          entra: "The password and the six-digit code she typed go straight on to Entra. Both are right, so MFA passes. Nothing about this check went wrong.",
          cookie: "Entra does what it should and issues a real session cookie, in reply to whoever asked: the proxy.",
          capture: "The proxy writes the cookie to its log, then passes it on. ATT&CK files this moment as T1539, Steal Web Session Cookie, under Credential Access.",
          attacker: "The cookie is imported into a browser on another network. This is T1550.004, Use Alternate Authentication Material: Web Session Cookie, under Lateral Movement.",
          exo: "The mailbox opens. The service took the cookie as proof, so no password, code or prompt ran on this side.",
        },
        traps: {
          fake: "A saved copy of a login page catches a password and stops there. It can't get a code checked and it never receives a session. This kit forwards everything live.",
          attacker: "Too early. No session exists until the sign-in service has seen both factors, so there's nothing to load into another browser yet.",
          maeve: "The cookie does reach Maeve's phone, which is why nothing looked wrong to her. But the proxy sits in the path, so it has the cookie first.",
          prompt: "No prompt runs. The cookie already carries the proof that MFA happened, so the service has nothing to ask.",
        },
        lesson: "A relay doesn't defeat MFA, it lets MFA finish and takes the result. Maeve did everything right on a real page, and the failure came after the check. That's why the phrase is 'made irrelevant', not 'bypassed'. A cookie replay has no authentication step on the attacker's side, so there's no failed logon to look for. The evidence has to come from comparing sign-ins.",
      },
    ],
    // ── Reading 5: session replay in the logs ──
    "mfast-r5": [
      {
        kind: "portal",
        title: "One Session, Two Places",
        prompt: "Tuesday, 11:50. Hyun-woo opens the admin center and slides the keyboard over: 'No alert fired on this account. Show me what the sign-in logs can prove, then shut it down.'",
        skin: "entra",
        primer: {
          fold: true,
          title: "Reading a sign-in row",
          points: [
            "**SessionId** names one sign-in session. Renewing tokens inside that session keeps the same value.",
            "**UniqueTokenIdentifier** names one token, so it changes each time a token is issued. It tracks a token to the resource that redeemed it.",
            "**IncomingTokenType** lists the token a client presented. Microsoft notes the list isn't complete, so `none` doesn't prove that no token came in.",
            "**AuthenticationProtocol** names the protocol or grant. `none` is common in a browser.",
            "Interactive rows are usually a person giving a factor. Non-interactive rows are a client presenting a token, and the log view opens on the interactive tab.",
          ],
          example: {
            label: "One quiet row, read top to bottom",
            lines: [
              "A pharmacy PC, Outlook renewing mail access at 11:05: non-interactive, device ID present, compliant.",
              "`IncomingTokenType: primaryRefreshToken`, the token the PC's broker holds. `AuthenticationProtocol: none`.",
              "Authentication Details: `Previously satisfied`. Nobody was asked anything, and on a PC like this that happens all day.",
              "So one row rarely says much. Ask which session it belongs to and where else that session has been.",
            ],
          },
        },
        product: "Identity admin center",
        resource: "Kingsmere Private Hospital",
        tenant: "kingsmerehospital.example",
        home: "overview",
        menu: [
          { items: [{ id: "overview", label: "Overview" }, { id: "users", label: "Users" }] },
          { group: "Sign-in logs", items: [{ id: "interactive", label: "User sign-ins (interactive)" }, { id: "noninteractive", label: "User sign-ins (non-interactive)" }] },
          { group: "Monitoring & health", items: [{ id: "audit", label: "Audit logs" }] },
        ],
        pages: {
          overview: {
            heading: "Overview",
            tiles: [{ label: "Users", value: "1,140" }, { label: "Devices", value: "1,620" }, { label: "Applications", value: "44" }],
            note: "Primary domain kingsmerehospital.example. Ticket KPH-30917, m.tierney: 09:40 mail to Accounts about a supplier's bank details. The user reports being in Theatre 2 at that time.",
          },
          users: {
            heading: "Users",
            table: {
              columns: ["Display name", "User principal name", "User type", "Account enabled"],
              rows: [
                { id: "u-hs", cells: ["Hyun-woo Salazar", "h.salazar@kingsmerehospital.example", "Member", "Yes"] },
                { id: "u-mt", cells: ["Maeve Tierney", MAEVE, "Member", "Yes"], record: "u-mt" },
                { id: "u-lp", cells: ["Lena Pryce", "l.pryce@kingsmerehospital.example", "Member", "Yes"] },
              ],
            },
          },
          interactive: {
            heading: "Sign-in events",
            filters: ["User contains: m.tierney", "Date: Last 48 hours", "Show dates as: Local"],
            table: {
              columns: ["Date", "User", "Application", "Status", "IP address", "Location", "Risk level (real-time)", "Conditional Access"],
              rows: [
                { id: "i-relay", cells: ["Today 08:52:31", "Maeve Tierney", "OfficeHome", "Success", "198.51.100.23", "Frankfurt, DE", "none", "Success"], record: "i-relay" },
                { id: "i-lap", cells: ["Today 07:41:18", "Maeve Tierney", "OfficeHome", "Success", "203.0.113.18", "Bristol, GB", "none", "Success"], record: "i-lap" },
                { id: "i-mon", cells: ["Monday 07:39:02", "Maeve Tierney", "OfficeHome", "Success", "203.0.113.18", "Bristol, GB", "none", "Success"], record: "i-mon" },
              ],
            },
          },
          noninteractive: {
            heading: "Sign-in events",
            filters: ["User contains: m.tierney", "Date: Last 48 hours", "Show dates as: Local"],
            table: {
              columns: ["Date", "User", "Application", "Status", "IP address", "Location", "Risk level (real-time)", "Conditional Access"],
              rows: [
                { id: "n-teams", cells: ["Today 09:58:12", "Maeve Tierney", "Microsoft Teams", "Success", "198.51.100.201", "Bristol, GB", "none", "Success"], record: "n-teams" },
                { id: "n-rep", cells: ["Today 09:31:07", "Maeve Tierney", "One Outlook Web", "Success", "203.0.113.140", "Bucharest, RO", "none", "Success"], record: "n-rep" },
                { id: "n-hot", cells: ["Today 08:21:40", "Maeve Tierney", "Microsoft Office", "Success", "198.51.100.177", "Bristol, GB", "none", "Success"], record: "n-hot" },
                { id: "n-lap", cells: ["Today 08:03:55", "Maeve Tierney", "Microsoft Office", "Success", "203.0.113.18", "Bristol, GB", "none", "Success"], record: "n-lap" },
              ],
            },
          },
          audit: {
            heading: "Audit logs",
            filters: ["Date: Last 48 hours", "Target contains: m.tierney"],
            table: {
              columns: ["Date", "Service", "Category", "Activity", "Status", "Target", "Initiated by"],
              rows: [
                { id: "a-method", cells: ["Today 09:36:52", "Authentication Methods", "UserManagement", "User registered security info", "Success", "Maeve Tierney", MAEVE], record: "a-method" },
                { id: "a-group", cells: ["Monday 16:20:11", "Core Directory", "GroupManagement", "Add member to group", "Success", "Maeve Tierney", "h.r.sync@kingsmerehospital.example"] },
              ],
            },
          },
        },
        records: {
          "i-relay": signIn({ id: "41f7c2e9-0b3a-4d16-8e75-a92c6d10f3b8", date: "Today 08:52:31", app: "OfficeHome", resource: "OfficeHome", client: "Browser", session: SESSION_RELAY, token: "mQ3xTz8VhE2pLk0sYb7rAA", incoming: "none", ip: "198.51.100.23", asn: "64502", place: "Frankfurt, Hesse, DE", deviceId: "", browser: "Mobile Safari 18.1", os: "iOS 18.1", compliant: "No", managed: "No", join: "", auth: FRESH_MFA }),
          "i-lap": signIn({ id: "b80d6a13-7e24-4f09-a1c6-3d5e92f7c014", date: "Today 07:41:18", app: "OfficeHome", resource: "OfficeHome", client: "Browser", session: SESSION_LAPTOP, token: "Zr9dKw1uJ0mNf5oXc2HtAA", incoming: "primaryRefreshToken", ip: "203.0.113.18", asn: "64500", place: "Bristol, England, GB", deviceId: LAPTOP_ID, browser: "Edge 130.0", os: "Windows 11", compliant: "Yes", managed: "Yes", join: "Microsoft Entra joined", auth: CLAIM_MFA }),
          "i-mon": signIn({ id: "6c1ae470-d52f-4b83-96e1-07fb3c28d5a9", date: "Monday 07:39:02", app: "OfficeHome", resource: "OfficeHome", client: "Browser", session: SESSION_MONDAY, token: "Pq6vHn4yTa1eUg8wLs3KAA", incoming: "primaryRefreshToken", ip: "203.0.113.18", asn: "64500", place: "Bristol, England, GB", deviceId: LAPTOP_ID, browser: "Edge 130.0", os: "Windows 11", compliant: "Yes", managed: "Yes", join: "Microsoft Entra joined", auth: CLAIM_MFA }),
          "n-teams": signIn({ id: "d3e95b07-1f6c-4a72-b4d8-5c20e7a196f3", date: "Today 09:58:12", app: "Microsoft Teams", resource: "Microsoft Teams Services", client: "Mobile Apps and Desktop clients", session: SESSION_PHONE, token: "Xc2bNf7qRi5oYw0jDe9MAA", incoming: "none", ip: "198.51.100.201", asn: "64503", place: "Bristol, England, GB", deviceId: PHONE_ID, browser: "Teams 7.26", os: "iOS 18.1", compliant: "Yes", managed: "Yes", join: "Microsoft Entra registered", auth: CLAIM_MFA }),
          "n-rep": signIn({ id: "2fa86d31-c94e-4e07-8b12-e6d370a5c9f4", date: "Today 09:31:07", app: "One Outlook Web", resource: "Office 365 Exchange Online", client: "Browser", session: SESSION_RELAY, token: "Hy4oKt9sWb2mZe6gRc1QAA", incoming: "none", ip: "203.0.113.140", asn: "64511", place: "Bucharest, Bucuresti, RO", deviceId: "", browser: "Chrome 131.0", os: "Windows 10", compliant: "No", managed: "No", join: "", auth: CLAIM_MFA }),
          "n-hot": signIn({ id: "a71c0e58-36bd-4f92-c5a0-18d4e9b27f63", date: "Today 08:21:40", app: "Microsoft Office", resource: "Office 365 Exchange Online", client: "Mobile Apps and Desktop clients", session: SESSION_LAPTOP, token: "Vd8jLq3xAf6tNu1pGy5EAA", incoming: "primaryRefreshToken", ip: "198.51.100.177", asn: "64503", place: "Bristol, England, GB", deviceId: LAPTOP_ID, browser: "Rich Client 16.0", os: "Windows 11", compliant: "Yes", managed: "Yes", join: "Microsoft Entra joined", auth: CLAIM_MFA }),
          "n-lap": signIn({ id: "58e2b9f4-a07d-41c6-9d38-f14c62b0e7d5", date: "Today 08:03:55", app: "Microsoft Office", resource: "Office 365 Exchange Online", client: "Mobile Apps and Desktop clients", session: SESSION_LAPTOP, token: "Tg1wEs7kCo4hBm9zIr2UAA", incoming: "primaryRefreshToken", ip: "203.0.113.18", asn: "64500", place: "Bristol, England, GB", deviceId: LAPTOP_ID, browser: "Rich Client 16.0", os: "Windows 11", compliant: "Yes", managed: "Yes", join: "Microsoft Entra joined", auth: CLAIM_MFA }),
          "a-method": {
            id: "Directory_7d41c0e2",
            title: "Audit log details: User registered security info",
            facts: [["Date", "Today 09:36:52"], ["Service", "Authentication Methods"], ["Category", "UserManagement"], ["Activity", "User registered security info"], ["Status reason", "User registered Authenticator App with Notification and Code"], ["Initiated by", MAEVE], ["IP address", "203.0.113.140"], ["Target", "Maeve Tierney"]],
          },
          "u-mt": {
            id: "e41b7a06-92c3-4d58-bf10-7a3d65c1e829",
            title: "Maeve Tierney",
            actions: [{ id: "revoke", label: "Revoke sessions" }, { id: "reset", label: "Reset password" }],
            facts: [["User principal name", MAEVE], ["Job title", "Theatre Manager"], ["Department", "Theatres"], ["Account enabled", "Yes"], ["Authentication methods", "2 registered"]],
          },
        },
        steps: [
          { id: "open", ask: "Start with the identity provider's own record. Open the interactive sign-ins.", hint: "User sign-ins (interactive), under Sign-in logs.", target: "menu:interactive", why: "These rows are usually moments when someone gave a factor. It's the view the log opens on, so it's where many investigations start and some end." },
          { id: "relay", ask: "Maeve scanned the QR code and typed a code just before 09:00. Open that sign-in.", hint: "Read the Date column.", target: "row:i-relay", why: "08:52:31, Success, from a hosting network in Frankfurt. Entra records whoever connected to it, so a relayed sign-in carries the relay's address, not the user's." },
          { id: "mfa", ask: "Did MFA really run on this sign-in?", hint: "The Authentication Details tab.", target: "action:auth", why: "Password, then an OATH verification code, both succeeded. A real person gave real factors, so this row has no failure to find." },
          { id: "sid", ask: "Find the value that names this session, and keep it in mind.", hint: "Session ID, on Basic info.", target: "action:basic", why: "c71e04ab-9f3d. The Unique token identifier beside it belongs to one token and will change. The session's value is the one that lets you follow it." },
          { id: "other", ask: "The other half of the log sits on the next tab. Open it.", hint: "User sign-ins (non-interactive).", target: "menu:noninteractive", why: "Here, clients present tokens and nobody gives a factor. None of these rows ever showed in the view you just left." },
          { id: "match", ask: "Find the row that carries that same Session ID.", hint: "Open rows and read Basic info. The Location column alone won't settle it.", target: "row:n-rep", why: "c71e04ab-9f3d again, 38 minutes later, from Bucharest on another network. One session, two places, and a new Unique token identifier. That pair of rows is your case." },
          { id: "device", ask: "Same session. Is it the same machine?", hint: "The Device info tab.", target: "action:dev", why: "Chrome on Windows 10 with no device ID, where the session began in Mobile Safari on iOS. Compare the 08:21 row: a new network too, but the same device ID and the same client, because that's Maeve's laptop moving to a hotspot." },
          { id: "claim", ask: "What did the person at this row prove when it was written?", hint: "Authentication Details again.", target: "action:auth", why: "`Previously satisfied`, `MFA requirement satisfied by claim in the token`. Nobody was asked anything. Outlook on Maeve's laptop writes that same line all day, so it only matters on this session, from that device." },
          { id: "green", ask: "Now see what the policy engine made of it.", hint: "The Conditional Access tab.", target: "action:capol", why: "Success, and the grid says risk none. Maeve holding this session would produce exactly the same row, so these two fields can't tell her apart from anyone else holding it." },
          { id: "audit", ask: "What did the session change? Open the directory's change record.", hint: "Audit logs, under Monitoring & health.", target: "menu:audit", why: "Sign-in logs say who got in. Audit logs say what changed in the directory while they were there." },
          { id: "method", ask: "Open the change made during the Bucharest session.", hint: "Compare Date with 09:31.", target: "row:a-method", why: "09:36: `User registered security info`, from 203.0.113.140. A method of the attacker's own is a way back that no longer needs this cookie." },
          { id: "users", ask: "Time to end it. Find the account.", hint: "Users, at the top of the menu.", target: "menu:users", why: "Containment acts on the account, so it's on the user's page and not on any log row." },
          { id: "maeve", ask: "Open Maeve's account.", hint: "The user the ticket names.", target: "row:u-mt", why: "Two registered methods, and Maeve set up only one of them." },
          { id: "revoke", ask: "Cut the live session first.", hint: "One of the buttons above the details.", target: "action:revoke", why: "Revoke sessions kills refresh tokens and session cookies. An access token already issued can live on until it expires, around an hour, unless the resource supports Continuous Access Evaluation. Next on the list: remove the added method, then reset the password." },
        ],
        traps: {
          "action:reset": "Not first. Cut the live session, clear anything added to the account, then reset.",
        },
        lesson: "A success with MFA on it tells you a prompt was answered, not who ended up with the session. Follow the Session ID across both log views, then compare device and client as well as place, because a laptop on a hotspot changes network too. The line 'satisfied by claim in the token' is ordinary on its own, and it's the session it sits on that matters.",
      },
      {
        kind: "worksheet",
        title: "Trip, Roam or Replay?",
        prompt: "Hyun-woo pulls three closed tickets from last quarter. A change of network or place sent all of them to the queue. Read the rows from SigninLogs and say what each one really was.",
        caption: "SigninLogs · three users · last quarter",
        columns: ["UserPrincipalName", "SessionId", "IPAddress", "ASN", "City", "DeviceId", "Browser"],
        rows: [
          ["r.khan", "4f10a2c7", "203.0.113.18", "64500", "Bristol", "3c8e91d0", "Edge 129"],
          ["r.khan", "a7c35e12", "198.51.100.66", "64505", "Lisbon", "3c8e91d0", "Edge 129"],
          ["p.hale", "1d9e60fb", "203.0.113.18", "64500", "Bristol", "b05f27a4", "Edge 129"],
          ["p.hale", "1d9e60fb", "198.51.100.180", "64503", "Bristol", "b05f27a4", "Edge 129"],
          ["a.novak", "62ab08d3", "198.51.100.41", "64502", "Warsaw", "", "Mobile Safari 17"],
          ["a.novak", "62ab08d3", "203.0.113.203", "64509", "Vilnius", "", "Firefox 131"],
        ],
        questions: [
          { id: "trip", q: "Who flew to a conference: two places, a new session, the same laptop?", hint: "Look for a SessionId that changes while the DeviceId doesn't.", answer: ["r.khan", "khan"], why: "r.khan signed in afresh in Lisbon on the same device. A new session is what a real trip looks like." },
          { id: "roam", q: "Whose session stayed on one device and only changed network?", hint: "Same SessionId, same DeviceId.", answer: ["p.hale", "hale"], why: "p.hale moved from hospital Wi-Fi to a phone hotspot. The session kept its device and browser, so the IP change on its own means little." },
          { id: "replay", q: "Whose one session ran in two browsers on two networks?", hint: "Same SessionId, different Browser and ASN.", answer: ["a.novak", "novak"], why: "a.novak: one SessionId, two networks, two browsers and no device ID on either row. That's the shape you just proved on Maeve's account." },
          { id: "city", q: "How many of the three would a rule on 'new city' alone have flagged?", hint: "Count users whose City changes.", answer: ["2", "two"], why: "Two: r.khan and a.novak. p.hale never left Bristol. Place helps as support, and it can't separate the honest trip from the replay. The session comparison can." },
        ],
      },
    ],
    // ── Reading 2: push fatigue ──
    "mfast-r2": [
      {
        kind: "sequence",
        title: "A Push Storm, From the Attacker's Chair",
        prompt: "Wednesday, 07:30. Accounts stopped the payment, and Hyun-woo finds the same crew tried another way in overnight. Agency nurses and locums sign in through Kingsmere's Okta org, with Okta Verify pushes. Put the crew's night in the order it ran.",
        primer: {
          fold: true,
          title: "How push MFA works",
          points: [
            "**Push MFA** (Okta Verify, Microsoft Authenticator, Duo) sends one Approve or Deny prompt to a phone for each sign-in attempt.",
            "**MFA fatigue**, or push bombing, is **T1621**, Multi-Factor Authentication Request Generation, under Credential Access.",
            "The attacker needs a working password first: from credential stuffing, a phishing kit or an infostealer log.",
            "There's no exploit and no malware. Each prompt comes from a real attempt against the real identity provider.",
          ],
          example: {
            label: "The same pressure in another job",
            lines: [
              "A ward bleeps the on-call doctor every two minutes through the night.",
              "Every bleep is a real bleep from a real phone, and the doctor can ignore the first ten.",
              "Whoever bleeps pays nothing for each try, and the doctor needs to slip only once.",
            ],
          },
        },
        items: [
          { id: "s3", text: "Submit the password again and again", note: "Each correct password raises a fresh push. Every one is real." },
          { id: "s6", text: "Hold a fully MFA-satisfied session", note: "Nothing about this session is forged. The identity provider issued it." },
          { id: "s1", text: "Buy a working password from an infostealer log", note: "A valid username and password is the entry fee." },
          { id: "s4", text: "Call the locum, claiming to be from IT", note: "'Approve the next one and the alerts will stop.' Often added once the prompts alone stall." },
          { id: "s2", text: "Wait until 01:50, in the middle of a night shift", note: "Tired people tap. Timing is part of the method." },
          { id: "s5", text: "The locum taps Approve on one push", note: "It takes one mistake, ever. The attacker can keep trying for free." },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "The crew never had the second factor. A person handed it over, one tap in a run of refusals. That's the difference from Maeve's case, where MFA finished properly and only the result was taken. Read any one row of that night and nothing is wrong. The evidence only exists when you read the run for one account.",
      },
    ],
    // ── Reading 3: detecting fatigue ──
    "mfast-r3": [
      {
        kind: "worksheet",
        title: "Read the Okta Trail",
        prompt: "Wednesday, 08:10. Hyun-woo pulls the System Log for l.fenn, a locum registrar on nights. Work these questions from the rows.",
        primer: {
          fold: true,
          title: "Okta's event names",
          points: [
            "`system.push.send_factor_verify_push`: a push left Okta for the user's phone. `okta.debugContext.debugData.factor` names the method, such as OKTA_VERIFY_PUSH.",
            "`user.mfa.okta_verify.deny_push`: the user tapped Deny, and `okta.outcome.result` reads FAILURE.",
            "`user.authentication.auth_via_mfa`: the MFA step finished. Read `okta.outcome.result` with it, because on Okta Identity Engine a denial can land here too, with `okta.outcome.reason: INVALID_CREDENTIALS`.",
            "**Number matching** ties an approval to the sign-in screen. Verified Duo Push, for example, has the user enter a code shown there, so a reflex tap can't finish. A relay can simply show its victim the real code, and a replayed session raises no prompt at all.",
            "A detection counts per actor inside a window, commonly 10 to 15 minutes, with a threshold commonly between 5 and 10.",
          ],
          example: {
            label: "Why the count is per actor",
            lines: [
              "Shift change. Two porters each refuse three prompts across an hour.",
              "Tenant-wide that's six denials. Per actor it's three and three.",
              "Grouped by actor, a threshold of 5 stays quiet, and that's correct for this data.",
            ],
          },
        },
        caption: "Okta System Log · actor l.fenn · Wednesday, times in UTC",
        columns: ["published", "eventType", "outcome.result", "client.ipAddress", "debugData.factor"],
        rows: [
          ["01:52:10", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:52:31", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:53:40", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:53:52", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:55:06", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:55:19", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:56:44", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:57:02", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:58:15", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["01:58:33", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["02:00:01", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
          ["02:00:06", "user.authentication.auth_via_mfa", "SUCCESS", "198.51.100.88", "OKTA_VERIFY_PUSH"],
        ],
        questions: [
          { id: "count", q: "How many pushes did l.fenn refuse?", hint: "Count the deny_push rows.", answer: ["5", "five"], why: "Five refusals in under seven minutes, and not one of those rows is wrong on its own." },
          { id: "span", q: "Roughly how many minutes from the first push to the last row?", hint: "01:52 to 02:00.", answer: ["8", "eight"], why: "Eight minutes. That span is the window a correlation rule has to hold open." },
          { id: "ip", q: "Did the last row come from the same client address as the refusals? (yes/no)", hint: "Compare client.ipAddress down the column.", answer: ["yes", "y"], why: "198.51.100.88 throughout, and l.fenn's phone is on the ward. One source producing the whole run is what ties the rows into one story." },
          { id: "rule", q: "Which eventType would a rule count to measure refusals?", hint: "The one that reads FAILURE.", answer: ["user.mfa.okta_verify.deny_push", "deny_push"], why: "`user.mfa.okta_verify.deny_push`, per actor, in a window. On Okta Identity Engine a good rule counts refused `auth_via_mfa` events as well." },
        ],
      },
      {
        kind: "tune",
        title: "Tune the Push-Storm Rule",
        prompt: "Wednesday, 09:00. Hyun-woo wants a detection for the Okta org: catch all six storms from last quarter and stay quiet on the six everyday bursts. You get three deploys. Set how many denials the rule needs, and how soon after the last denial a successful MFA must follow.",
        eventColumn: "Burst on one account",
        dials: [
          { id: "denies", label: "deny_push events for one actor in 15 minutes, at least", short: "Denials", min: 1, max: 20, step: 1, start: 1, dir: "above" },
          { id: "gap", label: "Minutes from the last denial to a successful auth_via_mfa, at most", short: "Gap", unit: "min", min: 1, max: 60, step: 1, start: 60, dir: "below" },
        ],
        events: [
          { id: "b1", label: "9 denials at 02:14, success 1 minute later, new hosting address", bad: true, values: { denies: 9, gap: 1 } },
          { id: "b2", label: "5 denials at 03:40, success 2 minutes later, source abroad", bad: true, values: { denies: 5, gap: 2 } },
          { id: "b3", label: "7 denials, a phone call, success 9 minutes after the last one", bad: true, values: { denies: 7, gap: 9 } },
          { id: "b4", label: "15 denials at lunchtime, success 1 minute later, VPN exit", bad: true, values: { denies: 15, gap: 1 } },
          { id: "b5", label: "5 denials in 12 minutes on a slow evening, success 6 minutes later", bad: true, values: { denies: 5, gap: 6 } },
          { id: "b6", label: "8 denials at 04:05, success 4 minutes later, new device enrolled at once", bad: true, values: { denies: 8, gap: 4 } },
          { id: "n1", label: "4 denials at the IT desk during a phone swap, success 1 minute later", bad: false, values: { denies: 4, gap: 1 } },
          { id: "n2", label: "3 denials at handover on a shared ward tablet, success 2 minutes later", bad: false, values: { denies: 3, gap: 2 } },
          { id: "n3", label: "9 denials from an old mail client at home, next success 40 minutes later on hospital Wi-Fi", bad: false, values: { denies: 9, gap: 40 } },
          { id: "n4", label: "7 denials from a stale desktop app, next success 25 minutes later on the ward PC", bad: false, values: { denies: 7, gap: 25 } },
          { id: "n5", label: "2 denials, phone in a scrub pocket, success 1 minute later", bad: false, values: { denies: 2, gap: 1 } },
          { id: "n6", label: "3 denials after a password change, success 5 minutes later", bad: false, values: { denies: 3, gap: 5 } },
        ],
        goal: { catch: 6, maxFalse: 0 },
        lesson: "No row in this table is suspicious because of one event: each push is real, so the rule has to measure the run and how it ended. Denials alone catch a stale client, and a success alone catches everyone. Add off-hours timing, a source the user has never used, or a method enrolled straight after, and the case gets stronger. One or two denials are a phone in a pocket, so they never go up the chain alone. A storm with no success is a different finding: somebody holds the password, so it belongs in its own lower-severity rule.",
      },
    ],
    // ── Verdict words, before the triage task ──
    "mfast-ac1": [
      {
        kind: "queue",
        title: "How Does It Close?",
        prompt: "Wednesday, 10:15. Hyun-woo hands you four alerts from the morning queue. Before the next one lands on your desk, get the close-out words right: decide what each alert really was.",
        primer: {
          fold: true,
          title: "Three ways an alert ends",
          points: [
            "**True positive**: the rule fired on a real event, and the event is malicious. It goes up.",
            "**Benign true positive**: the rule fired correctly on a real event, and there's a harmless explanation. Cite the explanation when you close it.",
            "**False positive**: the rule's condition wasn't really met, because the rule or its data was wrong.",
            "Check with the user or IT before you close. Severity is the rule's opinion, not a finding.",
          ],
          example: {
            label: "One rule, two closes",
            lines: [
              "A 'mass file delete' rule fires on Sunday night. A change ticket covers a file server migration, and the deletes are real: benign true positive.",
              "It fires again on Monday. The parser read renames as deletes, and nothing was deleted: false positive.",
            ],
          },
        },
        console: "SIEM · Identity alerts",
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "a1", time: "06:48", severity: "Medium", rule: "New MFA factor enrolled", entity: "j.lowe",
            fields: [{ k: "okta.eventType", v: "user.mfa.factor.activate" }, { k: "okta.client.ipAddress", v: "203.0.113.18" }, { k: "okta.outcome.result", v: "SUCCESS" }],
            context: "Ticket IT-58201: phone replaced under warranty. j.lowe's ward manager confirmed by phone. The enrolment came from the IT desk, on the hospital network.",
            answer: "btp", why: "The rule fired on exactly what it watches for: a real enrolment. The ticket and the call are your explanation, and you cite them when you close.",
          },
          {
            id: "a2", time: "07:20", severity: "Low", rule: "Sign-in outside rostered hours", entity: "m.ortega",
            fields: [{ k: "rota.lookup", v: "empty" }, { k: "okta.client.ipAddress", v: "203.0.113.18" }, { k: "okta.eventType", v: "user.session.start" }],
            context: "This week's rota file failed to load, so the lookup is empty and everyone on the team matched. m.ortega is on shift, on the published rota.",
            answer: "fp", why: "The condition was never true: m.ortega was rostered. The fault is in the rule's data, so fix the lookup, and note the close as a false positive.",
          },
          {
            id: "a3", time: "03:12", severity: "High", rule: "Repeated push denials then success", entity: "k.imai",
            fields: [{ k: "deny_push count", v: "8 in 9 minutes" }, { k: "okta.client.ipAddress", v: "198.51.100.88" }, { k: "success after last denial", v: "2 minutes" }],
            context: "Raised when the new rule was run back over the night. k.imai works days and was asleep. No ticket. At 08:00, k.imai says 'my phone kept going off, so I pressed it to make it stop'.",
            answer: "esc", why: "Same address as the l.fenn storm, the wrong hour, and a person telling you how it ended. Escalate, and revoke the session.",
          },
          {
            id: "a4", time: "09:02", severity: "Medium", rule: "Sign-in from a new country", entity: "s.amadi",
            fields: [{ k: "okta.client.geographicalContext.country", v: "Portugal" }, { k: "okta.client.device", v: "Computer" }, { k: "okta.outcome.result", v: "SUCCESS" }],
            context: "Annual leave is logged in HR for Porto this week. s.amadi confirms by phone from the registered number, on the usual laptop.",
            answer: "btp", why: "A real sign-in from a new country, so the rule was right. The leave record and the call explain it, which makes this benign, not false.",
          },
        ],
      },
    ],
    // ── Reading 6: two layers of token ──
    "mfast-r6": [
      {
        kind: "sort",
        title: "Which Log Holds It?",
        prompt: "Thursday, 09:30. Two weeks of Kingsmere tickets all say 'token theft'. Hyun-woo wants each evidence line sent to the team that can act on it, because the word means different things on different layers. Bin each one.",
        primer: {
          fold: true,
          title: "Same word, two layers",
          points: [
            "**T1134.001**, Access Token Manipulation: Token Impersonation/Theft, is mapped to Privilege Escalation and Stealth (TA0005). It copies a Windows security token on a host, with APIs such as `DuplicateTokenEx` and `ImpersonateLoggedOnUser`.",
            "Its evidence is endpoint telemetry: Sysmon Event ID 18 (Pipe Connected), Sysmon Event ID 10 (ProcessAccess), and Windows events 4672 and 4673.",
            "**T1528**, Steal Application Access Token, is under Credential Access. An attacker's app gets OAuth tokens, often through a real consent screen.",
            "Its evidence is in the identity provider: in Entra ID, the `Consent to application` audit operation, with the publisher, the app's age and the scopes requested.",
          ],
          example: {
            label: "Another word that lives on two layers",
            lines: [
              "A ticket says 'certificate expired'. Is that the TLS certificate on the web portal, or the code-signing certificate on an installer?",
              "The first shows up in web server errors, the second in a Windows signature check.",
              "The word doesn't tell you. The log the evidence sits in does, and that picks the team.",
            ],
          },
        },
        buckets: [{ id: "host", label: "One Windows host: endpoint team" }, { id: "idp", label: "Identity provider logs: identity team" }],
        items: [
          { id: "t1", text: "Sysmon 18: a SYSTEM process connects to \\\\.\\pipe\\spoolss_kph", bucket: "host", why: "Pipe Connected. Coercing a SYSTEM service to a named pipe is the classic 'potato' setup, so it's Windows evidence and T1134.001." },
          { id: "t2", text: "Audit log: Consent to application, Rota Sync, Files.ReadWrite.All, first seen today", bucket: "idp", why: "A consent record in the identity provider, for an app nobody has seen before asking for broad scope. That's T1528 evidence." },
          { id: "t3", text: "Sysmon 10: GrantedAccess 0x1410 against a SYSTEM process", bucket: "host", why: "ProcessAccess on one machine, and the access mask is the detail to quote." },
          { id: "t4", text: "Event 4673 on KPH-WARD-SRV2: SeImpersonatePrivilege exercised", bucket: "host", why: "A Windows Security event about a privilege in use on that server." },
          { id: "t5", text: "App first registered yesterday, unverified publisher, 3 users consented", bucket: "idp", why: "Publisher and registration age come from the tenant's app records, so the identity team owns it." },
          { id: "t6", text: "Audit log: Add delegated permission grant, Sites.Read.All for a survey app", bucket: "idp", why: "The grant is a directory event. It can outlive the user's password, so the fix is to revoke the grant." },
          { id: "t7", text: "EDR: DuplicateTokenEx called by a service process on a pharmacy PC", bucket: "host", why: "A Windows API call seen on one device. No browser, no cookie, no sign-in." },
          { id: "t8", text: "Event 4672 at 03:00: special privileges assigned to a new logon on KPH-WARD-SRV2", bucket: "host", why: "Windows Security on one server: it's the endpoint team's lead." },
          { id: "t9", text: "Weeks of non-interactive sign-ins for one app, with no prompt on any of them", bucket: "idp", why: "A token in use, seen in the identity provider's own sign-in log, so the identity team pulls the thread." },
        ],
      },
    ],
    // ── Reading 7: Golden SAML ──
    "mfast-r7": [
      {
        kind: "worksheet",
        title: "The Sign-In Nobody Issued",
        prompt: "Thursday, 14:00. Kingsmere took over a radiology group in 2023, and its staff still sign in through an old AD FS server, KPH-ADFS01. Hyun-woo lines up the cloud's sign-in rows beside the server's issuance records. Find what doesn't pair.",
        primer: {
          fold: true,
          title: "When the proof itself is forged",
          points: [
            "**SAML** is a federation protocol: **AD FS** (Active Directory Federation Services) vouches for a user by signing an assertion with a private key the cloud trusts.",
            "**T1606.002**, Forge Web Credentials: SAML Tokens, or Golden SAML: with that key an attacker signs an assertion for anyone, offline.",
            "Getting the key means already controlling AD FS, reading the DKM (Distributed Key Manager) master key from Active Directory and exporting the token-signing certificate.",
            "The cloud reads how strongly the user was verified from the signed claims, so a forged token can simply say MFA happened.",
            "A genuine federated login leaves Event ID 1200 on the AD FS server. A forgery never touches that server.",
          ],
          example: {
            label: "Evidence that is an absence",
            lines: [
              "A pharmacy holds a signed delivery note for 40 boxes.",
              "Every genuine note has a line in the supplier's dispatch book. This one has none.",
              "The note looks perfect, so the case rests on the missing line, not on the note.",
            ],
          },
        },
        caption: "SigninLogs beside KPH-ADFS01 Event ID 1200 · Thursday, times in UTC",
        columns: ["createdDateTime", "userPrincipalName", "tokenIssuerType", "ipAddress", "AD FS 1200"],
        rows: [
          ["03:21:47", "adm.k.rees", "ADFederationServices", "198.51.100.131", "-"],
          ["06:58:14", "s.vance", "ADFederationServices", "203.0.113.18", "06:58:13"],
          ["07:12:40", "t.bakare", "ADFederationServices", "203.0.113.18", "07:12:39"],
          ["07:30:05", "n.ferro", "ADFederationServices", "203.0.113.18", "07:30:04"],
          ["07:41:22", "e.lindqvist", "AzureAD", "203.0.113.18", "-"],
        ],
        questions: [
          { id: "who", q: "Which user's sign-in claims to come from AD FS with no issuance record behind it?", hint: "tokenIssuerType says AD FS, and the last column is empty.", answer: ["adm.k.rees", "k.rees", "rees"], why: "adm.k.rees: the row says the federation server issued it, and the server has no record of doing so. e.lindqvist's empty cell is normal, because AzureAD means AD FS was never involved." },
          { id: "prompt", q: "Was anyone prompted for MFA when that assertion was made? (yes/no)", hint: "Where was it signed?", answer: ["no", "n"], why: "No. It was signed on the attacker's own machine. The claim that MFA happened is just text inside a validly signed token." },
          { id: "reset", q: "adm.k.rees resets their password. Does the attacker lose this access? (yes/no)", hint: "Which secret did the forgery use?", answer: ["no", "n"], why: "No. The forgery used the signing key, not the password, so the password was never part of it." },
          { id: "roll", q: "How many times do you roll the AD FS token-signing certificate to retire the stolen key?", hint: "AD FS keeps a primary and a secondary.", answer: ["2", "two", "twice"], why: "Twice, so the stolen key is gone from both slots. Then revoke sessions and refresh tokens, and treat every federated account as exposed until the new key is in force." },
        ],
      },
    ],
    // ── Reading 8: the defence ladder ──
    "mfast-r8": [
      {
        kind: "tune",
        title: "How Short a Session?",
        prompt: "Friday, 10:00. Hyun-woo wants a sign-in frequency for the theatre team. Each row is one session from last quarter's sign-in logs: whose it was, where its sign-in and its last request came from, and how old the session was at that last request. A session reaching the limit forces a new sign-in, which only the person holding the password and the phone can complete, and nobody should be stopped mid-shift. Read which sessions moved to a device and address their owner never signed in from: you won't stop all of them here, so stop at least four, with no false prompts.",
        eventColumn: "Session: user, sign-in device, last request from",
        dials: [
          { id: "hours", label: "Sign-in frequency: force a new sign-in once a session reaches this age, in hours", short: "Age at last request", unit: "h", min: 1, max: 48, step: 1, start: 36, dir: "above" },
        ],
        events: [
          { id: "r1", label: "c.ibe · signed in on KPH-THR-PC02 · last request 198.51.100.61, no device ID, Chrome on Linux", bad: true, values: { hours: 31 } },
          { id: "r2", label: "r.mensah · signed in on a ward tablet · last request 203.0.113.151, no device ID, Edge on Windows", bad: true, values: { hours: 22 } },
          { id: "r3", label: "p.lowry · signed in on KPH-THR-PC05 · last request 198.51.100.17, no device ID, Chrome on Windows", bad: true, values: { hours: 15 } },
          { id: "r4", label: "d.achterberg · signed in on her registered phone · last request 203.0.113.92, no device ID, Firefox on Windows", bad: true, values: { hours: 13 } },
          { id: "r5", label: "s.farooq · signed in on KPH-THR-PC01 · last request 198.51.100.230, no device ID, Chrome on macOS", bad: true, values: { hours: 2 } },
          { id: "r6", label: "o.brandt · signed in on a ward tablet · last request 203.0.113.45, no device ID, Chrome on Windows", bad: true, values: { hours: 0.7 } },
          { id: "n1", label: "a.osei, theatre nurse · KPH-THR-PC04 all day, same device ID, hospital address", bad: false, values: { hours: 12 } },
          { id: "n2", label: "t.marsh, anaesthetist · KPH-THR-PC03 all day, same device ID, hospital address", bad: false, values: { hours: 11.5 } },
          { id: "n3", label: "g.whelan, theatre manager · registered laptop all day, same device ID, hospital address", bad: false, values: { hours: 11 } },
          { id: "n4", label: "k.adebayo, surgeon · KPH-THR-PC02 all day, same device ID, hospital address", bad: false, values: { hours: 10 } },
          { id: "n5", label: "l.ngata, scheduling clerk · registered desktop all day, same device ID, hospital address", bad: false, values: { hours: 8 } },
          { id: "n6", label: "b.carlin, stores assistant · registered desktop all day, same device ID, hospital address", bad: false, values: { hours: 7.5 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        lesson: "Thirteen hours spares every shift and ends the long replays, but no value reaches the two used inside two hours. Maeve's cookie did its work in 38 minutes. Sign-in frequency limits how long theft pays, it doesn't prevent theft. Entra's default is a rolling 90 days, and Microsoft warns that prompting too often teaches people to enter credentials without thinking, so shorter isn't simply safer.",
      },
      {
        kind: "pathway",
        title: "Where the Replay Stops",
        prompt: "Friday, 11:00, the pilot group. Hyun-woo copies a sign-in session token from a test laptop's desktop mail client onto a second laptop, the way an infostealer would, and points it at a test mailbox. Sign-in frequency is 13 hours. Walk that token through the tenant until something really stops it.",
        primer: {
          fold: true,
          title: "Controls that act after sign-in",
          points: [
            "**Token Protection** is a Conditional Access session control. It accepts only sign-in session tokens bound to the device they were issued to, such as a Primary Refresh Token (PRT).",
            "Coverage: native apps on Exchange Online, SharePoint Online and Teams, and on Windows also Azure Virtual Desktop and Windows 365. In browsers it's a preview for selected web apps that reach Azure Resource Manager.",
            "**Sign-in frequency** sets how long a user can reach a resource before signing in again.",
            "**Continuous Access Evaluation (CAE)** reacts near real time to critical events, such as a disabled account or a password reset.",
          ],
          example: {
            label: "Bound and unbound, at a staff car park",
            lines: [
              "A paper permit works on any car that displays it.",
              "A permit tied to one number plate fails on another car, however genuine the paper.",
              "That check doesn't care how the permit got there. It asks only whether permit and car match.",
            ],
          },
        },
        goal: "Reach the check that refuses the copied token",
        nodes: [
          { id: "stolen", label: "Copied token", sub: "on the second laptop", x: 12, y: 50 },
          { id: "nm", label: "Number matching", x: 24, y: 16 },
          { id: "ca", label: "Require MFA policy", x: 34, y: 52 },
          { id: "fido", label: "FIDO2 key", x: 36, y: 86 },
          { id: "sif", label: "Sign-in frequency", sub: "13 hours", x: 56, y: 54 },
          { id: "cae", label: "CAE", sub: "critical events", x: 70, y: 22 },
          { id: "exo", label: "Test mailbox", x: 66, y: 86 },
          { id: "tp", label: "Token Protection", x: 78, y: 52 },
          { id: "web", label: "Mail on the web", x: 88, y: 84 },
          { id: "deny", label: "Request refused", x: 90, y: 20 },
        ],
        edges: [["stolen", "nm"], ["stolen", "ca"], ["ca", "fido"], ["ca", "sif"], ["sif", "cae"], ["sif", "exo"], ["sif", "tp"], ["tp", "web"], ["tp", "deny"]],
        route: ["stolen", "ca", "sif", "tp", "deny"],
        notes: {
          stolen: "A valid token, copied from a device that really did MFA. In the log it would look like a client's ordinary renewals.",
          ca: "The token carries its MFA claim, so the grant is met. That's the same reason Maeve's replay read Success.",
          sif: "40 minutes old against 13 hours, so it's inside the window. At 13 hours the holder would face a sign-in that needs the real user's factors.",
          tp: "The token was issued to the first laptop and is being presented from the second. Binding needs a proof that only the first laptop can make.",
          deny: "Refused. The sign-in row's `tokenProtectionStatusDetails` carries `signInSessionStatus`, which reads `bound` or `unbound`. Microsoft advises report-only mode and a pilot group first, because unsupported clients get blocked too.",
        },
        traps: {
          nm: "Number matching changes how a prompt is answered. A copied token raises no prompt, so it never runs.",
          fido: "A FIDO2 key guards the sign-in ceremony. This token came out of a ceremony that's already over, so the key isn't asked.",
          cae: "CAE reacts to events such as a disabled account or a password reset. Nothing has changed on this account yet.",
          exo: "The session is inside its 13 hours, so frequency has no objection. But the pilot policy has one more check before mail opens.",
          web: "This token belongs to the desktop client, and browser coverage is a preview for selected web apps that reach Azure Resource Manager. This check doesn't run on mail on the web.",
        },
        lesson: "Conditional Access evaluates its policies together, so this map is a reading order, not a run order. Sign-in frequency shortens how long theft pays. Token Protection asks a different question: is this the device the token was issued to? Each control acts on one thing, in one place, so read its coverage table before you tell anyone a path is closed.",
      },
      {
        kind: "locks",
        title: "Does the Attack Cross That Gate?",
        prompt: "Friday, 15:00. The board wants to know what each new control buys. Hyun-woo's rule: name the moment the control acts, name the moment the attack happens, then see if the two ever meet. Open each door by applying it.",
        primer: {
          fold: true,
          title: "Where does a control act?",
          points: [
            "Every control acts at one moment: a prompt being answered, a site being checked, a token being presented, a session reaching an age, a key being used.",
            "Every attack passes through some of those moments and skips the rest.",
            "If an attack never crosses a control's moment, the control can't touch it, however strong it is.",
            "So a strong control only tells you about the attacks that cross it. Ask the question once for each attack.",
          ],
          example: {
            label: "Outside identity, at the mail gateway",
            lines: [
              "Control: an attachment sandbox. It acts when a file crosses the mail gateway.",
              "Attack one: a macro document by email. It crosses the gateway, so the sandbox has a say.",
              "Attack two: the same document on a USB stick. It never crosses the gateway, so the sandbox has no say at all.",
            ],
          },
        },
        locks: [
          {
            id: "key", letter: "F", name: "FIDO2 key",
            idea: "A FIDO2 or WebAuthn key signs the challenge together with the origin the browser is talking to. On a lookalike host the origin doesn't match, so it refuses to sign. CISA names two phishing-resistant technologies: FIDO2/WebAuthn and PIV/CAC smart cards. NIST SP 800-63B calls the property verifier impersonation resistance.",
            example: "Kingsmere's administrators move to FIDO2 keys. Their sign-ins can no longer pass through a reverse proxy.",
            check: { q: "An administrator with a key signs in correctly, then clicks Accept on a consent screen for an app asking to read all files. Does the key stop that app getting its token?", options: ["Yes, because the key signs each token the account grants later", "No, because consent comes after the ceremony the key guards", "Yes, because a consent screen can't reach an account with a key"], answer: 1, why: "The key guards the sign-in. Consent is a separate decision made inside a good session, and the app then holds its own tokens." },
          },
          {
            id: "match", letter: "N", name: "Number matching",
            idea: "Number matching, called Number Challenge in Okta, makes the user match a number from the sign-in screen: typed in Microsoft Authenticator, picked from three in Okta Verify. A reflex tap can't finish a sign-in. A reverse proxy can still show the real number to its victim, because it's showing the real page.",
            example: "Kingsmere's agency staff get Number Challenge on Okta Verify. A half-asleep tap on Approve no longer completes a sign-in by itself.",
            check: { q: "A forged SAML assertion for an admin reaches the cloud at 03:00. The admin has number matching. What does it do?", options: ["Nothing, because no prompt is ever raised", "It holds the sign-in until the admin types the number", "It sends the admin a number they can refuse"], answer: 0, why: "A forged assertion just states that MFA happened. No prompt exists, so there's nothing to match." },
          },
          {
            id: "freq", letter: "S", name: "Sign-in frequency",
            idea: "Sign-in frequency applies when a session reaches a resource through the identity provider and has grown too old. It's a cloud session control.",
            example: "The theatre team's sessions must sign in again every 13 hours.",
            check: { q: "A tool on a ward server copies a SYSTEM token with DuplicateTokenEx and runs as SYSTEM for three days. What does a one-hour sign-in frequency do to it?", options: ["It ends the copied token after an hour", "It forces a new Windows logon on the server", "Nothing, because that token never meets the identity provider"], answer: 2, why: "A Windows security token lives on the host. T1134.001 never reaches a cloud sign-in, so a cloud session control never meets it." },
          },
          {
            id: "roll", letter: "R", name: "Certificate roll",
            idea: "Rolling the AD FS token-signing certificate twice retires a stolen signing key everywhere it's honoured. There's no MFA rung for Golden SAML, because it forges the output of authentication. The defence is guarding that key with domain-controller rigour.",
            example: "After the 03:21 sign-in, Kingsmere rolls the certificate on KPH-ADFS01 twice.",
            check: { q: "Maeve's account is cloud-only, and Entra issued her stolen session. Does the certificate roll on KPH-ADFS01 end that session?", options: ["Yes, every session in the tenant depends on that certificate", "No, AD FS never signed anything in that session", "Yes, but only after a second roll"], answer: 1, why: "That session came from Entra, so the AD FS key had no part in it. The right control is the one the attack actually crossed: revoking sessions." },
          },
        ],
        finish: "Name the moment, then check that the attack crosses it. That question works for any control on any ticket.",
      },
    ],
  },
};
