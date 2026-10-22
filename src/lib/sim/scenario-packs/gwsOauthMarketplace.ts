/**
 * Scenario pack: "Consent, Not Credentials, a Malicious OAuth App in Google Workspace"
 *
 * INTERMEDIATE tier. A cloud-identity case with NO password compromise and NO
 * host to walk. A Revenue Operations lead is phished with a link that leads to a
 * Google consent screen for a third-party Marketplace-style app, "Docs Merge
 * Pro". She clicks Allow, and in that one action the app is granted an OAuth
 * refresh token carrying two of the broadest scopes Google issues:
 * https://mail.google.com/ (full Gmail) and .../auth/drive (full Drive). From
 * then on the app's own servers read her mailbox and pull Drive files over the
 * Gmail and Drive APIs, no password is ever used, MFA is never in the path, and
 * the access keeps working after the account's password is reset, because a reset
 * does not touch an already-issued OAuth token.
 *
 * The teaching spine has two halves the student must separate:
 *   • PERSISTENCE is the consent grant itself. The refresh token is the foothold;
 *     it survives password resets and sign-out. Only REVOKING the app's token /
 *     removing the grant stops it.
 *   • IMPACT is the API-driven collection that follows, mailbox reads and a Drive
 *     download burst, all authenticated by the token, from a hosting ASN.
 *
 * A BENIGN CONTROL is included and is the pedagogical crux: a different user
 * authorizes "Calendly" the same way, a user granting an OAuth app, but that
 * app is admin-allowlisted, marketplace-verified, from a named publisher, and
 * asks for one narrow calendar scope. Same shape ("a user consented to an app"),
 * opposite verdict. The discriminators are scope breadth, allowlist status, and
 * publisher verification, not the act of consenting. Allowlist status and
 * publisher are not part of an authorize audit event; they come from the Admin
 * console's app-access lookup, which the telemetry carries for both apps.
 *
 * Covers T1566.002 (Spearphishing Link, the consent lure), T1528 (Steal
 * Application Access Token, the consent grant that yields the token), T1550.001
 * (Application Access Token, the token used to authenticate API access, incl.
 * after the password reset), T1114.002 (Remote Email Collection, the mailbox
 * reads over the Gmail API) and T1530 (Data from Cloud Storage, the Drive
 * downloads).
 *
 * SOURCES: Google Workspace (Reports API login, token, drive, gmail and admin
 * activity, the Alert Center alert and the Admin console app-access lookup) and
 * the FortiGate web filter (the lure page opened from the corporate network).
 * This pack fits a Google Workspace estate (rocketstack.io).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { fgWeb } from "@/lib/sim/emitters/fortigate";

export function buildGwsOauthMarketplaceScenario(
  scenarioId = "gws-oauth-marketplace-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T09:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the whole case is a single OAuth-app-abuse investigation.
  const INCIDENT = "inc:gwsoauth:1";

  // The phished user and her normal working context.
  const victim = {
    email: "m.varga@rocketstack.io",
    name: "Miriam Varga",
    sam: "m.varga",
    title: "Revenue Operations Lead",
    ip: "82.166.51.23", // her corporate egress at consent time (Tel Aviv)
    host: "LAP-021",
    lanIp: "172.16.10.21",
  };

  // The malicious third-party app. Marketplace-style listing, unverified
  // publisher, its backend hosted on a VPS ASN in Frankfurt.
  const clientId = "849276150983-3f7qk2m9xr4vd8n1b6c0aptsu5wg2h7e.apps.googleusercontent.com";
  const appName = "Docs Merge Pro";
  const appDomain = "docsmergepro.app";
  const consentUrl = "https://docsmergepro.app/connect/google";
  const phishSender = "onboarding@docsmergepro.app";
  const serverIp = "45.87.43.19"; // the app backend's hosting-ASN egress
  const landingIp = "104.21.48.113"; // where docsmergepro.app resolves for the lure page

  // The admin who works the case and attempts the (insufficient) password reset.
  const adminEmail = "secops-admin@rocketstack.io";

  // The BENIGN CONTROL: a different user authorizes a narrow-scope, admin-
  // allowlisted, marketplace-verified app the ordinary way.
  const benign = {
    email: "t.nowak@rocketstack.io",
    name: "Tomas Nowak",
    sam: "t.nowak",
    ip: "82.166.51.40",
  };
  const benignClientId = "556123094817-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com";

  const scopes = ["https://mail.google.com/", "https://www.googleapis.com/auth/drive", "openid", "https://www.googleapis.com/auth/userinfo.email"];

  // One Drive download over the app's token (the app's backend, a hosting address).
  const download = (id: string, at: number, file: string, docType: string, severity: TelemetryEvent["severity"], description: string): TelemetryEvent => ({
    id, ts: T(at), source: "gws", vendor: "Google Workspace", event_type: "cloud_storage_access",
    user_email: victim.email, src_ip: serverIp, geo: { country: "Germany", city: "Frankfurt" }, severity,
    mitre_technique: "T1530", mitre_tactic: "Collection", incident_id: INCIDENT,
    file: { name: file, path: `/Drive/Finance/FY26/${file}`, extension: file.split(".").pop() },
    description,
    raw: {
      "gws.event.type": "drive.export",
      "storage.object.name": file,
      "application.name": appName,
      "application.id": clientId,
    },
  });
  // One Gmail API call over the app's token.
  const gmailCall = (id: string, at: number, kind: "list" | "get", description: string): TelemetryEvent => ({
    id, ts: T(at), source: "gws", vendor: "Google Workspace", event_type: "cloud_api_call",
    user_email: victim.email, src_ip: serverIp, geo: { country: "Germany", city: "Frankfurt" }, severity: "high",
    mitre_technique: "T1114.002", mitre_tactic: "Collection", incident_id: INCIDENT,
    description,
    raw: {
      "gws.event.type": kind === "list" ? "gmail.messages.list" : "gmail.messages.get",
      "application.name": appName,
      "application.id": clientId,
    },
  });

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL, a user grants an OAuth app the RIGHT way. Same shape
    //    as the incident (a token authorize), opposite verdict: one narrow scope
    //    and, in the Admin console lookup, allowlisted and verified.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_00_benign_grant",
      ts: "2026-08-30T12:15:00.000Z",
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: benign.email,
      user_title: "Account Executive",
      src_ip: benign.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "Benign. t.nowak authorized Calendly, also 'a user granting an OAuth app', but the discriminators all point the other way: the app is on the admin allowlist (Trusted), marketplace-listed with a verified publisher, and it requested a single narrow calendar scope. Compare with the Docs Merge Pro grant, which is unconfigured, unlisted, and asks for full Gmail and full Drive. The act of consenting is not the signal; scope breadth, allowlist status and publisher verification are.",
      description:
        "t.nowak authorized Calendly, requesting only the read/write calendar-events scope, a routine, sanctioned OAuth grant.",
      raw: {
        "gws.event.type": "authorize",
        "gws.parameters.scope": ["https://www.googleapis.com/auth/calendar.events", "openid", "https://www.googleapis.com/auth/userinfo.email"],
        "application.name": "Calendly",
        "application.id": benignClientId,
      },
    },
    {
      id: "evt_oauth_00b_benign_app_lookup",
      ts: "2026-08-30T12:16:00.000Z",
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: adminEmail,
      severity: "informational",
      description: "Admin console app-access lookup for the Calendly client id: Trusted, marketplace listing, verified publisher.",
      raw: {
        "gws.lookup.source": "Admin console, Security, API controls, App access control",
        "gws.lookup.client_id": benignClientId,
        "gws.lookup.app_name": "Calendly",
        "gws.lookup.access_status": "Trusted",
        "gws.lookup.marketplace_listing": "Yes",
        "gws.lookup.publisher": "Calendly LLC",
        "gws.lookup.publisher_verified": "Yes",
        "gws.lookup.users_granted": "41",
        "gws.lookup.domain_policy": "Allow users to access any third-party apps",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE CONSENT LURE, a link email that lands the user on the app's
    //    "connect your Google account" page. Spearphishing Link (T1566.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_01_consent_lure",
      ts: T(0),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "email_received",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: "209.85.220.41",
      severity: "low",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Gmail delivered a message to m.varga inviting her to connect a document-merge add-on, with a button linking to docsmergepro.app/connect/google. It passed SPF, DKIM and DMARC and went to the inbox.",
      network: { url: consentUrl, domain: appDomain, method: "GET" },
      raw: {
        "gws.event.type": "message_delivered",
        "gws.InternetMessageId": "<f19c72aa8b41@mail.docsmergepro.app>",
        "gws.SenderFromAddress": phishSender,
        "gws.RecipientEmailAddress": victim.email,
        "gws.Subject": "Finish setup: connect Docs Merge Pro to your Drive",
        "gws.EmailDirection": "Inbound",
        "gws.SenderIPv4": "209.85.220.41",
        "gws.spf_result": "pass",
        "gws.dkim_result": "pass",
        "gws.dmarc_result": "pass",
        "gws.url": consentUrl,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE SIGN-IN AND THE CLICK, her ordinary Google login, then the
    //    lure page opened from the office network (FortiGate web filter).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_01b_login_success",
      ts: T(7 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "auth_success",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: victim.ip,
      geo: { country: "Israel", city: "Tel Aviv" },
      severity: "informational",
      incident_id: INCIDENT,
      description: "m.varga signed in to Google from the office egress with her password and a Google prompt; nothing unusual about the sign-in.",
      raw: {
        "gws.id.applicationName": "login",
        "gws.event.type": "login",
        "gws.event.name": "login_success",
        "gws.parameters.login_type": "google_password",
        "gws.parameters.login_challenge_method": ["password", "google_prompt"],
        "gws.parameters.is_suspicious": false,
      },
    },
    fgWeb({
      companyId: "rocketstack", id: "evt_oauth_01c_lure_page_visit", ts: T(10 * MIN + 40 * SEC), host: victim.host, user: victim.email, srcIp: victim.lanIp,
      incidentId: INCIDENT, remoteIp: landingIp, url: consentUrl, domain: appDomain, category: "Newly Observed Domain", action: "passthrough",
      status: 200, bytesIn: 18_204, bytesOut: 912, severity: "low", userTitle: victim.title,
      description: "FortiGate web filter passed an HTTPS request from m.varga's laptop to docsmergepro.app/connect/google.",
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE CONSENT GRANT, the crux. m.varga clicks Allow and a token audit
    //    'authorize' records the app receiving full Gmail + full Drive scopes.
    //    This grant IS the persistence: an offline (refresh) token is issued.
    //    Steal Application Access Token (T1528).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_02_token_authorize",
      ts: T(11 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "account_modify",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: victim.ip,
      geo: { country: "Israel", city: "Tel Aviv" },
      severity: "high",
      mitre_technique: "T1528",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "A token audit 'authorize' recorded m.varga granting Docs Merge Pro the scopes https://mail.google.com/ and https://www.googleapis.com/auth/drive.",
      raw: {
        "gws.event.type": "authorize",
        "gws.parameters.scope": scopes,
        "application.name": appName,
        "application.id": clientId,
      },
    },
    // The Alert Center alert the grant raised: this opens the case.
    {
      id: "evt_oauth_02b_alert_center",
      ts: T(11 * MIN + 40 * SEC),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: victim.email,
      severity: "high",
      incident_id: INCIDENT,
      is_detection: true,   // the Alert Center alert that opens the case
      edr_scope: "non_edr", // cloud identity / SaaS only, no host process to walk
      description: "Alert Center raised the activity-rule alert 'Third-party app granted sensitive scopes' for m.varga's grant to Docs Merge Pro.",
      raw: {
        "gws.alert.type": "Activity Rule",
        "gws.alert.source": "Token activity",
        "gws.alert.id": "AC-2026-0831-4471",
        "gws.alert.createTime": T(11 * MIN + 40 * SEC),
        "gws.alert.data.displayName": "Third-party app granted sensitive scopes",
        "gws.alert.data.triggerSource": "Token",
        "gws.alert.data.actor": victim.email,
        "gws.alert.data.clientId": clientId,
        "gws.alert.data.appName": appName,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. ALLOWLIST CONTEXT, the Admin console app-access lookup for the client
    //    id (not an audit-log event): unconfigured, unlisted, publisher unverified,
    //    and a tenant policy that allows any third-party app.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_03_app_access_review",
      ts: T(14 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: adminEmail,
      severity: "medium",
      incident_id: INCIDENT,
      description:
        "An Admin console app-access lookup for the Docs Merge Pro client id returns Unconfigured, no marketplace listing and an unverified publisher, under a domain policy that lets users grant access to any third-party app.",
      raw: {
        "gws.lookup.source": "Admin console, Security, API controls, App access control",
        "gws.lookup.client_id": clientId,
        "gws.lookup.app_name": appName,
        "gws.lookup.access_status": "Unconfigured",
        "gws.lookup.marketplace_listing": "No",
        "gws.lookup.publisher": "unknown",
        "gws.lookup.publisher_verified": "No",
        "gws.lookup.users_granted": "1",
        "gws.lookup.first_authorized": T(11 * MIN),
        "gws.lookup.domain_policy": "Allow users to access any third-party apps",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. MAILBOX READS OVER THE GMAIL API, the token, not a password, reads the
    //    mailbox from the app's servers. Remote Email Collection (T1114.002).
    // ─────────────────────────────────────────────────────────────────────
    gmailCall("evt_oauth_04_gmail_api_read", 19 * MIN, "list",
      "A token audit 'activity' shows Docs Merge Pro calling gmail.users.messages.list for m.varga from 45.87.43.19 (Frankfurt), authenticated by the offline token, no interactive sign-in."),
    gmailCall("evt_oauth_04b_gmail_api_read", 21 * MIN, "get",
      "Docs Merge Pro called gmail.users.messages.get for m.varga from 45.87.43.19."),
    gmailCall("evt_oauth_04c_gmail_api_read", 23 * MIN, "get",
      "A further gmail.users.messages.get call from 45.87.43.19 under the same token."),

    // ─────────────────────────────────────────────────────────────────────
    // 6. DRIVE DOWNLOADS OVER THE DRIVE API, the app pulls her Finance files from
    //    the same hosting ASN. Data from Cloud Storage (T1530).
    // ─────────────────────────────────────────────────────────────────────
    download("evt_oauth_05_drive_download_burst", 27 * MIN, "FY26_Revenue_Forecast.xlsx", "spreadsheet", "high",
      "The Drive audit records a download of FY26_Revenue_Forecast.xlsx under m.varga's account, attributed to the Docs Merge Pro client id, from 45.87.43.19."),
    download("evt_oauth_05b_drive_download", 28 * MIN, "Q3_Pipeline_by_Region.xlsx", "spreadsheet", "high",
      "A second download under the same client id from 45.87.43.19."),
    download("evt_oauth_05c_drive_download", 30 * MIN, "Customer_Renewals_2026.xlsx", "spreadsheet", "high",
      "A third download under the same client id."),
    download("evt_oauth_05d_drive_download", 33 * MIN, "FY26_Board_Deck.pptx", "presentation", "high",
      "A fourth download under the same client id."),

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE INSUFFICIENT REMEDIATION, an admin resets the password. This
    //    changes the credential but NOT the OAuth token; no token revoke event
    //    follows. Response action (benign); it is the setup for the persistence lesson.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_06_password_reset",
      ts: T(55 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "account_modify",
      user_email: adminEmail,
      severity: "informational",
      incident_id: INCIDENT,
      description:
        "An admin reset m.varga's password at 10:10 as a first containment step.",
      raw: {
        "gws.id.applicationName": "admin",
        "gws.event.type": "USER_SETTINGS",
        "gws.event.name": "CHANGE_PASSWORD",
        "gws.parameters.USER_EMAIL": victim.email,
        "gws.parameters.DOMAIN_NAME": "rocketstack.io",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. THE TOKEN STILL WORKS, after the reset, the app keeps downloading from
    //    Drive and succeeding. The token predates the reset and was never
    //    revoked. Application Access Token (T1550.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      ...download("evt_oauth_07_token_survives_reset", 80 * MIN, "FY26_Revenue_Forecast_v2.xlsx", "spreadsheet", "critical",
        "At 10:35, 25 minutes after the password reset, the Docs Merge Pro client id downloaded another Drive file for m.varga from 45.87.43.19: the token issued at 09:26 remained valid; the reset did not revoke it."),
      mitre_technique: "T1550.001",
      mitre_tactic: "Stealth",
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: serverIp, // 45.87.43.19, the app backend's hosting-ASN egress
      first_seen: T(19 * MIN),
      last_seen: T(80 * MIN),
      reputation: "malicious",
      tags: ["oauth-app-backend", "hosting-asn"],
    },
    {
      type: "domain",
      value: appDomain, // docsmergepro.app, the sender domain, consent-landing and redirect domain
      first_seen: T(0),
      last_seen: T(11 * MIN),
      reputation: "malicious",
      tags: ["third-party-app", "consent-landing", "sender-domain"],
    },
    {
      type: "url",
      value: consentUrl,
      first_seen: T(0),
      last_seen: T(10 * MIN + 40 * SEC),
      reputation: "malicious",
      tags: ["consent-landing"],
    },
    {
      type: "user",
      value: clientId, // the OAuth client id, the durable pivot across events
      first_seen: T(11 * MIN),
      last_seen: T(80 * MIN),
      reputation: "malicious",
      tags: ["oauth-client-id", "third-party-app"],
    },
    {
      type: "email",
      value: victim.email, // m.varga@rocketstack.io, the affected account
      first_seen: T(0),
      last_seen: T(80 * MIN),
      reputation: "suspicious",
      tags: ["affected-account", "revenue-ops"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "At 10:10 an admin reset m.varga's password (evt_oauth_06), yet at 10:35 (evt_oauth_07) the Docs Merge Pro client id still downloads from her Drive. Why does the password reset fail to stop the access?",
      hint: "Look at what the admin log records in evt_oauth_06 and what it does not, and at which identity evt_oauth_07 presents.",
      kind: "single",
      options: [
        { value: "token_independent", label: "The OAuth refresh token authenticates the app independently of the password; issued at consent, it is neither expired nor revoked by a reset" },
        { value: "reset_not_applied", label: "The password reset had not yet propagated to the Drive API tier, and the calls would have started failing within the hour without further action" },
        { value: "cached_creds", label: "The app had cached m.varga's old password locally at consent and was replaying it, so the calls keep succeeding only until that cache expires" },
        { value: "second_account", label: "The app is signing in as a separate service account it created during setup, which the reset of m.varga's own password does not affect" },
      ],
      answer: "token_independent",
      xp: 65,
      explanation:
        "This is the core lesson. When m.varga consented, Google issued Docs Merge Pro an OAuth refresh token. That token is a bearer credential the app presents on every API call; it is not derived from, and does not check, the account password. A password reset invalidates the password and existing web sessions, but it does NOT revoke issued OAuth grants: evt_oauth_06 is a CHANGE_PASSWORD admin event and no token revoke event follows it, which is exactly why the 10:35 Drive download in evt_oauth_07, made under the same client id, still succeeds against a grant issued at 09:26. (b) is wrong, OAuth grants do not lapse on their own within an hour. (c) invents a cached password; the app never had the password, that is the whole point of consent. (d) invents a service account not present in any log. Remediation must revoke the token / remove the app authorization, not just reset the password.",
    },
    {
      id: "q2",
      prompt:
        "evt_oauth_00 shows t.nowak authorizing Calendly, also a user granting an OAuth app, but it is benign. Reading it, and the Admin console lookups for both apps (evt_oauth_00b, evt_oauth_03), against the Docs Merge Pro grant (evt_oauth_02), what actually separates the malicious grant from the benign one?",
      hint: "The act of consenting is the same in both. Compare the scope lists, the access status and the publisher fields in the lookups.",
      kind: "single",
      options: [
        { value: "scope_allowlist_publisher", label: "Scope and provenance: Docs Merge Pro wants full Gmail and Drive and is unconfigured and unverified; Calendly wants one calendar scope and is trusted and verified" },
        { value: "consent_itself", label: "The consent action itself, any user authorizing a third-party OAuth app is a compromise, so both grants should be opened as incidents and revoked" },
        { value: "client_type", label: "Calendly registers a WEB client type and Docs Merge Pro an installed-app client type, and that client-type difference alone marks one as malicious" },
        { value: "user_role", label: "t.nowak is in Sales and m.varga is in Revenue Operations, and the grant is malicious purely because a finance-adjacent user was the one who consented" },
      ],
      answer: "scope_allowlist_publisher",
      xp: 60,
      explanation:
        "Both events are a token 'authorize' by a user, so consenting cannot itself be the signal, which is why (b) is the trap the control disproves. The verdict comes from fields read together. Scope: Docs Merge Pro requested https://mail.google.com/ and .../auth/drive (full read/write to mail and all files), where Calendly requested only calendar.events. Access status and publisher, from the Admin console lookups: Docs Merge Pro is Unconfigured, has no marketplace listing and an unverified publisher; Calendly is Trusted, listed, from a verified publisher. (c) is false, client type is not recorded as a difference and is not a verdict. (d) invents role-based reasoning the logs do not support. Least-privilege scope plus provenance is the discriminator.",
    },
    {
      id: "q3",
      prompt:
        "m.varga has MFA enforced, and her sign-in at 09:22 (evt_oauth_01b) is an ordinary password-and-prompt login from the office; no failed logins or new-device sign-ins appear anywhere in the timeline. How is the app reading her mailbox and Drive without ever tripping an authentication control?",
      kind: "single",
      options: [
        { value: "token_bypasses_auth", label: "The app calls the Gmail and Drive APIs as an authorized client on a delegated OAuth token, there is no interactive login for MFA to challenge" },
        { value: "mfa_disabled", label: "The attacker must have disabled MFA on the account first through the admin console, which is what allowed the API calls to proceed unchallenged" },
        { value: "stolen_session", label: "A stolen browser session cookie is being replayed on each call, and MFA does not re-prompt while an existing authenticated web session is still valid" },
        { value: "password_phished", label: "Her password was phished through the lure page and the app is logging in with it, choosing legacy IMAP and API endpoints that skip the MFA step" },
      ],
      answer: "token_bypasses_auth",
      xp: 60,
      explanation:
        "OAuth delegation is the answer. By consenting, m.varga authorized the app to call Google APIs on her behalf using its own token, the calls in evt_oauth_04 and evt_oauth_05 originate from the app's servers (45.87.43.19) under the app's client id, not from a login form. The only login in the timeline is her own, from the office, at 09:22. MFA only ever guards an interactive authentication, and there is no interactive authentication here to guard, so nothing is bypassed or disabled, which is why (b) and (d) are wrong (no password use and no MFA change appear in any event). (c) describes a different technique, session-cookie replay, but the audit shows token activity by a registered OAuth client, not a replayed web session. This is why consent phishing is dangerous precisely against MFA-protected accounts.",
    },
    {
      id: "q4",
      prompt:
        "Separating persistence from impact: which statement correctly assigns the events?",
      kind: "single",
      options: [
        { value: "grant_persist_api_impact", label: "The consent grant is the persistence foothold, the token that keeps access alive; the Gmail reads and the Drive downloads are the impact it enabled" },
        { value: "download_is_persistence", label: "The Drive downloads are the persistence mechanism, because the downloaded copies are what let the attacker return to the files at any later point" },
        { value: "lure_is_impact", label: "The consent-lure email is the impact, since delivery into the user's inbox is the point at which the attacker's objective was achieved" },
        { value: "reset_is_persistence", label: "The password reset is the persistence step, because the admin action at 10:10 is what re-established the app's connection to the account" },
      ],
      answer: "grant_persist_api_impact",
      xp: 55,
      explanation:
        "The grant and the collection are different jobs. evt_oauth_02 issues the refresh token, that is the durable foothold (persistence): it is what survives the reset and keeps the door open. evt_oauth_04 (mailbox reads, T1114.002) and evt_oauth_05 (Drive downloads, T1530) are the impact, the data actually collected using that token. (b) confuses the stolen data with the mechanism that keeps access; a download is a one-time pull, the token is what would let the app pull again tomorrow. (c) mislabels the delivery email as impact. (d) is backwards, the reset was a containment attempt, and an insufficient one. Getting this split right is what tells you removing the grant, not chasing each download, is the fix.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the response. The evidence is a broad-scope consent grant to an unverified third-party app, mailbox reads and Drive downloads over its token, and access that outlived a password reset. What is the correct remediation and classification?",
      kind: "single",
      options: [
        { value: "revoke_and_scope", label: "Revoke the app's grant for m.varga, blocklist its client id, then scope what mail and files the token read, OAuth app abuse, not a password compromise" },
        { value: "reset_again", label: "Reset the password a second time and enforce MFA re-registration; once the credentials are fully rotated the app loses access with no further action needed" },
        { value: "block_ip_only", label: "Block 45.87.43.19 at the perimeter and close the case, cutting off the app's server IP stops its API calls, so no change to the tenant is needed" },
        { value: "monitor_only", label: "Leave the grant in place and monitor the token's activity for a few days to gather attribution evidence before taking any disruptive containment action" },
      ],
      answer: "revoke_and_scope",
      xp: 65,
      explanation:
        "The token is the access, so the fix is to kill the token: revoke Docs Merge Pro's grant for m.varga (and blocklist the client id so it cannot be re-authorized), which is the one action that actually ends it. Then scope the damage, which mailboxes and Drive files the token read, and tighten the tenant's third-party access policy so unlisted apps cannot be consented to. (b) repeats the mistake the timeline already disproved: a reset does not revoke an OAuth grant. (c) fails because the API traffic goes to Google's servers, not through your perimeter, blocking one hosting IP neither reaches Google's side nor stops the app moving to another IP, and it revokes nothing. (d) leaves an active exfiltration channel open. Classify as OAuth application abuse and escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sensitive-scope app grant alert at RocketStack",
    threat_actor: "Consent-phishing operator abusing a third-party OAuth app (cloud identity, no host foothold)",
    attack_kind: "oauth_abuse",
    briefing:
      "Google Workspace Alert Center raised a sensitive-scope alert: a third-party app was granted access for m.varga (RocketStack). Work out what the app accessed, whether the grant is legitimate and what contains it.",
    narrative: `This is a cloud-identity case with no malware and no password to crack. At 09:15 Gmail delivered a message to Miriam Varga, a Revenue Operations lead, inviting her to "finish setup" for a document-merge add-on. The link went to docsmergepro.app, and the message passed SPF, DKIM and DMARC, because the real domain, docsmergepro.app, sent it.

At 09:22 she signed in to Google the ordinary way from the office, and at 09:25 the FortiGate web filter passed her laptop's request to docsmergepro.app/connect/google. At 09:26 she clicked through to a genuine Google consent screen and pressed Allow. In that single action the third-party app "Docs Merge Pro" was granted an OAuth token carrying two of the broadest scopes Google issues: https://mail.google.com/ (full Gmail) and https://www.googleapis.com/auth/drive (full Drive). Alert Center raised a sensitive-scope grant alert, which is the ticket you picked up. An Admin console lookup confirmed the app is Unconfigured, has no marketplace listing, its publisher is unverified, and the domain policy lets users grant access to any third-party app.

From 09:34 the app's own servers in Frankfurt (45.87.43.19) began calling the Gmail API, and from 09:42 the Drive API, pulling her finance workbooks, all under the app's client id. No password was ever used and MFA was never in the path, because delegated API access has no interactive login to challenge. The Reports API records one event per call; the telemetry carries a representative few of them.

At 10:10 an admin reset Varga's password. It was not enough: at 10:35 the same client id downloaded from Drive again, because a password reset does not revoke an already-issued OAuth grant, and the admin log shows no token revoke at any point. Only removing the app's authorization stops it.

The instructive comparison is Tomas Nowak, who authorized Calendly the day before, the same act of granting an OAuth app, but Trusted in the Admin console, marketplace-listed, from a verified publisher, and asking for a single calendar scope. Same shape, opposite verdict: consenting is not the signal, scope breadth, allowlist status and publisher verification are.`,
    learning_objectives: [
      "Investigate an OAuth application abuse (consent phishing) in Google Workspace from the token audit: read the 'authorize' event's scopes and client id to identify the grant",
      "Explain why the consent grant is the persistence mechanism, an OAuth refresh token authenticates the app independently of the password and survives a password reset",
      "Separate persistence (the token grant) from impact (Gmail API mailbox reads T1114.002 and the Drive downloads T1530) carried out with the token from a hosting ASN",
      "Distinguish a malicious grant from a benign one using scope breadth, admin allowlist status, and publisher/marketplace verification, not the act of consenting",
      "Scope response for OAuth app abuse: revoke the app's token / remove the grant and blocklist the client id, review what mail and files were accessed, and restrict the tenant's third-party access policy",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T12:15:00.000Z", phase: "Context", action: `Benign control, ${benign.sam} authorizes Calendly (Trusted, verified, one narrow scope)` },
      { ts: T(0), phase: "Initial Access", action: `Consent-lure email from ${phishSender} delivered to ${victim.sam}, linking to ${appDomain} (T1566.002)` },
      { ts: T(10 * MIN + 40 * SEC), phase: "Initial Access", action: `The lure page ${consentUrl} is opened from the corporate network` },
      { ts: T(11 * MIN), phase: "Credential Access", action: `Consent grant, ${appName} issued a token with full Gmail + full Drive scopes (T1528)` },
      { ts: T(14 * MIN), phase: "Investigation", action: "Admin console lookup: app unconfigured, no marketplace listing, publisher unverified" },
      { ts: T(19 * MIN), phase: "Collection", action: "Gmail API mailbox reads over the token from a hosting ASN (T1114.002)" },
      { ts: T(27 * MIN), phase: "Collection", action: "Drive API downloads of finance workbooks via the token (T1530)" },
      { ts: T(55 * MIN), phase: "Containment", action: "Admin resets password, no OAuth token revoke follows" },
      { ts: T(80 * MIN), phase: "Persistence", action: "Token still valid, a Drive download succeeds 25 min after the reset (T1550.001)" },
    ],
    questions,
  };
}
