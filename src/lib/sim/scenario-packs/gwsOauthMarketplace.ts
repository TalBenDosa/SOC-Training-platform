/**
 * Scenario pack: "Consent, Not Credentials — a Malicious OAuth App in Google Workspace"
 *
 * INTERMEDIATE tier. A cloud-identity case with NO password compromise and NO
 * host to walk. A Revenue Operations lead is phished with a link that leads to a
 * Google consent screen for a third-party Marketplace-style app, "Docs Merge
 * Pro". She clicks Allow, and in that one action the app is granted an OAuth
 * refresh token carrying two of the broadest scopes Google issues:
 * https://mail.google.com/ (full Gmail) and .../auth/drive (full Drive). From
 * then on the app's own servers read her mailbox and pull hundreds of Drive
 * files over the Gmail and Drive APIs — no password is ever used, MFA is never
 * in the path, and the access keeps working after the account's password is
 * reset, because a reset does not touch an already-issued OAuth token.
 *
 * The teaching spine has two halves the student must separate:
 *   • PERSISTENCE is the consent grant itself. The refresh token is the foothold;
 *     it survives password resets and sign-out. Only REVOKING the app's token /
 *     removing the grant stops it.
 *   • IMPACT is the API-driven collection that follows — mailbox reads and a Drive
 *     download burst — all authenticated by the token, from a hosting ASN.
 *
 * A BENIGN CONTROL is included and is the pedagogical crux: a different user
 * authorizes "Calendly" the same way — a user granting an OAuth app — but that
 * app is admin-allowlisted, marketplace-verified, from a named publisher, and
 * asks for one narrow calendar scope. Same shape ("a user consented to an app"),
 * opposite verdict. The discriminators are scope breadth, allowlist status, and
 * publisher verification — not the act of consenting.
 *
 * Covers T1566.002 (Spearphishing Link — the consent lure), T1528 (Steal
 * Application Access Token — the consent grant that yields the token), T1550.001
 * (Application Access Token — the token used to authenticate API access, incl.
 * after the password reset), T1114.002 (Remote Email Collection — the mailbox
 * reads over the Gmail API) and T1530 (Data from Cloud Storage — the Drive
 * download burst).
 *
 * SOURCES: Google Workspace only — the admin audit, the token/OAuth audit, the
 * Gmail and Drive audit, and the Alert Center. This pack fits a Google Workspace
 * estate (rocketstack.io).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildGwsOauthMarketplaceScenario(
  scenarioId = "gws-oauth-marketplace-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T09:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident — the whole case is a single OAuth-app-abuse investigation.
  const INCIDENT = "inc:gwsoauth:1";

  // The phished user and her normal working context.
  const victim = {
    email: "m.varga@rocketstack.io",
    name: "Miriam Varga",
    sam: "m.varga",
    title: "Revenue Operations Lead",
    ip: "24.60.183.14", // her corporate egress at consent time (Boston)
  };

  // The malicious third-party app. Marketplace-style listing, unverified
  // publisher, its backend hosted on a VPS ASN in Frankfurt.
  const clientId = "849276150983-3f7qk2m9xr4vd8n1b6c0aptsu5wg2h7e.apps.googleusercontent.com";
  const appName = "Docs Merge Pro";
  const appDomain = "docsmergepro.app";
  const consentUrl = "https://docsmergepro.app/connect/google";
  const phishSender = "onboarding@docs-merge-pro.com";
  const serverIp = "45.87.43.19"; // the app backend's hosting-ASN egress

  // The admin who works the case and attempts the (insufficient) password reset.
  const adminEmail = "secops-admin@rocketstack.io";

  // A representative exfiltrated Drive workbook — its hash is the data IOC.
  const marqueeFile = "FY26_Revenue_Forecast.xlsx";
  const marqueeFileHash = makeSha256("rocketstack_fy26_revenue_forecast_drive_export_2026");

  // The BENIGN CONTROL: a different user authorizes a narrow-scope, admin-
  // allowlisted, marketplace-verified app the ordinary way.
  const benign = {
    email: "t.nowak@rocketstack.io",
    name: "Tomas Nowak",
    sam: "t.nowak",
    ip: "24.60.183.9",
  };
  const benignClientId = "556123094817-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a user grants an OAuth app the RIGHT way. Same shape
    //    as the incident (a token authorize), opposite verdict: admin-
    //    allowlisted, marketplace-verified, named publisher, one narrow scope.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_00_benign_grant",
      ts: T(-30 * HOUR),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "account_modify",
      user_email: benign.email,
      user_title: "Account Executive",
      src_ip: benign.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "Benign. t.nowak authorized Calendly — also 'a user granting an OAuth app', but the discriminators all point the other way: the app is on the admin allowlist (TRUSTED), marketplace-verified, from a named publisher, and it requested a single narrow calendar scope. Compare with the Docs Merge Pro grant, which is unlisted, unverified, and asks for full Gmail and full Drive. The act of consenting is not the signal; scope breadth, allowlist status and publisher verification are.",
      description:
        "t.nowak authorized Calendly, an admin-allowlisted, marketplace-verified app, requesting only the read/write calendar-events scope — a routine, sanctioned OAuth grant.",
      raw: {
        "gws.event.type": "token",
        "gws.event.name": "authorize",
        "gws.actor.email": benign.email,
        "gws.token.client_id": benignClientId,
        "gws.token.app_name": "Calendly",
        "gws.token.client_type": "WEB",
        "gws.token.scope": [
          "https://www.googleapis.com/auth/calendar.events",
          "openid",
          "https://www.googleapis.com/auth/userinfo.email",
        ],
        "gws.token.api_name": "calendar",
        "gws.app.allowlist_status": "TRUSTED",
        "gws.app.marketplace_verified": "true",
        "gws.app.publisher": "Calendly LLC",
        "source.ip": benign.ip,
        "source.geo.country_name": "United States",
        "application.name": "Calendly",
        "application.id": benignClientId,
        "application.type": "oauth2_web",
        "event.action": "authorize",
        "event.outcome": "success",
        "user.email": benign.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE CONSENT LURE — a link email that lands the user on the app's
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
      severity: "low",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Gmail delivered a message to m.varga inviting her to connect a document-merge add-on, with a button linking to docsmergepro.app/connect/google. It passed SPF, DKIM and DMARC and went to the inbox.",
      network: { url: consentUrl, domain: appDomain, method: "GET" },
      raw: {
        "gws.event.type": "message_delivered",
        "gws.event.name": "email_log_search",
        "gws.message_id": "<f19c72aa8b41@mail.docs-merge-pro.com>",
        "gws.sender": phishSender,
        "gws.recipient": victim.email,
        "gws.subject": "Finish setup: connect Docs Merge Pro to your Drive",
        "gws.direction": "INBOUND",
        "gws.link.url": consentUrl,
        "gws.link.domain": appDomain,
        "gws.spf_result": "PASS",
        "gws.dkim_result": "PASS",
        "gws.dmarc_result": "PASS",
        "gws.classification": "INBOX",
        "url.full": consentUrl,
        "url.domain": appDomain,
        "event.action": "email-delivered",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE CONSENT GRANT — the crux. m.varga clicks Allow and a token audit
    //    'authorize' records the app receiving full Gmail + full Drive scopes.
    //    This grant IS the persistence: an offline (refresh) token is issued.
    //    Alert Center flags the sensitive-scope grant → this opens the case.
    //    Steal Application Access Token (T1528). is_detection + non_edr.
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
      geo: { country: "United States", city: "Boston" },
      severity: "high",
      mitre_technique: "T1528",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      is_detection: true,  // the Alert Center detection that opens the case
      edr_scope: "non_edr", // cloud identity / SaaS only — no host process to walk
      description:
        "A token audit 'authorize' recorded m.varga granting Docs Merge Pro the scopes https://mail.google.com/ and https://www.googleapis.com/auth/drive, with an offline (refresh) token issued. Alert Center raised a sensitive-scope grant alert.",
      raw: {
        "gws.event.type": "token",
        "gws.event.name": "authorize",
        "gws.actor.email": victim.email,
        "gws.token.client_id": clientId,
        "gws.token.app_name": appName,
        "gws.token.client_type": "WEB",
        "gws.token.scope": [
          "https://mail.google.com/",
          "https://www.googleapis.com/auth/drive",
          "openid",
          "https://www.googleapis.com/auth/userinfo.email",
        ],
        "gws.token.api_name": ["gmail", "drive"],
        "gws.token.access_type": "offline",
        "gws.app.allowlist_status": "NOT_CONFIGURED",
        "gws.app.marketplace_verified": "false",
        "gws.app.publisher": "unverified",
        "gws.app.redirect_uri": "https://docsmergepro.app/oauth2/callback",
        "gws.alert.center.type": "Third-party app granted sensitive scopes",
        "gws.alert.center.id": "AC-2026-0831-4471",
        "source.ip": victim.ip,
        "source.geo.country_name": "United States",
        "source.geo.city_name": "Boston",
        "application.name": appName,
        "application.id": clientId,
        "application.type": "oauth2_web",
        "event.action": "authorize",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. ALLOWLIST CONTEXT — an admin-audit review of the app against the org's
    //    third-party access policy. The app is not allowlisted, not verified,
    //    and the tenant policy permits unlisted apps. Investigation context.
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
        "An admin-console app-access review for the Docs Merge Pro client id returns NOT_ALLOWLISTED and publisher-unverified, under a tenant policy that allows unlisted third-party apps by default.",
      raw: {
        "gws.event.type": "admin",
        "gws.event.name": "app_access_review",
        "gws.actor.email": adminEmail,
        "gws.query.client_id": clientId,
        "gws.app.name": appName,
        "gws.app.access_level": "UNRESTRICTED",
        "gws.app.allowlist_status": "NOT_ALLOWLISTED",
        "gws.app.marketplace_verified": "false",
        "gws.app.publisher_verified": "false",
        "gws.app.first_authorized": T(11 * MIN),
        "gws.app.total_users_granted": "1",
        "gws.org.third_party_access_policy": "ALLOW_ALL_EXCEPT_BLOCKLIST",
        "application.id": clientId,
        "application.name": appName,
        "event.action": "log-search",
        "event.outcome": "success",
        "user.email": adminEmail,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. MAILBOX READ OVER THE GMAIL API — the token, not a password, reads the
    //    mailbox from the app's servers. Remote Email Collection (T1114.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_04_gmail_api_read",
      ts: T(19 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: victim.email,
      src_ip: serverIp,
      geo: { country: "Germany", city: "Frankfurt" },
      severity: "high",
      mitre_technique: "T1114.002",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "A token audit 'activity' shows Docs Merge Pro calling the Gmail API for m.varga from 45.87.43.19 (Frankfurt) — 1,180 messages.list/get calls returning ~48 MB, authenticated by the offline token, no interactive sign-in.",
      raw: {
        "gws.event.type": "token",
        "gws.event.name": "activity",
        "gws.actor.email": victim.email,
        "gws.token.client_id": clientId,
        "gws.token.app_name": appName,
        "gws.token.api_name": "gmail",
        "gws.token.method_name": "gmail.users.messages.list",
        "gws.token.product_bucket": "GMAIL",
        "gws.token.access_type": "offline",
        "gws.api.call_count": "1180",
        "gws.api.response_bytes": "48211904",
        "source.ip": serverIp,
        "source.geo.country_name": "Germany",
        "source.geo.city_name": "Frankfurt",
        "api.endpoint": "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        "api.method": "GET",
        "application.name": appName,
        "application.id": clientId,
        "event.action": "api-access",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. DRIVE DOWNLOAD BURST OVER THE DRIVE API — hundreds of files pulled by
    //    the app from the same hosting ASN. Data from Cloud Storage (T1530).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_05_drive_download_burst",
      ts: T(27 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_storage_access",
      user_email: victim.email,
      src_ip: serverIp,
      geo: { country: "Germany", city: "Frankfurt" },
      severity: "high",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "The Drive audit records 612 download operations under m.varga's account in about nine minutes, all attributed to the Docs Merge Pro token from 45.87.43.19 — a representative record from a burst far above her norm.",
      file: {
        name: marqueeFile,
        path: `/Drive/Finance/FY26/${marqueeFile}`,
        extension: "xlsx",
        size: 8_734_208,
        sha256: marqueeFileHash,
      },
      raw: {
        "gws.event.type": "access",
        "gws.event.name": "download",
        "gws.actor.email": victim.email,
        "gws.token.client_id": clientId,
        "gws.token.app_name": appName,
        "gws.drive.doc_title": marqueeFile,
        "gws.drive.doc_id": "1A2b3C4d5E6f7G8h9I0jK1l2M3n4O5p6Q7r8S9t0",
        "gws.drive.doc_type": "spreadsheet",
        "gws.drive.owner": victim.email,
        "gws.drive.visibility": "private",
        "gws.drive.primary_event": "true",
        "gws.access.download_count_window": "612",
        "gws.access.via_oauth_app": appName,
        "file.name": marqueeFile,
        "file.path": `/Drive/Finance/FY26/${marqueeFile}`,
        "file.hash.sha256": marqueeFileHash,
        "file.size": "8734208",
        "source.ip": serverIp,
        "source.geo.country_name": "Germany",
        "source.geo.city_name": "Frankfurt",
        "application.name": appName,
        "application.id": clientId,
        "event.action": "download",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE INSUFFICIENT REMEDIATION — an admin resets the password and forces
    //    sign-out. This revokes sessions but NOT the OAuth token. Response
    //    action (benign); it is the setup for the persistence lesson.
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
        "An admin reset m.varga's password and forced a sign-out of all active sessions at 10:10 as a first containment step.",
      raw: {
        "gws.event.type": "admin",
        "gws.event.name": "CHANGE_PASSWORD",
        "gws.actor.email": adminEmail,
        "gws.target.user": victim.email,
        "gws.admin.action": "reset_user_password",
        "gws.admin.force_signout": "true",
        "gws.admin.oauth_tokens_revoked": "false",
        "target.user.email": victim.email,
        "event.action": "reset-password",
        "event.outcome": "success",
        "user.email": adminEmail,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE TOKEN STILL WORKS — after the reset, the app keeps calling the
    //    Drive API and succeeding. The token predates the reset and was never
    //    revoked. Application Access Token (T1550.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_oauth_07_token_survives_reset",
      ts: T(80 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "cloud_api_call",
      user_email: victim.email,
      src_ip: serverIp,
      geo: { country: "Germany", city: "Frankfurt" },
      severity: "critical",
      mitre_technique: "T1550.001",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "At 10:35, 25 minutes after the password reset, the Docs Merge Pro token successfully called the Drive API again for m.varga from 45.87.43.19 — the token was issued at 09:26 and remained valid; the reset did not revoke it.",
      raw: {
        "gws.event.type": "token",
        "gws.event.name": "activity",
        "gws.actor.email": victim.email,
        "gws.token.client_id": clientId,
        "gws.token.app_name": appName,
        "gws.token.api_name": "drive",
        "gws.token.method_name": "drive.files.list",
        "gws.token.product_bucket": "DRIVE",
        "gws.token.access_type": "offline",
        "gws.token.issued_at": T(11 * MIN),
        "gws.api.call_count": "204",
        "gws.api.response_bytes": "17330560",
        "source.ip": serverIp,
        "source.geo.country_name": "Germany",
        "source.geo.city_name": "Frankfurt",
        "api.endpoint": "https://www.googleapis.com/drive/v3/files",
        "api.method": "GET",
        "application.name": appName,
        "application.id": clientId,
        "event.action": "api-access",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: serverIp, // 45.87.43.19 — the app backend's hosting-ASN egress
      first_seen: T(19 * MIN),
      last_seen: T(80 * MIN),
      reputation: "malicious",
      tags: ["oauth-app-backend", "hosting-asn"],
    },
    {
      type: "domain",
      value: appDomain, // docsmergepro.app — the app / consent-landing domain
      first_seen: T(0),
      last_seen: T(11 * MIN),
      reputation: "malicious",
      tags: ["third-party-app", "consent-landing"],
    },
    {
      type: "user",
      value: clientId, // the OAuth client id — the durable pivot across events
      first_seen: T(11 * MIN),
      last_seen: T(80 * MIN),
      reputation: "malicious",
      tags: ["oauth-client-id", "third-party-app"],
    },
    {
      type: "email",
      value: victim.email, // m.varga@rocketstack.io — the affected account
      first_seen: T(0),
      last_seen: T(80 * MIN),
      reputation: "suspicious",
      tags: ["affected-account", "revenue-ops"],
    },
    {
      type: "sha256",
      value: marqueeFileHash, // a representative downloaded finance workbook
      first_seen: T(27 * MIN),
      last_seen: T(27 * MIN),
      reputation: "unknown",
      tags: ["drive-file", "finance-data"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "At 10:10 an admin reset m.varga's password and forced a sign-out, yet at 10:35 (evt_oauth_07) the app's Drive API calls still succeed. Why does the password reset fail to stop the access?",
      hint: "Look at gws.token.access_type and gws.token.issued_at in evt_oauth_07, and gws.admin.oauth_tokens_revoked in evt_oauth_06.",
      kind: "single",
      options: [
        { value: "token_independent", label: "An OAuth refresh token authenticates the app independently of the password; it was issued at consent and a reset neither expires nor revokes it, so calls keep succeeding until the grant is removed" },
        { value: "reset_not_applied", label: "The password reset simply had not propagated yet, and the calls would have started failing within the hour on their own" },
        { value: "cached_creds", label: "The app had cached the old password locally and was replaying it, so the calls succeed only until the cache expires" },
        { value: "second_account", label: "The app is signing in as a different service account it created, which the reset of m.varga's password does not affect" },
      ],
      answer: "token_independent",
      xp: 65,
      explanation:
        "This is the core lesson. When m.varga consented, Google issued Docs Merge Pro an OAuth refresh token (access_type offline). That token is a bearer credential the app presents on every API call; it is not derived from, and does not check, the account password. A password reset invalidates the password and existing web sessions — evt_oauth_06 even forces a sign-out — but it does NOT revoke issued OAuth grants (gws.admin.oauth_tokens_revoked is false), which is exactly why the 10:35 Drive calls in evt_oauth_07 still return success against a token issued at 09:26. (b) is wrong — OAuth grants do not lapse on their own within an hour. (c) invents a cached password; the app never had the password, that is the whole point of consent. (d) invents a service account not present in any log. Remediation must revoke the token / remove the app authorization, not just reset the password.",
    },
    {
      id: "q2",
      prompt:
        "evt_oauth_00 shows t.nowak authorizing Calendly — also a user granting an OAuth app — but it is benign. Reading it against the Docs Merge Pro grant (evt_oauth_02), what actually separates the malicious grant from the benign one?",
      hint: "The act of consenting is the same in both. Compare the scope list, gws.app.allowlist_status, and gws.app.marketplace_verified / publisher.",
      kind: "single",
      options: [
        { value: "scope_allowlist_publisher", label: "Breadth of access and provenance: Docs Merge Pro asks for full Gmail and full Drive, is not on the allowlist, and is publisher-unverified; Calendly asks for one calendar scope, is admin-trusted, and is verified" },
        { value: "consent_itself", label: "The consent action itself — any user authorizing a third-party OAuth app is a compromise, so both grants should be treated as incidents" },
        { value: "client_type", label: "Calendly uses a WEB client type and Docs Merge Pro does not, and that client-type difference alone marks one as malicious" },
        { value: "user_role", label: "t.nowak is in Sales and m.varga is in Revenue Operations, and the grant is malicious purely because it was a finance-adjacent user who consented" },
      ],
      answer: "scope_allowlist_publisher",
      xp: 60,
      explanation:
        "Both events are a token 'authorize' by a user — so consenting cannot itself be the signal, which is why (b) is the trap the control disproves. The verdict comes from three fields read together. Scope: Docs Merge Pro requested https://mail.google.com/ and .../auth/drive (full read/write to mail and all files), where Calendly requested only calendar.events. Allowlist: Docs Merge Pro is NOT_CONFIGURED / NOT_ALLOWLISTED, Calendly is TRUSTED. Publisher/marketplace: Docs Merge Pro is unverified, Calendly is marketplace-verified from a named publisher. (c) is false — both are WEB clients, and client type is not a verdict. (d) invents role-based reasoning the logs do not support. Least-privilege scope plus provenance is the discriminator.",
    },
    {
      id: "q3",
      prompt:
        "m.varga has MFA enforced, and no failed logins or new-device sign-ins appear anywhere in the timeline. How is the app reading her mailbox and Drive without ever tripping an authentication control?",
      kind: "single",
      options: [
        { value: "token_bypasses_auth", label: "The app acts on a delegated OAuth token, so it calls the Gmail and Drive APIs directly as an authorized client — there is no interactive login for MFA to challenge" },
        { value: "mfa_disabled", label: "The attacker must have disabled MFA on the account first, which is what allowed the API calls to proceed unchallenged" },
        { value: "stolen_session", label: "A stolen browser session cookie is being replayed on each call, and MFA does not re-prompt within an existing session" },
        { value: "password_phished", label: "Her password was phished and the app is logging in with it, simply choosing endpoints that skip the MFA step" },
      ],
      answer: "token_bypasses_auth",
      xp: 60,
      explanation:
        "OAuth delegation is the answer. By consenting, m.varga authorized the app to call Google APIs on her behalf using its own token — the calls in evt_oauth_04 and evt_oauth_05 originate from the app's servers (45.87.43.19) and present the token, not a password and not a login form. MFA only ever guards an interactive authentication, and there is no interactive authentication here to guard, so nothing is bypassed or disabled — which is why (b) and (d) are wrong (no password and no MFA change appear in any event). (c) describes a different technique — session-cookie replay — but the audit shows a token 'activity' by a registered OAuth client, not a replayed web session. This is why consent phishing is dangerous precisely against MFA-protected accounts.",
    },
    {
      id: "q4",
      prompt:
        "Separating persistence from impact: which statement correctly assigns the events?",
      kind: "single",
      options: [
        { value: "grant_persist_api_impact", label: "The consent grant (evt_oauth_02) is the persistence foothold — the token that keeps access alive — while the Gmail reads and Drive download burst (evt_oauth_04, evt_oauth_05) are the impact carried out with it" },
        { value: "download_is_persistence", label: "The Drive download burst is the persistence mechanism, because downloading the files is what lets the attacker return to them later" },
        { value: "lure_is_impact", label: "The consent-lure email (evt_oauth_01) is the impact, since it is the message that reached the user's inbox" },
        { value: "reset_is_persistence", label: "The password reset (evt_oauth_06) is the persistence, because forcing a sign-out is what kept the app connected" },
      ],
      answer: "grant_persist_api_impact",
      xp: 55,
      explanation:
        "The grant and the collection are different jobs. evt_oauth_02 issues the refresh token — that is the durable foothold (persistence): it is what survives the reset and keeps the door open. evt_oauth_04 (mailbox reads, T1114.002) and evt_oauth_05 (Drive download burst, T1530) are the impact — the data actually collected using that token. (b) confuses the stolen data with the mechanism that keeps access; the download is a one-time pull, the token is what would let the app pull again tomorrow. (c) mislabels the delivery email as impact. (d) is backwards — the reset was a containment attempt, and an insufficient one. Getting this split right is what tells you removing the grant, not chasing each download, is the fix.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the response. The evidence is a broad-scope consent grant to an unverified third-party app, mailbox reads and a Drive download burst over its token, and access that outlived a password reset. What is the correct remediation and classification?",
      kind: "single",
      options: [
        { value: "revoke_and_scope", label: "Revoke the app's OAuth token / remove the grant for m.varga, add the client id to the app blocklist, then scope what mail and files the token accessed — an OAuth app abuse, not a password compromise" },
        { value: "reset_again", label: "Reset the password a second time and enforce MFA re-registration; once the credentials are fully rotated the app loses access with no further action" },
        { value: "block_ip_only", label: "Block 45.87.43.19 at the perimeter and close the case — cutting the app's server IP stops the API calls and needs nothing else" },
        { value: "monitor_only", label: "Leave the grant in place and monitor the token's activity for a few days to gather more evidence before taking any disruptive action" },
      ],
      answer: "revoke_and_scope",
      xp: 65,
      explanation:
        "The token is the access, so the fix is to kill the token: revoke Docs Merge Pro's grant for m.varga (and blocklist the client id so it cannot be re-authorized), which is the one action that actually ends it. Then scope the damage — which mailboxes and Drive files the token read — and tighten the tenant's third-party access policy so unlisted apps cannot be consented to. (b) repeats the mistake the timeline already disproved: a reset does not revoke an OAuth grant. (c) fails because the API traffic goes to Google's servers, not through your perimeter — blocking one hosting IP neither reaches Google's side nor stops the app moving to another IP, and it revokes nothing. (d) leaves an active exfiltration channel open. Classify as OAuth application abuse and escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Consent, Not Credentials — a Malicious OAuth App in Google Workspace",
    threat_actor: "Consent-phishing operator abusing a third-party OAuth app (cloud identity, no host foothold)",
    attack_kind: "oauth_abuse",
    briefing:
      "Google Workspace Alert Center flagged that m.varga (RocketStack) allowed a third-party app broad reach into her mailbox and Drive after opening a link. Her password and sign-in look normal, and MFA is enforced. Work out how the app is reading company data, why it keeps working after remediation, and what actually stops it.",
    narrative: `This is a cloud-identity case with no malware and no password to crack. At 09:15 Gmail delivered a message to Miriam Varga, a Revenue Operations lead, inviting her to "finish setup" for a document-merge add-on. The link went to docsmergepro.app, and the message passed SPF, DKIM and DMARC — because a real domain sent it.

At 09:26 she clicked through to a genuine Google consent screen and pressed Allow. In that single action the third-party app "Docs Merge Pro" was granted an OAuth token carrying two of the broadest scopes Google issues: https://mail.google.com/ (full Gmail) and https://www.googleapis.com/auth/drive (full Drive). The token was offline — a refresh token — and Alert Center raised a sensitive-scope grant alert, which is the ticket you picked up. An admin-console review confirmed the app is not allowlisted, its publisher is unverified, and the tenant policy allows unlisted apps by default.

From 09:34 the app's own servers in Frankfurt (45.87.43.19) began calling the Gmail API — over a thousand messages read, ~48 MB returned — and at 09:42 the Drive API, 612 downloads in nine minutes, all authenticated by the token. No password was ever used and MFA was never in the path, because delegated API access has no interactive login to challenge.

At 10:10 an admin reset Varga's password and forced a sign-out. It was not enough: at 10:35 the same token successfully called the Drive API again, because a password reset does not revoke an already-issued OAuth grant. Only removing the app's authorization stops it.

The instructive comparison is Tomas Nowak, who authorized Calendly the day before — the same act of granting an OAuth app, but admin-allowlisted, marketplace-verified, from a named publisher, and asking for a single calendar scope. Same shape, opposite verdict: consenting is not the signal — scope breadth, allowlist status and publisher verification are.`,
    learning_objectives: [
      "Investigate an OAuth application abuse (consent phishing) in Google Workspace from the token audit: read the 'authorize' event's scopes, client id, and offline access_type to identify the grant",
      "Explain why the consent grant is the persistence mechanism — an OAuth refresh token authenticates the app independently of the password and survives a password reset and forced sign-out",
      "Separate persistence (the token grant) from impact (Gmail API mailbox reads T1114.002 and the Drive download burst T1530) carried out with the token from a hosting ASN",
      "Distinguish a malicious grant from a benign one using scope breadth, admin allowlist status, and publisher/marketplace verification — not the act of consenting",
      "Scope response for OAuth app abuse: revoke the app's token / remove the grant and blocklist the client id, review what mail and files were accessed, and restrict the tenant's third-party access policy",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-30 * HOUR), phase: "Context", action: `Benign control — ${benign.sam} authorizes Calendly (allowlisted, verified, one narrow scope)` },
      { ts: T(0), phase: "Initial Access", action: `Consent-lure email delivered to ${victim.sam}, linking to ${appDomain} (T1566.002)` },
      { ts: T(11 * MIN), phase: "Credential Access", action: `Consent grant — ${appName} issued an offline token with full Gmail + full Drive scopes (T1528)` },
      { ts: T(14 * MIN), phase: "Investigation", action: "Admin app-access review: app not allowlisted, publisher unverified, tenant allows unlisted apps" },
      { ts: T(19 * MIN), phase: "Collection", action: "Gmail API mailbox reads over the token from a hosting ASN (T1114.002)" },
      { ts: T(27 * MIN), phase: "Collection", action: "Drive API download burst — 612 files via the token (T1530)" },
      { ts: T(55 * MIN), phase: "Containment", action: "Admin resets password and forces sign-out — does NOT revoke the OAuth token" },
      { ts: T(80 * MIN), phase: "Defense Evasion", action: "Token still valid — Drive API calls succeed 25 min after the reset (T1550.001)" },
    ],
    questions,
  };
}
