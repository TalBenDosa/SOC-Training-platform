/**
 * Learning Rooms — Batch 37
 *
 * Closes an F-09 external-audit gap: the platform's identity scenarios that
 * run on Okta (mfa-fatigue-ato, okta-password-burst) require reading the
 * Okta System Log, but the platform only ever taught Entra ID (Azure AD) in
 * depth. This room teaches Okta's own event model on its own terms, and
 * explicitly contrasts it against Entra ID so a student who only knows
 * Entra does not misread an Okta tenant's logs by assuming the field names
 * carry over.
 *
 * Rooms in this batch:
 *  1. okta-identity-fundamentals
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Okta Identity & Authentication Fundamentals
// ===========================================================================

const passwordAcceptedEvent: TelemetryEvent = {
  id: "evt-oktaf-la1-001",
  ts: "2026-05-04T03:12:41.000Z",
  source: "okta",
  vendor: "Okta",
  event_type: "auth_failure",
  severity: "high",
  mitre_technique: "T1110.001",
  mitre_tactic: "Credential Access",
  user_email: "n.abara@globallogis.com",
  user_title: "Logistics Coordinator",
  src_ip: "185.220.101.44",
  geo: { country: "Romania", city: "Bucharest" },
  authentication: { method: "PASSWORD", result: "failure" },
  description:
    "A user.session.start event for n.abara@globallogis.com from 185.220.101.44, arriving after a run of earlier failures from the same address against the same account.",
  raw: {
    "okta.eventType": "user.session.start",
    "okta.displayMessage": "User login to Okta",
    "okta.outcome.result": "FAILURE",
    "okta.outcome.reason": "MFA_REQUIRED",
    "okta.severity": "INFO",
    "okta.actor.id": "00u7f0abcXyZ912Qk417",
    "okta.actor.type": "User",
    "okta.actor.alternateId": "n.abara@globallogis.com",
    "okta.actor.displayName": "Nkem Abara",
    "okta.client.ipAddress": "185.220.101.44",
    "okta.client.userAgent.rawUserAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "okta.client.userAgent.os": "Windows 10",
    "okta.client.userAgent.browser": "CHROME",
    "okta.client.geographicalContext.country": "Romania",
    "okta.client.geographicalContext.city": "Bucharest",
    "okta.securityContext.asNumber": "AS200019",
    "okta.securityContext.asOrg": "Alexhost SRL",
    "okta.securityContext.isp": "Alexhost SRL",
    "okta.securityContext.isProxy": "false",
    "okta.authenticationContext.authenticationStep": "1",
    "okta.authenticationContext.credentialType": "PASSWORD",
    "okta.authenticationContext.externalSessionId": "trsA91kQmpTLxV0nFqZ",
    "okta.transaction.id": "TxRvC91k",
    "okta.debugContext.debugData.requestUri": "/api/v1/authn",
    "okta.debugContext.debugData.threatSuspected": "false",
    "event.outcome": "failure",
    "source.ip": "185.220.101.44",
    "user.email": "n.abara@globallogis.com",
  },
};

const groupMembershipEvent: TelemetryEvent = {
  id: "evt-oktaf-la2-001",
  ts: "2026-05-04T03:19:02.000Z",
  source: "okta",
  vendor: "Okta",
  event_type: "group_modify",
  severity: "critical",
  mitre_technique: "T1098",
  mitre_tactic: "Persistence",
  user_email: "n.abara@globallogis.com",
  src_ip: "185.220.101.44",
  geo: { country: "Romania", city: "Bucharest" },
  description:
    "A group.user_membership.add event recorded n.abara@globallogis.com being added to the Okta-Admins group, actioned from the same IP address that had been signing in as that same account minutes earlier.",
  raw: {
    "okta.eventType": "group.user_membership.add",
    "okta.displayMessage": "Add user to group membership",
    "okta.outcome.result": "SUCCESS",
    "okta.severity": "INFO",
    "okta.actor.id": "00u7f0abcXyZ912Qk417",
    "okta.actor.type": "User",
    "okta.actor.alternateId": "n.abara@globallogis.com",
    "okta.actor.displayName": "Nkem Abara",
    "okta.client.ipAddress": "185.220.101.44",
    "okta.client.geographicalContext.country": "Romania",
    "okta.client.geographicalContext.city": "Bucharest",
    "okta.target.0.id": "00u7f0abcXyZ912Qk417",
    "okta.target.0.type": "User",
    "okta.target.0.alternateId": "n.abara@globallogis.com",
    "okta.target.1.id": "00g4kx19mZQ7pLbT417v",
    "okta.target.1.type": "UserGroup",
    "okta.target.1.displayName": "Okta-Admins",
    "okta.transaction.id": "TxRvC94q",
    "okta.debugContext.debugData.requestUri": "/api/v1/groups/00g4kx19mZQ7pLbT417v/users/00u7f0abcXyZ912Qk417",
    "event.outcome": "success",
    "source.ip": "185.220.101.44",
    "user.email": "n.abara@globallogis.com",
  },
};

const oktaIdentityFundamentalsRoom = {
  id: "okta-identity-fundamentals",
  title: "Okta Identity & Authentication Fundamentals",
  description:
    "The Okta counterpart to Entra ID: how to read the Okta System Log on its own terms — the okta.eventType taxonomy, outcome.result and outcome.reason (including the single field flip that separates a rejected password from an accepted one), securityContext network signals, factor enrollment and MFA types, and the admin/group events attackers target for persistence. Includes a direct, explicit contrast against Entra ID so a student who only knows Microsoft's identity platform doesn't misread an Okta tenant.",
  difficulty: "intermediate" as const,
  category: "Identity & Access",
  estimatedMinutes: 60,
  xp: 380,
  icon: "🔐",
  prerequisites: ["identity-basics", "entra-id"],
  tasks: [
    // ── Reading 1: what Okta is ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r1",
      heading: "Okta in the SOC: A Different Identity Provider, the Same Job",
      content:
        "Every organisation needs one authoritative place that answers the question 'is this really the person they claim to be, and what are they allowed to do' — an identity provider (IdP). This platform teaches Microsoft's answer, Entra ID, in depth elsewhere. Okta is a separate, independent company's answer to the exact same problem, used heavily by organisations that are not built primarily on Microsoft's stack, or that want a single-sign-on layer sitting in front of a mix of Microsoft, Google, and dozens of other cloud applications at once.\n\n" +
        "**The mental model.** Okta is a cloud-hosted identity platform providing three things together: a directory of users and groups (Okta calls this the Universal Directory, and it can hold its own accounts or synchronise from an existing on-prem Active Directory or another HR system), a single sign-on layer letting one Okta login carry a user into dozens of connected applications without re-authenticating to each one, and a policy engine deciding when a sign-in needs a second factor, what device posture is required, and from where access is allowed at all. None of that is conceptually new to a student who has learned Entra ID — the shapes rhyme closely. What differs, and what this room exists to teach, is the vocabulary, the log schema, and a handful of behavioural specifics that do not carry over.\n\n" +
        "**Why an analyst cannot skip this room even after learning Entra.** The single most common real mistake a Windows/Entra-trained analyst makes on their first Okta investigation is assuming a field name from one platform exists on the other. Entra's sign-in logs use fields like ResultType and ConditionalAccessStatus; Okta's System Log uses an entirely different structure built around outcome.result, outcome.reason, and a dot-notation eventType taxonomy. Querying an Okta System Log for an Entra field name returns nothing — not an error, just silence, which is exactly the kind of silent gap that lets a real incident slip past an analyst who assumes their old queries still work.\n\n" +
        "**What Okta calls itself, structurally.** An Okta customer's whole tenant is called an org (sometimes 'org' also refers to sub-organisational structures for larger customers running multiple orgs — but for a typical single-tenant customer, one org is the whole company's Okta presence). Every event this room covers is written to that org's System Log, viewable in the Okta Admin Console or exported to a SIEM, and it is the single authoritative activity record for that org — comparable in role, though not in schema, to Entra's sign-in and audit logs combined into one feed.\n\n" +
        "**What this room does and does not cover.** This room is entirely about reading Okta's own telemetry correctly. It does not re-teach identity fundamentals already covered elsewhere (authentication vs authorization, what MFA actually is, session tokens) — those concepts transfer directly from Entra ID and Identity Basics. What's new here is Okta's specific vocabulary for expressing them, and the small number of places where Okta's actual behaviour, not just its naming, genuinely differs from what an Entra-trained analyst would expect.",
      checkpoint: {
        question: "Why can't an analyst who already knows Entra ID's sign-in log fields simply reuse those same field names against an Okta tenant?",
        options: [
          "Okta's System Log uses an entirely different structure -- outcome.result/outcome.reason and a dot-notation eventType taxonomy -- so querying for an Entra field name against Okta returns nothing at all, silently",
          "Okta does not log authentication events at all, so there is nothing to query in the first place",
          "Okta's fields are identical to Entra's, just written in lowercase instead of PascalCase",
          "Okta requires a paid add-on before any log data becomes queryable",
        ],
        answer: 0,
        explanation:
          "The two platforms rhyme conceptually but do not share a schema. Reusing an Entra field name against Okta doesn't error -- it silently returns nothing, which is exactly the kind of gap that can hide a real incident from an analyst who assumes their old queries still work.",
      },
    },
    // ── Reading 2: System Log / eventType ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r2",
      heading: "The Okta System Log: One Event Type Taxonomy to Learn",
      content:
        "Every action inside an Okta org — a sign-in, a failed password, an admin granting a role, a factor being enrolled — is written as one event in the System Log, and almost every one of those events is identified by a single field: okta.eventType.\n\n" +
        "**The dot-notation pattern.** Okta's eventType values follow a consistent object.verb (or object.subobject.verb) structure. user.session.start covers a sign-in attempt. user.mfa.okta_verify.push_response covers a specific factor's response to a challenge. group.user_membership.add covers a group-membership change. system.org.rate_limit.warning covers Okta's own infrastructure defending itself. Once an analyst recognises the pattern, an unfamiliar eventType value is still readable at a glance: the leading segment names the broad category (user, group, policy, system, application), and the trailing segment names the specific action.\n\n" +
        "**okta.displayMessage: the human-readable companion.** Alongside the machine-readable eventType, every event carries a plain-English displayMessage — 'User login to Okta', 'Add user to group membership', 'Rate limit warning' — meant for a human scanning a log quickly. It's a convenience field, not a substitute for eventType in an actual detection rule, since displayMessage text can be shared across several distinct eventType values.\n\n" +
        "**okta.actor: who did this.** Every event names an actor — the identity (or system principal) that performed the action. For a sign-in, the actor is the person signing in. For an admin action, the actor is the admin who took it. actor.alternateId is typically the human-readable identifier (usually an email address), and actor.type distinguishes a real User from a SystemPrincipal (Okta's own infrastructure acting on its own, as seen in rate-limit events).\n\n" +
        "**okta.target: who or what it was done to.** Many events also carry one or more target entries — an array, because a single action can affect more than one object at once. A group-membership change names both the user being added (target.0) and the group they were added to (target.1). Reading actor and target together, and correctly telling them apart, is essential: in a group-membership event, the actor performed the change, and it is entirely possible (and highly significant when it happens) for the actor and the affected user in target.0 to be the exact same identity — someone adding themselves to a privileged group.\n\n" +
        "**Why the taxonomy matters more than any single event.** Because the same object.verb pattern applies everywhere, a detection built to watch for a category — every group.user_membership.* event, every policy.rule.* event — scales across the whole org without needing a separate rule per specific action. Learning the pattern, not memorising a fixed list of eventType strings, is what actually transfers to a real, unfamiliar Okta tenant.",
    },
    // ── Reading 3: outcome.result / outcome.reason / authenticationStep ──────
    {
      type: "reading" as const,
      id: "oktaf-r3",
      heading: "outcome.result and outcome.reason: How Far a Sign-In Actually Got",
      content:
        "The single richest pair of fields in any Okta sign-in event is okta.outcome.result and okta.outcome.reason, and reading them precisely is a core Okta-analyst skill this room is built around.\n\n" +
        "**outcome.result: the top-level verdict.** Common values include SUCCESS, FAILURE, ALLOW, DENY, SKIPPED, and CHALLENGE. On its own this answers only 'did this specific step succeed,' not why, and not how far the overall sign-in transaction actually progressed.\n\n" +
        "**outcome.reason: the specific cause.** This is where the real detail lives. INVALID_CREDENTIALS means the password itself was wrong — the transaction never got past the first stage. LOCKED_OUT means the account has exceeded its allowed failure count. MFA_REQUIRED is the one every analyst needs to internalise precisely: Okta only ever writes MFA_REQUIRED once the password stage has been satisfied and the policy is now demanding the second factor. USER_REJECTED_PUSH, on a related mfa event, means a push challenge was sent and the user explicitly declined it. Each of these describes a genuinely different situation, even though several of them can attach to the same broad outcome.result of FAILURE.\n\n" +
        "**The single field flip that matters most.** Picture a burst of sign-in failures against one account, all reason INVALID_CREDENTIALS, from the same address. If one later attempt in that same burst instead carries reason MFA_REQUIRED, something important changed: the password submitted on that attempt was correct. An analyst who only checks whether a session was ultimately created, and closes the ticket the moment they see no successful login, misses this entirely — the account's password is now known to whoever was making those attempts, even though they never got past the second factor.\n\n" +
        "**okta.authenticationContext.authenticationStep: the stage counter.** This numeric field corroborates the reason field directly: 0 means the transaction is still at the password (or equivalent primary factor) stage; 1 means it has moved on to a second factor. Seeing authenticationStep advance from 0 to 1 on an account that was previously failing at step 0 is independent, corroborating proof that the primary credential was just satisfied — exactly the same conclusion the reason field's flip to MFA_REQUIRED already pointed to, from a completely different field.\n\n" +
        "**Why this specific reading skill gets its own emphasis.** It is the most common real-world Okta-analyst mistake this room addresses: treating 'the attacker didn't get a session' and 'nothing happened here' as the same conclusion. They are not. A blocked sign-in can still mean a lost credential, and the only way to know is reading outcome.reason and authenticationStep together, not just outcome.result.",
      diagram:
        "flowchart LR\n" +
        "  A[Sign-in attempt] --> B{Password correct?}\n" +
        "  B -->|No| C[outcome.reason: INVALID_CREDENTIALS\\nauthenticationStep stays 0]\n" +
        "  B -->|Yes| D[outcome.reason: MFA_REQUIRED\\nauthenticationStep becomes 1]\n" +
        "  D --> E{Second factor satisfied?}\n" +
        "  E -->|No, e.g. USER_REJECTED_PUSH| F[Session NOT created\\nbut password is now known]\n" +
        "  E -->|Yes| G[Session created]\n",
      diagramCaption: "The reason field flip from INVALID_CREDENTIALS to MFA_REQUIRED is the tell that the password was correct",
      checkpoint: {
        question: "In a burst of failed Okta sign-ins against one account, the LAST attempt carries outcome.reason MFA_REQUIRED and authenticationContext.authenticationStep 1, where every earlier attempt showed INVALID_CREDENTIALS and step 0. What does that specific change mean?",
        options: [
          "The account was locked out, so Okta stopped checking the password at all",
          "The password submitted on that last attempt was correct -- MFA_REQUIRED is only ever written once the primary credential stage has been satisfied, and the step counter advancing to 1 confirms it independently",
          "It is simply Okta's alternate wording for the exact same rejected-password outcome",
          "A conditional-access policy change mid-burst started demanding MFA tenant-wide",
        ],
        answer: 1,
        explanation:
          "MFA_REQUIRED and a step advance to 1 both only ever occur after the password stage succeeds. Reading them together confirms, from two independent fields, that the correct password was used on that attempt -- a materially different fact than another rejected guess.",
      },
    },
    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q1",
      question:
        "A ticket describes an Okta account that received 80 sign-in failures overnight, all outcome.result FAILURE, and zero sessions were ever created. The analyst closes it as 'blocked, no impact.' Based on this room, what is wrong with that closure, if even one of those 80 events carried outcome.reason MFA_REQUIRED rather than INVALID_CREDENTIALS?",
      options: [
        "Nothing is wrong -- zero sessions created means zero impact by definition, regardless of any individual event's reason field",
        "It ignores that MFA_REQUIRED can only appear after the password stage succeeded -- meaning the account's real password is now known to whoever was making the attempts, even though no session was ever created",
        "The closure is correct, but only because Okta's own rate limiter would have already reset the password automatically",
        "MFA_REQUIRED in this context only ever indicates a benign, expected password-manager autofill retry, never a real credential exposure",
      ],
      answer: 1,
      explanation:
        "Reading 3 built the whole point of this room around exactly this failure mode: 'blocked' and 'no impact' are not the same fact. A single MFA_REQUIRED reason inside an otherwise-failing burst proves the password was correct at least once, which is a live credential-exposure finding regardless of whether a session was ever created. Okta's rate limiter (c) does not reset passwords, and nothing supports assuming benign autofill (d) without checking the source IP and user agent against the account's normal pattern.",
      xp: 25,
    },
    // ── Reading 4: securityContext ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r4",
      heading: "securityContext: Okta's View of the Network Behind an Attempt",
      content:
        "Every Okta sign-in event carries a securityContext object describing the network the request came from — and it's frequently the fastest way to separate an ordinary employee sign-in from an anomalous one, well before any password-correctness question comes into play.\n\n" +
        "**asNumber and asOrg.** These identify the Autonomous System (the network block, in internet-routing terms) the request's source IP belongs to, and the organisation that owns it. A residential or mobile-carrier ISP name is what an ordinary employee's home or office connection typically shows. A hosting-provider or datacenter ASN name — the kind of infrastructure a Virtual Private Server or bulletproof-hosting operation runs on — is not where employees normally sign in from, and its presence is one of the highest-signal, lowest-effort fields available in an Okta investigation. Real people do not work from datacenter address space; automated attack tooling frequently does.\n\n" +
        "**isp and domain.** These carry closely related information — the resolved internet service provider name and reverse-DNS domain for the source address — useful for confirming or refining what asOrg already suggests.\n\n" +
        "**isProxy.** A boolean flag indicating whether Okta's own network intelligence believes the request passed through a known proxy or anonymisation service. It's a useful corroborating signal, but a false value doesn't clear an attempt on its own — plenty of legitimate residential proxies and lesser-known VPN providers won't be flagged, and plenty of ordinary corporate egress setups can occasionally trip it.\n\n" +
        "**Reading securityContext alongside client.geographicalContext.** The two are related but distinct: geographicalContext is Okta's IP-based geolocation guess (country, city), while securityContext describes the network infrastructure itself. A sign-in from the right country but the wrong kind of network (a hosting ASN instead of a residential ISP, sitting in the same city an employee happens to live in) is still worth flagging — geography alone is a weak signal on its own, precisely because IP geolocation can be imprecise and VPN exit nodes can land anywhere.\n\n" +
        "**Why this matters even when a sign-in ultimately fails.** securityContext doesn't require a successful login to be useful. A burst of failures worth investigating at all should have its source infrastructure checked immediately — before spending time on the outcome.reason detail from the previous reading — because a hosting-ASN source on a failing burst already tells an analyst this almost certainly isn't the account's own user mistyping their password.",
    },
    // ── Reading 5: factor enrollment ─────────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r5",
      heading: "Factor Enrollment and Types: What Counts as a Second Factor in Okta",
      content:
        "Okta calls anything registered as a second authentication step a factor, and understanding the small set of factor types in play is necessary before an analyst can correctly read an mfa-related event.\n\n" +
        "**Factor enrollment.** Before a user can authenticate with a given factor, that factor has to be enrolled — registered to their account, usually during their first Okta setup or when an admin policy newly requires an additional factor. Okta's System Log tracks this lifecycle through its own event category (an AuthenticatorEnrollment target object appears on related events), and okta.target.0.displayName on an MFA event names the specific enrolled factor involved — for example, 'Okta Verify' — letting an analyst confirm exactly which factor a given challenge or response event refers to.\n\n" +
        "**The common factor types.** Okta Verify push is the most widely deployed: Okta's own mobile app receives a real-time approve/deny prompt tied to a specific sign-in attempt. Okta Verify can also generate a one-time passcode (OTP) the user types in manually, useful when push notifications aren't practical. WebAuthn/FIDO2 (physical security keys, or a platform authenticator like Touch ID) provides phishing-resistant authentication — meaningfully stronger than push, because it's cryptographically tied to the specific site being authenticated to and cannot be tricked into approving a login on a different, spoofed site. SMS and voice-call factors exist but are considered materially weaker, because a phone number can be hijacked (SIM-swapped) independently of anything the legitimate user does wrong.\n\n" +
        "**Why push factors specifically are a favourite attacker target.** A push notification demands only a single tap from the legitimate user to approve — no code to read or type, no cryptographic binding to the specific site requesting it. An attacker who already has a valid password can simply trigger repeated push challenges, hoping the user eventually approves one out of habit, annoyance, or genuine confusion about which login is legitimate. This pattern is significant enough that it has its own name and its own detection posture, covered in this platform's dedicated MFA fatigue content — this room's job is only to make sure the underlying Okta factor vocabulary (which factor, enrolled when, challenged how) is already familiar before that pattern is studied.\n\n" +
        "**Reading a full mfa-related event.** Put together, a single mfa_challenge or mfa_denied event names: which account (actor), which factor (target.0.displayName), what happened (outcome.result/reason), and from where the challenge was ultimately triggered (client.ipAddress on the challenge, which is the requester's address, not the device the factor notification itself was delivered to).",
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q2",
      question:
        "Why is a WebAuthn/FIDO2 security key considered meaningfully stronger against phishing than an Okta Verify push notification, even though both count as a second factor?",
      options: [
        "WebAuthn is cryptographically bound to the specific site being authenticated to, so it cannot be tricked into approving a login on a different, spoofed site -- a push notification only asks for a single tap with no such binding",
        "WebAuthn keys never expire, while push notifications expire after 30 seconds",
        "Push notifications are always sent over SMS, which is inherently insecure, while WebAuthn uses no network connection at all",
        "There is no real difference -- both provide identical protection against every kind of phishing attempt",
      ],
      answer: 0,
      explanation:
        "Reading 5 named this precisely: WebAuthn's cryptographic binding to the requesting site is what makes it phishing-resistant, whereas a push approval is just a tap with no such binding -- which is exactly why push-fatigue attacks work at all against push but not against WebAuthn. Expiry timing (b) is not the actual security distinction being tested, and push notifications are not SMS-based (c) -- Okta Verify push uses the app's own secure channel, not SMS.",
      xp: 25,
    },
    // ── Reading 6: Okta vs Entra contrast ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r6",
      heading: "Okta vs Entra ID: Where the Concepts Rhyme, and Where They Don't",
      content:
        "This reading exists specifically because this platform teaches Entra ID in depth, and an Entra-trained analyst's biggest real risk on their first Okta tenant is assuming more carries over than actually does.\n\n" +
        "**The activity log itself.** Entra ID splits activity across separate sign-in logs and audit logs. Okta writes essentially everything — sign-ins, admin actions, group and policy changes, system events — into one unified System Log, distinguished by eventType rather than by which log the event lives in. An Okta investigation typically means one log to search, not two to correlate.\n\n" +
        "**The verdict fields.** Entra's sign-in events centre on a numeric status/error code and a ConditionalAccessStatus field. Okta centres on the outcome.result / outcome.reason pair covered in Reading 3, plus the authenticationStep counter. Neither field set maps one-to-one onto the other; they encode overlapping information through structurally different mechanisms.\n\n" +
        "**The directory.** Entra ID is Microsoft's own directory service, natively integrated with Windows domain join, Group Policy heritage, and the wider Microsoft 365 ecosystem. Okta's Universal Directory is platform-agnostic by design — it can be the sole source of truth, or it can synchronise from an existing on-prem Active Directory, or from Google Workspace, or from an HR system, making Okta a common choice specifically for organisations that are not built primarily on a single vendor's stack.\n\n" +
        "**The policy layer.** Entra ID's Conditional Access is the policy engine deciding when to demand MFA, block risky sign-ins, or require a compliant device. Okta's rough equivalent is its own Sign-On Policies and Authentication Policies, expressed through Okta's own policy objects and evaluated by Okta's own rules engine — conceptually parallel, but a different rule syntax, a different admin console, and different log events (policy.rule.* in Okta's eventType taxonomy) recording changes to them.\n\n" +
        "**Risk detection.** Entra ID Premium layers Identity Protection on top of sign-in logs, scoring sign-in risk and user risk with Microsoft's own machine-learning signals. Okta has its own equivalent capability (ThreatInsight and Okta's own risk scoring in higher tiers), but the specific risk fields, scoring logic, and event names are Okta's own — not a reskinned copy of Microsoft's.\n\n" +
        "**The one habit this reading is trying to build.** Before running a single query against an unfamiliar tenant, check which IdP actually issues its logs. If it's Okta, expect okta.eventType and outcome.result/outcome.reason. If it's Entra ID, expect the sign-in/audit log split and ConditionalAccessStatus. Treating the two as interchangeable is the single most avoidable mistake this room can prevent.",
      checkpoint: {
        question: "An analyst who has only ever worked with Entra ID's sign-in logs is handed an Okta System Log export for the first time. What is the single most important adjustment per this reading?",
        options: [
          "None -- the two platforms use byte-for-byte identical field names, so existing Entra queries can be reused without modification",
          "Recognise this is one unified log distinguished by eventType (not separate sign-in/audit logs), and read verdicts through outcome.result/outcome.reason rather than Entra's status-code and ConditionalAccessStatus fields",
          "Assume Okta does not track admin or policy changes at all, since Entra keeps those in a separate audit log",
          "Convert every Okta timestamp to a Microsoft-specific format before any field can be read",
        ],
        answer: 1,
        explanation:
          "Reading 6 built the whole contrast around this: one unified System Log keyed by eventType, and a completely different verdict-field pair. Assuming field-for-field portability (a) is the exact mistake this room exists to prevent, and Okta absolutely does track admin/policy changes (c) -- just within the same unified log, not a separate one. Timestamp format (d) is not the substantive difference being taught here.",
      },
    },
    // ── Log Analysis 1: password accepted, escalating ────────────────────────
    {
      type: "log_analysis" as const,
      id: "oktaf-la1",
      heading: "One Field Changes, and the Story Changes With It",
      context:
        "GlobalLogis's SIEM raised a medium-priority correlation after a burst of failed sign-ins against n.abara@globallogis.com overnight. Most of the burst matched the pattern of an ordinary rejected-password attack. The event below is the last one recorded before the source address went quiet.",
      event: passwordAcceptedEvent,
      questions: [
        {
          question:
            "okta.outcome.reason on this event is MFA_REQUIRED, and okta.authenticationContext.authenticationStep is 1 -- both different from the INVALID_CREDENTIALS / step 0 pattern on the earlier failures in this same burst. What does that combination tell you?",
          options: [
            "The password submitted on this specific attempt was correct -- the transaction reached the second-factor stage, which only happens after the primary credential succeeds",
            "The account has been permanently locked, and no further sign-in attempts of any kind will be processed",
            "MFA_REQUIRED and INVALID_CREDENTIALS describe the exact same underlying rejection, just in different words",
            "Okta's rate limiter intervened and forced this specific attempt into a different validation path",
          ],
          answer: 0,
          explanation:
            "Reading 3 covered this exact pair of fields: MFA_REQUIRED only appears once the password stage has been satisfied, and the step counter advancing to 1 independently confirms it. This is a materially different, more serious fact than another rejected guess -- the account's real password is now known to whoever controls 185.220.101.44.",
          xp: 25,
        },
        {
          question:
            "okta.securityContext.asOrg on this event is 'Alexhost SRL', a hosting provider, and the client is Chrome on Windows 10 from Bucharest. Nkem Abara's own normal working pattern (not shown in this event) is a residential ISP from her home country. What does the asOrg value add to the investigation?",
          options: [
            "It independently corroborates that this sign-in did not originate from the account's legitimate owner, since ordinary employees do not authenticate from hosting-provider address space",
            "It proves conclusively that Chrome itself is a compromised or malicious browser build",
            "asOrg only describes billing information for Okta's own subscription and has no security relevance",
            "It confirms the sign-in is legitimate, since Bucharest is a real city with real residential users",
          ],
          answer: 0,
          explanation:
            "Reading 4 was explicit: a hosting-provider ASN like this is one of the highest-signal, lowest-effort fields in an Okta investigation, because real employees do not sign in from datacenter address space. It says nothing about the browser build itself (b) -- Chrome is simply the client software being used from that infrastructure. asOrg is a network-attribution field with direct security relevance, not billing metadata (c). And a real city name does not make the underlying network legitimate (d) -- the point is precisely that geography and network type are separate signals, and this one is a hosting ASN regardless of which city it resolves to.",
          xp: 25,
        },
        {
          question:
            "Given that the password is now confirmed correct and no session was created in this event, what is the correct immediate containment step?",
          options: [
            "Force a password reset for n.abara@globallogis.com and review whether any further activity followed from the same source before or after this event",
            "Take no action, since no session was ever created and therefore no actual access occurred",
            "Permanently deactivate the account, since a correct password guess proves the account is fully compromised",
            "Wait for Okta's own rate limiter to resolve the situation automatically",
          ],
          answer: 0,
          explanation:
            "The lost asset here is the password, so the fix is to invalidate it and check what else that source IP or account did around this window -- which is exactly what the next task in this room investigates. 'No session, no action' (b) repeats the precise mistake Question 1 in this room addressed. Deactivating the account outright (c) is disproportionate and punishes the legitimate user for a problem a reset solves. And a rate limiter defends Okta's infrastructure from request volume -- it does not reset a compromised password (d).",
          xp: 30,
        },
      ],
    },
    // ── Reading 7: rate limiting / system events ──────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r7",
      heading: "Rate Limiting and System Events: When Okta Defends Itself",
      content:
        "Not every event in the System Log describes a human or an application acting — some describe Okta's own infrastructure reacting to load or abuse, and reading these correctly means not mistaking self-defence for resolution.\n\n" +
        "**system.org.rate_limit.warning.** When a specific API endpoint (commonly /api/v1/authn, the authentication endpoint itself) receives requests faster than Okta's configured threshold allows, Okta logs a rate-limit warning and begins throttling further requests from that source. Its actor.type is SystemPrincipal — Okta's own infrastructure, not a human or an application account — and its outcome.result is typically SUCCESS, because from Okta's perspective the rate limiter itself worked exactly as designed.\n\n" +
        "**Why a rate-limit event is not, by itself, an incident's resolution.** A rate limiter's entire job is to slow down a high-volume source; it does not evaluate whether any individual request inside that volume already succeeded before the throttle kicked in. A burst that trips the rate limiter at request 61 may already have produced a correct-password result at request 40 — the limiter engaging afterward changes nothing about what already happened. Treating 'Okta throttled it' as equivalent to 'Okta stopped it' is a subtle but real analyst mistake.\n\n" +
        "**Other system.* events worth recognising.** system.api_token.create and related events track the creation of API tokens — powerful, often long-lived credentials that don't go through interactive MFA at all once issued, making unexpected token creation a meaningful persistence signal in its own right. Most other system.* events describe Okta's own housekeeping (org-level configuration, integration health) and are lower priority for security review, but the pattern-recognition skill is the same: the leading system. segment signals 'Okta's own infrastructure did this,' which is a fundamentally different actor category from a user or an admin.",
    },
    // ── Reading 8: admin / group / policy events ──────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r8",
      heading: "Admin Actions in the System Log: Users, Groups, and Policy Changes",
      content:
        "The events that most directly matter for detecting persistence or privilege abuse in an Okta org are rarely the sign-in events themselves — they're the administrative changes that follow a successful compromise.\n\n" +
        "**user.lifecycle and user.account events.** Actions like deactivating, reactivating, or unsuspending a user account, or resetting its password/factors, are tracked individually with their own eventType values. An attacker who has compromised one account sometimes uses it to reset another user's factors (clearing their enrolled MFA so a new, attacker-controlled factor can be enrolled instead) — a pattern only visible by reading the target of the event carefully, since the actor and the affected account are different identities in that case.\n\n" +
        "**group.user_membership.add and .remove.** Group membership changes are one of the highest-value events to monitor, because Okta group membership frequently controls real, consequential access — which applications a user can single-sign-on into, and in many orgs, administrative rights over Okta itself. An account added to an administrative group is an account whose privilege just changed, full stop, regardless of anything else in its recent history.\n\n" +
        "**policy.rule.create / policy.rule.update.** Changes to sign-on or authentication policy rules are exactly the kind of action a sophisticated actor makes to weaken defences quietly rather than trigger a loud, obvious alert — for example, narrowing an MFA requirement, or adding a new network zone exception. These events are comparatively rare in a healthy org, which makes an unexpected one — especially one actioned outside change-management hours — a high-priority review item on its own.\n\n" +
        "**Why actor and target both matter here, precisely.** For every one of these event types, the question 'who did this' (actor) and 'who or what was affected' (target) can be the same identity or different identities, and the distinction changes the finding completely. An account adding a completely different, previously low-privilege service account into an admin group is a different — and often more concerning — finding than an admin adding a new hire to a standard group, even though both are the exact same eventType. Reading the full event, not just recognising its type, is what separates routine administration from an attacker consolidating access.",
      checkpoint: {
        question: "A group.user_membership.add event shows actor.alternateId and target.0.alternateId as the SAME account, and target.1.displayName names a high-privilege administrative group. Why does that specific combination deserve particular scrutiny?",
        options: [
          "It doesn't -- group additions are routine administration regardless of who the actor and target are",
          "The account effectively added itself to an administrative group -- a materially different, higher-risk pattern than an admin granting access to a different, separate user",
          "It proves the event is a logging error, since an account cannot act on its own membership",
          "It means the event must have originated from Okta's own SystemPrincipal rather than a real user",
        ],
        answer: 1,
        explanation:
          "Reading 8 named this specific pattern directly: actor and target being the same identity in a privilege-granting event is a self-escalation shape, and it deserves more scrutiny than an admin granting access to someone else. It is a real, loggable action Okta permits (c is wrong), and the actor field here is a User type, not a SystemPrincipal (d is wrong).",
      },
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q3",
      question:
        "At 03:19, five minutes after n.abara@globallogis.com's password was confirmed correct in the earlier finding, a system.org.rate_limit.warning event appears for the same source IP. A junior analyst reasons that this rate-limit event means the incident is now resolved. What is the correct assessment?",
      options: [
        "Correct -- once Okta's rate limiter engages, no further risk exists from that source",
        "Incorrect -- a rate limiter only slows down further requests from that source; it does not undo or evaluate anything that already succeeded before it engaged, such as the confirmed-correct password",
        "Correct, but only because rate-limit events always follow, and therefore cause, an automatic password reset",
        "Incorrect, but only because rate-limit warnings are exclusively cosmetic and never actually throttle any traffic",
      ],
      answer: 1,
      explanation:
        "Reading 7 covered this precisely: a rate limiter's job is to slow down volume going forward -- it has no bearing on whether something inside that volume, like a correct password guess, already happened. Treating throttling as resolution is the exact mistake to avoid. Rate-limit events do not trigger password resets on their own (c), and they do genuinely throttle traffic, not merely log it cosmetically (d).",
      xp: 25,
    },
    // ── Log Analysis 2: group membership self-add ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "oktaf-la2",
      heading: "Seven Minutes Later, a Group Changes",
      context:
        "Following on from the earlier finding, the analyst pulls the System Log for the seven minutes after n.abara@globallogis.com's password was confirmed correct. The event below appears in that window.",
      event: groupMembershipEvent,
      questions: [
        {
          question:
            "Compare okta.actor.alternateId and okta.target.0.alternateId on this event. What do you find, and why does it matter?",
          options: [
            "They are the same account, n.abara@globallogis.com -- meaning this account added ITSELF to the Okta-Admins group, a self-escalation pattern rather than routine administration by someone else",
            "They are different accounts, showing a legitimate admin granted access to a new team member",
            "actor and target can never be the same identity in a group-membership event, so this must be a logging artefact",
            "The comparison is not meaningful, since target only ever names the group, never the user",
          ],
          answer: 0,
          explanation:
            "Reading 8 named this exact pattern: actor and target.0 being the same identity in a privilege-granting event is a self-escalation shape. Here it is n.abara@globallogis.com both performing the change and being the user added -- to Okta-Admins, named in target.1 -- which is a materially more serious finding than a separate admin actioning it.",
          xp: 25,
        },
        {
          question:
            "The source IP on this group-membership change is the same 185.220.101.44 seen in the earlier password-confirmation event. What does that shared value let you conclude?",
          options: [
            "It ties the privilege-escalation step directly to the same actor who had just obtained the correct password minutes earlier, extending the same incident rather than treating this as a separate, unrelated event",
            "It proves nothing at all, since IP addresses are reused constantly by unrelated parties and carry no evidentiary value",
            "It confirms the IP address itself must belong to GlobalLogis's own corporate network",
            "It means the group-membership change was performed by Okta's own SystemPrincipal, not by the account holder",
          ],
          answer: 0,
          explanation:
            "A shared source IP across two events involving the same account, minutes apart, is exactly the kind of pivot that links separate log lines into one coherent incident timeline -- the same actor who obtained the password used it, from the same infrastructure, to grant itself administrative access. IP addresses do carry real evidentiary weight when correlated this tightly (b is wrong), nothing here suggests this is GlobalLogis's own network -- 185.220.101.44 was already established as a hosting-provider address in the earlier finding (c is wrong), and the actor field names a real User, not a SystemPrincipal (d is wrong).",
          xp: 25,
        },
        {
          question:
            "What is the correct combined containment scope now that both events are read together?",
          options: [
            "Reset the account's password AND remove it from Okta-Admins immediately, then audit everything that account did while it held that elevated group membership",
            "Only reset the password -- removing the account from Okta-Admins can wait until the next scheduled access review",
            "Only remove the group membership -- the password itself is not actually a concern once the group change is reverted",
            "No additional action beyond what was already decided for the password-confirmation event alone",
          ],
          answer: 0,
          explanation:
            "Both findings compound: the password is known to an outside party, AND that party used it to grant itself administrative group membership. Fixing only one half leaves the other live -- resetting the password alone leaves a live admin-group membership in place, and removing the group membership alone leaves the password still compromised for future use. Both must be addressed together, plus a review of what the elevated access was actually used for in the interim.",
          xp: 30,
        },
      ],
    },
    // ── Matching: eventType prefix to category ────────────────────────────────
    {
      type: "matching" as const,
      id: "oktaf-m1",
      heading: "Match the eventType Prefix to Its Category",
      instructions: "Match each Okta System Log eventType prefix to the category of activity it represents.",
      pairs: [
        { id: "usersession", left: "user.session.*", right: "Sign-in and session activity for a specific user, such as user.session.start" },
        { id: "usermfa", left: "user.mfa.*", right: "Multi-factor challenge and response events, such as a push notification being approved or denied" },
        { id: "groupmembership", left: "group.user_membership.*", right: "A user being added to or removed from a group -- frequently the access-control event that matters most" },
        { id: "policyrule", left: "policy.rule.*", right: "A change to a sign-on or authentication policy rule, such as narrowing or loosening an MFA requirement" },
        { id: "systemorg", left: "system.org.*", right: "Okta's own infrastructure acting on itself, such as a rate-limit warning -- actor.type is SystemPrincipal, not a real user" },
      ],
      explanation:
        "The dot-notation pattern is the whole point: once you recognise object.verb, an eventType value you've never seen before is still readable at a glance from its leading segment alone.",
      xp: 35,
    },
    // ── Ordering: triage sequence ──────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "oktaf-o1",
      heading: "Order the Triage of an Okta Sign-In Anomaly",
      instructions: "Arrange these steps in the order an analyst should actually work them when a burst of Okta sign-in activity is flagged.",
      items: [
        { id: "securitycontext", text: "Check securityContext (asOrg, asNumber, isProxy) on the source of the activity -- is this infrastructure an ordinary employee would plausibly use" },
        { id: "outcome", text: "Read outcome.result AND outcome.reason together across the whole burst, watching specifically for any reason value that differs from the rest" },
        { id: "step", text: "Cross-check authenticationContext.authenticationStep against the reason field to confirm how far the transaction actually progressed" },
        { id: "pivot", text: "Pivot on the account and the source IP to find any other System Log events in the surrounding window -- group, policy, or admin changes" },
        { id: "scope", text: "Scope the full impact: was a password confirmed correct, was any privilege or group membership changed, was a session ever created" },
        { id: "contain", text: "Contain based on everything actually found -- reset credentials, revert privilege changes, document the full chain" },
      ],
      correct_order: ["securitycontext", "outcome", "step", "pivot", "scope", "contain"],
      explanation:
        "Start with the network context, since a hosting-ASN source is a fast, high-signal reason to keep investigating at all. From there, read the outcome fields across the whole burst rather than just the final event, since the single most important fact -- a password confirmed correct -- can sit anywhere inside a long run of ordinary-looking failures. Cross-checking the step counter corroborates that reading independently. Only once the sign-in picture is clear does it make sense to pivot on the account and source IP for follow-on activity, exactly the way the group-membership finding in this room extended the password finding into a larger incident. Scoping and containment come last, once the full chain -- not just the first event -- is actually known.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "oktaf-f1",
      prompt:
        "Look at the group-membership finding for n.abara@globallogis.com. What is the exact value of the okta.target.1.displayName field in the raw log?",
      answer: "Okta-Admins",
      hint: "Look inside the raw block of the log analysis event for the field named okta.target.1.displayName.",
      xp: 20,
    },
    // ── Question 4: Okta vs Entra applied ─────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q4",
      question:
        "An analyst is handed two tickets on the same morning: one from a company running Entra ID, one from a company running Okta. Both describe a suspicious sign-in. Which statement correctly reflects how the analyst should approach the two investigations?",
      options: [
        "Treat both identically, since Entra ID and Okta share the exact same log schema and field names",
        "Recognise the underlying identity concepts (authentication stages, MFA, risk signals) transfer between the two, but read each tenant's own native fields -- Entra's status codes and ConditionalAccessStatus versus Okta's outcome.result/outcome.reason and eventType taxonomy -- rather than assuming one platform's field names apply to the other",
        "Refuse to investigate the Okta ticket at all, since this platform primarily teaches Entra ID",
        "Assume Okta cannot produce any admin-level or policy-change logs, since Entra keeps those in a separate audit log and Okta must therefore lack an equivalent",
      ],
      answer: 1,
      explanation:
        "This is the exact synthesis Reading 6 built toward: the concepts rhyme (both are identity providers doing the same underlying job), but the schemas do not, and treating them as interchangeable is the mistake this room is designed to prevent. Refusing to investigate (c) isn't a real option a working analyst has, and Okta absolutely tracks admin and policy changes, just within its own unified System Log rather than a separate audit log (d).",
      xp: 25,
    },
    // ── Question 5: synthesis ──────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q5",
      question:
        "Summarising this room's central lesson: an Okta account shows a run of INVALID_CREDENTIALS failures from a hosting-provider ASN, then one MFA_REQUIRED event from the same source, then a rate-limit warning, and no session is ever created. What is the single most accurate way to classify this incident?",
      options: [
        "A blocked credential-stuffing attempt with a confirmed password exposure -- the account's password is now known to an outside party even though the attacker never obtained a session, so credential reset and further pivoting are still required",
        "A fully resolved, no-impact event, since Okta's own defences (MFA and the rate limiter) prevented any session from being created",
        "A false positive, since INVALID_CREDENTIALS is the dominant reason across the burst and should be treated as the only meaningful signal",
        "An unrelated pair of coincidental system events with no connection to each other",
      ],
      answer: 0,
      explanation:
        "This draws together the room's core threads: the reason-field flip (Reading 3) proves password exposure even without a session; the securityContext ASN (Reading 4) corroborates that this wasn't the legitimate user; and the rate-limit event (Reading 7) reflects Okta defending itself, not resolving the underlying exposure. Calling this 'no impact' (b) or dismissing the one differing reason value as noise (c) both repeat mistakes this room specifically addressed. And nothing here is coincidental (d) -- the events form one coherent, ordered chain.",
      xp: 30,
    },
  ],
};

export const roomsBatch37 = [oktaIdentityFundamentalsRoom];
