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
    "okta.authenticationContext.authenticationStep": "0",
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
    "The Okta counterpart to Entra ID: how to read the Okta System Log on its own terms, the okta.eventType taxonomy, outcome.result and outcome.reason (including the single field flip that separates a rejected password from an accepted one), securityContext network signals, factor enrollment and MFA types, and the admin/group events attackers target for persistence. Includes a direct, explicit contrast against Entra ID so a student who only knows Microsoft's identity platform doesn't misread an Okta tenant.",
  difficulty: "intermediate" as const,
  category: "Identity",
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
        "Every organisation needs one authoritative place that answers the question 'is this really the person they claim to be, and what are they allowed to do': an identity provider (IdP). This platform teaches Microsoft's answer, Entra ID, in depth elsewhere. Okta is a separate, independent company's answer to the exact same problem, used heavily by organisations that are not built primarily on Microsoft's stack, or that want a single-sign-on layer sitting in front of a mix of Microsoft, Google, and dozens of other cloud applications at once.\n\n" +
        "**The mental model.** Okta is a cloud-hosted identity platform providing three things together: a directory of users and groups (Okta calls this the Universal Directory, and it can hold its own accounts or synchronise from an existing on-prem Active Directory or another HR system), a single sign-on layer letting one Okta login carry a user into dozens of connected applications without re-authenticating to each one, and a policy engine deciding when a sign-in needs a second factor, what device posture is required, and from where access is allowed at all. None of that is conceptually new to a student who has learned Entra ID: the shapes rhyme closely. What differs, and what this room exists to teach, is the vocabulary, the log schema, and a handful of behavioural specifics that do not carry over.\n\n" +
        "**Why an analyst cannot skip this room even after learning Entra.** The single most common real mistake a Windows/Entra-trained analyst makes on their first Okta investigation is assuming a field name from one platform exists on the other. Entra's sign-in logs use fields like ResultType and ConditionalAccessStatus; Okta's System Log uses an entirely different structure built around outcome.result, outcome.reason, and a dot-notation eventType taxonomy. Querying an Okta System Log for an Entra field name returns nothing, not an error, just silence, which is exactly the kind of silent gap that lets a real incident slip past an analyst who assumes their old queries still work.\n\n" +
        "**What Okta calls itself, structurally.** An Okta customer's whole tenant is called an org (sometimes 'org' also refers to sub-organisational structures for larger customers running multiple orgs, but for a typical single-tenant customer, one org is the whole company's Okta presence). Every event this room covers is written to that org's System Log, viewable in the Okta Admin Console or exported to a SIEM, and it is the single authoritative activity record for that org. Comparable in role, though not in schema, to Entra's sign-in and audit logs combined into one feed.\n\n" +
        "**What this room does and does not cover.** This room is entirely about reading Okta's own telemetry correctly. It does not re-teach identity fundamentals already covered elsewhere (authentication vs authorization, what MFA actually is, session tokens). Those concepts transfer directly from Entra ID and Identity Basics. What's new here is Okta's specific vocabulary for expressing them, and the small number of places where Okta's actual behaviour, not just its naming, genuinely differs from what an Entra-trained analyst would expect.",
      checkpoint: {
        question: "An Entra-trained analyst runs a saved hunt that filters on ResultType and ConditionalAccessStatus against the Okta System Log data in the SIEM. It returns zero rows, with no error. What is the most likely explanation?",
        options: [
          "Okta's log has no such fields, so the filter matched nothing -- not that nothing happened",
          "No sign-in failures happened in that window, so the empty result is genuinely reassuring",
          "Okta exports to the SIEM in a daily batch, so today's events have simply not arrived yet",
          "The fields exist in Okta but in lowercase, so the query just needs a change of case",
        ],
        answer: 0,
        explanation:
          "Okta's System Log is built around outcome.result/outcome.reason and a dot-notation eventType, so Entra field names simply do not exist there; a filter on them silently matches nothing instead of failing. 'Nothing happened' is exactly the false comfort this causes -- an empty result from a query on non-existent fields says nothing about activity. 'A daily batch delay' is speculation with no evidence -- and even once the data arrived, a filter on fields that do not exist would still match nothing. 'Same fields in lowercase' assumes the schemas match; they differ in structure, not just spelling.",
      },
    },
    // ── Reading 2: System Log / eventType ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r2",
      heading: "The Okta System Log: One Event Type Taxonomy to Learn",
      content:
        "Every action inside an Okta org (a sign-in, a failed password, an admin granting a role, a factor being enrolled) is written as one event in the System Log, and almost every one of those events is identified by a single field: okta.eventType.\n\n" +
        "**The dot-notation pattern.** Okta's eventType values follow a consistent object.verb (or object.subobject.verb) structure. user.session.start covers a sign-in attempt. user.mfa.okta_verify.push_response covers a specific factor's response to a challenge. group.user_membership.add covers a group-membership change. system.org.rate_limit.warning covers Okta's own infrastructure defending itself. Once an analyst recognises the pattern, an unfamiliar eventType value is still readable at a glance: the leading segment names the broad category (user, group, policy, system, application), and the trailing segment names the specific action.\n\n" +
        "**okta.displayMessage: the human-readable companion.** Alongside the machine-readable eventType, every event carries a plain-English displayMessage ('User login to Okta', 'Add user to group membership', 'Rate limit warning') meant for a human scanning a log quickly. It's a convenience field, not a substitute for eventType in an actual detection rule, since displayMessage text can be shared across several distinct eventType values.\n\n" +
        "**okta.actor: who did this.** Every event names an actor, the identity (or system principal) that performed the action. For a sign-in, the actor is the person signing in. For an admin action, the actor is the admin who took it. actor.alternateId is typically the human-readable identifier (usually an email address), and actor.type distinguishes a real User from a SystemPrincipal (Okta's own infrastructure acting on its own, as seen in rate-limit events).\n\n" +
        "**okta.target: who or what it was done to.** Many events also carry one or more target entries, an array, because a single action can affect more than one object at once. A group-membership change names both the user being added (target.0) and the group they were added to (target.1). Reading actor and target together, and correctly telling them apart, is essential: in a group-membership event, the actor performed the change, and it is entirely possible (and highly significant when it happens) for the actor and the affected user in target.0 to be the exact same identity. Someone adding themselves to a privileged group.\n\n" +
        "**Why the taxonomy matters more than any single event.** Because the same object.verb pattern applies everywhere, a detection built to watch for a category. Every group.user_membership.* event, every policy.rule.* event. Scales across the whole org without needing a separate rule per specific action. Learning the pattern, not memorising a fixed list of eventType strings, is what actually transfers to a real, unfamiliar Okta tenant.",
    },
    // ── Reading 3: outcome.result / outcome.reason / follow-on MFA events ────
    {
      type: "reading" as const,
      id: "oktaf-r3",
      heading: "outcome.result and outcome.reason: How Far a Sign-In Actually Got",
      content:
        "The single richest pair of fields in any Okta sign-in event is okta.outcome.result and okta.outcome.reason, and reading them precisely is a core Okta-analyst skill this room is built around.\n\n" +
        "**outcome.result: the top-level verdict.** Common values include SUCCESS, FAILURE, ALLOW, DENY, SKIPPED, and CHALLENGE. On its own this answers only 'did this specific step succeed,' not why, and not how far the overall sign-in transaction actually progressed.\n\n" +
        "**outcome.reason: the specific cause.** This is where the real detail lives. INVALID_CREDENTIALS means the password itself was wrong: the transaction never got past the first stage. LOCKED_OUT means the account has exceeded its allowed failure count. MFA_REQUIRED is the one every analyst needs to internalise precisely: Okta only ever writes MFA_REQUIRED once the password stage has been satisfied and the policy is now demanding the second factor. USER_REJECTED_PUSH, on a related mfa event, means a push challenge was sent and the user explicitly declined it. Each of these describes a genuinely different situation, even though several of them can attach to the same broad outcome.result of FAILURE.\n\n" +
        "**The single field flip that matters most.** Picture a burst of sign-in failures against one account, all reason INVALID_CREDENTIALS, from the same address. If one later attempt in that same burst instead carries reason MFA_REQUIRED, something important changed: the password submitted on that attempt was correct. An analyst who only checks whether a session was ultimately created, and closes the ticket the moment they see no successful login, misses this entirely: the account's password is now known to whoever was making those attempts, even though they never got past the second factor.\n\n" +
        "**Corroborating it: the follow-on MFA events, not authenticationStep.** A field that looks like it should help. Okta.authenticationContext.authenticationStep, does not: Okta's own API reference documents it as 'the zero-based step number in the authentication pipeline. Currently unused and always set to 0.' It reads 0 on every event, so it cannot show how far a transaction got. The real corroboration is what Okta logs next for the same account and transaction (same externalSessionId / transaction.id): an MFA challenge being sent (for example a system.push.send_factor_verify_push event for an Okta Verify push), then either a denial (such as user.mfa.okta_verify.deny_push) or a successful second-factor event (user.authentication.auth_via_mfa) followed by a user.session.start with outcome SUCCESS. A push being sent to the user at all independently proves the password stage was passed.\n\n" +
        "**Why this specific reading skill gets its own emphasis.** It is the most common real-world Okta-analyst mistake this room addresses: treating 'the attacker didn't get a session' and 'nothing happened here' as the same conclusion. They are not. A blocked sign-in can still mean a lost credential, and the only way to know is reading outcome.reason together with the MFA events that follow it, not just outcome.result.",
      diagram:
        "flowchart LR\n" +
        "  A[Sign-in attempt] --> B{Password correct?}\n" +
        "  B -->|No| C[outcome.reason: INVALID_CREDENTIALS\\nno MFA challenge follows]\n" +
        "  B -->|Yes| D[outcome.reason: MFA_REQUIRED\\nan MFA challenge is sent next]\n" +
        "  D --> E{Second factor satisfied?}\n" +
        "  E -->|No, e.g. USER_REJECTED_PUSH| F[Session NOT created\\nbut password is now known]\n" +
        "  E -->|Yes| G[Session created]\n",
      diagramCaption: "The reason field flip from INVALID_CREDENTIALS to MFA_REQUIRED is the tell that the password was correct",
      checkpoint: {
        question: "In a burst of failed Okta sign-ins against one account, one attempt shows outcome.reason MFA_REQUIRED. Which follow-on evidence independently confirms that the password stage really was passed on that attempt?",
        options: [
          "authenticationStep reading 1 instead of 0 on the next event for that account",
          "An Okta Verify push sent to the user for the same transaction seconds later",
          "A system.org.rate_limit.warning for the same source IP a minute later",
          "Another user.session.start FAILURE right after it, with INVALID_CREDENTIALS",
        ],
        answer: 1,
        explanation:
          "Okta only sends a second-factor challenge once the password has been accepted, so a push sent for the same account and transaction is separate proof that the password stage was passed. authenticationStep cannot help: Okta documents it as unused and always 0, so it never moves to 1. A rate-limit warning reflects request volume from the source, not whether any password was right. A later INVALID_CREDENTIALS failure only shows a different attempt used a wrong password; it says nothing about the earlier one.",
      },
    },
    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q1",
      question:
        "A ticket describes an Okta account that received 80 sign-in failures overnight, all outcome.result FAILURE, and zero sessions were ever created. The analyst closes it as 'blocked, no impact.' Based on this room, what is wrong with that closure, if even one of those 80 events carried outcome.reason MFA_REQUIRED rather than INVALID_CREDENTIALS?",
      options: [
        "Nothing is wrong -- MFA_REQUIRED means the MFA stage blocked the attempt, so no password exposure occurred and zero sessions confirms the account was never actually reached",
        "It ignores that MFA_REQUIRED appears only after the password stage succeeded, so whoever made the attempts now knows the real password even though no session was created",
        "The closure needs revising only to flag a policy gap -- MFA_REQUIRED means the account has no enrolled factor, so the finding is an enrollment problem rather than credential exposure",
        "The closure holds, since MFA_REQUIRED in a failing burst most often reflects a legitimate user's autofill retrying a stale credential, with no external party involved",
      ],
      answer: 1,
      explanation:
        "Reading 3 built the whole point of this room around exactly this failure mode: 'blocked' and 'no impact' are not the same fact. A single MFA_REQUIRED reason inside an otherwise-failing burst proves the password was correct at least once, which is a live credential-exposure finding regardless of whether a session was ever created. The MFA stage only runs after primary authentication passed, so it does not mean the password stayed secret. MFA_REQUIRED is a challenge issued after a correct password, not an enrollment-gap signal. And nothing supports assuming benign autofill without checking the source IP and user agent against the account's normal pattern.",
      xp: 25,
    },
    // ── Reading 4: securityContext ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r4",
      heading: "securityContext: Okta's View of the Network Behind an Attempt",
      content:
        "Every Okta sign-in event carries a securityContext object describing the network the request came from, and it's frequently the fastest way to separate an ordinary employee sign-in from an anomalous one, well before any password-correctness question comes into play.\n\n" +
        "**asNumber and asOrg.** These identify the Autonomous System (the network block, in internet-routing terms) the request's source IP belongs to, and the organisation that owns it. A residential or mobile-carrier ISP name is what an ordinary employee's home or office connection typically shows. A hosting-provider or datacenter ASN name: the kind of infrastructure a Virtual Private Server or bulletproof-hosting operation runs on. Is not where employees normally sign in from, and its presence is one of the highest-signal, lowest-effort fields available in an Okta investigation. Real people do not work from datacenter address space; automated attack tooling frequently does.\n\n" +
        "**isp and domain.** These carry closely related information (the resolved internet service provider name and reverse-DNS domain for the source address) useful for confirming or refining what asOrg already suggests.\n\n" +
        "**isProxy.** A boolean flag indicating whether Okta's own network intelligence believes the request passed through a known proxy or anonymisation service. It's a useful corroborating signal, but a false value doesn't clear an attempt on its own. Plenty of legitimate residential proxies and lesser-known VPN providers won't be flagged, and plenty of ordinary corporate egress setups can occasionally trip it.\n\n" +
        "**Reading securityContext alongside client.geographicalContext.** The two are related but distinct: geographicalContext is Okta's IP-based geolocation guess (country, city), while securityContext describes the network infrastructure itself. A sign-in from the right country but the wrong kind of network (a hosting ASN instead of a residential ISP, sitting in the same city an employee happens to live in) is still worth flagging. Geography alone is a weak signal on its own, precisely because IP geolocation can be imprecise and VPN exit nodes can land anywhere.\n\n" +
        "**Why this matters even when a sign-in ultimately fails.** securityContext doesn't require a successful login to be useful. A burst of failures worth investigating at all should have its source infrastructure checked immediately. Before spending time on the outcome.reason detail from the previous reading, because a hosting-ASN source on a failing burst already tells an analyst this almost certainly isn't the account's own user mistyping their password.",
    },
    // ── Reading 5: factor enrollment ─────────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r5",
      heading: "Factor Enrollment and Types: What Counts as a Second Factor in Okta",
      content:
        "Okta calls anything registered as a second authentication step a factor, and understanding the small set of factor types in play is necessary before an analyst can correctly read an mfa-related event.\n\n" +
        "**Factor enrollment.** Before a user can authenticate with a given factor, that factor has to be enrolled. Registered to their account, usually during their first Okta setup or when an admin policy newly requires an additional factor. Okta's System Log tracks this lifecycle through its own event category (an AuthenticatorEnrollment target object appears on related events), and okta.target.0.displayName on an MFA event names the specific enrolled factor involved (for example, 'Okta Verify') letting an analyst confirm exactly which factor a given challenge or response event refers to.\n\n" +
        "**The common factor types.** Okta Verify push is the most widely deployed: Okta's own mobile app receives a real-time approve/deny prompt tied to a specific sign-in attempt. Okta Verify can also generate a one-time passcode (OTP) the user types in manually, useful when push notifications aren't practical. WebAuthn/FIDO2 (physical security keys, or a platform authenticator like Touch ID) provides phishing-resistant authentication. Meaningfully stronger than push, because it's cryptographically tied to the specific site being authenticated to and cannot be tricked into approving a login on a different, spoofed site. SMS and voice-call factors exist but are considered materially weaker, because a phone number can be hijacked (SIM-swapped) independently of anything the legitimate user does wrong.\n\n" +
        "**Why push factors specifically are a favourite attacker target.** A push notification demands only a single tap from the legitimate user to approve: no code to read or type, no cryptographic binding to the specific site requesting it. An attacker who already has a valid password can simply trigger repeated push challenges, hoping the user eventually approves one out of habit, annoyance, or genuine confusion about which login is legitimate. This pattern is significant enough that it has its own name and its own detection posture, covered in this platform's dedicated MFA fatigue content. This room's job is only to make sure the underlying Okta factor vocabulary (which factor, enrolled when, challenged how) is already familiar before that pattern is studied.\n\n" +
        "**Reading a full mfa-related event.** Put together, a single mfa_challenge or mfa_denied event names: which account (actor), which factor (target.0.displayName), what happened (outcome.result/reason), and from where the challenge was ultimately triggered (client.ipAddress on the challenge, which is the requester's address, not the device the factor notification itself was delivered to).",
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q2",
      question:
        "Why is a WebAuthn/FIDO2 security key considered meaningfully stronger against phishing than an Okta Verify push notification, even though both count as a second factor?",
      options: [
        "WebAuthn is cryptographically bound to the specific site being authenticated to, so it cannot approve a login on a spoofed site -- a push only asks for a single tap with no such binding",
        "WebAuthn responses have a much shorter validity window than a push approval, so a phished credential expires before an attacker can relay it to the real site",
        "Push approvals are delivered through the carrier network and are exposed to SIM swapping, while a WebAuthn key exchanges nothing over any network path that could be intercepted",
        "WebAuthn keeps the user's password inside a hardware secure element, so a phishing page has no password to collect, whereas a push still requires typing one",
      ],
      answer: 0,
      explanation:
        "Reading 5 named this precisely: WebAuthn's cryptographic binding to the requesting site is what makes it phishing-resistant, whereas a push approval is just a tap with no such binding -- which is exactly why push-fatigue attacks work at all against push but not against WebAuthn. Validity-window timing is not the actual security distinction, and push notifications are not carrier-delivered or SIM-swappable -- Okta Verify push uses the app's own secure channel, not SMS. WebAuthn also does not store or replace the password; it is a second factor tied to the site's origin.",
      xp: 25,
    },
    // ── Reading 6: Okta vs Entra contrast ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r6",
      heading: "Okta vs Entra ID: Where the Concepts Rhyme, and Where They Don't",
      content:
        "This reading exists specifically because this platform teaches Entra ID in depth, and an Entra-trained analyst's biggest real risk on their first Okta tenant is assuming more carries over than actually does.\n\n" +
        "**The activity log itself.** Entra ID splits activity across separate sign-in logs and audit logs. Okta writes essentially everything (sign-ins, admin actions, group and policy changes, system events) into one unified System Log, distinguished by eventType rather than by which log the event lives in. An Okta investigation typically means one log to search, not two to correlate.\n\n" +
        "**The verdict fields.** Entra's sign-in events centre on a numeric status/error code and a ConditionalAccessStatus field. Okta centres on the outcome.result / outcome.reason pair covered in Reading 3, read alongside the MFA events that follow it. Neither field set maps one-to-one onto the other; they encode overlapping information through structurally different mechanisms.\n\n" +
        "**The directory.** Entra ID is Microsoft's own directory service, natively integrated with Windows domain join, Group Policy heritage, and the wider Microsoft 365 ecosystem. Okta's Universal Directory is platform-agnostic by design. It can be the sole source of truth, or it can synchronise from an existing on-prem Active Directory, or from Google Workspace, or from an HR system, making Okta a common choice specifically for organisations that are not built primarily on a single vendor's stack.\n\n" +
        "**The policy layer.** Entra ID's Conditional Access is the policy engine deciding when to demand MFA, block risky sign-ins, or require a compliant device. Okta's rough equivalent is its own Sign-On Policies and Authentication Policies, expressed through Okta's own policy objects and evaluated by Okta's own rules engine. Conceptually parallel, but a different rule syntax, a different admin console, and different log events (policy.rule.* in Okta's eventType taxonomy) recording changes to them.\n\n" +
        "**Risk detection.** Entra ID Premium layers Identity Protection on top of sign-in logs, scoring sign-in risk and user risk with Microsoft's own machine-learning signals. Okta has its own equivalent capability (ThreatInsight and Okta's own risk scoring in higher tiers), but the specific risk fields, scoring logic, and event names are Okta's own, not a reskinned copy of Microsoft's.\n\n" +
        "**The one habit this reading is trying to build.** Before running a single query against an unfamiliar tenant, check which IdP actually issues its logs. If it's Okta, expect okta.eventType and outcome.result/outcome.reason. If it's Entra ID, expect the sign-in/audit log split and ConditionalAccessStatus. Treating the two as interchangeable is the single most avoidable mistake this room can prevent.",
      checkpoint: {
        question: "You suspect someone quietly loosened an MFA requirement in an Okta org last night. An Entra-trained colleague says to look for it in the separate audit log. Where will the change actually be recorded?",
        options: [
          "In a separate Okta audit log that mirrors Entra's sign-in/audit split",
          "In the same System Log as sign-ins, under a policy.rule.* eventType",
          "In the Admin Console's policy history, not in the System Log",
          "As a ConditionalAccessStatus change on the next user's sign-in event",
        ],
        answer: 1,
        explanation:
          "Okta writes sign-ins, admin actions, group and policy changes into one unified System Log, told apart by eventType -- a policy rule change appears as policy.rule.update (or .create). 'A separate audit log' carries Entra's structure over to Okta, which is the habit this reading warns about. 'The Admin Console's policy history' is wrong: policy changes are logged events in the System Log and can be exported to a SIEM. ConditionalAccessStatus is an Entra sign-in field; Okta has no such field, and a policy edit is its own event rather than a property of later sign-ins.",
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
            "okta.outcome.result on this event is FAILURE, and a junior analyst files it as 'one more failed guess'. Which field in the event contradicts that reading, and why?",
          options: [
            "outcome.reason MFA_REQUIRED -- Okta writes it only after the password has been accepted",
            "authenticationStep 0 -- the attempt stopped at step zero, so the password check failed",
            "threatSuspected false -- Okta judged the request benign, so it was the real user signing in",
            "credentialType PASSWORD -- only a password was tried, so the attempt went no further",
          ],
          answer: 0,
          explanation:
            "outcome.result FAILURE only says this step did not end in a session; outcome.reason says why, and MFA_REQUIRED is written only once the password stage is satisfied -- so the password on this attempt was correct and is now known to whoever controls 185.220.101.44. authenticationStep cannot show where an attempt stopped: Okta documents it as unused and always 0. threatSuspected false means Okta's own heuristics did not flag the request; it is not a verdict that the real user signed in, and the hosting-provider network says otherwise. credentialType PASSWORD names the first factor presented; it does not mean the transaction ended there.",
          xp: 25,
        },
        {
          question:
            "okta.securityContext.asOrg on this event is 'Alexhost SRL', a hosting provider, and the client is Chrome on Windows 10 from Bucharest. Nkem Abara's own normal working pattern (not shown in this event) is a residential ISP from her home country. What does the asOrg value add to the investigation?",
          options: [
            "Employees do not sign in from datacenter space, so it points away from the real user",
            "It likely shows the company's VPN egress, so the attempt is probably the user herself",
            "isProxy is false, so Okta has already cleared this network and asOrg adds nothing more",
            "It matters if the country is wrong too; a plausible city outweighs the ASN value",
          ],
          answer: 0,
          explanation:
            "A hosting-provider ASN is one of the highest-signal, lowest-effort fields in an Okta investigation, because real employees sign in from residential, mobile or corporate networks, not datacenter address space -- and Nkem's normal pattern is a residential ISP. 'Company VPN egress' would have to match her usual pattern, which it does not. 'isProxy false clears it' over-trusts one flag: plenty of hosting and VPN infrastructure is never flagged as a proxy, so a false value does not clear an attempt. 'A plausible city outweighs the ASN' gets it backwards: geography and network type are separate signals, and the wrong kind of network is worth flagging even in a believable city.",
          xp: 25,
        },
        {
          question:
            "Given that the password is now confirmed correct and no session was created in this event, what is the correct immediate containment step?",
          options: [
            "Force a password reset and review what else this source and account did around this time",
            "Block 185.220.101.44 at the edge; once that source is cut off the password is safe again",
            "Reset the account's MFA factors, since the attacker was stopped at the second factor",
            "Monitor the account for 24 hours and act if a session is then created from that address",
          ],
          answer: 0,
          explanation:
            "The lost asset is the password, so invalidate it and check what else that source or account did around this window -- which is exactly what the next task investigates. 'Block the IP' helps, but the password works from any address, so the exposure remains. 'Reset the MFA factors' targets the control that held; it does nothing about the known password and briefly weakens the account further. 'Monitor and wait for a session' repeats the 'no session, no impact' mistake -- by the time a session appears, the attacker is already in.",
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
        "Not every event in the System Log describes a human or an application acting: some describe Okta's own infrastructure reacting to load or abuse, and reading these correctly means not mistaking self-defence for resolution.\n\n" +
        "**system.org.rate_limit.warning.** When a specific API endpoint (commonly /api/v1/authn, the authentication endpoint itself) receives requests faster than Okta's configured threshold allows, Okta logs a rate-limit warning and begins throttling further requests from that source. Its actor.type is SystemPrincipal (Okta's own infrastructure, not a human or an application account) and its outcome.result is typically SUCCESS, because from Okta's perspective the rate limiter itself worked exactly as designed.\n\n" +
        "**Why a rate-limit event is not, by itself, an incident's resolution.** A rate limiter's entire job is to slow down a high-volume source; it does not evaluate whether any individual request inside that volume already succeeded before the throttle kicked in. A burst that trips the rate limiter at request 61 may already have produced a correct-password result at request 40: the limiter engaging afterward changes nothing about what already happened. Treating 'Okta throttled it' as equivalent to 'Okta stopped it' is a subtle but real analyst mistake.\n\n" +
        "**Other system.* events worth recognising.** system.api_token.create and related events track the creation of API tokens. Powerful, often long-lived credentials that don't go through interactive MFA at all once issued, making unexpected token creation a meaningful persistence signal in its own right. Most other system.* events describe Okta's own housekeeping (org-level configuration, integration health) and are lower priority for security review, but the pattern-recognition skill is the same: the leading system. segment signals 'Okta's own infrastructure did this,' which is a fundamentally different actor category from a user or an admin.",
    },
    // ── Reading 8: admin / group / policy events ──────────────────────────────
    {
      type: "reading" as const,
      id: "oktaf-r8",
      heading: "Admin Actions in the System Log: Users, Groups, and Policy Changes",
      content:
        "The events that most directly matter for detecting persistence or privilege abuse in an Okta org are rarely the sign-in events themselves. They're the administrative changes that follow a successful compromise.\n\n" +
        "**user.lifecycle and user.account events.** Actions like deactivating, reactivating, or unsuspending a user account, or resetting its password/factors, are tracked individually with their own eventType values. An attacker who has compromised one account sometimes uses it to reset another user's factors (clearing their enrolled MFA so a new, attacker-controlled factor can be enrolled instead): a pattern only visible by reading the target of the event carefully, since the actor and the affected account are different identities in that case.\n\n" +
        "**group.user_membership.add and .remove.** Group membership changes are one of the highest-value events to monitor, because Okta group membership frequently controls real, consequential access, which applications a user can single-sign-on into, and in many orgs, administrative rights over Okta itself. An account added to an administrative group is an account whose privilege just changed, full stop, regardless of anything else in its recent history.\n\n" +
        "**policy.rule.create / policy.rule.update.** Changes to sign-on or authentication policy rules are exactly the kind of action a sophisticated actor makes to weaken defences quietly rather than trigger a loud, obvious alert, for example, narrowing an MFA requirement, or adding a new network zone exception. These events are comparatively rare in a healthy org, which makes an unexpected one (especially one actioned outside change-management hours) a high-priority review item on its own.\n\n" +
        "**Why actor and target both matter here, precisely.** For every one of these event types, the question 'who did this' (actor) and 'who or what was affected' (target) can be the same identity or different identities, and the distinction changes the finding completely. An account adding a completely different, previously low-privilege service account into an admin group is a different, and often more concerning, finding than an admin adding a new hire to a standard group, even though both are the exact same eventType. Reading the full event, not just recognising its type, is what separates routine administration from an attacker consolidating access.",
      checkpoint: {
        question: "An event resets all enrolled factors for c.lee (finance director) -- actor j.ortiz (helpdesk), target.0 c.lee. An hour later a new factor is enrolled on c.lee's account from a hosting-provider network, and no helpdesk ticket mentions c.lee. What is the main concern?",
        options: [
          "Little -- helpdesk staff reset factors routinely, and the actor is a real named user",
          "j.ortiz's account may be compromised and used to clear c.lee's MFA for a new factor",
          "c.lee reset her own factors, because target names the account that performed it",
          "It is Okta housekeeping by a SystemPrincipal, since factor resets are automated",
        ],
        answer: 1,
        explanation:
          "Resetting another user's factors so a new, attacker-controlled factor can be enrolled is the pattern this reading describes -- and it is only visible by reading actor and target as different identities. With no ticket and a new factor enrolled from hosting infrastructure, the helpdesk account that made the change is itself suspect. 'Helpdesk resets are routine' is true in general, but the missing ticket and the follow-on enrolment are what make this one different. 'c.lee reset her own factors' swaps the roles: actor performs the action, target is affected. 'SystemPrincipal housekeeping' is wrong because the actor is a named user, j.ortiz.",
      },
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q3",
      question:
        "At 03:19, five minutes after n.abara@globallogis.com's password was confirmed correct in the earlier finding, a system.org.rate_limit.warning event appears for the same source IP. A junior analyst reasons that this rate-limit event means the incident is now resolved. What is the correct assessment?",
      options: [
        "Correct -- once Okta's rate limiter engages for that IP, further authentication from it is blocked, so the confirmed password can no longer be used from that source",
        "Incorrect -- a rate limiter only slows later requests from that source; it does not undo or assess the confirmed-correct password that was already obtained",
        "Correct -- a system.org.rate_limit.warning means Okta's threat detection judged the source malicious and queued the account for a forced password reset",
        "Incorrect, but only because the warning shows the attacker's tooling was fingerprinted, so blocking the source IP is the fix and the password question can be deferred",
      ],
      answer: 1,
      explanation:
        "Reading 7 covered this precisely: a rate limiter's job is to slow down volume going forward -- it has no bearing on whether something inside that volume, like a correct password guess, already happened. Treating throttling as resolution is the exact mistake to avoid. Blocking one source does not stop the same password being used from any other address; rate-limit events do not trigger password resets on their own; and blocking the IP while deferring the credential question still leaves a known-correct password live.",
      xp: 25,
    },
    // ── Log Analysis 2: group membership self-add ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "oktaf-la2",
      heading: "Seven Minutes Later, a Group Changes",
      context:
        "Following on from the earlier finding, the analyst pulls the System Log for the seven minutes after n.abara@globallogis.com's password was confirmed correct. At 03:15 the log shows an Okta Verify push sent to Nkem's phone and approved (user.authentication.auth_via_mfa, outcome SUCCESS), followed by user.session.start with outcome SUCCESS, both from 185.220.101.44. Okta's admin-role report also shows the account still holds a Group Administrator role delegated to it during a 2024 helpdesk project and never removed. The event below appears four minutes after that session started.",
      event: groupMembershipEvent,
      questions: [
        {
          question:
            "Compare okta.actor.alternateId and okta.target.0.alternateId on this event. What do you find, and why does it matter?",
          options: [
            "Same account -- it added itself to Okta-Admins, a self-escalation, not routine admin",
            "Same account -- but a Group Administrator adding itself is routine delegated work",
            "Different accounts -- target.0 is the group, so the actor added Okta-Admins itself",
            "Different accounts -- an admin with a separate ID granted access to a colleague",
          ],
          answer: 0,
          explanation:
            "actor.alternateId and target.0.alternateId are both n.abara@globallogis.com (and the IDs match too), and target.1 is the Okta-Admins group -- so this account added itself to an administrative group, a self-escalation shape that deserves more scrutiny than an admin granting access to someone else. 'Routine delegated work' misses the point: the stale Group Administrator role is what made the change possible, not what makes it legitimate -- and it was used minutes after a session opened from a hosting network. 'target.0 is the group' misreads the order: target.0 is the User and target.1 is the UserGroup. 'An admin with a separate ID' is contradicted by the identical actor.id and target.0.id.",
          xp: 25,
        },
        {
          question:
            "The source IP on this group-membership change is the same 185.220.101.44 seen in the earlier password-confirmation event. What does that shared value let you conclude?",
          options: [
            "It links the escalation to whoever confirmed the password, extending one incident",
            "Little -- hosting IPs are shared by many customers, so the match is likely chance",
            "It shows Nkem made the change herself, since the push was approved on her phone",
            "It shows the change was automated by Okta, since the request went to an /api/v1 path",
          ],
          answer: 0,
          explanation:
            "The same account, the same hosting-provider IP and a few minutes apart: that ties the password confirmation, the approved push, the new session and the group change into one timeline driven by one actor. 'Shared hosting, so chance' would need an unrelated party to act as this exact account minutes later -- far less likely than one actor. 'The push was approved on her phone' is the trap: an approval only means someone tapped Approve -- possibly a tired or confused user -- while the session itself came from the hosting network, not from Nkem's normal ISP. 'An /api/v1 path means Okta automated it' confuses the API endpoint with the actor; actor.type is User, not SystemPrincipal.",
          xp: 25,
        },
        {
          question:
            "What is the correct combined containment scope now that both events are read together?",
          options: [
            "Reset the password, revoke sessions, remove Okta-Admins and the stale admin role, then audit",
            "Reset the password and revoke sessions; the Okta-Admins removal can wait for access review",
            "Remove the Okta-Admins membership; once it is reverted the password reset is not urgent",
            "Reset MFA so the approved push stops working, and leave the group for its owner to review",
          ],
          answer: 0,
          explanation:
            "The findings compound: the password is known to an outside party, that party holds a live session (the push was approved), and it used that session -- via a stale delegated admin role -- to put the account into Okta-Admins. Contain all of it together: reset the password, revoke sessions, remove the Okta-Admins membership and the leftover Group Administrator role, then audit what the elevated access was used for. 'The group removal can wait' leaves admin rights in place even after the reset. 'Revert the group, the password can wait' leaves a known password live. 'Reset MFA' does not end the existing session or the known password, and leaving the group untouched keeps the escalation in place.",
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
        { id: "usersession", left: "user.session.*", right: "A person signing in to Okta, successfully or not, and the session that follows" },
        { id: "usermfa", left: "user.mfa.*", right: "A second-factor challenge and the response to it, such as a push being approved or denied" },
        { id: "groupmembership", left: "group.user_membership.*", right: "Someone gaining or losing access because they were added to or removed from a collection of users" },
        { id: "policyrule", left: "policy.rule.*", right: "A change to the rules deciding when a second factor is demanded, such as loosening an MFA requirement" },
        { id: "systemorg", left: "system.org.*", right: "Okta's own infrastructure acting on itself, such as a rate-limit warning -- actor.type is SystemPrincipal" },
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
        { id: "step", text: "Check the MFA events that follow for the same account and transaction (push sent, denied, or approved) to confirm how far the sign-in actually progressed" },
        { id: "pivot", text: "Pivot on the account and the source IP to find any other System Log events in the surrounding window -- group, policy, or admin changes" },
        { id: "scope", text: "Scope the full impact: was a password confirmed correct, was any privilege or group membership changed, was a session ever created" },
        { id: "contain", text: "Contain based on everything actually found -- reset credentials, revert privilege changes, document the full chain" },
      ],
      correct_order: ["securitycontext", "outcome", "step", "pivot", "scope", "contain"],
      explanation:
        "Start with the network context, since a hosting-ASN source is a fast, high-signal reason to keep investigating at all. From there, read the outcome fields across the whole burst rather than just the final event, since the single most important fact -- a password confirmed correct -- can sit anywhere inside a long run of ordinary-looking failures. Checking the follow-on MFA events (a push sent, denied or approved) corroborates that reading independently. Only once the sign-in picture is clear does it make sense to pivot on the account and source IP for follow-on activity, exactly the way the group-membership finding in this room extended the password finding into a larger incident. Scoping and containment come last, once the full chain -- not just the first event -- is actually known.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "oktaf-f1",
      prompt:
        "In the group-membership finding for n.abara@globallogis.com, find the Okta ID of the group the account was added to. You will need it to check which applications and admin rights that group grants. Enter the ID.",
      answer: "00g4kx19mZQ7pLbT417v",
      hint: "The event has two targets. One is a user and one is a group; check each target's type.",
      xp: 20,
    },
    // ── Question 4: Okta vs Entra applied ─────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q4",
      question:
        "An analyst is handed two tickets on the same morning: one from a company running Entra ID, one from a company running Okta. Both describe a suspicious sign-in. Which statement correctly reflects how the analyst should approach the two investigations?",
      options: [
        "Reuse the Entra query logic on the Okta tenant, since SIEM normalisation maps both vendors onto the same field names",
        "Carry the concepts across, but read each tenant's native fields -- Entra status codes and ConditionalAccessStatus, Okta outcome and eventType",
        "Triage the Okta ticket from IP and geography, the attributes both platforms share, and escalate anything deeper",
        "Assume Okta's System Log covers sign-ins alone, since Entra keeps admin and policy changes in a separate audit log",
      ],
      answer: 1,
      explanation:
        "This is the exact synthesis Reading 6 built toward: the concepts rhyme (both are identity providers doing the same underlying job), but the schemas do not, and treating them as interchangeable is the mistake this room is designed to prevent. Reducing the Okta ticket to IP and geography throws away the outcome.reason and eventType fields that carry the real signal, and Okta absolutely tracks admin and policy changes, just within its own unified System Log rather than a separate audit log.",
      xp: 25,
    },
    // ── Question 5: synthesis ──────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "oktaf-q5",
      question:
        "Applying this room's central lesson to a different ticket: a second Okta account shows a run of INVALID_CREDENTIALS failures from a hosting-provider ASN, then one MFA_REQUIRED event from the same source, then the push that followed was denied by the user, then a rate-limit warning, and no session is ever created and no other activity follows. What is the single most accurate way to classify this incident?",
      options: [
        "A blocked password-guessing attack with a confirmed password exposure -- the password is known to an outside party though no session was obtained, so reset and pivot checks are still required",
        "A contained brute-force attempt -- MFA stopped the attacker and the rate limiter capped the volume, so the account needs monitoring but no reset since no session ever existed",
        "A false positive -- INVALID_CREDENTIALS dominates the burst, so the single MFA_REQUIRED event is most likely a legitimate user retry and the ticket can be closed",
        "A misconfigured integration -- a datacenter-ASN burst plus a rate-limit warning is typical of a service retrying stale credentials, so the ticket belongs with the Okta admin team",
      ],
      answer: 0,
      explanation:
        "This draws together the room's core threads: the reason-field flip (Reading 3) proves password exposure even without a session; the securityContext ASN (Reading 4) corroborates that this wasn't the legitimate user; and the rate-limit event (Reading 7) reflects Okta defending itself, not resolving the underlying exposure. Calling this contained or no-impact, or dismissing the one differing reason value as a legitimate retry, both repeat mistakes this room specifically addressed. And this isn't a misconfigured integration: a service retrying stale credentials would never produce a correct-password MFA_REQUIRED, and the events form one coherent, ordered chain.",
      xp: 30,
    },
  ],
};

export const roomsBatch37 = [oktaIdentityFundamentalsRoom];
