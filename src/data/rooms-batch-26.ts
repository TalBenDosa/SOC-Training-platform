/**
 * Learning Rooms — Batch 26
 *
 * playbook-execution-and-escalation
 *
 * A single hands-on room in which the learner runs a compromised-account
 * playbook end to end against Entra ID sign-in telemetry. The early steps fit
 * and the learner is rewarded for executing them faithfully. At the scope step
 * the evidence quietly stops matching the playbook's core assumption — the
 * playbook assumes ONE compromised user, and the telemetry shows the same
 * source infrastructure authenticating successfully against three unrelated
 * accounts on first attempt. That makes this a credential-source compromise,
 * not a compromised account, and the playbook's prescribed containment would
 * close the ticket while leaving the intrusion running.
 *
 * Design constraint honoured throughout: the multi-account fact appears in NO
 * single log field. It is recoverable only by comparing IPAddress,
 * AutonomousSystemNumber and UserAgent across three separately-presented
 * events, and by noticing that two of the three carry no Entra risk at all —
 * which is precisely why no alert ever fired for them.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Event 1 — the alerted account. This is the sign-in the ticket was opened on.
// ---------------------------------------------------------------------------

const alertedSigninEvent: TelemetryEvent = {
  id: "evt-pbk-la1-001",
  ts: "2026-07-14T02:47:31.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "high",
  user_email: "a.brennan@northvale.com",
  src_ip: "45.135.232.71",
  mitre_technique: "T1078",
  mitre_tactic: "Initial Access",
  authentication: { method: "Password", result: "Success" },
  description:
    "Entra ID recorded an interactive sign-in for a.brennan@northvale.com against the Northvale Expense Portal. A SIEM correlation rule opened ticket INC-40912 on this record.",
  raw: {
    "OperationName": "Sign-in activity",
    "Category": "SignInLogs",
    "ResultType": "0",
    "UserPrincipalName": "a.brennan@northvale.com",
    "UserDisplayName": "Aoife Brennan",
    "UserId": "7f1c0a3e-58d9-4b21-9e07-2c4a6f80b115",
    "AppDisplayName": "Northvale Expense Portal",
    "AppId": "b91d47c2-3fa8-4e60-8d15-70c9a2e4f338",
    "ResourceDisplayName": "Northvale Expense Portal",
    "ClientAppUsed": "Browser",
    "IPAddress": "45.135.232.71",
    "AutonomousSystemNumber": 200651,
    "LocationDetails.city": "Vilnius",
    "LocationDetails.state": "Vilniaus apskritis",
    "LocationDetails.countryOrRegion": "LT",
    "UserAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "ConditionalAccessStatus": "notApplied",
    "AuthenticationRequirement": "singleFactorAuthentication",
    "AuthenticationDetails": [
      {
        authenticationMethod: "Password",
        authenticationStepResultDetail: "Correct password",
        succeeded: true,
      },
    ],
    "DeviceDetail.deviceId": "",
    "DeviceDetail.operatingSystem": "Windows 10",
    "DeviceDetail.browser": "Chrome 109.0.0",
    "DeviceDetail.isCompliant": false,
    "DeviceDetail.isManaged": false,
    "DeviceDetail.trustType": "",
    "RiskLevelDuringSignIn": "medium",
    "RiskState": "atRisk",
    "RiskEventTypes_V2": ["unfamiliarFeatures"],
    "TokenIssuerType": "AzureAD",
    "CorrelationId": "c2a5f7d0-91b3-4e88-a6c1-0d43e29b7f5a",
  },
};

// ---------------------------------------------------------------------------
// Event 2 — a second, unrelated account. Same IP / ASN / UserAgent. No risk,
// therefore no alert ever fired on it.
// ---------------------------------------------------------------------------

const secondAccountSigninEvent: TelemetryEvent = {
  id: "evt-pbk-la2-001",
  ts: "2026-07-14T02:59:06.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "medium",
  user_email: "t.okafor@northvale.com",
  src_ip: "45.135.232.71",
  mitre_technique: "T1078",
  mitre_tactic: "Initial Access",
  authentication: { method: "Password", result: "Success" },
  description:
    "Entra ID recorded an interactive sign-in for t.okafor@northvale.com against the Northvale Expense Portal. This record generated no alert of its own and was returned by a manual pivot query, not by the SIEM.",
  raw: {
    "OperationName": "Sign-in activity",
    "Category": "SignInLogs",
    "ResultType": "0",
    "UserPrincipalName": "t.okafor@northvale.com",
    "UserDisplayName": "Tunde Okafor",
    "UserId": "d40b6e19-7c22-4a5f-b83d-91e7c05a2f64",
    "AppDisplayName": "Northvale Expense Portal",
    "AppId": "b91d47c2-3fa8-4e60-8d15-70c9a2e4f338",
    "ResourceDisplayName": "Northvale Expense Portal",
    "ClientAppUsed": "Browser",
    "IPAddress": "45.135.232.71",
    "AutonomousSystemNumber": 200651,
    "LocationDetails.city": "Vilnius",
    "LocationDetails.state": "Vilniaus apskritis",
    "LocationDetails.countryOrRegion": "LT",
    "UserAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "ConditionalAccessStatus": "notApplied",
    "AuthenticationRequirement": "singleFactorAuthentication",
    "AuthenticationDetails": [
      {
        authenticationMethod: "Password",
        authenticationStepResultDetail: "Correct password",
        succeeded: true,
      },
    ],
    "DeviceDetail.deviceId": "",
    "DeviceDetail.operatingSystem": "Windows 10",
    "DeviceDetail.browser": "Chrome 109.0.0",
    "DeviceDetail.isCompliant": false,
    "DeviceDetail.isManaged": false,
    "DeviceDetail.trustType": "",
    "RiskLevelDuringSignIn": "none",
    "RiskState": "none",
    "RiskEventTypes_V2": [],
    "TokenIssuerType": "AzureAD",
    "CorrelationId": "8b17e4a9-2d60-4c39-95f2-6a0c81d3e7b4",
  },
};

// ---------------------------------------------------------------------------
// Event 3 — a third unrelated account, presented at the decision point.
// ---------------------------------------------------------------------------

const thirdAccountSigninEvent: TelemetryEvent = {
  id: "evt-pbk-ac1-001",
  ts: "2026-07-14T03:06:44.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "medium",
  user_email: "m.devlin@northvale.com",
  src_ip: "45.135.232.71",
  mitre_technique: "T1078",
  mitre_tactic: "Initial Access",
  authentication: { method: "Password", result: "Success" },
  description:
    "Entra ID recorded an interactive sign-in for m.devlin@northvale.com against the Northvale Expense Portal. Like the previous record, it produced no alert and surfaced only through the analyst's own pivot query.",
  raw: {
    "OperationName": "Sign-in activity",
    "Category": "SignInLogs",
    "ResultType": "0",
    "UserPrincipalName": "m.devlin@northvale.com",
    "UserDisplayName": "Marek Devlin",
    "UserId": "a6e3c918-40d7-4f2b-8c53-b712f904e6da",
    "AppDisplayName": "Northvale Expense Portal",
    "AppId": "b91d47c2-3fa8-4e60-8d15-70c9a2e4f338",
    "ResourceDisplayName": "Northvale Expense Portal",
    "ClientAppUsed": "Browser",
    "IPAddress": "45.135.232.71",
    "AutonomousSystemNumber": 200651,
    "LocationDetails.city": "Vilnius",
    "LocationDetails.state": "Vilniaus apskritis",
    "LocationDetails.countryOrRegion": "LT",
    "UserAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "ConditionalAccessStatus": "notApplied",
    "AuthenticationRequirement": "singleFactorAuthentication",
    "AuthenticationDetails": [
      {
        authenticationMethod: "Password",
        authenticationStepResultDetail: "Correct password",
        succeeded: true,
      },
    ],
    "DeviceDetail.deviceId": "",
    "DeviceDetail.operatingSystem": "Windows 10",
    "DeviceDetail.browser": "Chrome 109.0.0",
    "DeviceDetail.isCompliant": false,
    "DeviceDetail.isManaged": false,
    "DeviceDetail.trustType": "",
    "RiskLevelDuringSignIn": "none",
    "RiskState": "none",
    "RiskEventTypes_V2": [],
    "TokenIssuerType": "AzureAD",
    "CorrelationId": "f5d92b06-8e14-4a73-b0c8-31a7e6d4029c",
  },
};

// ---------------------------------------------------------------------------
// ROOM
// ---------------------------------------------------------------------------

const playbookExecutionRoom: Room = {
  id: "playbook-execution-and-escalation",
  title: "Running the Playbook — and Knowing When to Stop",
  description:
    "You are handed a routine impossible-travel ticket and Northvale's compromised-account playbook, IR-014. You will run it properly: validate, collect, scope, then contain. The early steps fit and doing them carefully is what makes the rest of the room possible. Then the evidence stops matching what the playbook assumes, and you have to decide whether to finish the procedure as written or stop and escalate — and then document that you deviated, and why. Built on real Entra ID sign-in fields, with no log field anywhere that tells you the answer.",
  difficulty: "intermediate",
  category: "Incident Response",
  estimatedMinutes: 50,
  xp: 345,
  icon: "📋",
  prerequisites: ["incident-response-methodology"],
  tasks: [
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "pbk-r1",
      heading: "What a Playbook Is For — and the One Thing It Cannot Know",
      content:
        `A playbook is a written procedure that tells an analyst what to do about a specific kind of alert, in what order, with what evidence collected at each step. Northvale's IR-014 covers suspected account compromise. It exists for three reasons, and all three are good ones.\n\n` +
        `**Why playbooks exist**\n\n` +
        `First, consistency: the ticket gets handled the same way at 03:00 on a Sunday by a tired tier-1 analyst as it does at 14:00 on a Tuesday by the shift lead. Second, completeness: under time pressure people skip steps, and the ones they skip are almost always the evidence-collection ones, because collection feels like delay when something urgent is happening. Third, defensibility: when someone asks six months later why an account was disabled, the answer is a procedure and a record, not one person's recollection. Think of it the way a pilot's pre-landing checklist works. The checklist is not there because pilots are forgetful. It is there because a checklist does not get tired, does not get distracted by the passenger call button, and does not decide it already knows this one.\n\n` +
        `**The thing a playbook cannot know**\n\n` +
        `Every playbook is written against an assumed situation. IR-014 assumes a specific one, stated in its own first line: a single user account has been accessed by someone who is not that user. Every step after that inherits the assumption. Reset the password — which password? That user's. Revoke the sessions — whose? That user's. Notify the manager — of that user. The whole procedure is shaped like the problem its author was picturing.\n\n` +
        `That author was picturing the common case, and they were right to, because the common case is common. The overwhelming majority of impossible-travel tickets really are one user whose password went somewhere it should not have. But a playbook is written before the incident and cannot see the one in front of you. It cannot know whether the situation you are actually holding is the situation it was written for. Only you can check that, and checking it is a step in its own right, not an interruption of the procedure.\n\n` +
        `**Which is why the order of the steps matters more than it looks**\n\n` +
        `Notice how IR-014 is sequenced below. Validation and collection come first, scoping comes third, and containment does not happen until step four. That ordering is not bureaucratic caution. Containment is where you start changing things — resetting a password, killing sessions, disabling an account — and every change you make destroys some of the evidence you have not collected yet and tells the intruder you have seen them. So you collect before you decide, and you decide the scope before you act on it. An analyst who runs the first three steps carefully has, without doing anything unusual, given themselves everything they need to notice if the assumption has broken.\n\n` +
        `That is the whole shape of this room. Run the playbook properly. Being thorough on the boring steps is what buys you the judgement call later.`,
      codeExample:
        "NORTHVALE IR-014 -- SUSPECTED ACCOUNT COMPROMISE\n" +
        "=================================================================\n" +
        "SCOPE OF THIS PLAYBOOK\n" +
        "  A single user account is suspected of having been accessed\n" +
        "  by a party other than the account owner.\n" +
        "=================================================================\n" +
        "STEP 1  VALIDATE\n" +
        "        Confirm the triggering sign-in is real and not a\n" +
        "        detection artefact. Record the result.\n\n" +
        "STEP 2  COLLECT\n" +
        "        Sign-in history for the account. Device state.\n" +
        "        Mailbox rule and app-consent changes. Session list.\n" +
        "        Collect BEFORE changing anything.\n\n" +
        "STEP 3  SCOPE\n" +
        "        Establish the boundary of the activity. Pivot on the\n" +
        "        source of the sign-in, not only on the user.\n" +
        "        Confirm this playbook's scope condition still holds.\n\n" +
        "STEP 4  CONTAIN\n" +
        "        Revoke refresh tokens and active sessions.\n" +
        "        Reset the account password. Re-register MFA.\n\n" +
        "STEP 5  RECOVER AND CLOSE\n" +
        "        Restore access. Notify the line manager.\n" +
        "        Write the ticket summary. Close.\n" +
        "=================================================================\n" +
        "IF THE STEP 3 SCOPE CONDITION DOES NOT HOLD, STOP AT STEP 3.\n" +
        "DO NOT PROCEED TO STEP 4. ESCALATE TO THE IR LEAD.\n" +
        "=================================================================",
    },
    // -----------------------------------------------------------------------
    {
      type: "ordering",
      id: "pbk-o1",
      heading: "Put IR-014 in Its Correct Running Order",
      instructions:
        "Arrange the five IR-014 stages in the order the playbook runs them. Think about which actions destroy evidence and which ones preserve it — that is what drives the sequence.",
      items: [
        {
          id: "contain",
          text: "Revoke the account's refresh tokens and active sessions, reset its password, and force MFA re-registration",
        },
        {
          id: "collect",
          text: "Pull the account's sign-in history, device state, mailbox rule changes and app consents, without altering anything",
        },
        {
          id: "close",
          text: "Restore the user's access, notify their line manager, write the ticket summary and close the incident",
        },
        {
          id: "validate",
          text: "Confirm the triggering sign-in actually occurred and is not a detection artefact or a duplicated record",
        },
        {
          id: "scope",
          text: "Establish the boundary of the activity by pivoting on the sign-in source, and confirm the playbook's scope condition still holds",
        },
      ],
      correct_order: ["validate", "collect", "scope", "contain", "close"],
      explanation:
        "Validate first, because everything downstream is wasted effort if the triggering record turns out to be a duplicated or mis-parsed event — and that does happen. Collect second, because containment actions are destructive: resetting a password and killing sessions changes state, ends the visibility you had into what the intruder was doing, and signals to them that they have been seen. Anything you did not collect before that moment may be gone. Scope third, because the size of the problem determines the shape of the response, and you cannot know the size until you have the evidence from step two in hand. Only then contain, and only then close. Putting containment earlier is the single most common real-world sequencing error, and it feels right in the moment precisely because it feels like doing something — but it trades away the evidence and the element of surprise for a few minutes of speed. Closing before containment is worse still: it books the incident as handled while the access is still live.",
      xp: 35,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "pbk-r2",
      heading: "The Scope Gate: Where a Playbook Checks Its Own Assumption",
      content:
        `Step 3 of IR-014 is the step most analysts treat as a formality, and it is the only step in the playbook that is capable of telling you the playbook is wrong. It deserves a name of its own. Call it the scope gate.\n\n` +
        `**What a scope gate actually asks**\n\n` +
        `The gate does not ask what happened. It asks: is the situation in front of me still the situation this procedure was written for? IR-014 states its scope condition in its own header — one user account, accessed by someone other than the owner. So the scope gate asks one concrete question: is the evidence I collected consistent with exactly one affected account, or is it consistent with more than one? Every well-written playbook has a gate like this somewhere, whether or not it is labelled. Finding it and taking it seriously is a large part of what separates an analyst who runs procedures from an analyst who runs incidents.\n\n` +
        `**Pivoting on the source, not the user**\n\n` +
        `Here is the practical technique, and it is the one skill this room most wants you to leave with. When you collect evidence about a suspicious sign-in, you naturally query by user, because the ticket names a user. That query can only ever return that user, so it can only ever confirm the assumption you started with. To test the assumption instead of confirming it, you have to query the other way round: take the observable properties of the sign-in itself — the source IP address, the network it came from, the exact user-agent string, the application that was targeted — and ask the identity provider who else matches those, across the whole tenant, in the same window.\n\n` +
        `That is a different question and it can come back with a different answer. Querying by user asks how bad is it for this person. Querying by source asks how big is it. Only the second one can tell you the playbook no longer fits.\n\n` +
        `**Why the alert queue will not do this for you**\n\n` +
        `An important and slightly uncomfortable fact: risk-based sign-in alerting fires on a per-sign-in assessment. A sign-in that looks unremarkable to the identity provider — an ordinary browser, a correct password on the first attempt, a location the provider has no strong prior about — is scored as unremarkable and generates no alert, no matter what else is happening in the tenant at the same moment. So if an intruder authenticates to five accounts and only one of those five happens to trip a risk detection, your queue shows you exactly one ticket. The other four are sitting in the sign-in logs, fully recorded and completely silent.\n\n` +
        `This is not a failure of the tooling. It is what per-event scoring means. The consequence for you is direct: the number of tickets in your queue is not a measurement of how many accounts are involved. Only a pivot query is. If you never run it, the four silent sign-ins stay silent, and the ticket you do have gets closed as resolved.\n\n` +
        `**The two branches**\n\n` +
        `The diagram below is IR-014 drawn as a decision tree. Both branches out of the scope gate are legitimate outcomes of running the playbook correctly. The left branch — one account, proceed to containment — is the common one and there is nothing second-rate about taking it. The right branch is not an error state and not a failure to finish; it is the playbook's own instruction for a situation it has told you it does not cover. Taking it when the evidence calls for it is the procedure working, not the procedure breaking.`,
      diagram:
        "flowchart TD\n" +
        '  A["Alert: impossible travel on one account"] --> B["Step 1 VALIDATE: is the sign-in record real?"]\n' +
        '  B --> C["Step 2 COLLECT: sign-in history, device state, mailbox rules, app consents"]\n' +
        '  C --> D["Step 3 SCOPE GATE: pivot on source IP, ASN, user agent, target app"]\n' +
        '  D --> E{"Does the same source touch only ONE account?"}\n' +
        '  E -->|"Yes: one account"| F["Step 4 CONTAIN: revoke sessions, reset password, re-register MFA"]\n' +
        '  F --> G["Step 5 RECOVER AND CLOSE: restore access, notify manager, close ticket"]\n' +
        '  E -->|"No: several unrelated accounts, same source"| H["STOP at Step 3. The scope condition has failed."]\n' +
        '  H --> I["Escalate to IR lead: the common factor is the credential source, not the user"]\n' +
        '  I --> J["Document in the ticket: which step you stopped at, the evidence, and why"]\n' +
        '  J --> K["IR lead opens a wider incident. Do NOT close INC-40912."]',
      diagramCaption: "IR-014 as a decision tree — both branches out of the scope gate",
    },
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "pbk-la1",
      heading: "Step 1 and Step 2 — Validate and Collect",
      context:
        "03:10 on 14 July 2026. Ticket INC-40912 lands in your queue: a SIEM correlation rule flagged an impossible-travel sign-in for a.brennan@northvale.com, who works in Accounts Payable. Her previous sign-in was 47 minutes earlier from the Dublin office network. You open IR-014 and begin at Step 1. The record below is the triggering sign-in, retrieved from Entra ID. Nothing has been changed on the account yet — you are still in collection.",
      event: alertedSigninEvent,
      questions: [
        {
          question:
            "Step 1 asks you to validate that this is a real sign-in and not a detection artefact. Which fields settle that, and what do they say?",
          options: [
            "RiskLevelDuringSignIn is medium and RiskState is atRisk, which is what confirms the sign-in genuinely occurred",
            "ResultType is 0 and AuthenticationDetails records Correct password with succeeded true — the authentication genuinely completed, so this is a real sign-in and not an artefact",
            "The record cannot be validated from Entra alone and you must wait for the user to confirm before continuing",
            "CorrelationId is populated, which is the field Entra uses to mark a record as verified and non-duplicated",
          ],
          answer: 1,
          explanation:
            "ResultType 0 is Entra's success code, and the AuthenticationDetails entry showing Correct password with succeeded true confirms the credential was actually accepted — together those establish that a real authentication completed, which is exactly what Step 1 asks. The risk fields describe Entra's opinion of how unusual the sign-in was, not whether it happened, so they cannot validate occurrence. Waiting for the user before doing any collection would stall the whole playbook and is not what Step 1 requires. CorrelationId simply groups related records from one request flow; it carries no verification meaning at all.",
          xp: 25,
        },
        {
          question:
            "Still in Step 2, you are cataloguing what this sign-in tells you about HOW it succeeded. ConditionalAccessStatus is notApplied and AuthenticationRequirement is singleFactorAuthentication. What is the significance?",
          options: [
            "Entra blocked the sign-in because Conditional Access could not be evaluated, so no access was actually granted",
            "No Conditional Access policy applied to this application, so the sign-in completed on password alone with no MFA prompt — knowing the password was sufficient to get in here",
            "The user has MFA disabled on her account entirely, which is why no second factor was requested",
            "singleFactorAuthentication means the second factor was satisfied earlier and carried forward from a previous session",
          ],
          answer: 1,
          explanation:
            "notApplied means no Conditional Access policy was in scope for this application, and singleFactorAuthentication confirms the consequence: the password alone was enough, with no second factor requested. Note carefully what this is a statement about — the application, not the user. It does not mean the sign-in was blocked; ResultType 0 shows it succeeded. It does not mean MFA is disabled on the account, which is a user-level setting this record says nothing about, and the account may well be prompted for MFA on other applications. And a carried-forward second factor would appear as multiFactorAuthentication with an MfaDetail entry describing how it was satisfied, not as singleFactorAuthentication.",
          xp: 25,
        },
        {
          question:
            "You have validated and collected. Your notes so far: successful sign-in, IP 45.135.232.71 on AS200651, Vilnius, unmanaged and non-compliant device, correct password on the first attempt, no MFA required by the target app. What does IR-014 have you do next, and why that rather than anything else?",
          options: [
            "Move straight to Step 4 and reset the password — the evidence is already strong enough to act on and every minute of delay is more access for the intruder",
            "Move to Step 3 and pivot on the sign-in's own properties — source IP, ASN, user agent, target app — to establish the boundary of the activity before choosing a response",
            "Close the ticket as a false positive, since a correct password on the first attempt indicates the legitimate user travelling",
            "Skip to Step 5 and notify the line manager so the user can confirm whether she was in Vilnius",
          ],
          answer: 1,
          explanation:
            "Step 3 is next, and its instruction is specific: pivot on the source, not the user, to establish the boundary before responding. The urge to jump to a password reset is understandable and it is the trap the ordering exercise was warning about — containment is destructive, it ends your visibility, and it commits you to a response whose size you have not measured yet. Closing as a false positive is not supportable: a correct first-attempt password from an unmanaged device on a hosting-provider network, 47 minutes after a Dublin sign-in, is not what a travelling employee looks like. Notifying the manager is a real step, but it is Step 5, and doing it now would tip off the intruder if the account is being watched.",
          xp: 25,
        },
      ],
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "pbk-q1",
      question:
        "A colleague reviewing your ticket says: 'You had enough at Step 2 to reset the password. Collecting mailbox rules and app consents first just gave the intruder ten more minutes.' What is the strongest reply?",
      options: [
        "They are right — collection is optional once the sign-in is confirmed malicious, and speed should win",
        "Collection is what makes the response correct rather than merely fast: the password reset is irreversible for evidence purposes, ends your visibility into what the intruder was doing, and warns them they are seen — and if a mailbox rule or app consent was planted, resetting the password alone leaves it in place",
        "They are right, but only because Northvale has no compliance requirement to preserve identity evidence",
        "Collection matters only for incidents that are eventually reported to a regulator, so it can be skipped on routine tickets",
      ],
      answer: 1,
      explanation:
        "The substantive point is that containment is not a free action. A password reset ends your window into what the intruder is doing, tells them they have been detected, and — critically — does not remove persistence they may have already established: a forwarding rule or a consented OAuth application survives a password reset untouched and keeps working. Ten minutes of collection is what tells you whether any of that exists. The reply that speed should simply win ignores this. Framing the answer around compliance requirements or regulatory reporting gets the reasoning backwards: evidence collection is an operational necessity for handling the incident correctly, and it would be the right call even if no regulator existed.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "matching",
      id: "pbk-m1",
      heading: "Match Each IR-014 Step to What It Actually Produces",
      instructions:
        "Match each playbook step to the specific artefact or outcome it is responsible for producing. Getting this straight is how you know whether a step has genuinely been completed or only ticked.",
      pairs: [
        {
          id: "validate",
          left: "Step 1 — Validate",
          right:
            "A recorded determination that the triggering sign-in really occurred, based on the result code and the authentication detail, rather than being a duplicated or mis-parsed record",
        },
        {
          id: "collect",
          left: "Step 2 — Collect",
          right:
            "An evidence set captured before any state is changed: sign-in history, device compliance and management state, mailbox rule changes, OAuth app consents, active session list",
        },
        {
          id: "scope",
          left: "Step 3 — Scope",
          right:
            "A pivot query on the sign-in's own observable properties — source IP, autonomous system number, user agent, target application — returning every account across the tenant that matches, and an explicit answer to whether the playbook's one-account condition still holds",
        },
        {
          id: "contain",
          left: "Step 4 — Contain",
          right:
            "Refresh tokens and active sessions revoked, the account password reset, and MFA registration cleared and re-enrolled — the first step at which system state is deliberately changed",
        },
        {
          id: "close",
          left: "Step 5 — Recover and close",
          right:
            "Access restored to the legitimate user, the line manager notified, and a ticket summary written that a reader in six months can follow without asking anyone what happened",
        },
      ],
      explanation:
        "Each step owns exactly one deliverable, and naming it is how you tell a completed step from a ticked one. Validation produces a determination, not a feeling. Collection produces a captured evidence set, and it has to be captured before Step 4 because Step 4 is the first step that changes state. Scoping produces something very specific and easy to skip: a query pivoted on the sign-in's properties rather than on the username, plus a stated yes-or-no answer to whether one account is still the right model. That stated answer is the deliverable — an analyst who pivots but never explicitly asks the question has done the query and skipped the step. Containment produces changed state, which is why it sits behind the gate. Closure produces a written record, and the standard is that a stranger can follow it later without you in the room.",
      xp: 35,
    },
    // -----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "pbk-la2",
      heading: "Step 3 — The Scope Query",
      context:
        "You run the Step 3 pivot as written: instead of querying by username, you query the tenant-wide Entra sign-in logs for every record sharing the triggering sign-in's source properties, across the preceding six hours. Two facts come back from that query before you look at any individual record. First, there are zero failed sign-ins from 45.135.232.71 anywhere in the tenant in the preceding fourteen days — this address has no history of unsuccessful attempts against Northvale at all. Second, the query returns successful sign-ins for three different user principal names, not one. You already have a.brennan from Accounts Payable. Below is the second. t.okafor works in Clinical Systems; he and a.brennan share no team, no manager, no project and no distribution list. Compare this record against the first one carefully.",
      event: secondAccountSigninEvent,
      questions: [
        {
          question:
            "Set this record beside the a.brennan record from the previous task. Which specific fields are identical across the two, and what does that combination establish?",
          options: [
            "Only LocationDetails.countryOrRegion matches, which shows both users happened to be in Lithuania and nothing more",
            "IPAddress, AutonomousSystemNumber, UserAgent and AppId are all identical, while UserPrincipalName and UserId differ — the same client, on the same network, authenticated to the same application as two different people twelve minutes apart",
            "The CorrelationId values match, which is Entra's way of linking sign-ins belonging to a single intruder session",
            "RiskLevelDuringSignIn matches across both records, which is what establishes they are part of the same activity",
          ],
          answer: 1,
          explanation:
            "The identical values are IPAddress 45.135.232.71, AutonomousSystemNumber 200651, the byte-for-byte identical UserAgent string, and the same AppId — while UserPrincipalName and UserId are plainly different people. That combination is what carries the finding: one client, one network, one application, two unrelated identities, twelve minutes apart. Country alone would be weak, since two colleagues could genuinely be in the same country. CorrelationId is the opposite of a link here — the values are different, because it scopes a single request flow and has no cross-session meaning. And RiskLevelDuringSignIn does not match: it is medium on the first record and none on this one, which is a finding in its own right rather than a similarity.",
          xp: 25,
        },
        {
          question:
            "This record shows RiskLevelDuringSignIn none, RiskState none and an empty RiskEventTypes_V2, and it produced no ticket — it surfaced only because you ran the pivot. Why did Entra score it as unremarkable, and what should you take from that?",
          options: [
            "Entra scored it as safe after evaluating it against the a.brennan sign-in, which means it has already been assessed as unrelated and can be set aside",
            "Risk is scored per sign-in against that user's own history, and nothing about this one looked unusual for t.okafor in isolation — the alert queue therefore undercounts the affected accounts, and only the pivot reveals the true number",
            "The empty risk fields mean the record has not finished processing yet, and the risk score will populate within a few hours",
            "Risk scoring is disabled for users outside Accounts Payable, so no comparison between the two records is meaningful",
          ],
          answer: 1,
          explanation:
            "Entra assesses each sign-in against that individual user's own baseline. a.brennan had signed in from Dublin 47 minutes earlier, so a Vilnius sign-in tripped an impossible-travel style detection; t.okafor had no comparable recent prior, so the same client on the same network from the same city scored as nothing at all. The lesson is the one from the reading, now concrete: your queue counts alerts, not affected accounts, and the gap between those two numbers is invisible until you pivot. Entra does not cross-compare sign-ins between users to produce a per-sign-in risk score, so nothing here has been assessed as unrelated. Empty risk fields are a scored result, not a pending one. And risk scoring is not scoped by department.",
          xp: 30,
        },
        {
          question:
            "Every one of the three sign-ins returned by your pivot shows Correct password succeeded true on the first attempt, and the tenant has recorded zero failed sign-ins from this address in fourteen days. What does the complete absence of failures tell you about how these credentials were obtained?",
          options: [
            "It shows the passwords were guessed efficiently, which is consistent with a password spray that happened to succeed on its first try against each account",
            "The intruder already held valid passwords for all three accounts before authenticating — there is no guessing phase anywhere in the telemetry, which points at a common source that supplied working credentials rather than at any attack against the login endpoint",
            "It shows the three users authenticated themselves and the sign-ins are legitimate, since only the real owner knows the password on the first attempt",
            "It indicates the accounts have no lockout policy configured, which is the finding to raise",
          ],
          answer: 1,
          explanation:
            "Guessing attacks are noisy by construction: brute forcing and password spraying both work by producing failures until something lands, so both leave a failure trail in the logs. Fourteen days with zero failures and then three first-attempt successes is the signature of credentials that were already known, which shifts the question from how did they break in to where did they get the passwords. That is a materially different incident. A spray succeeding first-try against three separate accounts with no failures at all is not a plausible reading of the same evidence. Knowing the password does not establish that the owner typed it, which is precisely why credential theft works. And lockout policy is irrelevant when nothing ever failed.",
          xp: 30,
        },
      ],
    },
    // -----------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "pbk-ac1",
      heading: "The Decision: Step 4, or Stop?",
      scenario:
        "03:52. Your Step 3 pivot returned a third account, below — m.devlin, Facilities. Same source address, same autonomous system, the same byte-for-byte user agent, the same application, first-attempt correct password, no risk score, no alert. Three accounts now: Accounts Payable, Clinical Systems, Facilities. No shared team, manager, project or distribution list among them. No failed sign-in from this source anywhere in the tenant in fourteen days. IR-014 Step 4 is open in front of you and it is unambiguous about what to do: revoke a.brennan's sessions, reset her password, re-register her MFA. The shift lead is off until 07:00 and the on-call IR lead has to be paged to be reached. You are one action away from a closed ticket. Decide.",
      event: thirdAccountSigninEvent,
      correct_verdict: "escalate",
      explanation:
        "Stopping at Step 3 and escalating is right, and it is right for a reason you can state in one sentence: the playbook's scope condition has failed. IR-014 declares its own scope in its header — a single user account — and your evidence now shows one source authenticating successfully as three unrelated people, with no guessing phase anywhere in the logs. The common factor across those three sign-ins is not any user; it is whatever supplied working passwords for all of them. That is a credential-source problem — an identity-provider or password-store compromise — and it is a different incident with a different response, owned by someone above your authority to declare.\n\nRun Step 4 as written and here is what actually happens: a.brennan's password is reset, her sessions die, INC-40912 closes as resolved, and t.okafor and m.devlin remain accessible to the same intruder with the same working passwords, silently, because neither of their sign-ins ever scored as risky and neither will generate a ticket tomorrow either. The procedure would have been followed to the letter and the intrusion would still be running. Note too what the Conditional Access finding adds: notApplied on this application across all three sign-ins means there is a gap in policy coverage that the intruder is using deliberately, and closing that gap is a tenant-level fix that no single-user containment step touches.\n\nWhat makes this the professional call rather than a rule broken is that the playbook itself told you to make it. Its final line instructs you to stop at Step 3 and escalate when the scope condition fails. You did not deviate from the procedure — you executed the branch of it that the evidence selected. And you only reached this point because you ran Steps 1 to 3 properly: the pivot in Step 3 is the only thing in the entire process capable of surfacing the other two accounts, and an analyst who skipped it would have reached Step 4 in good faith with no idea anything was wrong.",
      fp_trap:
        "Every wrong option here is genuinely defensible if you have not connected the three records, which is exactly why this decision is hard at 03:52. Completing Step 4 as written is the strongest of them: it is the documented procedure, it is what the ticket asks for, containment is undeniably urgent with live intruder access, and nobody gets criticised for following the playbook. It is also what an analyst who queried only by username would inevitably do, in complete good faith. Resetting all three passwords and then closing feels even better — more thorough, seemingly proportionate to what you found — but it quietly makes a scoping decision you have no basis for: three is how many accounts your pivot surfaced in a six-hour window, not how many exist, and if the credential source is still feeding the intruder then three resets buy hours, not containment, while closing the ticket removes the incident from anyone's view. Waiting until 07:00 to raise it with the shift lead is the option that sounds like good judgement and is the most costly: it is a deliberate choice to let confirmed live unauthorised access to multiple accounts continue for three more hours to avoid waking one person, and on-call exists precisely for this. The tell that separates escalation from all three is not any single field — it is that the same IPAddress, AutonomousSystemNumber and UserAgent appear under three different UserPrincipalName values, with zero failures behind them. Nothing in any one record says that. You can only see it by putting the records side by side, which is the skill this room exists to build.",
      xp: 40,
    },
    // -----------------------------------------------------------------------
    {
      type: "question",
      id: "pbk-q2",
      question:
        "You have decided to stop at Step 3 and page the on-call IR lead. What separates a correct deviation from an incorrect one — given that you are, factually, not completing the procedure you were assigned?",
      options: [
        "Nothing — deviating from an assigned playbook is always an error, and the correct action is to complete it and raise concerns afterwards",
        "The deviation is documented and communicated in the moment: the ticket records which step you stopped at, the specific evidence that broke the scope condition, and the escalation you raised — so the next person inherits your reasoning rather than an unexplained gap",
        "The deviation is acceptable as long as you complete the remaining steps yourself once the IR lead confirms your assessment",
        "The deviation is justified purely by being correct — if the assessment turns out right, no record of the decision is needed",
      ],
      answer: 1,
      explanation:
        "The distinction is documentation and communication, made at the time, not afterwards. Write down which step you stopped at, the exact evidence that failed the scope condition — three distinct UserPrincipalName values sharing one IPAddress, AutonomousSystemNumber and UserAgent, with no failed sign-ins behind them — and that you escalated. A silent deviation is the dangerous version even when the judgement is right, because the ticket then shows an incomplete playbook with no explanation, and the next analyst cannot tell whether you found something or simply abandoned the work. Completing the procedure and raising concerns later ignores that the playbook itself instructs you to stop. Waiting for confirmation before finishing the steps misreads what happened: the response is no longer a single-account containment for you to resume, it is a different and larger incident. And being right does not substitute for a record — an undocumented correct call is indistinguishable from an unfinished ticket to everyone who reads it after you.",
      xp: 25,
    },
    // -----------------------------------------------------------------------
    {
      type: "reading",
      id: "pbk-r3",
      heading: "Deviating Properly, and Why Your Ticket Is a Feedback Loop",
      content:
        `You have done the hardest thing in this room, so it is worth being precise about what you actually did — because if you file it under broke the rules and got away with it, you will learn the wrong lesson from having been right.\n\n` +
        `**You did not go off-procedure. You took a branch of it.**\n\n` +
        `IR-014's final line reads: if the Step 3 scope condition does not hold, stop at Step 3, do not proceed to Step 4, escalate to the IR lead. That instruction was in the playbook before you opened the ticket. Every playbook worth using has a line like it, because the people who write playbooks know they are writing against an assumed situation and cannot see yours. Following that line is compliance with the procedure, not an exception to it. The reason it feels like deviation is that the last three steps stay unticked and the ticket does not close, and there is real professional discomfort in leaving work visibly unfinished. Sit with that discomfort rather than resolving it by finishing the steps. An unclosed ticket that accurately represents an open, larger incident is worth far more than a closed one that does not.\n\n` +
        `**What a good escalation contains**\n\n` +
        `An IR lead woken at 03:52 needs four things, in this order, and nothing else. What you have: three accounts authenticated successfully from one source. What the evidence is: identical IPAddress, AutonomousSystemNumber and UserAgent across three distinct UserPrincipalName values in a nineteen-minute window, first-attempt correct password on all three, zero failed sign-ins from that source tenant-wide in fourteen days. Why it is being escalated rather than handled: IR-014 covers a single compromised account and this is not that, so the containment step in the playbook would not contain it. What you have and have not already done: collection is complete, nothing has been changed, no password has been reset, no session revoked, and the account owners have not been contacted.\n\n` +
        `That last item matters more than it looks. The IR lead's first decision is what to do right now, and they cannot make it without knowing which levers you have already pulled. Notice also that everything above is observation plus a scope determination — you are not diagnosing how the passwords were obtained, and you should not try to. That is the incident the IR lead is now going to open.\n\n` +
        `**Say what you do not know**\n\n` +
        `Your pivot covered a six-hour window and returned three accounts. That is what you searched, and it is not the same as what exists. There may be more accounts before that window, or after it, or reached from a second address you have not seen. Say so explicitly in the escalation. Handing over a bounded finding with its bounds stated is useful; handing over three accounts as though it were the total is worse than useless, because the person who inherits it will plan around a number you never actually established.\n\n` +
        `**Your ticket is how the playbook improves**\n\n` +
        `IR-014 will be revised after this incident, and the revision will be written from your ticket. If you recorded that the Step 3 pivot on source properties is what surfaced the additional accounts, that pivot becomes an explicit, mandatory sub-step with the query written out, and every analyst after you runs it without needing to invent it at 03:00. If you recorded that ConditionalAccessStatus was notApplied on the target application across all three sign-ins, that finding leaves the incident entirely and becomes a policy-coverage review — a permanent fix rather than a one-off cleanup. If you recorded nothing and simply escalated, the next analyst meets the same gap with the same tooling and the same three-in-the-morning.\n\n` +
        `This is the part of incident response that is invisible while you are doing it and compounds for years afterwards. The analysts who make a SOC better are not the ones who never deviate. They are the ones who notice when the procedure has stopped matching reality, stop, say so out loud, and write down what they saw.`,
      codeExample:
        "ESCALATION NOTE -- INC-40912 -- 03:52 14 JUL 2026\n" +
        "=================================================================\n" +
        "STOPPED AT: IR-014 Step 3 (Scope). Step 4 NOT executed.\n\n" +
        "WHAT I HAVE\n" +
        "  3 Northvale accounts authenticated successfully from a single\n" +
        "  external source between 02:47 and 03:06.\n" +
        "  a.brennan (Accounts Payable) / t.okafor (Clinical Systems)\n" +
        "  m.devlin (Facilities). No shared team, manager or project.\n\n" +
        "EVIDENCE\n" +
        "  IPAddress             45.135.232.71   -- identical, all 3\n" +
        "  AutonomousSystemNumber 200651         -- identical, all 3\n" +
        "  UserAgent             Chrome/109.0.0.0 -- identical, all 3\n" +
        "  AppId / target app    identical, all 3\n" +
        "  AuthenticationDetails Correct password, 1st attempt, all 3\n" +
        "  Failed sign-ins from this source, tenant-wide, 14 days: 0\n" +
        "  ConditionalAccessStatus  notApplied on target app, all 3\n" +
        "  Entra risk: medium on 1 of 3. Other 2 scored none --\n" +
        "  no alert was raised for them; found by manual pivot only.\n\n" +
        "WHY ESCALATED, NOT HANDLED\n" +
        "  IR-014 scope condition is a SINGLE account. It does not hold.\n" +
        "  No guessing phase in the telemetry -- passwords were already\n" +
        "  valid. Common factor is the credential source, not a user.\n" +
        "  Step 4 would contain 1 of 3 and close the ticket.\n\n" +
        "ACTIONS TAKEN / NOT TAKEN\n" +
        "  DONE:     Steps 1-3. Evidence collected and preserved.\n" +
        "  NOT DONE: No password reset. No session revocation.\n" +
        "            No MFA re-registration. Owners not contacted.\n\n" +
        "LIMITS OF THIS FINDING\n" +
        "  Pivot covered a 6-hour window and this source address only.\n" +
        "  3 accounts is what I searched and found -- NOT a confirmed\n" +
        "  total. Wider window and other sources not yet checked.\n\n" +
        "REQUESTED: IR lead decision on tenant-wide scope and\n" +
        "  containment. Ticket INC-40912 remains OPEN.\n" +
        "=================================================================",
    },
    // -----------------------------------------------------------------------
    {
      type: "flag",
      id: "pbk-f1",
      prompt:
        "The single strongest piece of evidence in this room is the network identifier shared by all three sign-ins — the value that is identical across the a.brennan, t.okafor and m.devlin records and shows they came from one place. Enter the Autonomous System Number exactly as it appears in the AutonomousSystemNumber field.",
      answer: "200651",
      hint: "Open any of the three sign-in records and look for the AutonomousSystemNumber field, directly below IPAddress. It is the same number in all three — that is the point.",
      xp: 25,
    },
  ],
};

export const roomsBatch26 = [playbookExecutionRoom];
