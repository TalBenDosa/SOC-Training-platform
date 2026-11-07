import type { BriefingLab, RoomExperience } from "./types";

// "Operation Extra Device" for the "device-registration-persistence" room.
// Script: docs/campaign/88-device-registration-persistence.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Stonehaven Credit Bureau (fictional), not the graded tasks' nexacorp.com records.
// Signature mechanic: an Entra-style portal over device registration, method changes, audit
// logs and a Primary Refresh Token, where the learner finds the phone nobody bought and sees
// that two password resets left the method list and the device list untouched.
// Game mix: deduce + portal + rush.
// Task order: the room's own order, unchanged.
// Lab data differs from the graded tasks: no m.delgado, p.oduya, 91.132.139.204, Frankfurt, Tel
// Aviv or HD-51142. The portal's account is g.tallis, from 203.0.113.58 in Riga, 17 minutes
// after the sign-in (la1 has 9), and the added method sits beside two existing ones (la1 has
// one). Diff practice uses PhoneAppOTP and voice methods, never the OneWaySMS removal in q1.
// The rush teaches on phone numbers, inbox rules and devices, and does not pair sessions or an
// IP block with a method (la1 question 3). The simulate shows three broken clean-ups and never
// a whole right order (o1). The queue uses a refresh wave, a locked-out user and a rule
// misfire, never a phone swap with a helpdesk call (ac1). The boss lab is a contractor's own
// laptop that outlived a password rotation, with no attacker and no Authenticator (q4). The
// worked examples use a jump host, a job title, a tablet, a mailbox, a pipe and a door pass.
// The method diff sits on the Core Directory Update user record, not on the Authentication
// Methods record that names the action, so the audit tab shows both.

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const SIGNIN_TABS = [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "dev", label: "Device info" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }];
const GWEN = "g.tallis@stonehavencredit.example";
const GWEN_ID = "f3a07c1e-52d8-4b96-8e14-6d2b9c07e1a5";
const INTRUDER_IP = "203.0.113.58";
const CORR = "6c2e91d4-07ab-4f53-b8e2-1a9d3f7c4e60";
const SEC_CORR = "b27e40d1-6f3a-4c85-9e12-7d0a5c3f8b46";
const LAPTOP_ID = "5e0b84a7-c3f2-4d19-92ab-08d7e6f1c324";

const DEVICE_LIST_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "The Phone Nobody Bought",
  prompt: "Friday, 08:40, Stonehaven. Gwen Tallis leads the Disputes team and can't sign in. IT reset that password on Wednesday after a phishing report and closed the ticket, so why has it stopped working? Adaeze Romero opens the admin center and slides you the keyboard: start with what this account owns.",
  primer: {
    title: "Two lists, one account",
    points: [
      "**The user's methods** are what can answer an MFA prompt. A new one is written to the audit log as `User registered security info`, and a companion `Update user` record holds the list before and after.",
      "**The tenant's devices** are objects with an owner, listed under All devices. A new one is written as `Register device`, then `Add registered owner to device`. A policy that checks the device reads this list.",
      "**Microsoft Entra registered** is the join type for a personal device. A **Primary Refresh Token (PRT)** is the token a broker app holds on a device for single sign-on: valid 90 days and renewed while it's in use.",
      "`MFA requirement satisfied by claim in the token` means nobody approved anything at that moment. The session already carried proof of an earlier MFA.",
      "**SSPR** (self-service password reset) lets someone set a new password by proving a registered method.",
    ],
    example: {
      label: "The method, on a meeting-room tablet",
      lines: [
        "Asset register: one tablet, STH-TAB-22, issued to Facilities.",
        "All devices: STH-TAB-22, owner r.doyle, MDM Microsoft Intune.",
        "Audit logs: `Register device` by r.doyle, the day it was issued.",
        "Register, list and record agree, so it's accounted for. When one of the three has no partner, that's your thread.",
      ],
    },
  },
  product: "Identity admin center",
  resource: "Stonehaven Credit Bureau",
  tenant: "stonehavencredit.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Overview" }, { id: "users", label: "Users" }] },
    { group: "Users > Gwen Tallis", items: [{ id: "methods", label: "Authentication methods" }] },
    { group: "Manage", items: [{ id: "devices", label: "All devices" }] },
    { group: "Protection", items: [{ id: "risky", label: "Risky users" }] },
    { group: "Monitoring & health", items: [{ id: "signins", label: "Sign-in logs" }, { id: "audit", label: "Audit logs" }] },
  ],
  pages: {
    overview: { heading: "Overview", tiles: [{ label: "Users", value: "640" }, { label: "Devices", value: "1,212" }, { label: "Applications", value: "37" }], note: "Primary domain stonehavencredit.example. Ticket HD-8104, g.tallis, closed Wednesday: password reset after a reported phishing mail." },
    users: {
      heading: "Users",
      table: {
        columns: ["Display name", "User principal name", "User type", "Account enabled"],
        rows: [
          { id: "u-ar", cells: ["Adaeze Romero", "a.romero@stonehavencredit.example", "Member", "Yes"], record: "u-ar" },
          { id: "u-gt", cells: ["Gwen Tallis", GWEN, "Member", "Yes"], record: "u-gt" },
          { id: "u-hs", cells: ["Hana Sorel", "h.sorel@stonehavencredit.example", "Member", "Yes"], record: "u-hs" },
        ],
      },
    },
    devices: {
      heading: "Devices | All devices",
      filters: ["Owner: g.tallis", "Enabled: Yes"],
      note: "Pinned by Adaeze, from the asset register. Issued to g.tallis: laptop STH-LT-0412, iPhone 13, and shared tablet STH-TAB-31.",
      table: {
        columns: ["Name", "OS", "Join type", "Owner", "MDM", "Compliant", "Registered", "Activity"],
        rows: [
          { id: "d-lap", cells: ["STH-LT-0412", "Windows", "Microsoft Entra joined", "g.tallis", "Microsoft Intune", "Yes", "2024-09-02", "Today 08:11"], record: "d-lap" },
          { id: "d-13", cells: ["Gwen's iPhone", "iOS", "Microsoft Entra registered", "g.tallis", "Microsoft Intune", "Yes", "2024-09-02", "Yesterday 18:12"], record: "d-13" },
          { id: "d-rogue", cells: ["iPhone", "iOS", "Microsoft Entra registered", "g.tallis", "None", "N/A", "Tuesday 10:38", "Today 02:17"], record: "d-rogue" },
          { id: "d-tab", cells: ["STH-TAB-31", "iOS", "Microsoft Entra registered", "g.tallis", "Microsoft Intune", "Yes", "2025-02-17", "Monday 15:40"], record: "d-tab" },
        ],
      },
    },
    methods: {
      heading: "Gwen Tallis | Authentication methods",
      note: "Number of methods required for self-service password reset in this tenant: 1.",
      table: {
        columns: ["Method", "Detail", "Mode", "Default", "Added"],
        rows: [
          { id: "m-own", cells: ["Microsoft Authenticator", "iPhone 13", "Code", "Yes", "2024-09-02"] },
          { id: "m-tel", cells: ["Phone number", "+44 7700 900142", "Voice call", "No", "2024-09-02"] },
          { id: "m-new", cells: ["Microsoft Authenticator", "iPhone 15 Pro", "Notification", "No", "Tuesday 10:31"] },
        ],
      },
    },
    risky: {
      heading: "Risky users",
      table: {
        columns: ["User", "Risk state", "Risk level", "Risk last updated"],
        rows: [{ id: "r-gt", cells: ["Gwen Tallis", "At risk", "High", "Today 02:20"], record: "r-gt", tone: "high" }],
      },
    },
    signins: {
      heading: "Sign-in events",
      filters: ["User contains: g.tallis", "Date: Last 7 days", "Show dates as: Local"],
      table: {
        columns: ["Date", "User", "Application", "Status", "IP address", "Location", "Conditional Access"],
        rows: [
          { id: "s-fail", cells: ["Today 08:12:40", "Gwen Tallis", "Office 365", "Failure", "198.51.100.40", "Aberdeen, GB", "Not Applied"], record: "s-fail", tone: "low" },
          { id: "s-prt", cells: ["Today 02:17:09", "Gwen Tallis", "Credit File Portal", "Success", INTRUDER_IP, "Riga, LV", "Success"], record: "s-prt", tone: "high" },
          { id: "s-wed", cells: ["Wednesday 10:02:51", "Gwen Tallis", "Office 365", "Success", "198.51.100.40", "Aberdeen, GB", "Success"], record: "s-wed" },
          { id: "s-tok", cells: ["Tuesday 10:14:33", "Gwen Tallis", "Office 365", "Success", INTRUDER_IP, "Riga, LV", "Success"], record: "s-tok", tone: "high" },
          { id: "s-mon", cells: ["Tuesday 08:51:02", "Gwen Tallis", "Office 365", "Success", "198.51.100.40", "Aberdeen, GB", "Success"], record: "s-mon" },
        ],
      },
    },
    audit: {
      heading: "Audit logs",
      filters: ["Date: Last 7 days", "Target: g.tallis"],
      table: {
        columns: ["Date", "Service", "Category", "Activity", "Status", "Initiated by (actor)"],
        rows: [
          { id: "a-sspr", cells: ["Thursday 23:41:26", "Self-service Password Management", "UserManagement", "Reset password (self-service)", "Success", GWEN], record: "a-sspr" },
          { id: "a-admin", cells: ["Wednesday 09:20:05", "Self-service Password Management", "UserManagement", "Reset password (by admin)", "Success", "h.sorel@stonehavencredit.example"], record: "a-admin" },
          { id: "a-own", cells: ["Tuesday 10:38:06", "Core Directory", "Device", "Add registered owner to device", "Success", GWEN], record: "a-own" },
          { id: "a-reg", cells: ["Tuesday 10:38:04", "Device Registration Service", "Device", "Register device", "Success", GWEN], record: "a-reg" },
          { id: "a-diff", cells: ["Tuesday 10:31:17", "Core Directory", "UserManagement", "Update user", "Success", GWEN], record: "a-diff" },
          { id: "a-sec", cells: ["Tuesday 10:31:17", "Authentication Methods", "UserManagement", "User registered security info", "Success", GWEN], record: "a-sec" },
          { id: "a-upd", cells: ["Monday 14:02:44", "Core Directory", "UserManagement", "Update user", "Success", "hr-sync@stonehavencredit.example"], record: "a-upd" },
        ],
      },
    },
  },
  records: {
    "d-lap": { id: "d-lap", title: "STH-LT-0412", facts: [["Model", "Latitude 7440"], ["Device ID", LAPTOP_ID], ["Join type", "Microsoft Entra joined"], ["MDM", "Microsoft Intune"], ["Asset register", "On the register"]] },
    "d-13": { id: "d-13", title: "Gwen's iPhone", facts: [["Model", "iPhone 13"], ["Join type", "Microsoft Entra registered"], ["MDM", "Microsoft Intune"], ["Asset register", "On the register"]] },
    "d-tab": { id: "d-tab", title: "STH-TAB-31", facts: [["Model", "iPad"], ["Join type", "Microsoft Entra registered"], ["MDM", "Microsoft Intune"], ["Asset register", "On the register: shared, Disputes floor"]] },
    "d-rogue": { id: "d-rogue", title: "iPhone", actions: [{ id: "disable", label: "Disable" }, { id: "delete", label: "Delete" }], facts: [["Model", "iPhone 15 Pro"], ["OS version", "iOS 18.1"], ["Device ID", "a81d3f60-29c7-4e15-b0d4-7f6e12c9a3b8"], ["Join type", "Microsoft Entra registered"], ["MDM", "None"], ["Compliant", "N/A"], ["Owner", "g.tallis"], ["Registered", "Tuesday 10:38"], ["Asset register", "No match"]] },
    "a-reg": { id: "a-reg", title: "Audit Log Details", facts: [["Activity", "Register device"], ["Service", "Device Registration Service"], ["Category", "Device"], ["Target", "iPhone (iPhone 15 Pro)"], ["Initiated by", GWEN], ["initiatedBy.user.ipAddress", INTRUDER_IP], ["Correlation ID", CORR]] },
    "a-own": { id: "a-own", title: "Audit Log Details", facts: [["Activity", "Add registered owner to device"], ["Service", "Core Directory"], ["Category", "Device"], ["Target", "iPhone (iPhone 15 Pro)"], ["Modified property", "Owner: g.tallis"], ["Correlation ID", CORR]] },
    "a-sec": { id: "a-sec", title: "Audit Log Details", facts: [["Activity", "User registered security info"], ["Service", "Authentication Methods"], ["Category", "UserManagement"], ["initiatedBy.user.userPrincipalName", GWEN], ["initiatedBy.user.id", GWEN_ID], ["initiatedBy.user.ipAddress", INTRUDER_IP], ["initiatedBy.user.roles", "[]"], ["targetResources[0].id", GWEN_ID], ["Correlation ID", SEC_CORR]] },
    "a-diff": { id: "a-diff", title: "Audit Log Details", facts: [["Activity", "Update user"], ["Service", "Core Directory"], ["Category", "UserManagement"], ["Target", GWEN], ["modifiedProperties[0].displayName", "StrongAuthenticationMethod"], ["oldValue", "[{\"MethodType\":\"PhoneAppOTP\",\"Default\":true},{\"MethodType\":\"TwoWayVoiceMobile\",\"Default\":false}]"], ["newValue", "[{\"MethodType\":\"PhoneAppOTP\",\"Default\":true},{\"MethodType\":\"TwoWayVoiceMobile\",\"Default\":false},{\"MethodType\":\"PhoneAppNotification\",\"Default\":false}]"], ["Correlation ID", SEC_CORR]] },
    "a-admin": { id: "a-admin", title: "Audit Log Details", facts: [["Activity", "Reset password (by admin)"], ["Service", "Self-service Password Management"], ["Target", GWEN], ["Initiated by", "h.sorel@stonehavencredit.example"], ["initiatedBy.user.roles", "[\"Helpdesk Administrator\"]"], ["Modified property", "Password"]] },
    "a-sspr": { id: "a-sspr", title: "Audit Log Details", facts: [["Activity", "Reset password (self-service)"], ["Service", "Self-service Password Management"], ["Target", GWEN], ["initiatedBy.user.ipAddress", INTRUDER_IP], ["Verification", "Microsoft Authenticator notification"], ["Modified property", "Password"]] },
    "a-upd": { id: "a-upd", title: "Audit Log Details", facts: [["Activity", "Update user"], ["Target", GWEN], ["Initiated by", "hr-sync@stonehavencredit.example"], ["Modified property", "Department"]] },
    "s-tok": { id: "s-tok", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", GWEN], ["Application", "Office 365"], ["Status", "Success"], ["RiskLevelDuringSignIn", "high"]], panes: { loc: [["IP address", INTRUDER_IP], ["Location", "Riga, LV"]], dev: [["Device ID", "(none)"], ["Browser", "Chrome 131"], ["Join type", "(none)"]], auth: [["Authentication requirement", "Multifactor authentication"], ["Result detail", "MFA requirement satisfied by claim in the token"], ["Fresh MFA prompt", "None"]], capol: [["Require MFA: all users", "Success"]] } },
    "s-prt": { id: "s-prt", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", GWEN], ["Application", "Credit File Portal"], ["Status", "Success"], ["RiskLevelDuringSignIn", "medium"]], panes: { loc: [["IP address", INTRUDER_IP], ["Location", "Riga, LV"]], dev: [["Device ID", "a81d3f60-29c7-4e15-b0d4-7f6e12c9a3b8"], ["Operating system", "iOS 18.1"], ["Join type", "Microsoft Entra registered"], ["Compliant", "No"], ["Managed", "No"]], auth: [["Authentication requirement", "Multifactor authentication"], ["Result detail", "MFA requirement satisfied by claim in the token"], ["Incoming token type", "Primary Refresh Token"]], capol: [["Require MFA: all users", "Success"], ["Block unregistered devices: Credit File Portal", "Not Applied"], ["Reason", "Device matched the exclude filter on device.trustType"]] } },
    "s-fail": { id: "s-fail", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", GWEN], ["Status", "Failure"], ["Failure reason", "Invalid username or password"]], panes: { loc: [["IP address", "198.51.100.40"], ["Location", "Aberdeen, GB"]], dev: [["Device ID", LAPTOP_ID], ["Join type", "Microsoft Entra joined"]], auth: [["Result", "No factor reached"]], capol: [["Result", "Not Applied: sign-in never got that far"]] } },
    "s-wed": { id: "s-wed", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", GWEN], ["Application", "Office 365"], ["Status", "Success"], ["RiskLevelDuringSignIn", "none"]], panes: { loc: [["IP address", "198.51.100.40"], ["Location", "Aberdeen, GB"]], dev: [["Device ID", LAPTOP_ID], ["Join type", "Microsoft Entra joined"]], auth: [["Authentication requirement", "Multifactor authentication"], ["Result detail", "MFA completed in Azure AD"], ["Method", "Authenticator app code"]], capol: [["Require MFA: all users", "Success"]] } },
    "s-mon": { id: "s-mon", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", GWEN], ["Application", "Office 365"], ["Status", "Success"], ["RiskLevelDuringSignIn", "none"]], panes: { loc: [["IP address", "198.51.100.40"], ["Location", "Aberdeen, GB"]], dev: [["Device ID", LAPTOP_ID], ["Join type", "Microsoft Entra joined"]], auth: [["Authentication requirement", "Multifactor authentication"], ["Result detail", "MFA completed in Azure AD"], ["Method", "Authenticator app code"]], capol: [["Require MFA: all users", "Success"]] } },
    "r-gt": { id: "r-gt", title: "Gwen Tallis", actions: [{ id: "confirm", label: "Confirm user compromised" }, { id: "dismiss", label: "Dismiss user risk" }], facts: [["Risk state", "At risk"], ["Risk level", "High"], ["Detections", "Anomalous token, Unfamiliar sign-in properties"]] },
    "u-gt": { id: "u-gt", title: "Gwen Tallis", actions: [{ id: "reset", label: "Reset password" }, { id: "revoke", label: "Revoke sessions" }], facts: [["User principal name", GWEN], ["Job title", "Disputes Team Lead"], ["Password", "Last changed Thursday 23:41"]] },
    "u-ar": { id: "u-ar", title: "Adaeze Romero", facts: [["User principal name", "a.romero@stonehavencredit.example"], ["Job title", "Identity Analyst"]] },
    "u-hs": { id: "u-hs", title: "Hana Sorel", facts: [["User principal name", "h.sorel@stonehavencredit.example"], ["Job title", "Helpdesk Technician"]] },
  },
  steps: [
    { id: "list", ask: "Gwen's account owns a list of devices. Open it.", hint: "All devices, under Manage in the menu.", target: "menu:devices", why: "Every registered or joined device is an object here, with an owner. Adaeze has pinned the asset register above the list: a laptop, an iPhone 13 and a shared tablet." },
    { id: "phone", ask: "One object here isn't on the asset register. Open it.", hint: "Check each name against the pinned note, then look at who manages it.", target: "row:d-rogue", why: "An iPhone 15 Pro, Microsoft Entra registered, no MDM, added on Tuesday at 10:38. Stonehaven never bought it, and it was active at 02:17 this morning." },
    { id: "audit", ask: "Something created that object. Go to where the tenant writes its changes down.", hint: "Monitoring & health.", target: "menu:audit", why: "Sign-in logs say who got a token. Audit logs say what changed. A device doesn't appear without a record here." },
    { id: "reg", ask: "Open the record that created the phone.", hint: "Tuesday, and the Device category.", target: "row:a-reg", why: "Register device, from 203.0.113.58. That's a whole device object in the tenant. The Add registered owner record beside it has the same Correlation ID: one action, two records." },
    { id: "sec", ask: "Seven minutes earlier the same session changed the account itself. Open the record that names what it did.", hint: "Tuesday 10:31, Authentication Methods.", target: "row:a-sec", why: "User registered security info. The actor id and target id are the same and roles is empty, so whoever held this session did it themselves, with no admin. This record names the action, not the list." },
    { id: "diff", ask: "The list itself is on a companion record written at the same moment. Open it.", hint: "Same second, Core Directory.", target: "row:a-diff", why: "Update user, same Correlation ID. Line up oldValue and newValue: two entries became three." },
    { id: "admin", ask: "Wednesday is when IT thought this ended. Open that reset.", hint: "Reset password, with a Helpdesk Administrator as actor.", target: "row:a-admin", why: "Hana Sorel reset the password after Gwen reported the mail. Read what the record changed: Password. Nothing about a method, nothing about a device." },
    { id: "sspr", ask: "Gwen's Wednesday password has stopped working. Find the record that explains it.", hint: "Late last night, same service.", target: "row:a-sspr", why: "Reset password (self-service) at 23:41 last night, from the same address, verified by an Authenticator notification. The password lasted a day and a half, because someone proved a registered method and chose a new one." },
    { id: "methods", ask: "Two resets later, check what's on the account's method list.", hint: "Authentication methods, on Gwen's own user entry in the menu.", target: "menu:methods", why: "Still three, and Tuesday's entry on the iPhone 15 Pro hasn't moved. Neither reset edited this list, and this tenant needs just one method to pass SSPR." },
    { id: "signins", ask: "Now find how Tuesday began.", hint: "Sign-in logs.", target: "menu:signins", why: "Audit logs gave you the time and the address. Sign-in logs tell you how that session got in." },
    { id: "tok", ask: "Open the sign-in that came just before Tuesday's changes.", hint: "Same address, a few minutes before 10:31.", target: "row:s-tok", why: "Tuesday 10:14 from Riga, RiskLevelDuringSignIn high, 17 minutes before the new method. Gwen was at her desk in Aberdeen at 08:51 that morning." },
    { id: "auth", ask: "Gwen says no prompt appeared on Tuesday. How did this pass MFA?", hint: "The detail tabs across the pane.", target: "action:auth", why: "MFA requirement satisfied by claim in the token. A stolen session brought its proof of MFA with it, so nobody was asked anything, and that session then walked to the security info page." },
    { id: "prt", ask: "Now open the newest successful sign-in. It reached the credit files.", hint: "This morning, Credit File Portal.", target: "row:s-prt", why: "Today 02:17, same address, and the incoming token type is Primary Refresh Token. That's the broker on a registered device getting tokens with no prompt at all." },
    { id: "dev", ask: "Which device is this sign-in from?", hint: "The tab for the device.", target: "action:dev", why: "The Device ID matches the iPhone from the list. The Conditional Access tab shows why it mattered: the portal blocks unregistered devices, and this one is registered." },
    { id: "risky", ask: "That's the story. Take it to where the account's risk is recorded.", hint: "Risky users, under Protection.", target: "menu:risky", why: "Entra has rated this account high. Your job is to say whether that's right, on the evidence you've just walked through." },
    { id: "row", ask: "Open Gwen's entry.", hint: "There's one row.", target: "row:r-gt", why: "Two detections, and now a timeline to go with them." },
    { id: "confirm", ask: "Record your call, so Adaeze can plan the clean-up.", hint: "The evidence supports one of these buttons.", target: "action:confirm", why: "Confirmed. An unknown phone, a method beside it, a sign-in with no prompt and a password changed by someone who wasn't Gwen. How to clean that up is the next job, and it isn't one more reset." },
  ],
  traps: {
    "action:reset": "It's been reset twice this week, and that's why you're here. A third password changes neither list.",
    "action:revoke": "Not yet. Adaeze wants the whole story on paper before anything on this account changes.",
    "action:disable": "Not yet. Adaeze wants the whole story on paper before anything on this account changes.",
    "action:delete": "Deleting the phone now destroys evidence you haven't read, and a delete can't be undone. The story comes first.",
    "action:dismiss": "Dismissing says this account is safe, and nothing in these logs says that.",
  },
  lesson: "A password reset changes the password. The method list and the device list stay exactly as they were, so a factor an intruder added keeps working, and can even reset the password back. Find what the account owns, tie each change to the sign-in behind it, and treat each list as its own clean-up.",
};

export const DEVICE_REGISTRATION_PERSISTENCE: RoomExperience = {
  roomId: "device-registration-persistence",
  codename: "Operation Extra Device",
  theme: "extradevice",
  handler: { name: "Adaeze Romero", role: "Identity Analyst, Stonehaven Credit Bureau" },
  briefing: [
    "Stonehaven Credit Bureau. 640 people, and the credit files of eleven million consumers behind one sign-in.",
    "On Wednesday IT reset a team lead's password after a phishing mail, and the ticket was closed by lunch.",
    "This morning that password doesn't work, and Adaeze Romero wants to know who changed it.",
    "Learn what an account really owns, read the records that change it, and work out why a reset wasn't the end of it.",
  ],
  mission: "Find the phone nobody bought, read how it and a new method got onto the account, learn what each clean-up really touches, pick the rogue from a week of registrations, close the routine ones properly, then make sure nothing stays open.",
  estimate: "~50 min",
  look: { primary: "#c5e478", secondary: "#9ad1ff", warn: "#ff6f59" },
  scene: "facilityextradevice",
  layout: "facility",
  stations: [
    {
      id: "devicelist",
      label: "The Device List",
      topic: "T1098.005 · self-service registration · StrongAuthenticationMethod · initiatedBy · Register device",
      tagline: "What does this account own?",
      building: "archive",
      taskIds: ["devreg-r1", "devreg-r2", "devreg-q1", "devreg-q1b"],
    },
    {
      id: "reset",
      label: "The Reset",
      topic: "What a password reset touches · SSPR · audit fields in one place",
      tagline: "So why did it stop working?",
      building: "vault",
      taskIds: ["devreg-r3", "devreg-m1"],
    },
    {
      id: "timing",
      label: "The Timing",
      topic: "Risky sign-ins, tickets and device history · reading a registration · the order of remediation",
      tagline: "What happened just before?",
      building: "lab",
      taskIds: ["devreg-r4", "devreg-la1", "devreg-o1"],
    },
    {
      id: "routine",
      label: "Routine or Not",
      topic: "New phones, planned refreshes and helpdesk help · closing with a reason",
      tagline: "Most of these are fine",
      building: "office",
      taskIds: ["devreg-r5", "devreg-ac1", "devreg-q3"],
    },
    {
      id: "close",
      label: "Close the Case",
      topic: "Correlating AuditLogs with SigninLogs · pivoting on an address · what stays behind",
      tagline: "Is anything still open?",
      building: "ticket",
      taskIds: ["devreg-qf1", "devreg-f1", "devreg-q4"],
      boss: true,
    },
  ],
  personas: {
    "devreg-q1": { name: "Adaeze Romero", role: "Identity Analyst", line: "Two lists. Tell me what changed between them." },
    "devreg-q1b": { name: "Adaeze Romero", role: "Identity Analyst", line: "Two activity names in the log. What's the real difference?" },
    "devreg-m1": { name: "Adaeze Romero", role: "Identity Analyst", line: "Before you read a live record, make sure you know what each field is for." },
    "devreg-la1": { name: "Adaeze Romero", role: "Identity Analyst", line: "Different company, different account. Read this one as if it landed on your desk." },
    "devreg-o1": { name: "Adaeze Romero", role: "Identity Analyst", line: "Put the steps in the order you'd sign your name to." },
    "devreg-ac1": { name: "Adaeze Romero", role: "Identity Analyst", line: "Same activity name again. Read what's around it, then call it." },
    "devreg-q3": { name: "Adaeze Romero", role: "Identity Analyst", line: "You've seen that field twice now. What's it really telling you?" },
    "devreg-qf1": { name: "Adaeze Romero", role: "Identity Analyst", line: "I don't want anyone doing this by hand again. Finish the query." },
    "devreg-f1": { name: "Adaeze Romero", role: "Identity Analyst", line: "One value from this record, exactly as it's written." },
    "devreg-q4": { name: "Adaeze Romero", role: "Identity Analyst", line: "Before I sign this off: what have we still got to do?" },
  },
  briefings: {
    // ── Reading 1: why an intruder edits the account ──
    "devreg-r1": [
      {
        kind: "sort",
        title: "Way In or Way Back?",
        prompt: "Adaeze keeps two columns on the whiteboard: how an intruder got in once, and what lets them come back. Last quarter's case notes got mixed up. Sort each one.",
        primer: {
          title: "Why an intruder edits the account",
          points: [
            "**T1098, Account Manipulation** (MITRE ATT&CK, Persistence): the goal isn't getting in. It's changing the account so access outlasts whatever got them in.",
            "**T1098.005, Device Registration** is the identity-provider version: with a working session in hand, add your own factor or device, and the provider trusts it from then on.",
            "A password reset is the most predictable first step any SOC takes. This move is built to outlast it.",
            "No new MFA has to be beaten. A stolen session carries an **MFA claim**: proof that the real user did MFA earlier.",
          ],
          example: {
            label: "The same idea, on a Linux jump host",
            lines: [
              "Way in: a reused password on an SSH login.",
              "Way back: a public key appended to `~/.ssh/authorized_keys`. That's T1098.004, SSH Authorized Keys.",
              "The password changes on Friday. The key still logs in on Monday.",
            ],
          },
        },
        buckets: [{ id: "in", label: "Gets them in once" }, { id: "back", label: "Lets them come back" }],
        items: [
          { id: "a", text: "A fake sign-in page relays a live session through a proxy", bucket: "in", why: "That captures one session. It's the way in, and nothing on the account has changed yet." },
          { id: "b", text: "A mobile number added on the My Security Info page", bucket: "back", why: "A new entry on the account's factor list. It stays after the session that added it has gone." },
          { id: "c", text: "A password from another company's breach, tried here", bucket: "in", why: "A credential, and one change of password ends its value." },
          { id: "d", text: "A tablet registered to the tenant with the victim as owner", bucket: "back", why: "A device object in the directory, with a life of its own." },
          { id: "e", text: "Push prompts sent until a tired user taps Approve", bucket: "in", why: "That passes MFA once. Next time the prompts have to start again, unless the intruder uses the moment to add something." },
          { id: "f", text: "A FIDO2 key enrolled against the account", bucket: "back", why: "A strong factor, and here it's the intruder's. Strong doesn't mean legitimate." },
          { id: "g", text: "A stolen session cookie replayed from a second browser", bucket: "in", why: "It lasts as long as the session does. Nothing has been added to the account, which is exactly why an intruder uses it to add something." },
        ],
      },
    ],
    // ── Reading 2: the fields, then the signature console ──
    "devreg-r2": [
      {
        kind: "anatomy",
        title: "Read One Registration Record",
        prompt: "A quiet record from Tuesday, on someone else's account. Adaeze wants you able to read this format cold before the morning's real work. Scan each field.",
        primer: {
          title: "Four questions for any audit record",
          points: [
            "Anyone with a signed-in session can add a method at **My Security Info**. That's by design: phone upgrades can't all go through a helpdesk.",
            "**Who acted** is in `initiatedBy.user`. **What was acted on** is in `targetResources[]`.",
            "The same id in both means **self-service**. An admin acting for someone shows a different actor id, and a role in `initiatedBy.user.roles`.",
            "`oldValue` and `newValue` hold the whole list before and after, not only the change.",
          ],
          example: {
            label: "The same four questions, on a job title",
            lines: [
              "Activity: `Update user`.",
              "Actor: hr-sync@stonehavencredit.example. Target: a.ibarra@stonehavencredit.example. Two ids, so someone else acted.",
              "`modifiedProperties[0].displayName`: JobTitle. `oldValue`: Analyst. `newValue`: Senior Analyst.",
            ],
          },
        },
        source: "Audit logs · Authentication Methods, with its Core Directory companion · n.brandt · Tuesday 14:06",
        fields: [
          { key: "activityDisplayName", value: "User registered security info", label: "What happened", note: "The operation Entra writes when an authentication method is registered on an account." },
          { key: "category", value: "UserManagement", label: "Filed under" },
          { key: "loggedByService", value: "Authentication Methods", label: "Written by" },
          { key: "correlationId", value: "d41b7e02-93c6-4a18-b5f7-2e8c60a1d739", label: "Grouping", note: "Every record from one underlying action carries the same value. Use it to pull the set together." },
          { key: "initiatedBy.user.userPrincipalName", value: "n.brandt@stonehavencredit.example", label: "Actor" },
          { key: "initiatedBy.user.id", value: "2b7f90c4-61de-4f08-a7c3-95e1d04b86f2", label: "Actor id" },
          { key: "initiatedBy.user.ipAddress", value: "198.51.100.40", label: "From where", note: "The network address of the session that acted. This is the value you pivot on in SigninLogs. It's Stonehaven's Aberdeen office." },
          { key: "initiatedBy.user.roles", value: "[]", label: "Directory role", note: "No directory role on the acting session. On an admin-assisted change this names one, such as Helpdesk Administrator." },
          { key: "targetResources[0].id", value: "2b7f90c4-61de-4f08-a7c3-95e1d04b86f2", label: "Target id", note: "Compare it with the actor id. Same value: the account acted on itself." },
          { key: "Companion record", value: "Update user, Core Directory, same moment, same target user", label: "Where the change sits", note: "The record above names the action. The next three fields come from this companion record." },
          { key: "modifiedProperties[0].displayName", value: "StrongAuthenticationMethod", label: "Property changed", note: "The property that holds the account's list of methods." },
          { key: "oldValue", value: "[{\"MethodType\":\"PhoneAppOTP\",\"Default\":true}]", label: "Before" },
          { key: "newValue", value: "[{\"MethodType\":\"PhoneAppOTP\",\"Default\":true},{\"MethodType\":\"TwoWayVoiceMobile\",\"Default\":false}]", label: "After", note: "One entry in both lists, and one only here. A mobile number was added, and the app stays the default." },
        ],
        summary: "n.brandt, from the Aberdeen office, added a mobile number beside the existing app entry, and no admin was involved. The record tells you what changed and who did it. Whether it should have happened is a different question.",
      },
      DEVICE_LIST_LAB,
    ],
    // ── q1: diff practice ──
    "devreg-q1": [
      {
        kind: "worksheet",
        title: "Old List, New List",
        prompt: "Adaeze has pulled six StrongAuthenticationMethod changes from the last month. Line each pair up, and answer from the lists. In the table, (D) marks the entry with Default:true.",
        primer: {
          title: "Reading two lists",
          points: [
            "Line the lists up entry by entry. Whatever appears in only one of them is what changed.",
            "Then find `Default:true` in `newValue`: that's the method Entra offers first.",
            "The same name twice is two methods, so count the entries as well as reading them.",
            "Go by the lists, not the activity name. The name gives you the kind of event, never the entry.",
          ],
          example: {
            label: "The method, on one record",
            lines: [
              "`oldValue`: `[{\"MethodType\":\"PhoneAppOTP\",\"Default\":true}]`",
              "`newValue`: `[{\"MethodType\":\"TwoWayVoiceMobile\",\"Default\":true},{\"MethodType\":\"PhoneAppOTP\",\"Default\":false}]`",
              "PhoneAppOTP is in both. TwoWayVoiceMobile is only in `newValue`, so it was added.",
              "`Default:true` went with it, so the new number gets the first prompt.",
            ],
          },
        },
        caption: "AuditLogs · StrongAuthenticationMethod · Last 30 days",
        columns: ["Change", "User", "oldValue", "newValue"],
        rows: [
          ["C1", "a.ibarra", "PhoneAppOTP (D)", "PhoneAppOTP (D), TwoWayVoiceOffice"],
          ["C2", "d.kowal", "TwoWayVoiceMobile (D), PhoneAppOTP", "TwoWayVoiceMobile, PhoneAppOTP (D)"],
          ["C3", "r.naidoo", "PhoneAppOTP (D), TwoWayVoiceMobile, TwoWayVoiceOffice", "PhoneAppOTP (D), TwoWayVoiceOffice"],
          ["C4", "s.lindqvist", "TwoWayVoiceOffice (D)", "TwoWayVoiceOffice, PhoneAppNotification (D)"],
          ["C5", "j.marsh", "PhoneAppNotification (D)", "PhoneAppNotification (D)"],
          ["C6", "h.mbeki", "PhoneAppOTP (D)", "PhoneAppOTP (D), PhoneAppOTP"],
        ],
        questions: [
          { id: "q1", q: "Which change took a method off the account?", hint: "Find an entry that's in oldValue and missing from newValue.", answer: ["C3"], why: "r.naidoo went from three entries to two. TwoWayVoiceMobile is in oldValue and not in newValue." },
          { id: "q2", q: "Which change only moved the default, with the same methods before and after?", hint: "The same names on both sides, and a different (D).", answer: ["C2"], why: "d.kowal has the same two methods either side. Only the Default flag has crossed over." },
          { id: "q3", q: "In which change does a brand-new method now get the first prompt?", hint: "New in newValue, and marked (D).", answer: ["C4"], why: "s.lindqvist gained PhoneAppNotification and it took the default, so the old office line is now second." },
          { id: "q4", q: "How many methods does a.ibarra have after the change?", hint: "Count newValue, not the difference.", answer: ["2", "two"], why: "newValue is the whole list after the change: PhoneAppOTP and TwoWayVoiceOffice." },
          { id: "q5", q: "Which change added a method that a quick read of the names would miss?", hint: "Count the entries on each side, row by row.", answer: ["C6"], why: "h.mbeki has one entry before and two after. Both say PhoneAppOTP, and that's two separate registrations." },
        ],
      },
    ],
    // ── Reading 3: what each clean-up touches ──
    "devreg-r3": [
      {
        kind: "rush",
        title: "What Did It Touch?",
        prompt: "Adaeze wants this as a reflex before anyone at Stonehaven touches Gwen's account again. Each card names one action and one object. Straight after that action, is the object still there, or gone?",
        primer: {
          title: "One action, one object",
          points: [
            "An account isn't one thing. It's a password, a set of refresh tokens, a list of methods, and any device objects it owns.",
            "**Reset password** replaces the password. **Revoke sessions** invalidates refresh tokens. A list only changes when someone edits that list.",
            "**Delete** on a method removes that entry. **Require re-register MFA** deletes the phone numbers and Authenticator apps together.",
            "**Disable** on a device revokes its PRT and refresh tokens, and the object stays listed. **Delete** removes the object. A PRT obtained with a password also ends when that password changes.",
            "A leftover entry is a key that never expires. It fits the next stolen password, and at SSPR it needs no password at all.",
          ],
          example: {
            label: "The method, on a mailbox",
            lines: [
              "An intruder adds an inbox rule that forwards invoices outside the company.",
              "IT resets the password.",
              "The rule still forwards. It lives in the mailbox, and nobody edited the mailbox.",
              "So ask of every clean-up: which object did that action change?",
            ],
          },
        },
        seconds: 75,
        target: 11,
        trueLabel: "Still there",
        falseLabel: "Gone",
        cards: [
          { id: "c1", text: "After a password reset: the old password", answer: false, why: "That's the one thing a reset does replace." },
          { id: "c2", text: "After a password reset: a rogue phone number in security info", answer: true, why: "It's on the method list, and a reset doesn't edit that list." },
          { id: "c3", text: "After Revoke sessions: refresh tokens issued before it", answer: false, why: "Invalidating refresh tokens is precisely what Revoke sessions does." },
          { id: "c4", text: "After Revoke sessions: the current password", answer: true, why: "Sessions and passwords are different objects. Whoever knows the password can sign in again." },
          { id: "c5", text: "After a password reset: an intruder's inbox rule", answer: true, why: "The rule lives in the mailbox, so it needs its own removal." },
          { id: "c6", text: "After Delete on a method: that method", answer: false, why: "It's off the list, and the audit log records Admin deleted security info." },
          { id: "c7", text: "After Delete on a rogue method: the user's own Authenticator entry", answer: true, why: "Delete acts on one entry, so the rest of the list stays." },
          { id: "c8", text: "After Disable on a device: the device object", answer: true, why: "A disabled device is still listed, with Enabled set to No. It can't authenticate, but the object is there." },
          { id: "c9", text: "After Disable on a device: that device's PRT", answer: false, why: "Disabling a device revokes its PRT and any refresh tokens on it." },
          { id: "c10", text: "After Delete on a device: the device object", answer: false, why: "Delete removes the object and everything attached to it, which is why it comes after you've read it." },
          { id: "c11", text: "After Require re-register MFA: the user's Authenticator apps", answer: false, why: "It deletes phone numbers and Authenticator apps together, the user's real ones included, so the user must enrol again." },
          { id: "c12", text: "After Require re-register MFA: the user's password", answer: true, why: "It's an action on methods, and the password is a separate object." },
          { id: "c13", text: "After Block sign-in: the methods on the account", answer: true, why: "Blocking stops the account being used. It doesn't edit what's on it." },
          { id: "c14", text: "After an intruder's own SSPR: the password IT issued", answer: false, why: "SSPR replaces the password, and IT's has stopped working. That's what Gwen found this morning." },
          { id: "c15", text: "After a password change: a PRT obtained with that password", answer: false, why: "That PRT is invalidated by the change, and the next good sign-in on that device gets a new one." },
        ],
        lesson: "Every clean-up action changes one kind of object. Before you tick a step, name the object it changed, then name the ones it didn't.",
      },
    ],
    // ── Reading 4: what surrounds a registration ──
    "devreg-r4": [
      {
        kind: "deduce",
        title: "Six Registrations, One Intruder",
        prompt: "Gwen's isn't the only alert. Stonehaven's rule on new security info fired six times this week, and the Collections floor is halfway through a phone refresh. Adaeze wants one name to escalate. Everyone here really did register something, so strike out who the clues clear.",
        primer: {
          title: "What surrounds a registration",
          points: [
            "The operation almost never decides it. Most `User registered security info` records are someone with a new phone.",
            "Look around it in time for three things: a **risky or unfamiliar sign-in** close by, a **ticket or enrolment record** that explains it, and a match with the account's **device history**.",
            "`riskLevelDuringSignIn` is Entra's own rating of a sign-in. How MFA was met, by a fresh approval or by a claim in the token, is recorded in the same log.",
            "None of these works alone. It's the combination that turns a routine record into a containment.",
          ],
          example: {
            label: "The method, on a new laptop",
            lines: [
              "Record: `Register device`, one laptop, Monday 09:10.",
              "Nearby sign-in: quiet, from the office.",
              "Ticket: an asset request for a new starter.",
              "History: the serial is on the purchase order. Three checks, three explanations: routine.",
            ],
          },
        },
        nameColumn: "Account",
        columns: ["initiatedBy roles", "Source", "Nearest sign-in", "Ticket or record", "Device history"],
        suspects: [
          { id: "ibarra", name: "a.ibarra", cells: ["[]", "Aberdeen office", "Quiet, push approved", "REF-2219 refresh batch", "Matches issued phone"] },
          { id: "mackay", name: "t.mackay", cells: ["[]", "Home broadband (usual)", "Quiet, push approved", "None", "No record"] },
          { id: "sandhu", name: "k.sandhu", cells: ["[Helpdesk Administrator]", "Aberdeen office", "None that day", "HD-7731 locked out, ID checked", "Replacement issued"] },
          { id: "oyelaran", name: "f.oyelaran", cells: ["[]", "Hotel Wi-Fi, Lisbon", "Medium risk, 3 hours before, push approved", "TR-118 travel notice", "Matches issued phone"] },
          { id: "vance", name: "e.vance", cells: ["[]", "Aberdeen office", "Medium risk, 20 min before, push approved", "None", "No record"] },
          { id: "quigley", name: "m.quigley", cells: ["[]", "Broadband, Glasgow (new)", "Medium risk, 12 min before, claim in token", "None", "No record"] },
        ],
        clues: [
          "Start with what explains the change. Strike anyone with a ticket or record that fits it.",
          "A new phone at home, with a quiet sign-in beside it, is someone upgrading. Whoever's left needs a risky sign-in close by.",
          "An approved push means someone was asked at that moment, and e.vance still gets a call to confirm it was them. A claim in the token means nobody was asked.",
        ],
        culprit: "quigley",
        why: "m.quigley has no ticket, no device history, and a risky sign-in 12 minutes before where nobody was asked for MFA. Some other rows share one or two of those, and each one has an explanation or a person behind it. Now look back at the roles column: it never helped you once.",
      },
    ],
    // ── o1: why a clean-up has an order ──
    "devreg-o1": [
      {
        kind: "simulate",
        title: "Three Clean-ups That Went Wrong",
        prompt: "Stonehaven's post-incident file holds three old cases. Each one found an intruder's factor, and each one broke a rule on the way out. Pick a case, say which rule you think broke, then run it. None of these is the way to do it.",
        primer: {
          title: "Why a clean-up has an order",
          points: [
            "A removal isn't finished until the sign-in logs show that factor has stopped working.",
            "While an intruder can still sign in, anything you remove can be put back.",
            "A new password is only safe once nobody else can pass SSPR on that account.",
          ],
          example: {
            label: "The same logic, on a leaking pipe",
            lines: [
              "Turn the valve off before you touch the pipe, or you're working under pressure.",
              "Repair, then test, and only then let the water back.",
              "The tenant who moved out for the work returns only after the landlord has confirmed who they are.",
              "The repair note gets written at the very end, once nothing is still changing.",
              "The order isn't habit. Each step protects the one after it.",
            ],
          },
        },
        checks: [
          { name: "Proved", question: "Did someone read the sign-in and audit logs before the user came back?" },
          { name: "Factors first", question: "Was every rogue factor gone before a new password went out?" },
          { name: "Door shut", question: "Was the account closed to new sign-ins while the team worked?" },
        ],
        scenarios: [
          {
            id: "payroll",
            label: "Case 1: The Payroll Clerk",
            detail: "Helpdesk issued a new password at 09:00, then went looking. A rogue mobile number was found at 11:30 and deleted.",
            results: ["pass", "fail", "fail"],
            why: ["The logs were read, and that's how the 09:20 reset came to light.", "At 09:20 the intruder took the account back: SSPR sent the code to their own number.", "Sign-in stayed open all morning."],
            verdict: "A new password went out with a rogue factor still listed, so it lasted twenty minutes.",
          },
          {
            id: "underwriter",
            label: "Case 2: The Underwriter",
            detail: "The team deleted a rogue Authenticator entry while the account stayed enabled and the intruder's session stayed live. A different entry appeared twelve minutes later.",
            results: ["pass", "fail", "fail"],
            why: ["The logs showed the second entry, so the case was reopened.", "A second rogue entry was already on the account when the new password went out.", "Nobody closed the account, so the live session went straight back to Security Info."],
            verdict: "They removed the factor with the intruder still in the room.",
          },
          {
            id: "broker",
            label: "Case 3: The Broker Desk",
            detail: "Tidy work all morning, and the user was back at their desk by lunch. Nobody opened the sign-in logs first. On Friday the same address signed in on a laptop nobody had looked at.",
            results: ["fail", "pass", "pass"],
            why: ["The user was restored on an assumption. The logs would have shown a second foothold the same day.", "No new password went out early.", "The account was closed while they worked."],
            verdict: "Nobody proved the work had held, so the access lasted until Friday.",
          },
        ],
      },
    ],
    // ── Reading 5: legitimate registration ──
    "devreg-r5": [
      {
        kind: "queue",
        title: "Close It With a Reason",
        prompt: "Monday's queue on the same rule. Adaeze's standard is simple: nobody closes one of these without saying why. Open each alert, read what's around the record, and take the call you'd defend.",
        primer: {
          title: "Three ways an alert ends",
          points: [
            "A **planned refresh** shows up as a wave across many users, with an enrolment or change record that explains the timing.",
            "**Helpdesk help** for a locked-out user shows a role in `initiatedBy.user.roles`, and a ticket that records the identity check.",
            "**Benign true positive**: the rule fired on a real event, and the event has an authorised reason. Close it and cite that reason.",
            "**False positive**: the rule misfired, and what it watches for never happened.",
          ],
          example: {
            label: "The method, on a different rule",
            lines: [
              "Rule: new admin role assigned.",
              "IT really did add the role, under change CHG-3310.",
              "Benign true positive: close it, cite CHG-3310, and leave the rule as it is.",
            ],
          },
        },
        console: "Identity alerts · New security info · Status: New",
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "contain", label: "Escalate: contain", tone: "contain" },
        ],
        alerts: [
          {
            id: "wave", time: "09:02", severity: "Medium", rule: "New authentication method registered", entity: "38 accounts, Collections",
            fields: [{ k: "Activity", v: "User registered security info" }, { k: "initiatedBy.user.roles", v: "[]" }, { k: "Window", v: "08:30 to 10:15, Monday" }, { k: "Source", v: "198.51.100.40 (Aberdeen office)" }, { k: "Change record", v: "CHG-3402 Collections phone refresh, Intune enrolment list attached" }],
            context: "Every one of the 38 accounts is on the enrolment list, and no sign-in near the window is rated risky.",
            answer: "btp", why: "Real registrations, which is what the rule is for, with a change record that explains the wave. Close it and cite CHG-3402.",
          },
          {
            id: "locked", time: "10:40", severity: "Medium", rule: "New authentication method registered", entity: "l.marchetti",
            fields: [{ k: "Activity", v: "Admin registered security info" }, { k: "initiatedBy.user.userPrincipalName", v: "h.sorel@stonehavencredit.example" }, { k: "initiatedBy.user.roles", v: "[\"Helpdesk Administrator\"]" }, { k: "Ticket", v: "HD-8122: lost all methods, identity checked on a video call" }],
            context: "l.marchetti's only phone is in for repair, and the temporary method matches the ticket.",
            answer: "btp", why: "An admin acted for someone else, the role says so, and the ticket records how identity was checked. Authorised, so close it and cite HD-8122.",
          },
          {
            id: "reviewed", time: "11:15", severity: "Low", rule: "New authentication method registered", entity: "b.ostrowski",
            fields: [{ k: "Activity", v: "User reviewed security info" }, { k: "modifiedProperties", v: "(none)" }, { k: "Rule filter", v: "OperationName contains \"security info\"" }],
            context: "Entra asked the user to confirm their details, and they did. The method list is the same as last month's.",
            answer: "fp", why: "Nothing was registered. The rule's filter is too wide and matched a review, so this one is a misfire worth a tuning note.",
          },
          {
            id: "lookalike", time: "13:27", severity: "Medium", rule: "New authentication method registered", entity: "c.dunmore",
            fields: [{ k: "Activity", v: "User registered security info" }, { k: "initiatedBy.user.roles", v: "[]" }, { k: "Source", v: "203.0.113.141 (new to this account)" }, { k: "Nearest sign-in", v: "13:16, high risk, MFA satisfied by claim in the token" }, { k: "Change record", v: "None. c.dunmore is in Finance, not on CHG-3402" }],
            context: "It landed in the middle of the refresh, so it looks like one more phone. The enrolment list says otherwise.",
            answer: "contain", why: "Busy week, same activity name, but no change record, an unknown source and nobody asked for MFA eleven minutes earlier. The refresh is a good place to hide.",
          },
        ],
      },
    ],
    // ── qf1: the two tables ──
    "devreg-qf1": [
      {
        kind: "sort",
        title: "Which Table Holds It?",
        prompt: "Adaeze wants the correlation you did by hand on Friday turned into a query. First, know where each column lives. Put them on the right side.",
        primer: {
          title: "Two tables, one question",
          points: [
            "`AuditLogs` records what changed in the tenant. `SigninLogs` records who got a token, from where, and how.",
            "A detection that pairs them reads: a change in one table, close in time to a sign-in in the other.",
            "`=~` compares without case. `join kind=inner` keeps rows that match on both sides, and `datetime_diff` gives the gap between two times.",
            "After a join, the right-hand table's `TimeGenerated` comes back as `TimeGenerated1`.",
          ],
          example: {
            label: "The shape of it, on a different operation",
            lines: [
              "`AuditLogs | where OperationName =~ \"User deleted security info\"`",
              "`| extend UPN = tostring(InitiatedBy.user.userPrincipalName)`",
              "`| join kind=inner (SigninLogs | where AppDisplayName == \"Credit File Portal\") on $left.UPN == $right.UserPrincipalName`",
              "Every deleted method, beside that user's portal sign-ins.",
            ],
          },
        },
        buckets: [{ id: "audit", label: "AuditLogs" }, { id: "signin", label: "SigninLogs" }],
        items: [
          { id: "a", text: "OperationName", bucket: "audit", why: "The name of the change, such as Register device. SigninLogs has this column too, but it only ever says Sign-in activity." },
          { id: "b", text: "AuthenticationRequirement", bucket: "signin", why: "What the sign-in had to prove, so it belongs to the sign-in." },
          { id: "c", text: "InitiatedBy", bucket: "audit", why: "Who made a change. A sign-in has a user, and a change has an actor." },
          { id: "d", text: "ConditionalAccessStatus", bucket: "signin", why: "The policy outcome for one sign-in." },
          { id: "e", text: "TargetResources", bucket: "audit", why: "What the change was made to, including its modified properties." },
          { id: "f", text: "AppDisplayName", bucket: "signin", why: "Which application the token was for." },
          { id: "g", text: "UserAgent", bucket: "signin", why: "The client that asked for the token." },
          { id: "h", text: "LoggedByService", bucket: "audit", why: "Which Entra service wrote the record, such as Authentication Methods." },
        ],
      },
    ],
    // ── q4: the boss's decisive idea, on a case with no attacker ──
    "devreg-q4": [
      {
        kind: "trace",
        title: "The Laptop That Outlived the Rotation",
        prompt: "One last file before Adaeze closes Gwen's case. Nothing malicious this time: a records contractor, a fortnight of home working in January, and a review in June that doesn't add up. Follow it through three logs.",
        primer: {
          title: "A device has a life of its own",
          points: [
            "A device object has its own record, owner and state, separate from anything on the user.",
            "A policy that checks the device asks that object, not the password.",
            "A PRT is how a registered device stays useful. Disable or delete the device and its PRT is invalidated.",
            "So a clean-up names every device an account owns, and the audit log shows `Unregister device` or `Delete device` for each one that goes.",
          ],
          example: {
            label: "The same idea, on a door pass",
            lines: [
              "HR changes a leaver's PIN on Friday.",
              "The door reads the pass list, not the PIN, so the pass still opens it on Monday.",
              "Only taking the pass off the list ends it.",
            ],
          },
        },
        lead: "The Credit File Portal admits registered devices only. Every Records password was rotated on 6 May. Stonehaven's own machines are named STH-.",
        steps: [
          {
            id: "signin",
            ask: "Which sign-in passed the device policy on a machine that isn't Stonehaven's?",
            source: "SigninLogs · Credit File Portal · 11 June",
            columns: ["Time", "User", "Device", "Join type", "Result"],
            rows: [
              ["09:02", "d.farrow", "STH-LT-0388", "Microsoft Entra joined", "Success"],
              ["09:14", "a.ibarra", "STH-LT-0251", "Microsoft Entra joined", "Success"],
              ["18:47", "d.farrow", "DESKTOP-7QK2LM", "Microsoft Entra registered", "Success"],
              ["19:03", "s.lindqvist", "(none)", "(none)", "Failure: blocked by policy"],
            ],
            answer: 2,
            why: "Same user as the morning, a different machine, and a success. The blocked row shows the policy working: no device object, no entry.",
            learned: "DESKTOP-7QK2LM passed the device policy on 11 June.",
          },
          {
            id: "object",
            ask: "Open the object behind that sign-in. Was it there before the May rotation?",
            source: "All devices · Owner: d.farrow",
            columns: ["Name", "Join type", "MDM", "Registered", "Activity", "Enabled"],
            rows: [
              ["DESKTOP-7QK2LM", "Microsoft Entra registered", "None", "14 January", "11 June", "Yes"],
              ["STH-LT-0388", "Microsoft Entra joined", "Microsoft Intune", "3 November", "11 June", "Yes"],
              ["STH-TAB-09", "Microsoft Entra registered", "Microsoft Intune", "20 February", "2 June", "Yes"],
            ],
            answer: 0,
            why: "Registered on 14 January, nearly four months before the rotation, and active on 11 June. The password changed, and the object carried on answering the device check.",
            learned: "The device predates the rotation and is still enabled.",
          },
          {
            id: "exit",
            ask: "The home working ended in January, so what should have happened? Find the kind of record that takes a device off the tenant.",
            source: "AuditLogs · Records team · This year",
            columns: ["Date", "Activity", "Target", "Actor"],
            rows: [
              ["14 January", "Register device", "DESKTOP-7QK2LM", "d.farrow"],
              ["22 April", "Unregister device", "STH-LT-0190", "h.sorel"],
              ["6 May", "Reset password (by admin)", "d.farrow", "h.sorel"],
              ["14 January", "Add registered owner to device", "DESKTOP-7QK2LM", "d.farrow"],
            ],
            answer: 1,
            why: "Unregister device, on an old laptop. Search this log for DESKTOP-7QK2LM and you get two records, both from the day it arrived. Nobody ever closed it.",
            learned: "A device leaves only through its own record, and this one never got one.",
          },
        ],
      },
    ],
  },
};
