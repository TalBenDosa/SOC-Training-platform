import type { RoomExperience } from "./types";

// "Operation Gatekeeper" for the "identity-basics" room.
// Script: docs/campaign/11-identity-basics.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Caldera Health (fictional). Lab data differs from the graded tasks: the factor
// combos never pair a password with a security question (q1), the credential
// sort asks "is it proof?" rather than "what does stealing it give?" (m1), the
// cleanup duel is the review step on an account already blocked and revoked,
// so it never gives the order (o1), the push-storm log is a real attack
// at another tenant, not ac1's verified helpdesk case, the account sort explains
// how to recognise each type, not why attackers want service accounts (q3), and
// the 4625 burst alert uses other accounts and addresses, never la1's
// b.osei, SRV-FILE03 or 185.220.101.47 (la1, f1).

export const IDENTITY_BASICS: RoomExperience = {
  roomId: "identity-basics",
  codename: "Operation Gatekeeper",
  theme: "identity",
  handler: { name: "Noa Peretz", role: "Identity Security Lead, Caldera Health" },
  briefing: [
    "Caldera Health. Eleven thousand staff, one identity provider, and every door in the company opens through it.",
    "Last night a session token for a radiologist turned up in an infostealer dump. MFA was on. It did not matter.",
    "Noa Peretz runs identity security. She wants an analyst who knows what a login really proves, and what it doesn't.",
    "Prove, permit, issue, revoke. Then read the logs that show all four.",
  ],
  mission: "Work the identity gate: tell authentication from authorization, sort the three kinds of proof, decode a stolen token, review what an attacker left behind after containment, read a push-fatigue attack in Okta's log, and hunt a guessed password through Windows logon events.",
  estimate: "~60 min",
  look: { primary: "#a78bfa", secondary: "#fbbf24", warn: "#f43f5e" },
  scene: "idgate",
  layout: "stage",
  story: {
    intro: { title: "The Token in the Dump", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-intro-3068e998.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-intro-e2aa4f8d.jpg" },
    afterStation: {
      tokens: { title: "What's Inside a Token", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-ch2-de914915.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-ch2-c0918ac2.jpg" },
      contain: { title: "Block, Revoke, Review", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-ch3-9dd42c3b.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-ch3-e13f1802.jpg" },
      logons: { title: "Nine Failures, One Success", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-finale-74b2b779.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/identity-basics/gatekeeper-finale-591c4bdc.jpg" },
    },
  },
  stations: [
    {
      id: "gate",
      label: "Prove It, Then Permit It",
      topic: "Authentication (who you are) vs authorization (what you may do)",
      tagline: "Two checks, two moments: tell which one failed",
      building: "vault",
      taskIds: ["idbasics-r1"],
    },
    {
      id: "factors",
      label: "Three Kinds of Proof",
      topic: "Something you know, have, are · why two of one kind isn't MFA",
      tagline: "Sort the proofs, then judge which logins are really multi-factor",
      building: "lab",
      taskIds: ["idbasics-r2", "idbasics-q1"],
    },
    {
      id: "tokens",
      label: "Credentials and Tokens",
      topic: "Passwords, hashes, keys, certificates · session tokens and what's inside a JWT",
      tagline: "Judge a stolen token by its claims",
      building: "archive",
      taskIds: ["idbasics-r3", "idbasics-m1", "idbasics-r4", "idbasics-q2"],
    },
    {
      id: "contain",
      label: "Shut the Door",
      topic: "Block sign-in, reset, revoke · then review what the attacker left",
      tagline: "The account is locked; find what the attacker planted while inside",
      building: "control",
      taskIds: ["idbasics-r5", "idbasics-o1"],
    },
    {
      id: "mfa",
      label: "The Prompt Storm",
      topic: "What MFA proves · push fatigue · phishable vs phishing-resistant factors",
      tagline: "Read a push-bombing attack in Okta's System Log",
      building: "office",
      taskIds: ["idbasics-r6", "idbasics-ac1"],
    },
    {
      id: "logons",
      label: "Accounts and Their Logons",
      topic: "User, admin, service, machine accounts · events 4624 and 4625 · LogonType",
      tagline: "Hunt a guessed password through the Security log",
      building: "ticket",
      taskIds: ["idbasics-r7", "idbasics-q3", "idbasics-r8", "idbasics-la1", "idbasics-f1"],
      boss: true,
    },
  ],
  personas: {
    "idbasics-q1": { name: "Noa Peretz", role: "Identity Security Lead", line: "A vendor swears their portal has MFA. Look at what it actually asks for." },
    "idbasics-q2": { name: "Noa Peretz", role: "Identity Security Lead", line: "The proxy grabbed the token after she approved MFA. What can the attacker do with it?" },
    "idbasics-q3": { name: "Noa Peretz", role: "Identity Security Lead", line: "Red teams always go for the service accounts. Tell me why." },
    "idbasics-ac1": { name: "Jonas Berg", role: "Service Desk Lead", line: "Five pushes, then an approval. Same pattern as the attack you just read. Is it?" },
  },
  briefings: {
    // ── Reading 1: authentication vs authorization ──
    "idbasics-r1": [
      {
        kind: "sort",
        title: "Which Check Was It?",
        prompt: "Every event below is one of the two checks. Sort each into the gate (who are you?) or the door (may you do this?).",
        buckets: [
          { id: "authn", label: "Authentication: proving who you are" },
          { id: "authz", label: "Authorization: deciding what you may do" },
        ],
        items: [
          { id: "pw", text: "The sign-in page rejects a password for r.alvarez", bucket: "authn", why: "Checking a credential against the record is the identity check itself." },
          { id: "share", text: "j.okafor opens \\\\fs01\\Finance and gets 'Access is denied'", bucket: "authz", why: "She is already signed in. The share's permissions refused her: that's the door, not the gate." },
          { id: "cert", text: "The VPN accepts a laptop's client certificate", bucket: "authn", why: "A certificate signed by a trusted issuer proves which device is connecting." },
          { id: "role", text: "A nurse's account can read patient charts but not edit billing", bucket: "authz", why: "Role-based permissions decide which actions a proven identity may take." },
          { id: "key", text: "A security key is tapped to finish signing in", bucket: "authn", why: "A second factor is still part of proving who you are." },
          { id: "scope", text: "An app's token says scp=Mail.Read, so the API refuses to send mail", bucket: "authz", why: "Scopes inside a token are permissions: what this session may do, checked on every call." },
        ],
      },
    ],
    // ── Reading 2: the three factors ──
    "idbasics-r2": [
      {
        kind: "sort",
        title: "Know, Have, Are",
        prompt: "Each proof belongs to exactly one category. Sort them, then use the categories to judge real logins in the next lab.",
        buckets: [
          { id: "know", label: "Something you know" },
          { id: "have", label: "Something you have" },
          { id: "are", label: "Something you are" },
        ],
        items: [
          { id: "pin", text: "A 6-digit smart-card PIN", bucket: "know", why: "A PIN is a memorised secret, however short." },
          { id: "push", text: "Approving a push in Okta Verify on your phone", bucket: "have", why: "The proof is possession of the enrolled phone." },
          { id: "face", text: "Face recognition on a laptop camera", bucket: "are", why: "A biometric measurement of the person." },
          { id: "totp", text: "A 30-second code from an authenticator app", bucket: "have", why: "The code comes from a seed stored on your device: possession, not memory." },
          { id: "pass", text: "A passphrase like 'correct horse battery staple'", bucket: "know", why: "Long or short, a passphrase is still memorised." },
          { id: "fido", text: "A YubiKey tapped in a USB port", bucket: "have", why: "A physical security key: the classic possession factor." },
          { id: "print", text: "A fingerprint on the reader", bucket: "are", why: "Biometric. It can't be reset if leaked, which is why systems keep only a template, never the image." },
        ],
      },
      {
        kind: "sort",
        title: "Real MFA or Not?",
        prompt: "Six login flows at Caldera's suppliers. Real MFA crosses two different categories. Which ones do?",
        buckets: [
          { id: "mfa", label: "Real MFA: two different categories" },
          { id: "single", label: "Not MFA: one category twice, or one factor" },
        ],
        items: [
          { id: "a", text: "Password, then a code from Microsoft Authenticator", bucket: "mfa", why: "Know + have." },
          { id: "b", text: "Password, then a 4-digit account PIN", bucket: "single", why: "Know + know. Phish one and the same fake page asks for the other." },
          { id: "c", text: "Smart card inserted, then its PIN", bucket: "mfa", why: "Have + know: the card is useless without the PIN, the PIN useless without the card." },
          { id: "d", text: "Fingerprint, then face scan", bucket: "single", why: "Are + are: two biometrics are still one category." },
          { id: "e", text: "Password typed twice to 'confirm identity'", bucket: "single", why: "The same factor, twice. More friction, no more proof." },
          { id: "f", text: "Windows Hello: face unlock of a key stored in the laptop's TPM", bucket: "mfa", why: "Are + have: the biometric unlocks a key bound to that specific device." },
        ],
      },
    ],
    // ── Reading 3: what a credential is ──
    "idbasics-r3": [
      {
        kind: "sort",
        title: "Proof or Just a Name?",
        prompt: "An attacker's dump lists everything it took from one laptop. Which items would a system accept as proof of identity, and which only say who someone is?",
        buckets: [
          { id: "cred", label: "Credential: a system accepts it as proof" },
          { id: "id", label: "Identifier: names someone, proves nothing" },
        ],
        items: [
          { id: "nt", text: "NT hash 8846f7eaee8fb117ad06bdd830b7586c for m.santos", bucket: "cred", why: "NTLM accepts the hash itself. Nobody needs to crack it to use it." },
          { id: "upn", text: "UPN m.santos@calderahealth.example", bucket: "id", why: "A sign-in name. Everyone in her inbox already knows it." },
          { id: "cookie", text: "Browser cookie ESTSAUTHPERSISTENT for login.microsoftonline.com", bucket: "cred", why: "A session cookie is proof of a login that already happened." },
          { id: "pfx", text: "vpn-client.pfx with its private key", bucket: "cred", why: "With the private key, the certificate can sign challenges as its owner." },
          { id: "cer", text: "Caldera-RootCA.cer (public certificate only)", bucket: "id", why: "A public certificate is meant to be shared. Without its private key it signs nothing." },
          { id: "api", text: "AWS access key AKIAIOSFODNN7EXAMPLE with its secret", bucket: "cred", why: "An API key pair authenticates a program, usually with no expiry and no MFA." },
          { id: "sid", text: "SID S-1-5-21-3623811015-3361044348-30300820-1013", bucket: "id", why: "A SID is how Windows names an account internally. It identifies; it doesn't authenticate." },
        ],
      },
    ],
    // ── Reading 4: sessions and tokens ──
    "idbasics-r4": [
      {
        kind: "intercept",
        title: "Token at the Records API",
        prompt: "Noa has put you on the Caldera records API. Every call arrives with a token already decoded for you. A token is a claim sheet: accept the calls whose claims fit this API, reject the ones that do not.",
        protect: "the records API",
        blockLabel: "Reject",
        passLabel: "Accept",
        seconds: 11,
        items: [
          { id: "t1", text: "GET /records/2210", sub: "aud api://caldera-records · scp Records.Read · amr pwd, mfa · exp in 38 min", bad: false, why: "Right audience, a scope that covers a read, MFA recorded in amr and time left on exp. Every claim the API cares about fits." },
          { id: "t2", text: "GET /records/2210", sub: "aud https://graph.microsoft.com · scp Mail.Read · amr pwd, mfa · exp in 20 min", bad: true, why: "A genuine token, but aud names Microsoft Graph. A token minted for another service must not work here, or one stolen mailbox token opens every API." },
          { id: "t3", text: "GET /records/2210", sub: "aud api://caldera-records · scp Records.Read · amr pwd, mfa · exp 3 min ago", bad: true, why: "Every claim is perfect except exp, which is in the past. Expiry is the only thing that limits a stolen token, so it is never skipped." },
          { id: "t4", text: "GET /records/7312", sub: "aud api://caldera-records · scp Records.Read · amr pwd · exp in 50 min", bad: true, why: "Patient records require MFA, and amr lists only pwd. This session was issued from a password alone, whatever the user's account is enrolled for." },
          { id: "t5", text: "GET /records/7312", sub: "aud api://caldera-records · scp Records.Read Records.Write · amr pwd, mfa · ipaddr 203.0.113.9 · exp in 30 min", bad: false, why: "An unfamiliar ipaddr feels wrong, but the API enforces audience, expiry and scope. A new location is a question for the sign-in log and risk policy, not a reason to reject a valid claim sheet here." },
          { id: "t6", text: "GET /records/2210", sub: "aud api://caldera-records · scp Records.Read · amr pwd, mfa · signature invalid, kid not in the tenant keys", bad: true, why: "Claims in a token are only text until the signature checks out. Anyone can write a payload that looks right; the signature is what makes it a claim." },
          { id: "t7", text: "DELETE /records/2210", sub: "aud api://caldera-records · scp Records.Read · amr pwd, mfa · exp in 40 min", bad: true, why: "Authentication is fine, authorization is not: scp grants reads, and this call deletes. The scope is the door, and this one is closed." },
          { id: "t8", text: "GET /records/export", sub: "appid svc-patch · roles Records.Read.All · no user, no amr · exp in 55 min", bad: false, why: "An app token has no amr because no person signed in, so a missing MFA claim is normal here. Its authority is in roles, and Records.Read.All covers the call." },
          { id: "t9", text: "GET /records/2210", sub: "header alg none · no signature part · aud api://caldera-records · exp in 59 min", bad: true, why: "alg none claims no signature is needed. A validator must pin the expected algorithm and keys, never take them from the token." },
          { id: "t10", text: "GET /records/8841", sub: "aud api://caldera-records · scp Records.Read · amr pwd, mfa · nbf 58 min ago · exp in 2 min", bad: false, why: "Two minutes left is still valid. Compare with the expired token: the question is exp against the clock, not how close it is." },
        ],
        lesson: "A token is a claim sheet you check in order: signature first, then aud, exp, scp or roles, and amr when the data demands MFA. App tokens carry roles and no amr, and a strange ipaddr is a detection question rather than a validation failure.",
      },
    ],
    // ── Reading 5: containment, then review ──
    "idbasics-r5": [
      {
        kind: "duel",
        title: "What the Intruder Left",
        prompt: "Maya's account is already blocked, but the on-call needs your review. The intruder planted things while the session was live. Each move below is something still standing: play the one card that removes it.",
        attacker: "The intruder (live session, 11:00 to 12:41 UTC)",
        moves: [
          { id: "d1", move: "A second phone for MFA", detail: "User registered security info at 11:24: an alternateMobile Maya never added.", counter: "kdelphone", hint: "It is a factor the attacker will pass at the next reset.", why: "A planted MFA method turns any later password reset into a clean takeover. Delete the method from the authentication methods list; resetting the password alone leaves it in place." },
          { id: "d2", move: "A rule named with one character", detail: "Inbox rule: forward everything to an outside address, mark as read, move to RSS Feeds.", counter: "krule", hint: "Revoking sessions does not touch mailbox settings.", why: "Rules live in the mailbox, not in the sign-in. Block and revoke leave them running, so remove the rule and check ForwardingSmtpAddress too." },
          { id: "d3", move: "Consent to an app at 11:37", detail: "The app now holds its own tokens for Maya's mail and files.", counter: "kconsent", hint: "The tokens belong to the app, not to her session.", why: "A consent grant gives the app its own refresh tokens that outlive the user's sessions. Remove the consent and the app's access for that user." },
          { id: "d4", move: "A refresh token issued before the block", detail: "Replayed from a new IP: the token was minted at 11:08, with MFA already satisfied.", counter: "krevoke", hint: "Time is on the attacker's side until the validity line moves.", why: "Revoking sign-in sessions moves SignInSessionsValidFromDateTime forward so every earlier refresh token dies, including the stolen one. Check that the line moved after the block." },
          { id: "d5", move: "The password, still known", detail: "Captured on the phishing page at 10:57. The account is blocked, but the password is not changed.", counter: "kreset", hint: "Blocking is a pause, not a change.", why: "Unblock the account later with the old password and the attacker walks back in. Reset it, and clear the planted factor too, so the account is clean before it is unblocked." },
        ],
        cards: [
          { id: "kdelphone", name: "Delete the unknown phone method", effect: "Removes an MFA method the user did not register." },
          { id: "krule", name: "Remove the inbox rule", effect: "Deletes the rule and clears mailbox-level forwarding." },
          { id: "kconsent", name: "Revoke the app consent", effect: "Removes the grant and the app's tokens for this user." },
          { id: "krevoke", name: "Revoke sign-in sessions", effect: "Invalidates every refresh token issued before now." },
          { id: "kreset", name: "Reset the password", effect: "Replaces the secret the attacker captured." },
          { id: "kblock", name: "Block sign-in again", effect: "Disables the account, which is already blocked in this case." },
          { id: "knumber", name: "Turn on number matching", effect: "Hardens future push approvals for the whole tenant." },
        ],
        lesson: "Containment and cleanup are different jobs. Blocking and revoking end the session; the factor, the rule, the consent and the password are separate footholds, and each needs its own removal. The order is: block sign-in first, so no new sign-in or token refresh can succeed; then reset the password and revoke sessions back-to-back; then review what was planted; re-enable last. Resetting or revoking on an account that is still enabled leaves a window: a live stolen token, or a fresh sign-in with the known password.",
      },
    ],
    // ── Reading 6: what MFA proves ──
    "idbasics-r6": [
      {
        kind: "worksheet",
        title: "Read the Prompt Storm",
        prompt: "Okta System Log from another tenant Noa helps run, 02:10 last Sunday. The user called in an hour later. Read what happened, line by line.",
        caption: "Okta System Log · actor a.kowalski@harbourlab.example · user is based in Boston",
        columns: ["published (UTC)", "eventType", "outcome.result", "client.ipAddress", "geo"],
        rows: [
          ["02:10:58", "user.session.start", "FAILURE (MFA required)", "198.51.100.61", "Amsterdam, NL"],
          ["02:11:04", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
          ["02:11:21", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.61", "Amsterdam, NL"],
          ["02:11:40", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
          ["02:11:52", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.61", "Amsterdam, NL"],
          ["02:12:15", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
          ["02:12:31", "user.mfa.okta_verify.deny_push", "FAILURE", "198.51.100.61", "Amsterdam, NL"],
          ["02:13:30", "system.push.send_factor_verify_push", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
          ["02:13:47", "user.authentication.auth_via_mfa", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
          ["02:13:48", "user.session.start", "SUCCESS", "198.51.100.61", "Amsterdam, NL"],
        ],
        questions: [
          { id: "pw", q: "The first line failed only because MFA was required. What does that tell you about the password?", hint: "Okta asks for MFA after the password is accepted.", answer: ["correct", "it was correct", "valid", "known", "stolen", "compromised"], why: "The password was right. Whoever is in Amsterdam at 2 a.m. already has it: reset it whatever else you decide." },
          { id: "deny", q: "How many pushes did the user deny before giving in?", hint: "Count user.mfa.okta_verify.deny_push.", answer: ["3", "three"], why: "Three denials: the user knew something was wrong, then approved the fourth to make it stop. MFA held, until the person didn't." },
          { id: "ok", q: "At what time did the attacker get a session? (HH:MM:SS)", hint: "The last user.session.start.", answer: ["02:13:48"], why: "From 02:13:48 the attacker holds a real, MFA-satisfied session: the same position as a stolen token." },
          { id: "fix", q: "What push setting would have made blind approval much harder? (two words)", hint: "The user has to type a number shown on the sign-in screen.", answer: ["number matching", "number challenge"], why: "Number matching stops tapping 'approve' to silence the phone. It still can't stop a fake page relaying the number: only phishing-resistant factors do that." },
        ],
      },
      {
        kind: "sort",
        title: "Relayable or Bound?",
        prompt: "An adversary-in-the-middle proxy sits between the user and the real sign-in page. Which factors can it relay, and which refuse to work on the wrong domain?",
        buckets: [
          { id: "phish", label: "Phishable: the proxy can relay it" },
          { id: "bound", label: "Phishing-resistant: bound to the real domain" },
        ],
        items: [
          { id: "sms", text: "SMS one-time code", bucket: "phish", why: "The user types it into the fake page; the proxy replays it. SIM swapping adds a second way in." },
          { id: "voice", text: "Phone call: press # to approve", bucket: "phish", why: "Approves whatever sign-in is waiting, including the proxy's." },
          { id: "totp", text: "Authenticator app 6-digit code", bucket: "phish", why: "Off the phone network, but still a code a human can type into the wrong site." },
          { id: "num", text: "Push with number matching", bucket: "phish", why: "The fake page simply shows the number the real page gave the proxy." },
          { id: "fido", text: "FIDO2 security key", bucket: "bound", why: "The key signs a challenge that includes the site's origin. On a look-alike domain it has no credential to use." },
          { id: "passkey", text: "Passkey in the phone's platform authenticator", bucket: "bound", why: "Same WebAuthn binding: the browser only offers it to the domain it was created for." },
          { id: "whfb", text: "Windows Hello for Business", bucket: "bound", why: "A device-bound key with the same origin binding." },
        ],
      },
    ],
    // ── Reading 7: account types ──
    "idbasics-r7": [
      {
        kind: "sort",
        title: "Who Is This Account?",
        prompt: "An export from Caldera's directory. Recognise each account's type from its name and how it is used.",
        buckets: [
          { id: "user", label: "User" },
          { id: "admin", label: "Admin" },
          { id: "svc", label: "Service" },
          { id: "machine", label: "Machine" },
        ],
        items: [
          { id: "m", text: "m.santos · interactive logons 07:50-18:10 on CALD-WS0412", bucket: "user", why: "A person's everyday account, following a working day." },
          { id: "adm", text: "adm-j.reyes · member of Server Operators · logs on only to patch servers", bucket: "admin", why: "A separate privileged account for one person's admin work, kept apart from their daily login." },
          { id: "sql", text: "svc_sqlbackup · logon type 5 (service) on SRV-SQL01 every night at 01:00", bucket: "svc", why: "Named for a job and started by the service controller, not by a person. Service accounts are attractive targets: often over-privileged, rarely rotated, and frequently exempt from MFA because no human can approve a prompt." },
          { id: "ws", text: "CALD-WS0412$ · Kerberos tickets every few hours", bucket: "machine", why: "A trailing $ marks a computer account: the device itself joining in domain services." },
          { id: "gmsa", text: "gmsa_web$ · group managed service account for the IIS app pool", bucket: "svc", why: "Ends in $, but it runs an application. A gMSA is a service account whose password the domain rotates for you." },
          { id: "da", text: "da-noa.p · Domain Admins · smart card required", bucket: "admin", why: "Tier-0 privilege, used rarely, behind a stronger sign-in." },
          { id: "srv", text: "SRV-JUMP02$ · authenticates at boot and on Group Policy refresh", bucket: "machine", why: "The jump server's own computer account." },
        ],
      },
    ],
    // ── Reading 8: Windows authentication events ──
    "idbasics-r8": [
      {
        kind: "tune",
        title: "Set the Guessing Alert",
        prompt: "SRV-JUMP02 is Caldera's RDP jump server, and Noa wants an alert on guessed passwords without paging the desk for every forgotten one. Each row is a burst of 4625 failures against one account. Set how many failures and how tight a window, deploy, and see what the rule caught.",
        eventColumn: "4625 burst on one account",
        dials: [
          { id: "fails", label: "Failures before the alert", short: "failures", unit: "fails", min: 2, max: 15, step: 1, start: 3 },
          { id: "span", label: "All inside this window", short: "window", unit: "min", min: 1, max: 120, step: 1, start: 120, dir: "below" },
        ],
        events: [
          { id: "e1", label: "k.vogel · RDP from 203.0.113.58 · LogonType 3, then a 4624 LogonType 10", bad: true, values: { fails: 9, span: 1 } },
          { id: "e2", label: "svc_scan · one service account hit from one address · NTLM", bad: true, values: { fails: 14, span: 3 } },
          { id: "e3", label: "d.marsh · RDP from 203.0.113.58 · LogonType 3", bad: true, values: { fails: 6, span: 2 } },
          { id: "e4", label: "a.fischer · RDP from 198.51.100.140 · LogonType 3, then a 4624 LogonType 10", bad: true, values: { fails: 7, span: 4 } },
          { id: "e5", label: "t.novak · first Monday after leave, typed an old password", bad: false, values: { fails: 5, span: 2 } },
          { id: "e6", label: "r.imani · new starter, first logon at the desk", bad: false, values: { fails: 4, span: 3 } },
          { id: "e7", label: "h.berg · one typo with caps lock on", bad: false, values: { fails: 3, span: 1 } },
          { id: "e8", label: "m.santos · phone mail app with a stale saved password", bad: false, values: { fails: 7, span: 55 } },
          { id: "e9", label: "svc_patch · scheduled task after a password expiry", bad: false, values: { fails: 11, span: 120 } },
          { id: "e10", label: "reception kiosk · shared logon, staff taking turns", bad: false, values: { fails: 5, span: 40 } },
          { id: "e11", label: "j.cole · old laptop retrying after a reset", bad: false, values: { fails: 8, span: 90 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        deploys: 3,
        lesson: "Guessing is failures packed into a short window, and a raw 4625 count cannot tell it from a stale phone password retrying slowly. Raise the threshold past honest typing and shrink the window until retry loops fall outside it. Over RDP with NLA the failures show LogonType 3, and a success afterward shows 10, RemoteInteractive.",
      },
    ],
    // Drill before the graded file-server record: a 4625 from the jump-server hunt, field by field.
    "idbasics-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a 4625",
        prompt: "Before the graded record, take one of the jump-server failures apart. A 4625 tells you who, from where, how, and exactly why it failed.",
        source: "Windows Security · SRV-JUMP02.caldera.local · Event 4625",
        fields: [
          { key: "TimeCreated", value: "2026-11-04T02:14:51.218Z", label: "When", note: "The event's timestamp, stored in UTC." },
          { key: "TargetUserName", value: "t.lindqvist", label: "Who was tried", note: "The account the attempt claimed to be. On a 4625 it may not even exist." },
          { key: "TargetDomainName", value: "CALDERA" },
          { key: "Status", value: "0xC000006D", label: "Why it failed", note: "Generic 'bad user name or password'." },
          { key: "SubStatus", value: "0xC000006A", label: "The precise reason", note: "Wrong password for an account that exists. 0xC0000064 would mean the account doesn't exist; 0xC0000234 that it's locked out." },
          { key: "LogonType", value: "3", label: "How", note: "Network. With NLA, a failed RDP attempt is checked as a network logon before any desktop opens." },
          { key: "AuthenticationPackageName", value: "NTLM", label: "Protocol", note: "NTLM from an outside address: no Kerberos ticket, and no MFA on this path." },
          { key: "WorkstationName", value: "kali", label: "Client's own name", note: "The attacker's machine announced itself. Attacker-controlled, so useful but never proof." },
          { key: "IpAddress", value: "198.51.100.77", label: "From where", note: "The source to pivot on: every other account this address tried." },
          { key: "IpPort", value: "51844" },
        ],
        summary: "At 02:14:51 an outside machine calling itself 'kali' tried t.lindqvist's password over NTLM and got it wrong. Nine of these, then a success: now read the graded record the same way.",
      },
    ],
  },
};
