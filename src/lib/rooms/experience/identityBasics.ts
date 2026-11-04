import type { RoomExperience } from "./types";

// "Operation Gatekeeper" for the "identity-basics" room.
// Script: docs/campaign/11-identity-basics.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Caldera Health (fictional). Lab data differs from the graded tasks: the factor
// combos never pair a password with a security question (q1), the credential
// sort asks "is it proof?" rather than "what does stealing it give?" (m1), the
// containment console is the review step on an account already blocked and
// revoked, so it never gives the order (o1), the push-storm log is a real attack
// at another tenant, not ac1's verified helpdesk case, the account sort explains
// how to recognise each type, not why attackers want service accounts (q3), and
// the 4625/4624 hunt is RDP on SRV-JUMP02 from 198.51.100.77, never la1's
// b.osei, SRV-FILE03 or 185.220.101.47 (la1, f1).
const JWT =
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" +
  ".eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83ZjNjMmE5MS01ZTRiLTRkOGEtOWMyMS0wYjZlNGY4ZDJhMTcvIiwiaWF0IjoxNzkzNzkwMDAwLCJuYmYiOjE3OTM3OTAwMDAsImV4cCI6MTc5Mzc5NDgwNSwiYW1yIjpbInB3ZCIsIm1mYSJdLCJpcGFkZHIiOiIyMDMuMC4xMTMuNDQiLCJuYW1lIjoiTWF5YSBTYW50b3MiLCJ1cG4iOiJtLnNhbnRvc0BjYWxkZXJhaGVhbHRoLmV4YW1wbGUiLCJzY3AiOiJNYWlsLlJlYWQgRmlsZXMuUmVhZC5BbGwifQ" +
  ".TRAINING-ONLY-not-a-real-signature";
const PAYLOAD =
  "{\"aud\":\"https://graph.microsoft.com\",\"iss\":\"https://sts.windows.net/7f3c2a91-5e4b-4d8a-9c21-0b6e4f8d2a17/\",\"iat\":1793790000,\"nbf\":1793790000,\"exp\":1793794805,\"amr\":[\"pwd\",\"mfa\"],\"ipaddr\":\"203.0.113.44\",\"name\":\"Maya Santos\",\"upn\":\"m.santos@calderahealth.example\",\"scp\":\"Mail.Read Files.Read.All\"}";
const CUT = "cut\\s+-d\\s*['\"]?\\.['\"]?\\s+-f\\s*";
const UPN = "m.santos@calderahealth.example";

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
      tagline: "Decode a stolen token on the command line",
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
        kind: "terminal",
        title: "Decode the Stolen Token",
        prompt: "This token was found in an infostealer dump this morning. A JWT is three base64url parts joined by dots: header, payload (the claims), signature. Decode it and tell Noa what it unlocks.",
        shell: "bash",
        host: "analyst@ir-box:~/case-4471$",
        commands: [
          { match: "cat\\s+token\\.txt", help: "cat token.txt                                  the raw token: header.payload.signature",
            output: JWT },
          { match: CUT + "1\\s+token\\.txt\\s*\\|\\s*base64\\s+(-d|--decode).*", help: "cut -d. -f1 token.txt | base64 -d              decode the header",
            output: "{\"alg\":\"RS256\",\"typ\":\"JWT\"}" },
          { match: CUT + "2\\s+token\\.txt\\s*\\|\\s*base64\\s+(-d|--decode).*\\|\\s*jq.*", help: "cut -d. -f2 token.txt | base64 -d 2>/dev/null | jq .   decode the claims, pretty-printed",
            output: "{\n  \"aud\": \"https://graph.microsoft.com\",\n  \"iss\": \"https://sts.windows.net/7f3c2a91-5e4b-4d8a-9c21-0b6e4f8d2a17/\",\n  \"iat\": 1793790000,\n  \"nbf\": 1793790000,\n  \"exp\": 1793794805,\n  \"amr\": [\n    \"pwd\",\n    \"mfa\"\n  ],\n  \"ipaddr\": \"203.0.113.44\",\n  \"name\": \"Maya Santos\",\n  \"upn\": \"m.santos@calderahealth.example\",\n  \"scp\": \"Mail.Read Files.Read.All\"\n}" },
          { match: CUT + "2\\s+token\\.txt\\s*\\|\\s*base64\\s+(-d|--decode).*", help: "cut -d. -f2 token.txt | base64 -d              decode the claims, raw",
            output: PAYLOAD + "base64: invalid input\n(base64url drops the '=' padding, so base64 complains at the end. The JSON above is complete.)" },
          { match: "date\\s+(-u\\s+)?(-d|--date)\\s*['\"]?@1793794805['\"]?(\\s+-u)?", help: "date -u -d @1793794805                         turn an epoch claim into a UTC time",
            output: "Wed Nov  4 12:20:05 UTC 2026" },
          { match: "date\\s+(-u\\s+)?(-d|--date)\\s*['\"]?@1793790000['\"]?(\\s+-u)?",
            output: "Wed Nov  4 11:00:00 UTC 2026" },
        ],
        objectives: [
          { id: "who", task: "Whose session is this? Give the upn claim.", hint: "cut -d. -f2 token.txt | base64 -d 2>/dev/null | jq .", answer: [UPN], why: "upn is the signed-in user. The token is Maya Santos, a radiologist, as far as Microsoft Graph is concerned." },
          { id: "aud", task: "Which service will accept it (aud)?", hint: "Read the aud claim.", answer: ["https://graph.microsoft.com", "graph.microsoft.com", "microsoft graph", "graph"], why: "aud is the audience: Microsoft Graph, the API behind her mail and files." },
          { id: "scp", task: "What may it do? Name one permission in scp.", hint: "scp holds space-separated scopes.", answer: ["Mail.Read", "Files.Read.All", "Mail.Read Files.Read.All"], why: "Mail.Read and Files.Read.All: whoever holds it can read her mailbox and every file she can see." },
          { id: "amr", task: "Was MFA performed when it was issued? Which amr value says so?", hint: "amr lists the authentication methods used.", answer: ["mfa"], why: "amr [\"pwd\",\"mfa\"]: password and a second factor. The thief never has to pass either; that already happened." },
          { id: "exp", task: "Until what UTC time is it valid? (HH:MM)", hint: "date -u -d @1793794805", answer: ["12:20", "12:20:05"], why: "exp 1793794805 is 12:20:05 UTC: about 80 minutes after iat. Short, but enough to download a mailbox." },
        ],
      },
    ],
    // ── Reading 5: containment, then review ──
    "idbasics-r5": [
      {
        kind: "terminal",
        title: "What Did They Leave Behind?",
        prompt: "The on-call has already contained Maya's account. Your step is the review: check the containment held, then find what the attacker created while the session was live.",
        shell: "powershell",
        host: "PS C:\\IR>",
        commands: [
          { match: "get-mguser\\s+.*", help: `Get-MgUser -UserId ${UPN} -Property AccountEnabled,SignInSessionsValidFromDateTime | Format-List AccountEnabled,SignInSessionsValidFromDateTime   is it contained?`,
            output: "AccountEnabled                  : False\nSignInSessionsValidFromDateTime : 11/4/2026 12:41:07 PM" },
          { match: "get-mgauditlogdirectoryaudit.*", help: `Get-MgAuditLogDirectoryAudit -Filter "targetResources/any(t:t/userPrincipalName eq '${UPN}')" -Top 6 | Format-Table ActivityDateTime,ActivityDisplayName,Result   directory changes to her account`,
            output: "ActivityDateTime      ActivityDisplayName           Result\n----------------      -------------------           ------\n11/4/2026 12:41:07 PM Update user                   success\n11/4/2026 11:37:15 AM Consent to application        success\n11/4/2026 11:24:40 AM User registered security info success\n11/2/2026 6:00:12 AM  Update user                   success" },
          { match: "get-mguserauthenticationphonemethod.*", help: `Get-MgUserAuthenticationPhoneMethod -UserId ${UPN}   phone numbers registered for MFA`,
            output: "Id                                   PhoneNumber     PhoneType       SmsSignInState\n--                                   -----------     ---------       --------------\n3179e48a-750b-4051-897c-87b9720928f7 +1 4255550142   mobile          notConfigured\nb6332ec1-7057-4abe-9331-3d72feddfe41 +44 7700900318  alternateMobile notConfigured" },
          { match: "get-inboxrule\\s+.*\\|\\s*(format-list|fl).*", help: `Get-InboxRule -Mailbox ${UPN} | Format-List Name,Enabled,From,ForwardTo,MarkAsRead,MoveToFolder   every rule, every setting`,
            output: "Name         : Out of office\nEnabled      : False\nFrom         :\nForwardTo    :\nMarkAsRead   : False\nMoveToFolder :\n\nName         : .\nEnabled      : True\nFrom         : {}\nForwardTo    : {\"ledger.sync@outlook-mail.example\" [SMTP:ledger.sync@outlook-mail.example]}\nMarkAsRead   : True\nMoveToFolder : RSS Feeds" },
          { match: "get-inboxrule\\s+.*", help: `Get-InboxRule -Mailbox ${UPN}                   list her mailbox rules`,
            output: "Name          Enabled Priority RuleIdentity\n----          ------- -------- ------------\nOut of office False   1        11392810893418348545\n.             True    2        11392810893418348546" },
        ],
        objectives: [
          { id: "held", task: "From what UTC time are only fresh sign-ins valid? (HH:MM)", hint: `Get-MgUser -UserId ${UPN} -Property AccountEnabled,SignInSessionsValidFromDateTime | Format-List AccountEnabled,SignInSessionsValidFromDateTime`, answer: ["12:41", "12:41:07"], why: "SignInSessionsValidFromDateTime is the revocation line: every refresh token and session issued before 12:41:07 is now dead, including the stolen one." },
          { id: "phone", task: "The attacker registered a second phone for MFA. What number?", hint: `Get-MgUserAuthenticationPhoneMethod -UserId ${UPN}`, answer: ["+44 7700900318", "+447700900318", "07700900318", "7700900318"], why: "An alternateMobile she never added, registered at 11:24 during the stolen session. Left in place, the attacker passes MFA on the next reset. Delete it." },
          { id: "rule", task: "Where does her hidden inbox rule forward mail?", hint: `Get-InboxRule -Mailbox ${UPN} | Format-List Name,Enabled,From,ForwardTo,MarkAsRead,MoveToFolder`, answer: ["ledger.sync@outlook-mail.example"], why: "A rule named '.' that forwards everything, marks it read and hides it in RSS Feeds: classic. Revoking sessions does not delete it; the mail keeps flowing until you do." },
          { id: "consent", task: "What else happened at 11:37 that needs review? (the activity name)", hint: "Read the audit log rows during the session.", answer: ["Consent to application", "consent", "app consent"], why: "A consent grant gives an app its own tokens to her data. Those survive a session revoke, so the grant must be removed separately." },
        ],
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
          { id: "sql", text: "svc_sqlbackup · logon type 5 (service) on SRV-SQL01 every night at 01:00", bucket: "svc", why: "Named for a job and started by the service controller, not by a person." },
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
        kind: "terminal",
        title: "Hunt the Guessed Password",
        prompt: "SRV-JUMP02 is Caldera's RDP jump server, reachable from the VPN pool. The overnight report flagged failures on it. Pull the events and find out whether anyone got in.",
        shell: "powershell",
        host: "PS C:\\Users\\analyst>",
        commands: [
          { match: "get-winevent\\s+.*4625.*(count|group).*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Group-Object {$_.Properties[5].Value} | Select Count,Name   failures per account",
            output: "Count Name\n----- ----\n    9 t.lindqvist\n    1 m.santos" },
          { match: "get-winevent\\s+.*4625.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Select TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[10].Value}},@{n='IP';e={$_.Properties[19].Value}}   failed logons",
            output: "TimeCreated          User        Type IP\n-----------          ----        ---- --\n11/4/2026 2:14:51 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:44 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:37 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:30 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:23 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:16 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:09 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:14:02 AM t.lindqvist    3 198.51.100.77\n11/4/2026 2:13:55 AM t.lindqvist    3 198.51.100.77\n11/3/2026 8:12:40 AM m.santos       3 10.20.31.14" },
          { match: "get-winevent\\s+.*4624.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 4 | Select TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[8].Value}},@{n='IP';e={$_.Properties[18].Value}}   successful logons",
            output: "TimeCreated          User         Type IP\n-----------          ----         ---- --\n11/4/2026 2:15:03 AM t.lindqvist    10 198.51.100.77\n11/4/2026 2:15:02 AM t.lindqvist     3 198.51.100.77\n11/4/2026 1:00:04 AM svc_patch       5 -\n11/3/2026 8:12:58 AM m.santos       10 10.20.31.14" },
        ],
        objectives: [
          { id: "acct", task: "Which account took the burst of failures?", hint: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Group-Object {$_.Properties[5].Value} | Select Count,Name", answer: ["t.lindqvist"], why: "Nine failures in under a minute against one account from one address: guessing, not a typo." },
          { id: "ip", task: "From which IP?", hint: "List the failed logons with their IP.", answer: ["198.51.100.77"], why: "One external address, seven seconds apart: a script, not a person." },
          { id: "in", task: "Did it get in? Give the time of the successful RDP logon (H:MM:SS AM).", hint: "Pull the 4624 events.", answer: ["2:15:03 AM", "2:15:03", "02:15:03"], why: "Twelve seconds after the last failure, a 4624 from the same IP. The guess worked." },
          { id: "type", task: "What LogonType is that success, and what does it mean?", hint: "Read the Type column on the 4624.", answer: ["10", "rdp", "remoteinteractive", "10 rdp", "remote desktop"], why: "10 is RemoteInteractive: a full desktop on the jump server. The failures show 3 because with NLA, RDP checks the password as a network logon before the session opens." },
        ],
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
