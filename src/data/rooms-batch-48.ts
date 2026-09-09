/**
 * Learning Rooms -- Batch 48
 *
 * Closes a P2 coverage gap (topic 8 of 9): Vishing & Voice-Based Social
 * Engineering -- The Help-Desk Attack. T1566.004 (Spearphishing Voice) is
 * already exercised inside this platform's real-time-communication scenario
 * content but had ZERO standalone theory room teaching the vocabulary,
 * attack flow, real incidents, or detection philosophy that content assumes
 * a student already knows. This room is that missing theory.
 *
 * Rooms in this batch:
 *  1. vishing-helpdesk-social-engineering
 *
 * TECHNIQUES COVERED, verified directly against attack.mitre.org at write
 * time (2026-09-09):
 *   - T1566.004 -- Spearphishing Voice, sub-technique of T1566 (Phishing),
 *     Initial Access (TA0001).
 *   - T1656 -- Impersonation, Defense Evasion (TA0005).
 *   - T1078 -- Valid Accounts, verified to carry FOUR tactics: Initial
 *     Access (TA0001), Persistence (TA0003), Privilege Escalation (TA0004),
 *     Defense Evasion (TA0005) -- all four listed throughout this room's
 *     readings, never just one.
 *   - T1621 -- Multi-Factor Authentication Request Generation, Credential
 *     Access (TA0006).
 *   - T1589 -- Gather Victim Identity Information, Reconnaissance (TA0043).
 *   - T1591 -- Gather Victim Org Information, Reconnaissance (TA0043).
 *   - T1098.005 -- Account Manipulation: Device Registration, referenced as
 *     a cross-link to this platform's existing Device Registration & MFA
 *     Persistence room (rooms-batch-27.ts), NOT re-taught in depth here.
 *
 * REAL INCIDENTS covered, with technique(s) each maps to:
 *   - MGM Resorts (10 Sep 2023) -> T1656 -> T1078, via CISA/FBI advisory
 *     AA23-320A (Scattered Spider / UNC3944 / Scatter Swine / Oktapus /
 *     Octo Tempest / Storm-0875 / Muddled Libra).
 *   - Caesars Entertainment (Sep 2023) -> SIM swap + T1656 -> T1078, same
 *     advisory.
 *   - Retool (27 Aug 2023) -> smishing + deepfake T1566.004 -> T1098.005
 *     (cross-linked, not re-taught).
 *   - Twilio (2022, threat cluster alias 0ktapus) -> smishing + T1566.004.
 *   - Cisco (Aug 2022) -> T1621 (MFA-push spam) + T1566.004, per Cisco
 *     Talos's own public incident writeup; attributed to an initial-access
 *     broker linked to the Yanluowang ransomware group.
 *
 * The room's own log_analysis/analyst_choice pair is a FRESH fictional
 * scenario (Solstice Financial Group, employees r.castillo and m.alvarez,
 * help-desk agents j.whitfield and d.nakamura) built on real Microsoft Entra
 * ID audit-log operation names verified directly against Microsoft Learn's
 * "Microsoft Entra audit log activity reference" at write time: "Reset
 * password (by admin)" (UserManagement category, under the Self-service
 * password management section), "Disable Strong Authentication", and
 * "Update user". Fields used (azure.auditlogs.* prefix) are registered in
 * scripts/log-field-registry.json. edr_scope:"non_edr" on both events --
 * this is control-plane identity telemetry with no host process, so no
 * hashDatabase dependency applies. it_verify_result/it_verify_message
 * (never a raw field) is the sanctioned FP-resolution mechanism for the
 * analyst_choice control case, exactly as used elsewhere on this platform.
 * No raw field states a conclusion (e.g. no invented "is_malicious" or
 * "verification_status" field) -- the only verdict-bearing signal is
 * it_verify_result/it_verify_message, which lives at the event level, not
 * inside raw, and is never shown before the student answers.
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK, T1566.004 Spearphishing Voice
 *    (attack.mitre.org/techniques/T1566/004/)
 *  - MITRE ATT&CK, T1656 Impersonation (attack.mitre.org/techniques/T1656/)
 *  - MITRE ATT&CK, T1078 Valid Accounts (attack.mitre.org/techniques/T1078/)
 *  - MITRE ATT&CK, T1621 Multi-Factor Authentication Request Generation
 *    (attack.mitre.org/techniques/T1621/)
 *  - MITRE ATT&CK, T1589 Gather Victim Identity Information
 *    (attack.mitre.org/techniques/T1589/)
 *  - MITRE ATT&CK, T1591 Gather Victim Org Information
 *    (attack.mitre.org/techniques/T1591/)
 *  - CISA/FBI Advisory AA23-320A, Scattered Spider
 *    (cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
 *  - Retool, "A tale of social engineering and a compromised Retool
 *    account" (retool.com/blog/mfa-isnt-mfa)
 *  - Cisco Talos, "Cisco Talos shares insights related to recent cyber
 *    attack on Cisco" (blog.talosintelligence.com/recent-cyber-attack/)
 *  - Microsoft Learn, "Microsoft Entra audit log activity reference"
 *    (learn.microsoft.com/en-us/entra/identity/monitoring-health/
 *    reference-audit-activities)
 *  - Microsoft Learn, "Sign-in event details for Microsoft Entra
 *    multifactor authentication" (learn.microsoft.com/en-us/entra/identity/
 *    authentication/howto-mfa-reporting)
 */

export const roomsBatch48 = [
{
  "id": "vishing-helpdesk-social-engineering",
  "title": "Vishing and Voice-Based Social Engineering: The Help-Desk Attack",
  "description": "Every technical email control this platform's other rooms teach -- SPF/DKIM/DMARC, URL sandboxing, attachment detonation -- inspects a message, and a phone call has no message to inspect. This room covers vishing (voice phishing), MITRE ATT&CK's T1566.004 (Spearphishing Voice), through the single highest-leverage target it exploits inside almost every organization: the IT help desk, whose job is to say yes to a locked-out caller. Follow the full attack arc from LinkedIn-sourced reconnaissance (T1589/T1591) through impersonation (T1656) to a help-desk-performed password or MFA reset and the resulting valid-account access (T1078); study four real, publicly documented incidents -- MGM Resorts and Caesars Entertainment (Scattered Spider/UNC3944, September 2023, per CISA advisory AA23-320A), Retool's 2023 deepfake voice call, and the Twilio/Cisco 2022 MFA-push pattern; read genuine Microsoft Entra ID identity-administration and sign-in log fields for the fingerprints a call leaves behind; and learn the one fact that actually separates a legitimate help-desk reset from a vishing-driven takeover -- an out-of-band identity check the caller cannot control, not the sound of a voice a deepfake can now convincingly fake.",
  "difficulty": "intermediate",
  "category": "Threat Detection",
  "estimatedMinutes": 80,
  "xp": 275,
  "icon": "☎️",
  "prerequisites": [
    "phishing-analysis",
    "auth-identity-monitoring"
  ],
  "tasks": [
    {
      "type": "reading" as const,
      "id": "vish-r0",
      "heading": "What Is Vishing? Voice Phishing and Why the Phone Bypasses Your Email Controls",
      "content": "Vishing (a portmanteau of \"voice\" and \"phishing\") is social engineering conducted over a live phone call or other voice channel, rather than email, text message, or a fake website. The mechanics are the same con any phishing attack runs -- create a plausible pretext, borrow the trust of a real person or organization, and pressure the target into an action they would not take on reflection -- but the delivery medium changes everything about how well an organization's existing security controls can catch it.\n\nEvery technical control this platform's Email Security and Phishing Analysis rooms teach -- SPF/DKIM/DMARC authentication, URL sandboxing, attachment detonation, spam filtering -- inspects a message. A phone call carries no headers, no URLs, and no attachment to scan. There is no equivalent of a mail gateway sitting between the public telephone network and the person answering the phone. This is not a minor gap; it is the entire reason vishing has become one of the most consistently effective initial-access techniques against well-defended organizations. An attacker facing a company with excellent email filtering, strong DMARC enforcement, and a security-aware workforce can simply pick up the phone instead, and none of that investment stops them.\n\n### Vishing Is a Sub-Technique of Phishing, Not a Separate Category\n\nMITRE ATT&CK does not treat vishing as a standalone technique. It is `T1566.004`, Spearphishing Voice, one of four sub-techniques under `T1566`, Phishing (the others being Spearphishing Attachment, Spearphishing Link, and Spearphishing via Service), and it sits under the Initial Access tactic (`TA0001`) -- the same tactic every other phishing sub-technique carries. MITRE's own documentation names this exact vector directly: adversaries use phone calls or other voice communications to solicit information or gain access, often impersonating a trusted entity such as help desk or IT support staff, with named real-world examples including the group Scattered Spider directing victims to install remote monitoring software, and the group Storm-1811 prompting victims to run malicious scripts, both over the phone.\n\n### Why This Room Narrows to One Specific Target: the Help Desk\n\nVishing can target anyone -- a finance employee asked to change a wire transfer's destination account, an executive asked for a \"quick verification\" -- but this room focuses on the single highest-leverage target inside almost every organization: the IT help desk or service desk, the team whose entire job is to lower the barrier for a person who is locked out, and who therefore has a business-justified reason to reset a password, reset a multi-factor authentication (MFA -- a login proof requiring more than one type of evidence, such as a password plus a code from a phone) method, or register a new device on someone else's account. An attacker who successfully impersonates a real employee to that one team does not need to defeat any technical control at all -- they simply ask a human being, whose job is to help, to hand them exactly what they need.\n\n### Deepfake Voice: Raising the Ceiling, Not Changing the Floor\n\nGenerative AI-based voice cloning -- deepfake audio, synthetic speech built from a small sample of someone's real voice -- has started appearing in real, documented vishing incidents, covered later in this room's 2023 Retool case, letting an attacker's call sound like a specific known colleague rather than a generic \"IT support\" caller. This is a real escalation in how convincing a vishing call can be, but it does not change the fundamental countermeasure: none of the defenses this room teaches rely on trusting a voice at all. They rely on verifying identity through a channel and method the caller cannot control -- exactly the discipline this room builds toward.",
      "checkpoint": {
        "question": "Per this reading, under which MITRE ATT&CK tactic and parent technique does T1566.004 (Spearphishing Voice) sit?",
        "options": [
          "It sits under the Initial Access tactic (TA0001), as one of four sub-techniques of T1566, Phishing",
          "It sits under the Defense Evasion tactic (TA0005), as a sub-technique of T1656, Impersonation",
          "It sits under the Credential Access tactic (TA0006), as a sub-technique of T1621, MFA Request Generation",
          "It sits under the Persistence tactic (TA0003), as a sub-technique of T1098, Account Manipulation"
        ],
        "answer": 0,
        "explanation": "This reading states it directly: T1566.004 is Spearphishing Voice, one of four sub-techniques of T1566 Phishing, filed under Initial Access (TA0001) -- the same tactic every other phishing sub-technique carries. T1656 (Impersonation), T1621 (MFA Request Generation), and T1098 (Account Manipulation) are all real, separate techniques this room covers later, but none of them is T1566.004's parent or tactic."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "vish-r1",
      "heading": "The Help-Desk Attack, End to End: From OSINT to Account Takeover",
      "content": "Every real vishing-against-a-help-desk incident this room covers follows the same four-stage arc, whether the target is a casino operator, a software company, or a telecom. Understanding the stages in order is what lets an analyst recognize which stage a piece of evidence belongs to, rather than treating a single reset ticket as the whole story.\n\n### Stage 1: Reconnaissance -- Building a Convincing Identity to Steal\n\nBefore ever placing a call, an attacker gathers exactly the personal and organizational details a help-desk verification script is likely to ask for: full name, job title, manager's name, employee ID format, recent projects, even a home address or the last four digits of a phone number. MITRE ATT&CK names two Reconnaissance-tactic (`TA0043`) techniques for this: `T1589`, Gather Victim Identity Information (personal details about a specific person -- names, credentials, security-question-style answers), and `T1591`, Gather Victim Org Information (organizational structure, departments, and internal terminology that makes an impersonation sound like it comes from inside the building). LinkedIn, a company's own public \"About the team\" page, a data broker site, or an unrelated prior data breach are all realistic sources -- none of this requires hacking anything.\n\n### Stage 2: The Call -- Spearphishing Voice and Impersonation\n\nThe attacker calls the target's help desk (or, in some documented cases, sends a text first to build a pretext before calling). This is `T1566.004`, Spearphishing Voice, and the act of claiming to be someone the agent will trust -- a real, named employee, sometimes even referencing a real manager or ticket number gathered in Stage 1 -- is `T1656`, Impersonation. MITRE places `T1656` under the Defense Evasion tactic (`TA0005`): the impersonation itself is what lets the fraudulent request slip past the human verification step that exists specifically to catch it, the same functional role a spoofed sender header plays in email phishing.\n\n### Stage 3: The Ask -- What the Attacker Actually Requests\n\nOnce the agent believes the caller is legitimate, the request itself is almost always one of three things, and all three appear in this room's real-incident readings: a password reset, so the attacker can sign in with a credential they now control; disabling or resetting the account's existing MFA method, so a stolen or reset password is sufficient on its own; or registering a brand-new authentication method or device on the account, which -- as this platform's Device Registration & MFA Persistence room covers in depth (`T1098.005`, Account Manipulation: Device Registration) -- creates a standing foothold that a later password reset alone will not remove. This room focuses on the moment a help-desk agent performs one of these three actions believing they are helping a real employee; that other room covers what an attacker does with the foothold once obtained.\n\n### Stage 4: The Payoff -- Valid Accounts\n\nWith a reset password, a disabled MFA requirement, or a newly registered device in hand, the attacker signs in using entirely legitimate, working credentials. This is `T1078`, Valid Accounts -- MITRE ATT&CK's own name for exactly this situation, and one of the few techniques listed under four different tactics at once: Initial Access (`TA0001`), Persistence (`TA0003`), Privilege Escalation (`TA0004`), and Defense Evasion (`TA0005`). The reason for all four listings is direct: a valid, working login gets an attacker in the door (Initial Access), keeps working after the original entry point is closed (Persistence), can carry whatever privileges the compromised account already held (Privilege Escalation), and produces a sign-in that looks, to nearly every automated control, identical to the real employee logging in (Defense Evasion) -- because, technically, it is the real employee's account.\n\n### A Second Flavor Worth Knowing: Vishing the Victim Directly\n\nNot every vishing case targets the help desk. A related but distinct pattern -- covered with real examples later in this room -- has the attacker call the actual account owner instead, already holding a valid password from an earlier compromise, and talk them into approving a live MFA push notification the attacker just triggered. MITRE names this specific abuse `T1621`, Multi-Factor Authentication Request Generation, filed under the Credential Access tactic (`TA0006`). The difference matters for an investigator: a help-desk-targeted vishing case leaves its fingerprints in identity-administration logs (who reset what, and who authorized it); an MFA-push vishing case leaves its fingerprints in authentication logs (an approved push the real user did not consciously mean to approve).",
      "checkpoint": {
        "question": "Per this reading, why is T1078 (Valid Accounts) listed under four different MITRE ATT&CK tactics at once?",
        "options": [
          "Because a valid, working login gets an attacker in the door (Initial Access), keeps working after the entry point is closed (Persistence), carries whatever privileges the account already held (Privilege Escalation), and looks identical to the real employee logging in (Defense Evasion)",
          "Because MITRE ATT&CK lists every technique in the Initial Access tactic under three additional tactics automatically, as a fixed rule applied uniformly across the entire framework with no exceptions",
          "Because T1078 is actually four separate, unrelated sub-techniques that merely happen to share the same technique ID number by historical accident in the framework's design",
          "Because a password reset performed by a help-desk agent is, by MITRE's own definition, always classified as all four tactics simultaneously regardless of what the resulting login is later used for"
        ],
        "answer": 0,
        "explanation": "This reading states the reason for each of the four tactics directly: initial entry, surviving remediation, inherited privilege, and blending in as a legitimate login. MITRE does not apply a blanket four-tactic rule to every Initial Access technique (option b is invented and false -- most Initial Access techniques carry only one or two tactics). T1078 is one technique with sub-techniques for account type (Default/Domain/Local/Cloud), not four unrelated techniques sharing an ID (option c). Option d overstates the claim into an absolute rule this reading never makes."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "vish-r2",
      "heading": "Real Incident: MGM Resorts and Caesars, September 2023 (Scattered Spider / UNC3944)",
      "content": "On 10 September 2023, MGM Resorts International -- one of the largest casino and hospitality operators in the United States -- went offline. Slot machines stopped working, hotel room keys stopped programming, and reservation systems failed across MGM's Las Vegas properties, including the MGM Grand and Bellagio. The outage lasted roughly ten days, and public reporting has since estimated MGM's losses at 80 to 100 million dollars. Within days, a related attack hit Caesars Entertainment.\n\n### The Threat Actor\n\nBoth intrusions have been attributed to a financially motivated group that CISA (the U.S. Cybersecurity and Infrastructure Security Agency), the FBI, and security vendors track under several overlapping names: `UNC3944`, `Scattered Spider`, `Scatter Swine`, `Oktapus`, `Octo Tempest`, `Storm-0875`, and `Muddled Libra` -- different organizations' internal labels for activity from the same cluster. CISA and the FBI published a joint advisory on this group, AA23-320A, first released 16 November 2023 and updated as recently as July 2025 as the group's tooling and targeting continued to evolve.\n\n### What Actually Happened at MGM\n\nAccording to CISA's advisory and extensive public post-incident reporting, a Scattered Spider member found an MGM employee's identity on LinkedIn, then called MGM's IT help desk claiming to be that employee and reporting they were locked out. The call reportedly lasted about ten minutes. The help desk's identity-verification process at the time relied substantially on knowledge-based authentication (KBA) -- questions whose answers an attacker can often find or infer from public sources, exactly the kind of information Stage 1 of this room's attack-flow reading (`T1589`/`T1591`) describes gathering in advance. The agent reset the account's credentials, and the attacker used the resulting access to reach MGM's Okta identity environment, then pivoted from there into MGM's broader IT and hospitality-management systems.\n\n### What Happened at Caesars, and Why the Group's Preferred Path Matters\n\nAt Caesars, public reporting describes a similar social-engineering path against an IT help-desk vendor, in some accounts preceded by a SIM swap (convincing a target's mobile carrier to move their phone number onto an attacker-controlled SIM card, defeating SMS-based verification) aimed at high-value accounts before the help-desk call itself. CISA's advisory names this exact combination as one of Scattered Spider's core techniques: after using SIM swaps or vishing to gather information, the group convinces IT help-desk personnel to reset passwords or MFA tokens, taking over single-sign-on (SSO) accounts that then provide broad access across an organization's connected applications.\n\n### The Professional Takeaway\n\nNeither breach involved a software exploit, a phishing email, or malware at the point of initial entry. Every technical control MGM and Caesars had almost certainly deployed -- endpoint detection, email filtering, network segmentation -- was irrelevant to how the attacker got in, because the attacker never touched any of it. The entry point was a phone call to a team whose job is to say yes to people who sound legitimate. This is the exact reason this room exists: the vulnerability was procedural (an identity-verification process an attacker could defeat with public information), not technical, and the fix has to be procedural too.",
      "checkpoint": {
        "question": "Per this reading, what specific weakness in MGM's help-desk verification process did the attacker exploit, and what MITRE ATT&CK techniques does this room's earlier reading assign to gathering the information needed to exploit it?",
        "options": [
          "Knowledge-based authentication (KBA) questions, whose answers an attacker can often find or infer from public sources -- gathered in advance via T1589 (Gather Victim Identity Information) and T1591 (Gather Victim Org Information)",
          "A hardware security key requirement, which the attacker physically stole from the employee's desk the week before making the call to MGM's help desk",
          "A biometric voice-recognition system that the help desk used to verify callers, which the attacker defeated using T1656 (Impersonation) alone with no reconnaissance",
          "An SMS one-time-passcode requirement that the attacker bypassed using T1078 (Valid Accounts) before ever contacting MGM's help desk at all"
        ],
        "answer": 0,
        "explanation": "This reading states the weakness directly: KBA relying on answers findable through public sources, with T1589/T1591 named as the reconnaissance techniques that gather exactly that information in advance. This reading never describes a stolen hardware key (option b), a biometric voice system (option c -- and this room's later reading is explicit that voice itself should never be treated as a verification method), or an SMS bypass preceding the call (option d, which also misuses T1078 as a bypass technique rather than the resulting access)."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "vish-r3",
      "heading": "Real Incidents: Retool's Deepfake Call and the Twilio/Cisco MFA-Push Pattern",
      "content": "Not every vishing case runs through a help desk. Two more public incidents show the technique's range -- one showing the deepfake escalation this room flagged earlier, the others showing the direct MFA-push variant introduced in this room's second reading.\n\n### Retool (27 August 2023) -- Smishing, Then a Deepfake Call\n\nRetool, a software company, disclosed that several employees received a text message impersonating IT support, warning that an account problem would disrupt the employee's healthcare open-enrollment benefits unless they acted. The message (smishing, SMS-based phishing) linked to a page that closely mimicked Retool's own internal identity portal and included a fake MFA-code entry field. One employee entered credentials and an MFA code there. Shortly after, the same employee received a phone call from someone identifying themselves as a member of Retool's IT team -- using a voice reportedly cloned (deepfaked) to resemble a real, specific colleague, and conversant enough about the office layout and coworkers to sound credible. The employee grew suspicious partway through the call but still supplied one additional MFA code before ending it. That single additional code was enough: Retool has publicly stated the attacker used the access to register their own MFA method on the employee's account -- the same `T1098.005` persistence mechanism this platform's companion room covers in depth -- reaching internal systems and ultimately 27 of Retool's cloud customers, all in the cryptocurrency industry. Retool notified affected customers on 29 August 2023.\n\n### Twilio (2022) and Cisco (2022) -- MFA-Push Vishing\n\nTwilio, a cloud communications company, was targeted across mid-2022 by a group tracked as `0ktapus` -- one of the same aliases CISA's advisory lists for the broader Scattered Spider cluster. In late June, a caller impersonating Twilio's IT team convinced an employee to hand over working credentials directly, producing roughly twelve hours of unauthorized access to customer contact data. Weeks later, a large smishing campaign texted current and former employees fake IT alerts containing password-reset links that led to convincing fake login pages. The confirmed impact reached 209 of Twilio's then more than 270,000 customers and 93 end users of Authy, Twilio's own consumer authentication app.\n\nCisco's August 2022 incident began differently -- an employee had synced Cisco credentials into a personal Google account via a browser's password-sync feature, and that personal account was compromised first, giving the attacker a working Cisco password with no vishing involved yet. Getting past MFA is where vishing entered: Cisco's own incident-response team (Talos) reported that the attacker ran a sustained combination of MFA-push spam (triggering repeated authentication prompts, hoping the employee would eventually tap \"approve\" just to stop the notifications -- the pattern MITRE names `T1621`) together with voice-phishing calls impersonating a range of trusted organizations, aimed at convincing the employee to approve one of those pushes. The attacker was eventually let in. Talos found no evidence the intrusion reached Cisco's most sensitive internal systems, such as product development or code-signing infrastructure, and publicly linked the activity to an initial-access broker associated with the Yanluowang ransomware group.\n\n### Why This Pair of Cases Belongs Next to MGM and Caesars\n\nMGM and Caesars show vishing aimed at a help desk, producing a reset or registration performed by someone else on the victim's behalf. Retool, Twilio, and Cisco show the second flavor this room's earlier reading named: vishing aimed straight at the account owner, either to harvest a credential and code directly or to talk them into approving an authentication prompt the attacker already triggered. An analyst who only watches for suspicious help-desk tickets will miss this second pattern entirely -- it never touches a help-desk queue at all.",
      "checkpoint": {
        "question": "Per this reading, what specifically made the deepfake element in the Retool incident significant, compared to a generic IT-impersonation call?",
        "options": [
          "The cloned voice resembled a real, specific colleague and the caller was conversant about office layout and coworkers, which kept the call credible even after the employee grew suspicious partway through",
          "The deepfake voice was used to defeat a biometric voice-recognition lock on Retool's building, allowing the attacker physical entry to the office before making any phone call at all",
          "Retool's own security team stated that the deepfake was technically indistinguishable from a live phone connection, making detection during the call itself completely impossible",
          "The deepfake call was the very first stage of the Retool incident, with no smishing or any other message ever sent to any employee at any point before this call took place"
        ],
        "answer": 0,
        "explanation": "This reading states the significance directly: a cloned voice resembling a real, specific colleague, familiar with real office details, kept the call credible enough that the employee -- despite growing suspicious -- still supplied one more MFA code. Retool's biometric building access (option b) is never mentioned or implied. This reading does not claim the deepfake was 'technically indistinguishable' in some absolute sense (option c). Option d reverses the actual sequence -- the smishing message with the fake identity-portal link came FIRST, and the deepfake call followed it."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "vish-q1",
      "question": "An analyst reconstructs a suspected vishing case: an attacker found an employee's name and manager on LinkedIn, then called the help desk claiming to be that employee, and the agent reset the account's password. Which two MITRE ATT&CK techniques describe the LinkedIn research step and the impersonation-during-the-call step, and under which tactics does each sit?",
      "options": [
        "T1589 (Gather Victim Identity Information) under Reconnaissance (TA0043) for the LinkedIn research, and T1656 (Impersonation) under Defense Evasion (TA0005) for claiming to be the employee during the call",
        "T1566.004 (Spearphishing Voice) under Initial Access for the LinkedIn research, and T1078 (Valid Accounts) under Persistence for the impersonation during the call",
        "T1591 (Gather Victim Org Information) under Collection for the LinkedIn research, and T1621 (MFA Request Generation) under Credential Access for the impersonation during the call",
        "T1098.005 (Device Registration) under Persistence for the LinkedIn research, and T1589 (Gather Victim Identity Information) under Reconnaissance for the impersonation during the call"
      ],
      "answer": 0,
      "explanation": "This room's attack-flow reading assigns these two steps exactly this way: LinkedIn-based research is T1589 (Gather Victim Identity Information) under Reconnaissance (TA0043), and claiming to be a real employee on the call is T1656 (Impersonation) under Defense Evasion (TA0005). Option b assigns the wrong technique to each step and the wrong tactic to T1078 (which carries Initial Access/Persistence/Privilege Escalation/Defense Evasion, never alone under Persistence for an impersonation act). Option c places T1591 under a nonexistent 'Collection' assignment for this technique and misapplies T1621, which describes MFA push generation, not a help-desk impersonation call. Option d swaps in T1098.005, a post-access persistence technique, for reconnaissance that happens before any access exists at all.",
      "xp": 25
    },
    {
      "type": "matching" as const,
      "id": "vish-m1",
      "heading": "Match Each Real Incident to Its Primary Vishing Mechanism",
      "instructions": "Match each real, publicly documented incident this room covers to the mechanism this room's readings describe as its primary attack path.",
      "pairs": [
        {
          "id": "p1",
          "left": "MGM Resorts (September 2023)",
          "right": "A roughly ten-minute help-desk impersonation call led to a password reset that opened access into MGM's Okta identity environment"
        },
        {
          "id": "p2",
          "left": "Caesars Entertainment (September 2023)",
          "right": "SIM swapping combined with help-desk social engineering convinced IT support to reset passwords or MFA tokens on high-value SSO accounts"
        },
        {
          "id": "p3",
          "left": "Retool (August 2023)",
          "right": "SMS phishing harvested an MFA code, then a deepfake voice call impersonating a real colleague obtained one additional MFA code"
        },
        {
          "id": "p4",
          "left": "Cisco (August 2022)",
          "right": "MFA-push spam combined with voice-phishing calls convinced the account owner directly to approve a login the attacker had already triggered"
        }
      ],
      "explanation": "Each pairing matches this room's incident readings exactly: MGM's help-desk call led directly to a password reset and Okta access; Caesars combined SIM swapping with help-desk social engineering targeting SSO accounts; Retool combined smishing with a deepfake vishing call to extract a second MFA code; and Cisco's attacker, already holding a stolen password, used MFA-push spam plus vishing aimed at the account owner rather than a help desk at all. The MGM/Caesars pair and the Retool/Cisco pair illustrate this room's two distinct flavors: vishing a help desk to act on your behalf, versus vishing the account owner directly.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "vish-r4",
      "heading": "Post-Call Fingerprints: What Actually Shows Up in the SIEM",
      "content": "The phone call itself leaves no trace anywhere a SOC (Security Operations Center) can see -- no log source in this platform, or in any real identity provider, records the content of a voice call. Everything an analyst investigating a suspected help-desk vishing case actually works from is what happened immediately before and after the call, inside systems that do log.\n\n### Signal 1: The Identity-Administration Action Itself\n\nMicrosoft Entra ID (the identity platform behind Microsoft 365 and Azure) logs every account-administration action to its audit log, under the `UserManagement` category. Three specific operation names matter most here: `Reset password (by admin)` -- a help-desk or admin-role account resetting someone else's password, distinct from `Reset password (self-service)`, which the account holder triggers themselves; `Disable Strong Authentication` -- removing an account's existing MFA requirement outright, sometimes used by a help desk to \"unblock\" someone who claims to have lost their MFA device; and `Update user`, which covers changes to account attributes including a registered phone number -- relevant because a registered phone number can itself be an MFA method or an account-recovery destination.\n\n### Signal 2: Who Actually Performed the Action\n\nEvery Entra ID audit record carries an `initiatedBy.user` block naming who performed the action, including their `id`, `userPrincipalName` (their login identity), and `roles` -- the directory role(s) their account held at the time. Two comparisons matter: whether `initiatedBy.user.id` matches the affected account's own ID under `targetResources[0].id` (a match means self-service -- the account holder did this to their own account; a mismatch means someone else acted on the account), and whether `initiatedBy.user.roles` is populated with an administrative role such as Helpdesk Administrator or Authentication Administrator (present specifically when an admin, rather than a peer employee, performed the action). A `Reset password (by admin)` record where the initiating role is Helpdesk Administrator and the target is a different user is exactly the shape a legitimate help-desk-assisted reset takes -- and, indistinguishably at this layer alone, exactly the shape a successful vishing call against that same help desk takes too. Neither the operation name nor the role field can tell the two apart on its own; this room's next reading covers what can.\n\n### Signal 3: What Happens on the Account Immediately Afterward\n\nThe decisive corroborating evidence usually sits in the sign-in logs that follow. Entra ID's sign-in log records, per attempt, the source `ipAddress`, `location.city` and `location.countryOrRegion`, `deviceDetail.deviceId` and `deviceDetail.trustType` (whether the device is Entra-joined, hybrid-joined, or unmanaged), `riskState` and `riskLevelDuringSignIn` (Microsoft's own automated risk scoring for that specific sign-in), and `authenticationRequirement` (whether MFA was actually satisfied on that attempt, or waived). A password reset followed within minutes by a successful sign-in from a device ID the account has never used before, from a country the account's normal history never shows, is the single strongest post-call fingerprint this room can offer -- the identity-administration action created the opportunity, and the sign-in log shows someone immediately using it.\n\n### The Timing Window Is the Correlation\n\nNone of these three signals alone proves a vishing case. What makes the pattern legible is timing: a `Reset password (by admin)` or `Disable Strong Authentication` record, followed -- usually within minutes to a few hours, not days -- by a sign-in or a new MFA registration that does not match the account's established device and location history. This room's log-analysis and analyst-choice tasks are both built around reading exactly that timing relationship correctly.",
      "checkpoint": {
        "question": "Per this reading, which two fields together indicate that a password reset was performed by an ADMIN acting on someone else's account, rather than the account holder resetting their own password?",
        "options": [
          "initiatedBy.user.id differing from targetResources[0].id, combined with initiatedBy.user.roles containing an administrative role such as Helpdesk Administrator",
          "riskLevelDuringSignIn and authenticationRequirement, since these two sign-in log fields alone directly record who performed a password reset action",
          "deviceDetail.trustType and location.countryOrRegion, since a reset performed from an untrusted device in an unfamiliar country is definitionally always admin-performed",
          "event.outcome and operationType, since a reset event recording a successful outcome is, by itself, sufficient proof that an administrator rather than the account holder performed it"
        ],
        "answer": 0,
        "explanation": "This reading names exactly this pairing: a mismatch between initiatedBy.user.id and targetResources[0].id (someone else acted on the account) together with an administrative role present in initiatedBy.user.roles. riskLevelDuringSignIn and authenticationRequirement are sign-in log fields covering a later, separate event, not the reset action's actor (option b). deviceDetail.trustType and location describe the SIGN-IN that follows, not who performed the reset, and carry no such absolute rule (option c). event.outcome and operationType describe whether the action succeeded and what kind of change it was, not who initiated it (option d)."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "vish-r5",
      "heading": "The Discriminator: Telling a Legitimate Help-Desk Reset From a Vishing Takeover",
      "content": "Reading the raw identity-administration and sign-in logs, as the previous reading covered, narrows a suspicious case down -- but it cannot, by itself, produce a verdict, because a completely legitimate help-desk reset produces some of the identical fields a vishing-driven one does: an admin-role actor, a different target user, and even, sometimes, a new device shortly after (an employee genuinely getting a replacement phone is a routine event this platform's Device Registration & MFA Persistence room covers directly). The fact that actually resolves the case almost never lives in the identity platform's own logs at all -- it lives in whatever the help desk's own verification process actually did before acting.\n\n### Why Knowledge-Based Authentication Fails Against a Prepared Attacker\n\nKnowledge-based authentication (KBA) -- verifying a caller's identity by asking questions only the \"real\" employee should know, such as an employee ID, a manager's name, a home address, or the last four digits of a phone number -- is exactly what MGM's help-desk process reportedly relied on in 2023, and exactly what a Stage 1 reconnaissance effort (`T1589`/`T1591`, from this room's second reading) is specifically built to defeat in advance. If the answer to a verification question can be found on LinkedIn, in a prior breach dump, or through a few minutes of pretexting a different department, it verifies nothing.\n\n### What Actually Works: Out-of-Band Callback Verification\n\nThe countermeasure that resolves nearly every real case is callback verification through a channel the caller does not control: the help-desk agent ends the inbound call, looks up the phone number already on file for that employee in the organization's own HR or identity system (never a number the caller supplies), and calls that number back before taking any action. A caller who is genuinely the employee answers their own known phone. An attacker calling from a spoofed or unrelated number cannot intercept a callback to a number they were never given. Other solid alternatives include a live video check against a badge photo already on file, or requiring a manager's independent, out-of-band confirmation for any password or MFA change on a privileged account.\n\n### The Trap: Escalating Every Reset After Learning About MGM\n\nA student who has just read three high-profile vishing breaches is primed to treat any `Reset password (by admin)` or `Disable Strong Authentication` record as inherently suspicious. That overcorrection is exactly wrong: help desks perform legitimate resets constantly, for people who are genuinely locked out, and flooding a queue with escalations on every one destroys the signal-to-noise ratio that makes a SOC useful at all. The single question that actually resolves a case is narrow and specific: did the help desk complete a genuine out-of-band identity check -- a callback to a known number, a video/badge check, or independent manager confirmation -- before acting, and is that check documented? This room's analyst-choice task is built to test exactly that judgment, using this platform's `it_verify_result` / `it_verify_message` mechanism to represent a completed, documented verification outcome the same way every other room on this platform does.",
      "checkpoint": {
        "question": "Per this reading, what is the specific weakness of knowledge-based authentication (KBA) that makes it unreliable against a vishing caller, and what actually resolves the ambiguity instead?",
        "options": [
          "KBA answers (employee ID, manager's name, home address) can often be found through the same reconnaissance (T1589/T1591) an attacker performs in advance -- what resolves the case is a documented out-of-band check, such as a callback to a number already on file",
          "KBA is unreliable because it requires expensive hardware tokens that most help desks cannot afford to issue -- what resolves the case is simply asking the caller to repeat their answers a second time",
          "KBA is unreliable only when conducted in a language other than English -- what resolves the case is requiring the caller to speak in their verified native language",
          "KBA is unreliable because it was deprecated by NIST in 2020 and is no longer a recognized verification method at all -- what resolves the case is any password reset performed outside business hours"
        ],
        "answer": 0,
        "explanation": "This reading states the weakness precisely: KBA answers are exactly the kind of information T1589/T1591 reconnaissance gathers in advance, and the resolving control is a documented out-of-band check like a callback to a number already on file. KBA has nothing to do with hardware token cost (option b -- KBA is knowledge-based, not hardware-based, by definition). Language is never mentioned as a factor anywhere in this room (option c is invented). NIST has raised concerns about certain authenticator types over the years, but this reading never states KBA was formally 'deprecated,' and business hours are never named as a resolving fact in this room (option d)."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "vish-q2",
      "question": "Incident A: an attacker who already held a stolen password called the employee directly to get them to approve a live MFA push. Incident B: an attacker called the company's help desk, impersonating the employee, to get an agent to reset the account's password and MFA method. Based on this room's incident readings, which technique and log-source pairing correctly matches each incident?",
      "options": [
        "Incident A matches T1621 (MFA Request Generation), visible in authentication/sign-in logs; Incident B matches T1656 (Impersonation) leading to T1078 (Valid Accounts), visible in identity-administration audit logs",
        "Incident A matches T1078 (Valid Accounts), visible in identity-administration audit logs; Incident B matches T1621 (MFA Request Generation), visible in authentication/sign-in logs",
        "Both incidents match T1566.004 (Spearphishing Voice) alone, and this room's readings state that both produce the identical log signature in the identical log source",
        "Incident A matches T1098.005 (Device Registration), visible in DNS logs; Incident B matches T1589 (Gather Victim Identity Information), visible in firewall logs"
      ],
      "answer": 0,
      "explanation": "This room's Twilio/Cisco reading covers exactly Incident A's pattern (calling the account owner directly to approve a push) as T1621, visible in authentication/sign-in logs. This room's MGM/Caesars reading covers exactly Incident B's pattern (calling the help desk to get someone else to act) as T1656 leading to T1078, visible in identity-administration audit logs. Option b swaps the two pairings entirely. Option c is false -- this room's post-call-fingerprints reading is explicit that these two flavors leave fingerprints in DIFFERENT log sources, not identical ones. Option d assigns technique IDs and log sources this room never connects to either incident (DNS and firewall logs play no role in either pattern as described).",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "vish-r6",
      "heading": "Professional Detection: Correlation Rules and a Callback-Verification Policy",
      "content": "Reading identity-admin logs and sign-in logs side by side manually does not scale past a handful of suspected cases a day. A detection engineer's job is to turn the timing relationship the previous two readings described into a standing correlation rule that raises its own alert, without a human having to think to go looking.\n\n### The Shape of the Rule\n\nThe rule joins two data sources on the same account, within a bounded time window: an Entra ID audit-log event whose operation name is `Reset password (by admin)` or `Disable Strong Authentication`, and a subsequent Entra ID sign-in-log event for the same user whose device ID has no prior history for that account, or whose country does not match the account's established baseline. Expressed as pseudocode close to how Microsoft Sentinel's Kusto Query Language (KQL) would express it:\n\n```\nAuditLogs\n| where OperationName in (\"Reset password (by admin)\", \"Disable Strong Authentication\")\n| where InitiatedBy.user.roles has_any (\"Helpdesk Administrator\", \"Authentication Administrator\")\n| project ResetTime = TimeGenerated, TargetUser = TargetResources[0].userPrincipalName\n| join kind=inner (\n    SigninLogs\n    | project SignInTime = TimeGenerated, UserPrincipalName,\n              DeviceId = tostring(DeviceDetail.deviceId),\n              Country = tostring(LocationDetails.countryOrRegion)\n  ) on $left.TargetUser == $right.UserPrincipalName\n| where SignInTime between (ResetTime .. ResetTime + 4h)\n| where DeviceId !in (KnownDeviceIds) or Country != BaselineCountry\n```\n\nThe exact field and table names vary by platform, but the shape is universal: an admin-performed identity change, then a bounded time window, then a login-context field that does not match the account's own history.\n\n### Why a Bounded Window Matters\n\nSetting the window too wide (days) produces false correlations with routine, unrelated activity; setting it too narrow (seconds) misses a patient attacker who waits before using fresh access. Public reporting on the MGM incident describes the attacker moving from the initial help-desk reset into Okta and onward within the same operational period, not days later -- a multi-hour window is a reasonable, evidence-grounded starting point, tuned against an organization's own baseline of how quickly employees typically sign back in after a legitimate reset.\n\n### The Policy Half: What a Help Desk Should Actually Require\n\nThe correlation rule catches what already happened; a callback-verification policy is what prevents it from happening at all. A minimum, auditable policy for any password reset, MFA reset, or device registration performed by help-desk staff on someone else's behalf should require, and log: the specific out-of-band method used (callback to a number on file, video/badge check, or manager confirmation -- never a number or email address the caller supplies live on the call), the identity of the person who performed that verification, and a ticket reference tying the verification to the account action. When that documentation exists and holds up, a reset is resolved as legitimate quickly and confidently. When it does not exist, or the \"verification\" amounts to KBA answers alone, the case escalates -- exactly the judgment this room's analyst-choice task is built to exercise.",
      "checkpoint": {
        "question": "Per this reading's correlation-rule pseudocode, what THREE conditions together must be true for the rule to fire?",
        "options": [
          "An admin-role password reset or MFA-disable event on an account, followed within a bounded time window by a sign-in from that same account using a device ID or country not seen in the account's prior history",
          "Any password reset event at all, occurring at any time, from any account, regardless of who performed it or what happens on the account afterward",
          "A sign-in from a new device, occurring at any time before OR after a password reset, with no requirement that the two events belong to the same user account",
          "An MFA-disable event performed by the account holder themselves (self-service), followed by a sign-in from that same account's own previously known device"
        ],
        "answer": 0,
        "explanation": "The pseudocode's three conditions are exactly this: an admin-role reset or MFA-disable operation, a bounded time window (4 hours in the example), and a subsequent sign-in whose device or country does not match the account's baseline. Option b drops the admin-actor and anomaly conditions entirely, which would make the rule fire constantly on routine activity. Option c drops the same-account join, which the pseudocode's 'on $left.TargetUser == $right.UserPrincipalName' line explicitly requires. Option d describes a routine, self-service, no-anomaly case -- the opposite of what this rule is built to catch."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "vish-r7",
      "heading": "Hardening the Help Desk: The Limits of Voice Verification in the Deepfake Era",
      "content": "Everything this room has covered so far is about recognizing a vishing-driven takeover after it happens. The organizational question is how to make the attack harder to pull off in the first place -- and here, the honest answer includes an uncomfortable admission about what does not work as well as people assume.\n\n### What CISA's Own Advisory Actually Recommends\n\nCISA's joint advisory on this threat cluster (AA23-320A) is direct about its top mitigation: implement phishing-resistant MFA -- specifically FIDO/WebAuthn or PKI-based (Public Key Infrastructure) authentication -- because, in the advisory's own words, these methods \"are resistant to phishing and not susceptible to push bombing or SIM swap attacks.\" A FIDO2 security key or passkey cannot be intercepted by a SIM swap, cannot be approved by an exhausted user tapping the wrong button, and is not a code an employee can accidentally read aloud to a caller. The advisory also names user training against vishing and spearphishing specifically, and enforcing NIST-standard password policies (length, no reuse, lockout thresholds) as complementary layers. Notably, the advisory does not lay out a specific help-desk callback procedure as a named mitigation -- that particular control is an industry best practice this room draws from post-incident reporting and analyst consensus, not a direct CISA prescription, and it is worth being precise about which claim comes from which source.\n\n### The Honest Limit: Voice Itself Is Not a Verification Method\n\nThe single most important hardening principle this room can offer is a negative one: no help-desk process should ever treat \"the caller sounded right\" or \"I recognized the voice\" as a verification step on its own. The Retool incident earlier in this room is the direct, documented proof of why -- a cloned voice sounded convincingly like a real, specific colleague, familiar with real office details, and still nearly succeeded outright. Voice authenticity is not a control; it is exactly the surface an attacker is now equipped to fake.\n\n### Practical Layers That Do Not Depend on Trusting a Voice\n\nBeyond phishing-resistant MFA, the controls that hold up are the ones this room's earlier reading already named: out-of-band callback to a number already on file, a live video/badge check against a photo on record, and independent manager confirmation for any action on a privileged account -- each one verifies identity through a channel the caller cannot redirect, rather than through anything the caller says or sounds like. A further structural control worth naming: restricting what a help-desk role can do unilaterally. An organization that requires a second approver for any full MFA disablement on a privileged account, rather than letting one help-desk agent both verify and act alone, closes the exact single point of failure MGM's ten-minute call exploited.\n\n### Why This Belongs at the End of This Room\n\nDetection, the previous readings' focus, tells an analyst what already happened. Hardening tells an organization how to make the next call fail before it produces anything for an analyst to find at all. Both matter, and a mature SOC pushes findings from the first back into changes in the second.",
      "checkpoint": {
        "question": "Per this reading, what does CISA's AA23-320A advisory name as its top mitigation against this threat cluster's vishing and MFA-abuse tactics, and why specifically?",
        "options": [
          "Phishing-resistant MFA using FIDO/WebAuthn or PKI-based authentication, because the advisory states this type is resistant to phishing and not susceptible to push bombing or SIM swap attacks",
          "A mandatory biometric voice-recognition check for every help-desk call, because the advisory states voice biometrics cannot be defeated by any known deepfake technology",
          "A 24-hour mandatory waiting period before any password reset takes effect, because the advisory states this specific waiting period is sufficient to stop every case in this room",
          "Disabling all remote help-desk password resets permanently, because the advisory states in-person-only identity verification is the sole mitigation it recommends for any organization"
        ],
        "answer": 0,
        "explanation": "This reading quotes the advisory directly: phishing-resistant MFA (FIDO/WebAuthn or PKI-based) is resistant to phishing and not susceptible to push bombing or SIM swap attacks. This reading explicitly warns AGAINST trusting voice as a verification method at all (option b is the opposite of this reading's point, and no such CISA claim exists). No 24-hour waiting period is mentioned anywhere in this room (option c is invented). The advisory does not call for eliminating remote resets entirely (option d overstates it into a claim this reading never makes)."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "vish-q3",
      "question": "A help-desk agent resets an employee's password after a phone call. The audit record shows initiatedBy.user.roles containing Helpdesk Administrator, a target user different from the initiator, and a sign-in from a new device 20 minutes later. Per this room, what single additional fact would most reliably resolve whether this was a legitimate reset or a vishing-driven takeover?",
      "options": [
        "Whether the agent completed and documented an out-of-band identity check -- a callback to the number already on file, a video/badge check, or manager confirmation -- before performing the reset",
        "Whether the reset was completed during standard business hours rather than overnight, since this room establishes business-hours timing as the deciding factor in every comparable case",
        "Whether the new device that signed in afterward is a mobile phone rather than a laptop, since this room establishes device category alone as sufficient to resolve any comparable case",
        "Whether the employee whose account was reset has ever contacted the help desk before this specific incident, since this room treats prior contact history as the deciding factor"
      ],
      "answer": 0,
      "explanation": "This room's discriminator reading is explicit: the fact that actually resolves the case is whether a documented out-of-band verification occurred, not anything visible in the audit record alone. Business-hours timing is never established as a deciding factor anywhere in this room (option b is invented, and this room's own analyst-choice and log-analysis cases do not turn on time of day). Device category (phone vs. laptop) is never treated as decisive either (option c). Prior help-desk contact history is not a fact this room names as relevant at all (option d).",
      "xp": 25
    },
    {
      "type": "ordering" as const,
      "id": "vish-o1",
      "heading": "Reconstruct the Vishing-to-Takeover Chain",
      "instructions": "Put these five stages of a help-desk vishing attack, as this room's reading described them, into the order they actually occur.",
      "items": [
        {
          "id": "recon",
          "text": "Attacker gathers the target's name, manager, and internal details from LinkedIn and public sources (T1589 / T1591)"
        },
        {
          "id": "call",
          "text": "Attacker calls the help desk, impersonating the employee (T1566.004 + T1656)"
        },
        {
          "id": "ask",
          "text": "Help-desk agent, believing the caller, resets the password and/or disables MFA"
        },
        {
          "id": "login",
          "text": "Attacker signs in using the now-valid credentials (T1078)"
        },
        {
          "id": "persist",
          "text": "Attacker registers their own MFA method on the account, so a later password reset alone will not remove their access (T1098.005)"
        }
      ],
      "correct_order": [
        "recon",
        "call",
        "ask",
        "login",
        "persist"
      ],
      "explanation": "This is the exact four-stage arc this room's second reading walked, with the optional fifth persistence step this room cross-references to the Device Registration & MFA Persistence room: reconnaissance builds the identity to steal (T1589/T1591), the call and impersonation follow (T1566.004 + T1656), the help desk performs the requested reset believing the caller, the attacker signs in with now-valid credentials (T1078), and only after all of that can the attacker optionally register their own MFA method to outlast a later remediation attempt (T1098.005). Reversing recon and the call would require the attacker to already know details they have not yet gathered; performing the reset before the call has no impersonation to act on; and registering a persistence method requires the working access that only comes after a successful login.",
      "xp": 30
    },
    {
      "type": "log_analysis" as const,
      "id": "vish-la1",
      "heading": "Investigate: A Password Reset Requested by Phone",
      "context": "You are reviewing Solstice Financial Group's Entra ID audit log. A help-desk ticket closed a few minutes ago for a password reset on r.castillo's account. There is no host telemetry for this event -- it is entirely a control-plane, identity-administration record.",
      "event": {
        "id": "evt-vish-la1-001",
        "ts": "2026-07-14T14:07:00.000Z",
        "source": "o365",
        "vendor": "Microsoft Entra ID",
        "event_type": "account_modify",
        "severity": "high",
        "mitre_technique": "T1656",
        "mitre_tactic": "Defense Evasion",
        "edr_scope": "non_edr",
        "user_email": "r.castillo@solsticefg.com",
        "src_ip": "198.51.100.44",
        "geo": {
          "country": "United States",
          "city": "Chicago"
        },
        "description": "Solstice Financial Group's IT help desk received a call at 14:02 from someone identifying themselves as r.castillo, reporting he was traveling and had lost his phone. Agent j.whitfield reset the account's password during the call. The ticket notes on file list only the caller's stated employee ID and date of birth as the verification performed.",
        "raw": {
          "azure.auditlogs.category": "AuditLogs",
          "azure.auditlogs.operationName": "Reset password (by admin)",
          "azure.auditlogs.properties.activityDisplayName": "Reset password (by admin)",
          "azure.auditlogs.properties.activityDateTime": "2026-07-14T14:07:00.000Z",
          "azure.auditlogs.properties.category": "UserManagement",
          "azure.auditlogs.properties.loggedByService": "Core Directory",
          "azure.auditlogs.properties.operationType": "Update",
          "azure.auditlogs.properties.result": "success",
          "azure.auditlogs.properties.resultReason": "",
          "azure.auditlogs.properties.correlationId": "6e2f1a83-4d97-4c1b-9a02-7f6d3e8b91c4",
          "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "j.whitfield@solsticefg.com",
          "azure.auditlogs.properties.initiatedBy.user.id": "a17c9e42-5b31-4f7d-8e16-2c9a4d0f7b53",
          "azure.auditlogs.properties.initiatedBy.user.ipAddress": "198.51.100.44",
          "azure.auditlogs.properties.initiatedBy.user.roles": [
            "Helpdesk Administrator"
          ],
          "azure.auditlogs.properties.targetResources[0].type": "User",
          "azure.auditlogs.properties.targetResources[0].userPrincipalName": "r.castillo@solsticefg.com",
          "azure.auditlogs.properties.targetResources[0].id": "d94b6f11-8a25-4c90-b3e7-1f5c8d2a6e09",
          "source.ip": "198.51.100.44"
        }
      },
      "questions": [
        {
          "question": "Which combination of raw fields proves this reset was performed BY SOMEONE ELSE, not by r.castillo himself, and that the person who performed it held an administrative help-desk role?",
          "options": [
            "initiatedBy.user.id (a17c9e42...) differs from targetResources[0].id (d94b6f11...), and initiatedBy.user.roles lists \"Helpdesk Administrator\" -- together showing an admin-role account, not the account holder, made this change",
            "event.outcome, since a value of \"success\" on this field alone conclusively distinguishes an admin-performed reset from a self-service one regardless of any other field in the record",
            "azure.auditlogs.properties.operationType, since only self-service resets ever record \"Update\" as this value while every admin-performed reset instead records \"Delete\" as its operationType",
            "azure.auditlogs.properties.result, since a value of \"success\" on this specific field appears exclusively on admin-initiated resets and never on any genuinely self-service reset event"
          ],
          "answer": 0,
          "explanation": "This room's post-call-fingerprints reading names exactly this pairing: a mismatch between initiatedBy.user.id and targetResources[0].id, combined with an administrative role in initiatedBy.user.roles. event.outcome only records whether the action succeeded or failed, not who performed it, and carries no such rule (option b). operationType records the kind of change (Update, Delete, Add), not who initiated it, and this room never states any self-service-versus-admin split tied to that field (option c). azure.auditlogs.properties.result records the same success/failure fact as event.outcome and, likewise, says nothing about the actor (option d).",
          "xp": 20
        },
        {
          "question": "Given this record alone -- with no documentation yet of what verification j.whitfield actually performed on the call -- what is the single most useful next step to resolve whether this was legitimate or a vishing-driven takeover?",
          "options": [
            "Pull the help-desk ticket to check whether an out-of-band verification (a callback to r.castillo's number on file, a video/badge check, or manager confirmation) was completed and documented, and correlate this reset's timestamp against r.castillo's subsequent sign-in logs for an unfamiliar device or location",
            "Immediately disable r.castillo's account and report the case as confirmed malicious, since any admin-role password reset is inherently suspicious on its own with no further investigation needed",
            "Close the ticket as routine with no further action, since Helpdesk Administrator is a legitimate directory role and any role-based reset is, by definition, always authorized",
            "Contact r.castillo's mobile carrier directly to request a list of recent SIM card changes on his account, since this room names that as the only fact relevant to resolving this type of case"
          ],
          "answer": 0,
          "explanation": "This room's discriminator reading is explicit that the deciding fact is whether a documented out-of-band verification occurred, and its post-call-fingerprints reading names correlating the reset against subsequent sign-in anomalies as the corroborating step -- exactly what this option does. Disabling the account outright (option b) skips the actual investigation this room teaches and treats a routine-shaped event as automatically confirmed without evidence. Closing the ticket with no check at all (option c) is the opposite failure this room warns against -- a legitimate-looking role does not make a reset automatically legitimate. Contacting the mobile carrier for SIM records (option d) is relevant to a SIM-swap-preceded case like Caesars, not to this scenario, and this room never names it as the universal next step for every case.",
          "xp": 20
        }
      ]
    },
    {
      "type": "analyst_choice" as const,
      "id": "vish-ac1",
      "heading": "Triage: A Traveling Employee's Password Reset",
      "scenario": "This case has the identical surface shape as the log_analysis case you just worked through: a Helpdesk Administrator resets a different employee's password, and a sign-in from an unfamiliar device follows shortly after. Review the it_verify data before deciding.",
      "event": {
        "id": "evt-vish-ac1-001",
        "ts": "2026-06-02T09:18:00.000Z",
        "source": "o365",
        "vendor": "Microsoft Entra ID",
        "event_type": "account_modify",
        "severity": "medium",
        "mitre_technique": "T1656",
        "mitre_tactic": "Defense Evasion",
        "edr_scope": "non_edr",
        "user_email": "m.alvarez@solsticefg.com",
        "src_ip": "203.0.113.19",
        "geo": {
          "country": "United States",
          "city": "Denver"
        },
        "user_title": "Solstice Financial Group Help Desk",
        "description": "m.alvarez called Solstice's help desk reporting she was locked out after her phone was replaced under the corporate device-upgrade program. Agent d.nakamura reset her password and re-registered her MFA method during the call. A sign-in from a device not previously seen on this account followed nine minutes later.",
        "it_verify_result": "confirmed",
        "it_verify_message": "Ticket HD-30217: d.nakamura ended the inbound call and called back the number on file for m.alvarez in Solstice's HR system (not the number the caller provided). The callback was answered by m.alvarez, who confirmed the device replacement and completed identity verification before any reset was performed.",
        "raw": {
          "azure.auditlogs.category": "AuditLogs",
          "azure.auditlogs.operationName": "Reset password (by admin)",
          "azure.auditlogs.properties.activityDisplayName": "Reset password (by admin)",
          "azure.auditlogs.properties.activityDateTime": "2026-06-02T09:18:00.000Z",
          "azure.auditlogs.properties.category": "UserManagement",
          "azure.auditlogs.properties.loggedByService": "Core Directory",
          "azure.auditlogs.properties.operationType": "Update",
          "azure.auditlogs.properties.result": "success",
          "azure.auditlogs.properties.correlationId": "9c4e7b21-3f68-4a05-9d17-6b2c8f4e0a91",
          "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "d.nakamura@solsticefg.com",
          "azure.auditlogs.properties.initiatedBy.user.id": "f38a1c6d-2e94-4b70-8c15-9a3d6e1b4f82",
          "azure.auditlogs.properties.initiatedBy.user.ipAddress": "203.0.113.19",
          "azure.auditlogs.properties.initiatedBy.user.roles": [
            "Helpdesk Administrator"
          ],
          "azure.auditlogs.properties.targetResources[0].type": "User",
          "azure.auditlogs.properties.targetResources[0].userPrincipalName": "m.alvarez@solsticefg.com",
          "azure.auditlogs.properties.targetResources[0].id": "5b8d3f92-6c41-4e0a-9f18-2d7c5b9e3a06",
          "source.ip": "203.0.113.19"
        }
      },
      "correct_verdict": "false_positive",
      "explanation": "Every discriminator this room's readings name checks out here: d.nakamura ended the inbound call and independently called back the number already on file for m.alvarez in Solstice's own HR system -- never a number the caller supplied -- exactly the out-of-band verification this room's discriminator reading describes as the control that actually resolves these cases. The it_verify_message confirms the callback was completed and answered by the real m.alvarez before any action was taken, and the new device afterward is consistent with a legitimate replacement device, not an attacker's.",
      "fp_trap": "A student who has just read about MGM, Caesars, and Retool, and has just worked through a case built on the same raw-field shape, is primed to escalate this reflexively because the surface pattern (admin reset, new device shortly after) looks identical. That is exactly the overcorrection this room's discriminator reading warned about by name: the raw audit fields alone never resolve a case, and here the documented out-of-band callback -- not the shape of the reset -- is what actually makes this legitimate.",
      "xp": 25
    },
    {
      "type": "question" as const,
      "id": "vish-q4",
      "question": "An organization wants to reduce vishing risk against its help desk after reading this room's MGM/Caesars case. Per this room, which control does CISA's own advisory on this threat cluster name as most directly resistant to push bombing and SIM swapping, because it removes voice, SMS, and simple approval taps from the authentication decision entirely?",
      "options": [
        "Phishing-resistant MFA using FIDO/WebAuthn or PKI-based authentication",
        "Knowledge-based authentication (KBA) with a longer list of more detailed personal questions asked during each call",
        "SMS-based one-time passcodes sent to the employee's registered phone number for every help-desk-assisted action",
        "A mandatory 24-hour cooling-off period between a password reset request and the reset actually taking effect"
      ],
      "answer": 0,
      "explanation": "This room's hardening reading quotes CISA's own advisory directly: FIDO/WebAuthn or PKI-based MFA is resistant to phishing and not susceptible to push bombing or SIM swap attacks. Expanding KBA (option b) does not fix its core weakness, since more detailed questions are still answerable through the same reconnaissance this room covers. SMS one-time passcodes (option c) are exactly what a SIM swap defeats, per this room's MGM/Caesars reading. A 24-hour cooling-off period (option d) is never mentioned anywhere in this room's readings.",
      "xp": 25
    },
    {
      "type": "flag" as const,
      "id": "vish-f1",
      "prompt": "This room's reading on MGM and Caesars describes an attacker falsely claiming, during a help-desk phone call, to be a real, trusted employee. What MITRE ATT&CK technique ID names this specific act?",
      "answer": "T1656",
      "hint": "Covered in \"The Help-Desk Attack, End to End,\" Stage 2.",
      "xp": 15
    }
  ]
}
];
