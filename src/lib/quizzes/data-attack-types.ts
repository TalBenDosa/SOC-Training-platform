// ─── Quiz Data: Attack Types & Threat Actors ───────────────────────────────
// A beginner quiz on the attack vocabulary an analyst triages against — phishing
// variants, ransomware, APTs, insider threat, DDoS, supply chain, the three
// password attacks (brute force / spray / stuffing), MITM/AiTM, zero-day, and
// malware families (virus / worm / trojan). Options are length-balanced so the
// answer can't be guessed by shape. Same contract as ./data.ts.

import type { Quiz } from "./data";

export const QUIZZES_ATTACK_TYPES: Quiz[] = [
  {
    slug: "attack-types-threat-actors",
    title: "Attack Types & Threat Actors",
    description: "Name the threat: phishing variants, ransomware, APTs, insider threat, DDoS, supply chain, the three password attacks, MITM, zero-day, and malware families.",
    difficulty: "Beginner",
    category: "Threat Framework",
    icon: "🎯",
    estimatedMinutes: 13,
    questions: [
      {
        id: "at_01",
        question: "A finance director receives a highly personalised email, apparently from the CEO, asking for an urgent wire transfer. What is this attack called?",
        options: [
          "Vishing — a voice-phone scam that pressures the victim into acting over a call.",
          "Whaling — spear phishing that targets a high-value executive or their close staff.",
          "Smishing — an SMS-based lure that tricks the victim into tapping a malicious link.",
          "Tailgating — physically following an employee through a secured door without a badge.",
        ],
        answer: 1,
        explanation: "Whaling is spear phishing aimed at 'big fish' — executives or the people who can move money on their behalf. It's highly researched and personalised. When it succeeds at authorising fraudulent payments it becomes Business Email Compromise (BEC), one of the costliest attack types.",
        xp: 10,
      },
      {
        id: "at_02",
        question: "What defines an Advanced Persistent Threat (APT)?",
        options: [
          "Any piece of malware that is difficult for antivirus to detect and remove.",
          "A single opportunistic attacker who breaks in, grabs what they can, and leaves fast.",
          "A well-resourced actor that maintains long-term, stealthy access to a specific target.",
          "A vulnerability so severe that it is exploited automatically the moment it is disclosed.",
        ],
        answer: 2,
        explanation: "An APT is a threat actor — usually nation-state or state-aligned, well-funded and patient — that gains access to a chosen target and stays hidden for months or years to achieve espionage or strategic goals. 'Advanced' (capability), 'Persistent' (long dwell time), 'Threat' (a directed human adversary).",
        xp: 10,
      },
      {
        id: "at_03",
        question: "What does ransomware do, and what makes 'double extortion' worse?",
        options: [
          "It encrypts the victim's data for ransom; double extortion also steals it first and threatens to leak it.",
          "It floods a website with traffic; double extortion also defaces the site's home page.",
          "It logs the victim's keystrokes; double extortion also records the screen at the same time.",
          "It mines cryptocurrency on the host; double extortion also spreads to two networks at once.",
        ],
        answer: 0,
        explanation: "Ransomware encrypts files and demands payment for the key. In double extortion, the crew exfiltrates the data BEFORE encrypting — so even a victim with good backups faces a second threat: pay, or we publish your data. This is why an availability incident is now also a confidentiality breach.",
        xp: 10,
      },
      {
        id: "at_04",
        question: "A departing employee copies the customer database to a personal USB drive on their last day. Which threat category is this?",
        options: [
          "Supply chain attack — a trusted third-party vendor is used to reach the target.",
          "Watering hole attack — a site the target frequents is compromised to infect them.",
          "Insider threat — a person with legitimate access misuses it to harm the organisation.",
          "Zero-day attack — a previously unknown software flaw is exploited before a patch exists.",
        ],
        answer: 2,
        explanation: "An insider threat comes from someone with legitimate access — an employee, contractor, or partner — who misuses it, whether maliciously (data theft, sabotage) or negligently. Because the access is authorised, insider activity often bypasses perimeter controls and is best caught by DLP and UEBA.",
        xp: 10,
      },
      {
        id: "at_05",
        question: "Thousands of compromised devices simultaneously flood a company's website with traffic until it goes offline. What is this?",
        options: [
          "A DDoS attack — a distributed flood of traffic that exhausts the target's capacity.",
          "A brute-force attack — repeated password guesses against a single login page.",
          "A phishing campaign — mass emails designed to harvest credentials from users.",
          "A privilege-escalation attack — abusing a flaw to gain higher account permissions.",
        ],
        answer: 0,
        explanation: "A DDoS (Distributed Denial of Service) uses many sources — often a botnet of compromised devices — to overwhelm a target's bandwidth, connections, or application resources so legitimate users can't reach it. It attacks Availability. Mitigations: upstream scrubbing, rate limiting, and CDN/anti-DDoS services.",
        xp: 10,
      },
      {
        id: "at_06",
        question: "The SolarWinds incident is the classic example of which attack type?",
        options: [
          "A watering hole attack — a popular website was booby-trapped to infect its visitors.",
          "A supply chain attack — a trusted software update was poisoned to reach many victims at once.",
          "An MFA-fatigue attack — users were spammed with push prompts until one approved.",
          "A password-spray attack — one common password was tried across thousands of accounts.",
        ],
        answer: 1,
        explanation: "A supply chain attack compromises a trusted supplier to reach that supplier's customers. In SolarWinds (attributed to APT29), attackers inserted a backdoor into a legitimate signed software update, which then deployed to thousands of organisations that trusted the vendor. It weaponises trust in the supply chain.",
        xp: 15,
      },
      {
        id: "at_07",
        question: "Which description matches a PASSWORD-SPRAY attack (as opposed to brute force or credential stuffing)?",
        options: [
          "Trying thousands of passwords against one account until the correct one is found.",
          "Trying one or two common passwords across many accounts to avoid triggering lockouts.",
          "Reusing username-and-password pairs leaked from a different site's earlier breach.",
          "Guessing the answers to a single user's account-recovery security questions.",
        ],
        answer: 1,
        explanation: "Password spray flips brute force around: instead of many passwords against one account (which trips lockout), it tries one or two common passwords (Summer2024!) against thousands of accounts, so each account sees only 1-2 failures. In logs it looks like many failed logins spread across accounts from one source. Credential stuffing, by contrast, replays real credentials leaked elsewhere.",
        xp: 15,
      },
      {
        id: "at_08",
        question: "An attacker sits between a user and a website, relaying and reading the traffic in real time — even capturing the session after MFA. What is this?",
        options: [
          "A Man-in-the-Middle (Adversary-in-the-Middle) attack that intercepts the live session.",
          "A SQL-injection attack that manipulates the website's backend database queries.",
          "A cross-site-scripting attack that runs the attacker's script in the victim's browser.",
          "A denial-of-service attack that blocks the user from reaching the website at all.",
        ],
        answer: 0,
        explanation: "MITM / AiTM inserts the attacker into the communication path so they can read and alter traffic. Modern AiTM phishing kits (Evilginx) proxy the real login — the victim completes MFA, and the attacker steals the resulting session cookie, bypassing MFA entirely. Phishing-resistant FIDO2 keys defeat this.",
        xp: 15,
      },
      {
        id: "at_09",
        question: "What is a 'zero-day' vulnerability?",
        options: [
          "A flaw that has been public for exactly zero days because it was responsibly disclosed.",
          "A flaw the vendor is unaware of, so no patch exists when it is first exploited.",
          "A flaw that can only be exploited within zero days of a system being installed.",
          "A flaw rated zero on the severity scale and therefore safe to leave unpatched.",
        ],
        answer: 1,
        explanation: "A zero-day is a vulnerability unknown to the vendor (and thus unpatched) at the time it's exploited — defenders have had 'zero days' to fix it. They're dangerous because signature-based defences don't yet recognise them; behavioural detection (EDR/anomaly) is the fallback until a patch ships.",
        xp: 10,
      },
      {
        id: "at_10",
        question: "An attacker phones the help desk pretending to be a locked-out executive and talks an agent into resetting the password. What broad technique is this?",
        options: [
          "Privilege escalation — abusing a software flaw to gain higher system permissions.",
          "Social engineering — manipulating a person into breaking normal security procedure.",
          "Lateral movement — using one foothold to reach additional systems on the network.",
          "Data exfiltration — moving stolen information out of the organisation's environment.",
        ],
        answer: 1,
        explanation: "Social engineering manipulates people rather than machines — pretexting, phishing, vishing, tailgating, help-desk impersonation. Humans are targeted because it's often easier than defeating technical controls. Defences: verification callbacks, strict identity-proofing at the help desk, and user awareness training.",
        xp: 10,
      },
      {
        id: "at_11",
        question: "How does a computer WORM differ from a classic VIRUS?",
        options: [
          "A worm only infects Linux hosts, while a virus only infects Windows hosts.",
          "A worm spreads by itself across the network, while a virus needs a host file and user action to spread.",
          "A worm merely displays messages, while a virus is the only one that can damage data.",
          "A worm is always signed and trusted, while a virus is always unsigned and blocked.",
        ],
        answer: 1,
        explanation: "A virus attaches to a file or program and needs a user to run the host to spread. A worm is self-propagating — it exploits network services to copy itself to other hosts with no user action (WannaCry via SMB is the classic example). A trojan, by contrast, is malware disguised as something legitimate the user is tricked into running.",
        xp: 10,
      },
      {
        id: "at_12",
        question: "Attackers compromise a niche industry news site that their real targets visit, so those visitors get infected. What is this called?",
        options: [
          "A brute-force attack — systematically guessing the target site's admin credentials.",
          "A watering hole attack — poisoning a site the intended victims are known to frequent.",
          "A credential-stuffing attack — replaying leaked passwords against the site's users.",
          "A denial-of-service attack — knocking the news site offline to disrupt its readers.",
        ],
        answer: 1,
        explanation: "A watering hole attack compromises a legitimate site the intended victims are likely to visit — an industry portal, a supplier's site — and serves malware (often via a drive-by exploit) to those visitors. It's indirect and patient, favoured by APTs targeting a specific sector rather than a single organisation.",
        xp: 15,
      },
    ],
  },
];
