// ─── Quiz Data: Security Models & Core Principles ──────────────────────────
// A beginner quiz on the foundational models every analyst reasons with — the
// CIA triad, least privilege, Zero Trust, defense in depth, AAA, separation of
// duties, non-repudiation, default-deny, and the risk equation. Options are
// length-balanced so the answer can't be guessed by shape. Same contract as
// ./data.ts.

import type { Quiz } from "./data";

export const QUIZZES_SECURITY_MODELS: Quiz[] = [
  {
    slug: "security-models-principles",
    title: "Security Models & Core Principles",
    description: "The mental models behind every control: the CIA triad, least privilege, Zero Trust, defense in depth, AAA, and the risk equation — the 'why' under the tools.",
    difficulty: "Beginner",
    category: "Foundations",
    icon: "⚖️",
    estimatedMinutes: 12,
    questions: [
      {
        id: "sm_01",
        question: "What do the three letters of the CIA triad stand for?",
        options: [
          "Control, Isolation, Auditing — the three duties of a security operations team.",
          "Confidentiality, Integrity, Availability — the three core goals of information security.",
          "Compliance, Identity, Access — the three pillars of a governance programme.",
          "Cryptography, Inspection, Alerting — the three technical layers of a defence stack.",
        ],
        answer: 1,
        explanation: "The CIA triad is the foundation of security: Confidentiality (only authorised parties can read data), Integrity (data isn't altered without authorisation), and Availability (systems and data are accessible when needed). Almost every control maps to protecting one or more of these three.",
        xp: 10,
      },
      {
        id: "sm_02",
        question: "An attacker encrypts a company's files with ransomware so no one can open them. Which part of the CIA triad is primarily harmed?",
        options: [
          "Confidentiality — the data has been exposed to an unauthorised party.",
          "Integrity — the contents of the data have been silently altered.",
          "Availability — legitimate users can no longer access the data they need.",
          "Non-repudiation — the origin of the data can no longer be proven.",
        ],
        answer: 2,
        explanation: "Ransomware's primary impact is on Availability — the data still exists and isn't (necessarily) stolen or changed, but no one can use it. Modern 'double extortion' ransomware also steals data first, which then adds a Confidentiality impact.",
        xp: 15,
      },
      {
        id: "sm_03",
        question: "What does the principle of 'least privilege' require?",
        options: [
          "Every user should hold administrator rights so they are never blocked from their work.",
          "Users and processes get only the minimum access needed for their task — and no more.",
          "All permissions should be granted to a single trusted team that acts on everyone's behalf.",
          "Access should be reviewed once at hire and then left unchanged for the life of the account.",
        ],
        answer: 1,
        explanation: "Least privilege gives each identity only the access its role genuinely needs. It shrinks the blast radius of any compromise — a breached account can only reach what it was entitled to. Over-privileged accounts are the single biggest amplifier of an attacker's reach.",
        xp: 10,
      },
      {
        id: "sm_04",
        question: "Which statement best captures the core idea of Zero Trust?",
        options: [
          "Once a device is inside the corporate network, it is trusted and no longer re-checked.",
          "Trust is granted permanently to any user who has passed authentication once before.",
          "Never trust by default; verify every request based on identity, device, and context.",
          "Security is enforced only at the network perimeter, which is treated as the trust boundary.",
        ],
        answer: 2,
        explanation: "Zero Trust replaces the old 'castle and moat' model (trusted inside, hostile outside) with 'never trust, always verify'. Every access request is authenticated, authorised, and evaluated against context — identity, device health, location, risk — regardless of where it originates.",
        xp: 15,
      },
      {
        id: "sm_05",
        question: "What is 'defense in depth'?",
        options: [
          "Relying on one very strong control — usually the firewall — to stop every attack.",
          "Layering multiple independent controls so that if one fails, others still protect the asset.",
          "Placing all security controls as deep inside the network as physically possible.",
          "Investing the entire security budget in detection while skipping prevention entirely.",
        ],
        answer: 1,
        explanation: "Defense in depth layers controls — perimeter, network, endpoint, identity, data — so a single failure doesn't mean compromise. An attacker who slips past the firewall still faces EDR, MFA, segmentation, and monitoring. No single control is assumed to be perfect.",
        xp: 10,
      },
      {
        id: "sm_06",
        question: "In the AAA model of access control, what do the three A's stand for?",
        options: [
          "Authentication, Authorization, Accounting — proving identity, granting access, and logging it.",
          "Access, Auditing, Alerting — the three tasks a SIEM performs on identity events.",
          "Approval, Assignment, Attestation — the three steps of an access-request workflow.",
          "Antivirus, Analysis, Automation — the three capabilities of a modern endpoint agent.",
        ],
        answer: 0,
        explanation: "AAA is: Authentication (who are you? — verified by password, MFA, certificate), Authorization (what are you allowed to do? — enforced by roles and policies), and Accounting (what did you do? — recorded in logs for audit and forensics). RADIUS and TACACS+ are classic AAA protocols.",
        xp: 10,
      },
      {
        id: "sm_07",
        question: "What security property does 'non-repudiation' provide?",
        options: [
          "It guarantees that a system will remain available even during a denial-of-service attack.",
          "It ensures data cannot be read by anyone who lacks the correct decryption key.",
          "It proves who performed an action, so the actor cannot credibly deny having done it.",
          "It automatically restores a file to its previous state if it is modified without approval.",
        ],
        answer: 2,
        explanation: "Non-repudiation binds an action to an actor so it can't be denied later — provided by digital signatures, strong authentication, and tamper-evident audit logs. It's why chain-of-custody and signed logs matter: they make findings defensible if an incident reaches legal proceedings.",
        xp: 15,
      },
      {
        id: "sm_08",
        question: "Why do organisations enforce 'separation of duties' for sensitive processes?",
        options: [
          "So that a single person cannot both perform and approve a critical action, preventing fraud.",
          "So that every employee learns to perform every job, improving overall team flexibility.",
          "So that duties can be automated and no human is ever involved in a sensitive process.",
          "So that all approvals are concentrated in one senior role for faster decision-making.",
        ],
        answer: 0,
        explanation: "Separation of duties splits a sensitive process so no one person controls it end to end — e.g. the person who requests a payment can't also approve it. It prevents both fraud and single-actor mistakes, and it forces collusion (harder to pull off) rather than a lone bad actor.",
        xp: 10,
      },
      {
        id: "sm_09",
        question: "A firewall is configured to block all traffic except what is explicitly allowed. What is this principle called?",
        options: [
          "Default allow — everything is permitted unless a specific rule blocks it.",
          "Fail-open — when a rule is uncertain, the traffic is allowed through.",
          "Default deny — nothing is permitted unless a specific rule allows it.",
          "Best-effort — traffic is allowed or blocked based on current system load.",
        ],
        answer: 2,
        explanation: "Default deny (deny-by-default, allow-list) blocks everything and permits only what's explicitly needed — the secure default for firewalls, application control, and access policies. Its opposite, default allow, leaves unknown traffic open and is far riskier.",
        xp: 10,
      },
      {
        id: "sm_10",
        question: "In risk assessment, which relationship best expresses how risk is estimated?",
        options: [
          "Risk equals the number of security tools deployed divided by the size of the IT budget.",
          "Risk is a function of a threat exploiting a vulnerability, weighted by the resulting impact.",
          "Risk is simply the total count of vulnerabilities found in the most recent scan.",
          "Risk equals the number of past incidents multiplied by the size of the security team.",
        ],
        answer: 1,
        explanation: "Risk is commonly framed as threat × vulnerability × impact (or likelihood × impact). A vulnerability with no threat to exploit it, or with negligible impact, is low risk. This is why SOCs prioritise: high-likelihood, high-impact risks first, not raw vulnerability counts.",
        xp: 15,
      },
      {
        id: "sm_11",
        question: "What is the difference between encryption 'at rest' and 'in transit'?",
        options: [
          "At rest protects stored data on disk; in transit protects data moving across a network.",
          "At rest protects only backups; in transit protects only the contents of live databases.",
          "At rest uses symmetric keys only; in transit is always limited to asymmetric keys.",
          "At rest applies to personal devices; in transit applies only to corporate servers.",
        ],
        answer: 0,
        explanation: "Encryption at rest protects stored data — full-disk encryption, encrypted database columns — so a stolen disk or backup is useless. Encryption in transit (TLS, VPN) protects data crossing a network from interception. A complete posture needs both; neither alone covers the other's exposure.",
        xp: 10,
      },
      {
        id: "sm_12",
        question: "Multi-factor authentication combines factors from different categories. Which set correctly lists the three factor types?",
        options: [
          "Something long, something random, and something rotated on a fixed schedule.",
          "Something you know, something you have, and something you are.",
          "Something encrypted, something signed, and something hashed.",
          "Something on-premises, something in the cloud, and something on a mobile device.",
        ],
        answer: 1,
        explanation: "MFA strength comes from combining DIFFERENT categories: something you know (password/PIN), something you have (a phone, token, or FIDO2 key), and something you are (fingerprint, face). Two passwords aren't MFA — they're the same factor twice. Phishing-resistant MFA (FIDO2) is the strongest 'have' factor.",
        xp: 10,
      },
    ],
  },
];
