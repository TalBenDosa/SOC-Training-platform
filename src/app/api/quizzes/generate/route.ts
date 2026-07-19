import Anthropic from "@anthropic-ai/sdk";
import { requireAdmin } from "@/lib/auth/apiGuard";
import type { Quiz, QuizQuestion } from "@/lib/quizzes/data";

// ─── Extended type for generated quizzes ─────────────────────────────────────

export interface GeneratedQuiz extends Quiz {
  id: string;
  published_at: string;
}

// ─── Local fallback ───────────────────────────────────────────────────────────

const TEMPLATE_QUESTIONS: Record<string, QuizQuestion[]> = {
  "MITRE ATT&CK": [
    {
      id: "tq_1", xp: 10,
      question: "Which MITRE ATT&CK tactic covers an adversary's efforts to gain initial access to a target network?",
      options: ["Execution", "Initial Access", "Persistence", "Discovery"],
      answer: 1,
      explanation: "Initial Access (TA0001) covers techniques like phishing (T1566), exploit public-facing application (T1190), and valid accounts (T1078) used to gain a foothold.",
    },
    {
      id: "tq_2", xp: 10,
      question: "T1059.001 refers to which specific technique?",
      options: ["Python scripting", "JavaScript execution", "PowerShell", "Bash/Shell"],
      answer: 2,
      explanation: "T1059.001 is Command and Scripting Interpreter: PowerShell. Adversaries frequently abuse PowerShell for execution, lateral movement, and C2 communication.",
    },
    {
      id: "tq_3", xp: 10,
      question: "Which sub-technique describes using LOLBins (Living off the Land Binaries) to bypass detection?",
      options: ["T1218 — System Binary Proxy Execution", "T1055 — Process Injection", "T1003 — OS Credential Dumping", "T1070 — Indicator Removal"],
      answer: 0,
      explanation: "T1218 covers the use of signed system binaries (certutil, mshta, regsvr32, etc.) to proxy execution of malicious code, evading application whitelisting.",
    },
  ],
  "Incident Response": [
    {
      id: "tq_4", xp: 10,
      question: "What does MTTD stand for in SOC metrics?",
      options: ["Mean Time To Deploy", "Mean Time To Detect", "Mean Time To Defend", "Mean Time To Document"],
      answer: 1,
      explanation: "MTTD (Mean Time To Detect) measures the average time between when a breach occurs and when it's detected. Lower is better — the industry average is still measured in days.",
    },
    {
      id: "tq_5", xp: 10,
      question: "During which IR phase should an analyst create a forensic image of the compromised host?",
      options: ["Identification", "Containment", "Eradication", "Recovery"],
      answer: 1,
      explanation: "Forensic imaging should occur during Containment, before evidence is altered by eradication steps. NIST SP 800-61 recommends preserving evidence while limiting damage.",
    },
    {
      id: "tq_6", xp: 10,
      question: "Which containment action is MOST appropriate when ransomware is detected actively encrypting files?",
      options: ["Block the IOC at the firewall", "Disable the user account", "Isolate the host from the network immediately", "Take a memory dump"],
      answer: 2,
      explanation: "Network isolation prevents ransomware from spreading laterally and communicating with its C2. This is the highest priority action — evidence collection comes after isolation.",
    },
  ],
  "Log Analysis & SIEM": [
    {
      id: "tq_7", xp: 10,
      question: "Windows Event ID 4624 indicates what type of event?",
      options: ["Account logon failure", "An account was successfully logged on", "A process was created", "Scheduled task was registered"],
      answer: 1,
      explanation: "Event ID 4624 (Logon Success) is critical for detecting lateral movement. Logon Type 3 (Network) and Type 10 (RemoteInteractive/RDP) are especially important to monitor.",
    },
    {
      id: "tq_8", xp: 10,
      question: "Which Sysmon Event ID captures process creation with full command-line logging?",
      options: ["Event ID 1", "Event ID 3", "Event ID 7", "Event ID 11"],
      answer: 0,
      explanation: "Sysmon Event ID 1 (Process Create) captures the full command line, hashes, parent process, and user context — essential for hunting malicious execution patterns.",
    },
    {
      id: "tq_9", xp: 10,
      question: "A SIEM alert shows 500 failed logins from one IP to many accounts in 5 minutes. This most likely indicates:",
      options: ["Credential stuffing from a breach list", "Password spray attack", "Brute force on a single account", "User-initiated lockout"],
      answer: 1,
      explanation: "Low-and-slow attempts against many accounts = password spray (T1110.003). Brute force targets one account. Credential stuffing uses known breach passwords against specific accounts.",
    },
  ],
  "Threat Intelligence": [
    {
      id: "tq_10", xp: 10,
      question: "What does a 'Diamond Model' represent in threat intelligence?",
      options: ["A scoring framework for vulnerability severity", "A model linking adversary, capability, infrastructure, and victim", "The four stages of the cyber kill chain", "A framework for classifying malware families"],
      answer: 1,
      explanation: "The Diamond Model of Intrusion Analysis connects adversary, infrastructure, capability, and victim — helping analysts pivot between indicators and understand attacker campaigns holistically.",
    },
    {
      id: "tq_11", xp: 10,
      question: "Which threat intel format is used for structured sharing of CTI (Cyber Threat Intelligence)?",
      options: ["MISP", "STIX/TAXII", "OpenIOC", "YARA"],
      answer: 1,
      explanation: "STIX (Structured Threat Information eXpression) defines the data format; TAXII (Trusted Automated eXchange of Intelligence Information) defines the transport protocol for sharing CTI.",
    },
  ],
  "Network Security": [
    {
      id: "tq_12", xp: 10,
      question: "Which network indicator most strongly suggests C2 beaconing behavior?",
      options: ["High-volume traffic spikes", "Regular outbound connections at fixed intervals to an unusual external IP", "DNS requests for well-known domains", "HTTPS traffic to CDN providers"],
      answer: 1,
      explanation: "C2 beaconing (T1071) typically shows periodic, jitter-based outbound connections. Fixed intervals and low-reputation external IPs are key detection signals in firewall/proxy logs.",
    },
    {
      id: "tq_13", xp: 10,
      question: "Port 443 is used for HTTPS. A malware sample is found communicating on port 443 to an IP. Which additional check is most useful?",
      options: ["Check if port 443 is in the default allow list", "Perform TLS inspection and check the certificate's CN/SAN fields", "Block all port 443 traffic", "Check if the IP is in the internal subnet"],
      answer: 1,
      explanation: "TLS inspection reveals whether the certificate matches a known benign service. Malware often uses valid certificates or self-signed certs with suspicious SNI fields to blend in.",
    },
  ],
  "Cloud Security": [
    {
      id: "tq_14", xp: 10,
      question: "An AWS CloudTrail log shows `ConsoleLogin` with `MFAUsed: No` from an unusual IP. What is the first action?",
      options: ["Disable CloudTrail logging temporarily", "Immediately revoke all IAM policies for that user", "Investigate the login — review subsequent API calls and consider session invalidation", "Whitelist the IP address"],
      answer: 2,
      explanation: "The first step is investigation — check what API calls were made after login (S3 GetObject, IAM CreateUser etc.). Then contain by invalidating active sessions and rotating credentials.",
    },
    {
      id: "tq_15", xp: 10,
      question: "Which AWS IAM policy element grants a user permission to list S3 buckets?",
      options: [`Action: "s3:GetObject"`, `Action: "s3:ListAllMyBuckets"`, `Action: "s3:PutBucketPolicy"`, `Action: "s3:DeleteBucket"`],
      answer: 1,
      explanation: "`s3:ListAllMyBuckets` allows listing bucket names. Attackers with this permission during recon can enumerate storage to identify sensitive data targets.",
    },
  ],
};

function buildLocalQuiz(
  title: string,
  topic: string,
  difficulty: "Beginner" | "Intermediate" | "Advanced",
  count: number,
): GeneratedQuiz {
  const pool = TEMPLATE_QUESTIONS[topic] ?? TEMPLATE_QUESTIONS["Incident Response"];
  const questions: QuizQuestion[] = [];
  for (let i = 0; i < Math.min(count, pool.length * 2); i++) {
    const base = pool[i % pool.length];
    questions.push({ ...base, id: `gen_${Date.now()}_${i}` });
  }

  return {
    id: `gen-quiz-${Date.now()}`,
    slug: `gen-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`,
    title,
    description: `AI-generated quiz covering ${topic} concepts for ${difficulty.toLowerCase()}-level SOC analysts. Tests detection knowledge, incident response skills, and tool proficiency.`,
    difficulty,
    category: topic,
    icon: "🤖",
    estimatedMinutes: Math.ceil(count * 1.5),
    questions,
    published_at: new Date().toISOString(),
  };
}

// ─── Route ────────────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;

  const body = await req.json().catch(() => ({}));
  const {
    title = "Generated Quiz",
    topic = "Incident Response",
    difficulty = "Intermediate",
    count = 8,
    focus = "",
  } = body as { title?: string; topic?: string; difficulty?: "Beginner" | "Intermediate" | "Advanced"; count?: number; focus?: string };

  const clampedCount = Math.max(3, Math.min(12, count));

  if (!process.env.ANTHROPIC_API_KEY) {
    return Response.json(buildLocalQuiz(title, topic, difficulty, clampedCount));
  }

  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  const prompt = `You are an expert SOC training instructor creating a multiple-choice quiz for security analysts.

Quiz Title: ${title}
Topic: ${topic}
Difficulty: ${difficulty}
Number of Questions: ${clampedCount}
Focus Areas: ${focus || "Cover key detection, investigation, and response skills"}

Create ${clampedCount} unique, challenging multiple-choice questions. Each question should test practical SOC analyst knowledge — not just definitions, but real-world decision-making and tool usage.

Return ONLY valid JSON:
{
  "description": "2-sentence quiz description",
  "questions": [
    {
      "question": "Specific, practical question a SOC analyst would face",
      "options": ["Option A", "Option B", "Option C", "Option D"],
      "answer": 0,
      "explanation": "Detailed explanation of why the correct answer is right and why others are wrong. Include tool names, MITRE technique IDs, or log field references where relevant.",
      "xp": 10
    }
  ]
}

Rules:
- answer is the 0-based index of the correct option
- All 4 options must be plausible (no obviously wrong distractors)
- Questions must be specific to ${topic}, not generic
- ${difficulty} difficulty: ${difficulty === "Beginner" ? "Focus on fundamentals and definitions" : difficulty === "Intermediate" ? "Mix conceptual and scenario-based questions" : "Focus on complex scenarios, edge cases, and advanced techniques"}
- Exactly ${clampedCount} questions`;

  try {
    const response = await client.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 5000,
      messages: [{ role: "user", content: prompt }],
    });

    const text = response.content[0].type === "text" ? response.content[0].text : "";
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("Model did not return valid JSON");

    const parsed = JSON.parse(jsonMatch[0]);

    const questions: QuizQuestion[] = (parsed.questions ?? []).map((q: Partial<QuizQuestion>, i: number) => ({
      id: `gen_${Date.now()}_${i}`,
      question: q.question ?? "Question",
      options: q.options ?? ["A", "B", "C", "D"],
      answer: typeof q.answer === "number" ? q.answer : 0,
      explanation: q.explanation ?? "",
      xp: q.xp ?? 10,
    }));

    const quiz: GeneratedQuiz = {
      id: `gen-quiz-${Date.now()}`,
      slug: `gen-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`,
      title,
      description: parsed.description ?? `Generated quiz on ${topic}`,
      difficulty: difficulty as "Beginner" | "Intermediate" | "Advanced",
      category: topic,
      icon: "🤖",
      estimatedMinutes: Math.ceil(clampedCount * 1.5),
      questions,
      published_at: new Date().toISOString(),
    };

    return Response.json(quiz);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return Response.json({ error: message }, { status: 500 });
  }
}
