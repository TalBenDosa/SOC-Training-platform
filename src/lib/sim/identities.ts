/**
 * Synthetic enterprise identities — diverse departments, roles, and global names.
 * Designed for realistic SOC training scenarios across many industry verticals.
 */

export const COMPANY = {
  name: "Cryotech Industries",
  domain: "cryotech.io",
  ad_domain: "CRYOTECH",
  hq_country: "US",
  hq_city: "San Jose, CA",
};

export const SUBNETS = {
  corp:    "10.20.0.0/16",
  servers: "10.30.0.0/16",
  vpn:     "10.40.0.0/16",
  dmz:     "172.21.0.0/16",
  cloud:   "10.100.0.0/16",
} as const;

// ── Diverse global first names ─────────────────────────────────────────────────
export const FIRST_NAMES = [
  // Anglo / gender-neutral
  "Avery","Riley","Jordan","Taylor","Casey","Morgan","Skyler","Drew","Quinn","Hayden",
  "Alex","Sam","Jamie","Cameron","Reese","Parker","Logan","Rowan","Emerson","Sage",
  "Blake","Charlie","Devon","Elliot","Finley","Harper","Jesse","Kendall","Lane","Marlow",
  // South Asian
  "Priya","Arjun","Kavya","Rohan","Neha","Vikram","Ananya","Siddharth","Pooja","Rahul",
  "Divya","Aditya","Shreya","Nikhil","Tanvi","Ravi","Meera","Kiran","Deepa","Suresh",
  // East Asian
  "Wei","Mei","Chen","Hiro","Yuki","Kenji","Aiko","Sakura","Jing","Xin",
  "Ji-woo","Soo-jin","Min-jun","Ye-jin","Hyun","Ling","Fang","Jian","Qing","Yu",
  // Latino / Hispanic
  "Diego","Sofia","Mateo","Lucia","Carlos","Elena","Valeria","Miguel","Isabella","Alejandro",
  "Camila","Sebastián","Valentina","Andrés","Mariana","Joaquín","Natalia","Fernando","Rosa","Gabriela",
  // African / Middle Eastern
  "Olu","Adaeze","Fatima","Tariq","Noor","Chidi","Amara","Kwame","Zainab","Ibrahim",
  "Amir","Yasmin","Hassan","Layla","Omar","Amira","Idris","Hana","Kofi","Yetunde",
  // Eastern European
  "Anastasia","Dmitri","Olga","Mikhail","Natasha","Ivan","Katerina","Alexei","Vera","Boris",
  "Lukasz","Monika","Piotr","Zofia","Andrzej","Marta","Tomasz","Agnieszka","Karol","Ewa",
];

// ── Diverse global last names ──────────────────────────────────────────────────
export const LAST_NAMES = [
  // Asian
  "Park","Nguyen","Patel","Singh","Kim","Chen","Wang","Zhang","Li","Yamamoto",
  "Tanaka","Suzuki","Choi","Lee","Nakamura","Sharma","Gupta","Verma","Rao","Iyer",
  // Hispanic / European
  "Lopez","Garcia","Rivera","Martinez","Rodriguez","Hernandez","Rossi","Ferrari","Müller","Schmidt",
  "Bauer","Weber","Meyer","Wagner","Fischer","Bernard","Dupont","Leroy","Martin","Thomas",
  // English / American
  "Smith","Johnson","Brown","Davis","Miller","Wilson","Moore","Anderson","Jackson","White",
  "Harris","Taylor","Thompson","Robinson","Clark","Lewis","Walker","Hall","Allen","Young",
  // African / Middle Eastern
  "Okafor","Mensah","Hassan","Khan","Ahmed","Al-Rashid","Nkosi","Diallo","Kamara","Toure",
  "Adesanya","Osei","Asante","Mubarak","Aziz","Saleh","Ibrahim","Yilmaz","Kaya","Celik",
  // Eastern European
  "Kowalski","Nowak","Wojciechowski","Kozlowski","Jankowski","Petrov","Volkov","Ivanov","Smirnov","Sokolov",
];

// ── Departments across industries ──────────────────────────────────────────────
export const DEPARTMENTS = [
  { code: "FIN",    name: "Finance",              risk: "high"   },
  { code: "HR",     name: "Human Resources",      risk: "medium" },
  { code: "ENG",    name: "Engineering",          risk: "medium" },
  { code: "SEC",    name: "Security",             risk: "low"    },
  { code: "EXEC",   name: "Executive",            risk: "high"   },
  { code: "SALES",  name: "Sales",                risk: "medium" },
  { code: "OPS",    name: "Operations",           risk: "low"    },
  { code: "LEGAL",  name: "Legal & Compliance",   risk: "high"   },
  { code: "MKT",    name: "Marketing",            risk: "medium" },
  { code: "CS",     name: "Customer Success",     risk: "medium" },
  { code: "PROD",   name: "Product",              risk: "low"    },
  { code: "DATA",   name: "Data & Analytics",     risk: "medium" },
  { code: "PROC",   name: "Procurement",          risk: "high"   },
  { code: "INFRA",  name: "Infrastructure",       risk: "low"    },
  { code: "R&D",    name: "Research & Development", risk: "medium" },
] as const;

export type DeptCode = typeof DEPARTMENTS[number]["code"];

// ── Job titles per department ──────────────────────────────────────────────────
export const TITLES_BY_DEPT: Record<string, string[]> = {
  FIN:   ["Financial Analyst","Senior Controller","Treasury Specialist","Accounts Payable Clerk","FP&A Manager","Payroll Specialist","Audit Manager","Tax Analyst"],
  HR:    ["HR Business Partner","Talent Acquisition Specialist","Recruiter","People Ops Manager","Compensation Analyst","HR Director","Benefits Coordinator","Employee Relations Manager"],
  ENG:   ["Software Engineer","Senior Software Engineer","Staff Engineer","Engineering Manager","DevOps Engineer","SRE","Backend Developer","Full-Stack Engineer","Platform Engineer","Tech Lead"],
  SEC:   ["Security Analyst","SOC Analyst","Detection Engineer","Incident Responder","Threat Hunter","Security Engineer","IAM Engineer","Penetration Tester","GRC Analyst"],
  EXEC:  ["CFO","CEO","CTO","CISO","VP of Engineering","VP of Finance","Chief of Staff","President","EVP Operations"],
  SALES: ["Account Executive","Senior AE","Sales Engineer","Regional Sales Manager","Business Development Rep","Channel Partner Manager","SDR"],
  OPS:   ["IT Administrator","Helpdesk Specialist","Systems Administrator","Network Engineer","IT Manager","Desktop Support","Infrastructure Analyst"],
  LEGAL: ["General Counsel","Paralegal","Compliance Manager","Privacy Officer","Corporate Attorney","Contract Manager","Regulatory Affairs Specialist"],
  MKT:   ["Marketing Manager","Content Strategist","Digital Marketing Specialist","Brand Manager","SEO Analyst","Growth Marketing Lead","Demand Generation Manager","Social Media Manager"],
  CS:    ["Customer Success Manager","Support Engineer","Implementation Consultant","Account Manager","Technical Support Specialist","Customer Onboarding Manager"],
  PROD:  ["Product Manager","Senior PM","Director of Product","UX Designer","Product Analyst","Program Manager","Technical Program Manager"],
  DATA:  ["Data Analyst","Data Scientist","Analytics Engineer","BI Developer","Data Engineer","ML Engineer","Quantitative Analyst"],
  PROC:  ["Procurement Specialist","Vendor Manager","Sourcing Manager","Supply Chain Analyst","Category Manager","Purchasing Agent"],
  INFRA: ["Cloud Architect","Site Reliability Engineer","Network Operations Specialist","Database Administrator","Storage Engineer","Virtualization Engineer"],
  "R&D": ["Research Engineer","Principal Researcher","Lab Technician","R&D Manager","Scientist","Innovation Lead"],
};

// ── OS distribution ────────────────────────────────────────────────────────────
export const OS_POOL = [
  "Windows 11","Windows 11","Windows 11","Windows 10",
  "macOS 14","macOS 13",
  "Ubuntu 22.04","Ubuntu 20.04",
] as const;

export type Identity = {
  email: string;
  display_name: string;
  username: string;
  upn: string;
  department: string;
  title: string;
  hostname: string;
  os: typeof OS_POOL[number];
  ip: string;
  mfa: boolean;
  privileged: boolean;
  employee_id: string;
  location: string;
};

export type Host = {
  name: string;
  os: typeof OS_POOL[number];
  ip: string;
  role: "workstation" | "server" | "domain_controller" | "file_server" | "jump_host" | "db_server" | "mail_server" | "proxy_server";
  owner_email?: string;
  asset_tag?: string;
};

// ── Office locations ───────────────────────────────────────────────────────────
export const OFFICE_LOCATIONS = [
  "San Jose, CA", "New York, NY", "Chicago, IL", "Austin, TX", "Seattle, WA",
  "London, UK", "Amsterdam, NL", "Frankfurt, DE", "Singapore, SG", "Sydney, AU",
  "Toronto, CA", "Tel Aviv, IL", "Dublin, IE", "Warsaw, PL", "Bangalore, IN",
];

// ── Server infrastructure ──────────────────────────────────────────────────────
export const SERVERS: Host[] = [
  { name: "DC01.cryotech.local",         os: "Windows 11",    ip: "10.30.0.10",  role: "domain_controller",  asset_tag: "SRV-DC-001" },
  { name: "DC02.cryotech.local",         os: "Windows 11",    ip: "10.30.0.11",  role: "domain_controller",  asset_tag: "SRV-DC-002" },
  { name: "FS-FIN01.cryotech.local",     os: "Windows 11",    ip: "10.30.4.21",  role: "file_server",        asset_tag: "SRV-FS-011" },
  { name: "FS-HR01.cryotech.local",      os: "Windows 11",    ip: "10.30.4.22",  role: "file_server",        asset_tag: "SRV-FS-012" },
  { name: "FS-LEGAL01.cryotech.local",   os: "Windows 11",    ip: "10.30.4.23",  role: "file_server",        asset_tag: "SRV-FS-013" },
  { name: "JMP-ADMIN01",                 os: "Windows 11",    ip: "10.30.9.5",   role: "jump_host",          asset_tag: "SRV-JMP-001" },
  { name: "JMP-ADMIN02",                 os: "Windows 11",    ip: "10.30.9.6",   role: "jump_host",          asset_tag: "SRV-JMP-002" },
  { name: "WEB-EDGE01",                  os: "Ubuntu 22.04",  ip: "172.21.1.10", role: "server",             asset_tag: "SRV-WEB-001" },
  { name: "APP-CRM01",                   os: "Ubuntu 22.04",  ip: "10.30.7.40",  role: "server",             asset_tag: "SRV-APP-001" },
  { name: "DB-PROD01.cryotech.local",    os: "Ubuntu 22.04",  ip: "10.30.5.11",  role: "db_server",          asset_tag: "SRV-DB-001" },
  { name: "DB-PROD02.cryotech.local",    os: "Ubuntu 22.04",  ip: "10.30.5.12",  role: "db_server",          asset_tag: "SRV-DB-002" },
  { name: "MAIL-EXCH01.cryotech.local",  os: "Windows 11",    ip: "10.30.6.10",  role: "mail_server",        asset_tag: "SRV-MAIL-001" },
  { name: "PROXY-INET01",                os: "Ubuntu 22.04",  ip: "172.21.2.5",  role: "proxy_server",       asset_tag: "SRV-PRXY-001" },
];

import { rng, pick, intBetween, hashString } from "./rng";

// ── Identity factory ───────────────────────────────────────────────────────────
export function generateIdentities(count: number, seed = 42): Identity[] {
  const r = rng(seed);
  const out: Identity[] = [];
  const usedUsernames = new Set<string>();
  const usedHosts = new Set<string>();
  let attempt = 0;

  while (out.length < count && attempt < count * 10) {
    attempt++;
    const fn   = pick(r, FIRST_NAMES);
    const ln   = pick(r, LAST_NAMES);
    const dept = pick(r, DEPARTMENTS);

    // Varied username formats
    const fmt = Math.floor(r() * 4);
    let username: string;
    switch (fmt) {
      case 0:  username = `${fn[0].toLowerCase()}.${ln.toLowerCase()}`; break;
      case 1:  username = `${fn.toLowerCase()}.${ln.toLowerCase().slice(0, 4)}`; break;
      case 2:  username = `${fn.toLowerCase()[0]}${ln.toLowerCase()}`; break;
      default: username = `${fn.toLowerCase()}.${ln.toLowerCase()}`; break;
    }
    // Sanitise unicode chars
    username = username.normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9.]/g, "");
    if (usedUsernames.has(username)) continue;
    usedUsernames.add(username);

    const email = `${username}@${COMPANY.domain}`;
    const id    = hashString(username);
    const ip    = `10.20.${(id >> 8) & 0xff}.${(id & 0xff) || 23}`;

    // Unique hostname per person
    let hostname: string;
    let hAttempt = 0;
    do {
      hostname = `WS-${dept.code}-${String(intBetween(r, 1000, 9999))}`;
      hAttempt++;
    } while (usedHosts.has(hostname) && hAttempt < 20);
    usedHosts.add(hostname);

    const isPrivileged = dept.code === "SEC" || dept.code === "OPS" || dept.code === "INFRA"
      || (dept.code === "EXEC" && r() > 0.4);

    out.push({
      email,
      display_name: `${fn} ${ln}`,
      username,
      upn: email,
      department: dept.code,
      title: pick(r, TITLES_BY_DEPT[dept.code] ?? ["Specialist"]),
      hostname,
      os: pick(r, OS_POOL),
      ip,
      mfa: r() > 0.12,
      privileged: isPrivileged,
      employee_id: `EMP-${String((id % 90000) + 10000)}`,
      location: pick(r, OFFICE_LOCATIONS),
    });
  }
  return out;
}

// ── Vendor / contractor identities ────────────────────────────────────────────
export const VENDOR_COMPANIES = [
  "Accenture","Deloitte","KPMG","PwC","IBM Consulting","Cognizant","Infosys","Wipro",
  "TCS","Capgemini","DXC Technology","Unisys","NTT Data","HCL","Atos",
];

export function makeVendorIdentity(seed: number): Identity {
  const r = rng(seed);
  const fn       = pick(r, FIRST_NAMES);
  const ln       = pick(r, LAST_NAMES);
  const vendor   = pick(r, VENDOR_COMPANIES);
  const domain   = `${vendor.toLowerCase().replace(/[^a-z]/g, "")}.com`;
  const username = `${fn[0].toLowerCase()}.${ln.toLowerCase()}`.replace(/[^a-z.]/g, "");
  const id       = hashString(username);
  return {
    email: `${username}@${domain}`,
    display_name: `${fn} ${ln}`,
    username,
    upn: `${username}@${domain}`,
    department: "VENDOR",
    title: pick(r, ["Consultant","Senior Consultant","Technical Analyst","Project Manager","Contractor"]),
    hostname: `VENDOR-${String(intBetween(r, 1000, 9999))}`,
    os: pick(r, OS_POOL),
    ip: `10.40.${(id >> 8) & 0xff}.${(id & 0xff) || 5}`,  // VPN range
    mfa: true,
    privileged: false,
    employee_id: `VEND-${String((id % 90000) + 10000)}`,
    location: pick(r, OFFICE_LOCATIONS),
  };
}
