# אימות עיוני: כיסוי תוכן מול תכנית הלימודים (11 קורסים)

תאריך: 2026-11-02 · נבדק מול הקוד החי בענף main (2c237fe)

מטרה: לוודא, נושא-אחר-נושא, האם לפלטפורמה יש **תוכן עיוני**, **סרטון** ו**מצגת** על כל נושא ותת-נושא בתכנית הלימודים בת 11 הקורסים. זהו מסמך אימות בלבד; הוא לא משנה שום קובץ.

---

## סימון

| סימן | פירוש |
|---|---|
| ✅ | קיים בעומק טוב |
| 🟡 | קיים חלקית, או מזווית אחרת (לרוב: הזווית ההגנתית/SOC במקום הגדרה/תצורה) |
| ❌ | חסר |

שלוש העמודות הן שלושת סוגי הנכסים שביקשת: **תוכן** (עמודי השיעור), **סרטון** (lesson-videos ב-Supabase), **מצגת** (lesson-decks).

---

## תמונת מצב כללית

הפלטפורמה בנויה כ**ספריית מומחה של אנליסט SOC / צוות כחול**. היא כוללת שני גופי תוכן:

1. **ספריית explainer** (כ-85 שיעורים עצמאיים). כל שיעור כזה הוא שלמות של **תוכן עמוק + סרטון + מצגת**. רמת התוכן גבוהה (לדוגמה, שיעור Kerberoasting כולל דוגמה מעשית מקצה לקצה, ניתוח שדות 4769, שאילתת KQL מכוונת, ו-Defender for Identity).
2. **Learning Path** (5 מסלולים: SOC Analyst, Threat Hunter, Incident Responder, Detection Engineer, Purple Team). לשיעורי המסלול יש **תוכן + מצגת**, אבל **לרבים אין סרטון**.

**המשמעות לאימות:** בכל מקום שבו הנושא הוא SOC/כחול, הכיסוי חזק ולרוב כולל את שלושת הנכסים. אבל תכנית הלימודים שהבאת רחבה הרבה יותר מ-SOC, והיא כוללת תחומים שלמים שהפלטפורמה כמעט לא נוגעת בהם: **יסודות Linux ברמת LPI, CCNA ברמת תצורת ציוד, OSINT, ו-AWS Practitioner ברוחב של ההסמכה**. שם הפערים גדולים.

**כלל ברזל:** האודיט מודד כיסוי בלבד. אין בו ערבוב תוכן בין סביבות.

---

## אבן דרך 1 — יסודות

### 01. מבוא לתקשורת ורשתות

| תת-נושא | תוכן | סרטון | מצגת | שיעור בפלטפורמה |
|---|---|---|---|---|
| 1. יסודות רשת ותקשורת | ✅ | 🟡 | ✅ | how-computers-and-networks-work-for-analysts (מצגת, בלי סרטון) |
| 2. סוגי רשתות מחשבים (LAN/WAN/…) | 🟡 | ❌ | 🟡 | נגזר מתוך שיעורי הרשת, אין שיעור ייעודי לטופולוגיות |
| 3. מודלי תקשורת | ✅ | ✅ | ✅ | osi-model-vs-tcp-ip-explained |
| 4. פרוטוקולים נפוצים | ✅ | ✅ | ✅ | core-protocols + DNS/DHCP/HTTP/SMB/SMTP/FTP/SSH/RDP נפרדים |
| 5. מודל OSI | ✅ | ✅ | ✅ | osi-model-vs-tcp-ip-explained |
| 6. ציוד תקשורת בסיסי | 🟡 | ❌ | 🟡 | אין שיעור ייעודי (נתב/מתג/hub) |
| 7. מודל TCP/IP | ✅ | ✅ | ✅ | osi-model-vs-tcp-ip-explained |

**מסקנה:** כיסוי טוב מהזווית של אנליסט. חסרים שני שיעורים ייעודיים: סוגי רשתות וציוד תקשורת, ושני סרטונים לשיעורי היסוד שיש להם מצגת בלבד.

### 02. יסודות Linux (LPI – Linux Essentials)

| תת-נושא | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. יסודות Linux ומבוא | 🟡 | ❌ | ✅ | linux-fundamentals-for-soc-analysts (מצגת בלבד) |
| 2. שורת הפקודה ופקודות בסיס | ❌ | ❌ | ❌ | — |
| 3. מערכת הקבצים ב-Linux | ❌ | ❌ | ❌ | — |
| 4. שירותי רשת וקבצי לוג | 🟡 | ❌ | 🟡 | נגזר משיעורי ניתוח לוגים, לא Linux-ספציפי |
| 5. רשתות ופתרון בעיות | ❌ | ❌ | ❌ | — |
| 6. ניהול משתמשים והרשאות | ❌ | ❌ | ❌ | — |
| 7. יסודות Bash Scripting | ❌ | ❌ | ❌ | — |

**מסקנה: פער גדול.** קיימת מצגת Linux אחת בלבד. אין תוכן ברמת LPI, אין סרטונים, ואין כיסוי ל-CLI, מערכת קבצים, משתמשים/הרשאות ו-Bash.

### 03. תקשורת רשתות (CCNA Routing & Switching)

| מודול | תוכן | סרטון | מצגת | הערה |
|---|---|---|---|---|
| 1. יסודות תקשורת נתונים | ✅ | ✅ | ✅ | osi/tcp-ip + ip-addressing-subnets-nat (רמת מבוא) |
| 2. Switching (VLAN/Trunk/VTP/STP/EtherChannel) | ❌ | ❌ | ❌ | — |
| 3. Routing (VLSM/inter-VLAN/DHCP/פרוטוקולי ניתוב) | 🟡 | 🟡 | 🟡 | subnetting קיים; ניתוב בפועל ❌ |
| 4. ניתוב מתקדם (EIGRP/OSPF/HSRP) | ❌ | ❌ | ❌ | — |
| 5. שירותי רשת ואבטחה (NAT/SSH/SYSLOG/Port-Security/ACL) | 🟡 | 🟡 | 🟡 | NAT ו-SSH קיימים; ACL/Port-Security ❌ |
| 6. אלחוט (LAP/WLC) | ❌ | ❌ | ❌ | — |
| 7. IPv6 ואוטומציה (API/JSON) | ❌ | ❌ | ❌ | — |
| 8. ניהול ותפעול רשת | ❌ | ❌ | ❌ | — |

**מסקנה: פער גדול.** הפלטפורמה מלמדת פרוטוקולים לצורך *זיהוי*, לא *תצורת ציוד Cisco*. כל מה שהוא ברמת הגדרת מתג/נתב חסר. זהו תחום שונה מזהות הפלטפורמה (ראו "הערת תחום" בסוף).

---

## אבן דרך 2 — ניטור וזיהוי

### 04. אנליסט SOC (ליבה)

| מודול | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. סביבות Windows / וירטואליזציה / מעבדה | 🟡 | ❌ | ✅ | windows-internals (מצגת); אין שיעור הקמת-מעבדה |
| 2. יסודות הגנה (CIA/סיכונים/Hashing/הצפנה/Web/נוזקות) | ✅ | ✅ | ✅ | cia-triad, hashing-encryption, malware-types, owasp, web-app-attacks |
| 3. נקודת מבט התוקף (Kill Chain/IOCs) | ✅ | 🟡 | ✅ | mitre-attack-and-the-cyber-kill-chain, lateral-movement, social-engineering |
| 4. יסודות SOC ו-SIEM | ✅ | 🟡 | ✅ | what-a-soc-is, siem-fundamentals-and-alert-triage, ibm-qradar |
| 5. QRadar מעשי (DSM/Parsing/Rules/Reference) | 🟡 | ✅ | ✅ | ibm-qradar-for-soc-analysts (סקירה; עומק hands-on חלקי) |
| 6. פורנזיקה/TI/SOAR (Sysinternals/Sysmon) | ✅ | ✅ | ✅ | windows-event-log (Sysmon), threat-intelligence-in-practice; SOAR 🟡 |
| 7. מעבדות SOC (WinCollect/קליטת לוגים) | 🟡 | 🟡 | 🟡 | נלמד דרך rooms/scenarios, לא כמעבדת-התקנה |

**מסקנה: כיסוי חזק.** זהו לב הפלטפורמה. פערים קטנים: הקמת-מעבדה, עומק hands-on של QRadar, SOAR.

---

## אבן דרך 3 — חקירה ותגובה

### 05. תגובה לאירועי סייבר – שלב 1 (IR L1)

| תת-נושא | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. מתודולוגיית תקיפה והגנה | ✅ | 🟡 | ✅ | mitre/kill-chain |
| 2. Scope וניתוח איומים | ✅ | ❌ | 🟡 | LP: Incident Responder › Detection & Analysis |
| 3. Artifacts בתחנות קצה | ✅ | ✅ | ✅ | windows-forensic-artifacts |
| 4. ניתוח לוגים ב-Windows | ✅ | ✅ | ✅ | windows-event-log-analysis |
| 5. Artifacts ב-Registry | ✅ | ✅ | ✅ | windows-registry-fundamentals |
| 6. ניתוח רשת ותקשורת | ✅ | ✅ | ✅ | network-traffic-analysis-pcap-wireshark |
| 7. Evidence of Execution | ✅ | 🟡 | ✅ | windows-forensic-artifacts (prefetch/shimcache וכו') |
| 8. תרחישי חקירה ותרגול | ✅ | — | — | rooms + scenarios + T3 Forensic Workbench |

**מסקנה: כיסוי טוב.** חסרים סרטונים לשניים-שלושה תת-נושאים.

### 06. חקר נוזקות – שלב 1

| תת-נושא | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. מבוא למחקר נוזקות | ✅ | ✅ | ✅ | malware-types-field-guide, static-vs-dynamic |
| 2. הקמת סביבת מעבדה | ❌ | ❌ | ❌ | — |
| 3. אנטומיה של תהליך וקובץ הרצה | ✅ | ✅ | ✅ | processes-pids, dlls-explained, process-injection |
| 4. ניתוח סטטי ודינמי | ✅ | ✅ | ✅ | static-vs-dynamic-malware-analysis |
| 5. ניתוח התנהגותי | 🟡 | 🟡 | 🟡 | מכוסה חלקית ב-static-vs-dynamic |
| 6. כלי Sysinternals | 🟡 | ❌ | 🟡 | מוזכר, אין שיעור ייעודי |
| 7. YARA | ✅ | ✅ | ✅ | yara-rules-writing-detection-signatures |
| 8. דוחות ופרויקט מחקר | 🟡 | ❌ | ✅ | malware-triage-without-reverse-engineering (מצגת) |

**מסקנה: כיסוי בינוני-טוב.** פערים: הקמת-מעבדה, Sysinternals ייעודי, ניתוח התנהגותי בעומק.

### 07. איסוף מודיעין ממקורות פתוחים (OSINT)

| תת-נושא | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. מבוא ל-OSINT ו-Sock Puppets | ❌ | ❌ | ❌ | — |
| 2. חיפוש מתקדם ומנועי חיפוש | ❌ | ❌ | ❌ | — |
| 3. OSINT מבוסס תמונה ומיקום | ❌ | ❌ | ❌ | — |
| 4. OSINT לאימיילים/משתמשים/סיסמאות | 🟡 | 🟡 | 🟡 | enrichment-tools (WHOIS/passive-DNS) — זווית העשרה, לא OSINT-אדם |
| 5. OSINT ברשתות חברתיות | ❌ | ❌ | ❌ | — |
| 6. OSINT טכנולוגי ועסקי | 🟡 | 🟡 | 🟡 | enrichment-tools חלקית |
| 7. כלי OSINT ודוחות | ❌ | ❌ | ❌ | — |
| 8. OSINT מתקדם – ניתוח מיקום | ❌ | ❌ | ❌ | — |

**מסקנה: פער גדול.** אין תכנית OSINT ייעודית; יש רק חפיפה חלקית דרך כלי העשרה של אנליסט.

---

## קורסי ענן

### 08. יסודות AWS (AWS Practitioner)

| מודול | תוכן | סרטון | מצגת | הערה |
|---|---|---|---|---|
| 1. מבוא ל-AWS/ענן + אחריות משותפת | ✅ | ✅ | ✅ | cloud-security-fundamentals (זווית SOC) |
| 2. IAM | ✅ | ✅ | ✅ | cloud-authentication-and-access-keys, cloud-iam-privilege-escalation |
| 3. EC2 | 🟡 | 🟡 | 🟡 | מוזכר, אין שיעור EC2-fundamentals |
| 4. אחסון ו-Scaling (ELB/Auto Scaling) | ❌ | ❌ | ❌ | — |
| 5. S3 | ✅ | ✅ | ✅ | cloud-storage-permissions (זווית חשיפה) |
| 6. מסדי נתונים/אנליטיקה (RDS/DynamoDB) | ❌ | ❌ | ❌ | — |
| 7. Serverless (Lambda/ECS) | ❌ | ❌ | ❌ | — |
| 8. תשתית/Deployment (CloudFormation/CI-CD) | ❌ | ❌ | ❌ | — |
| 9. רשתות ואבטחה בענן (VPC/Subnets/VPN) | 🟡 | 🟡 | 🟡 | cloud-exposure/security-groups חלקי |
| 10. ניטור/חיוב/ארכיטקטורה (CloudWatch/W-A) | 🟡 | ✅ | ✅ | cloud-audit-logs (CloudTrail); חיוב/W-A ❌ |

**מסקנה: פער לרוחב ההסמכה.** הפלטפורמה מכסה את *פרוסות האבטחה* של AWS, לא את רוחב השירותים/הארכיטקטורה שההסמכה דורשת.

### 09. אבטחת ענן AWS

| תת-נושא | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. IAM וניהול זהויות | ✅ | ✅ | ✅ | cloud-iam-privilege-escalation |
| 2. אבטחת S3 ואחסון | ✅ | ✅ | ✅ | cloud-storage-permissions |
| 3. אבטחת רשת – VPC | 🟡 | 🟡 | 🟡 | חלקי |
| 4. אבטחת EC2/משאבים | 🟡 | 🟡 | 🟡 | חלקי |
| 5. ניטור וזיהוי איומים | ✅ | ✅ | ✅ | cloud-audit-logs; GuardDuty 🟡 |
| 6. הקשחה ו-Best Practices | 🟡 | 🟡 | 🟡 | מפוזר בין השיעורים |

**מסקנה: כיסוי סביר** מהזווית ההגנתית. פערי עומק ב-VPC/EC2 הקשחה.

---

## התמחות והעשרה

### 10. תקיפות Active Directory מתקדמות

| תת-נושא | תוכן | סרטון | מצגת | שיעור (זווית הגנתית/זיהוי) |
|---|---|---|---|---|
| 1. יסודות AD לתוקף | ✅ | ✅ | ✅ | active-directory-and-domain-controllers |
| 2. איסוף מידע על הדומיין | ✅ | ✅ | ✅ | ldap-bloodhound-ad-recon, discovery-enumeration |
| 3. השגת דריסת רגל | 🟡 | 🟡 | 🟡 | מכוסה דרך phishing/credential |
| 4. מיפוי אובייקטים | ✅ | ✅ | ✅ | ldap-bloodhound-ad-recon |
| 5. גישה מרחוק ותנועה רוחבית | ✅ | ✅ | ✅ | lateral-movement, pass-the-hash-and-pass-the-ticket |
| 6. העלאת הרשאות | ✅ | ✅ | ✅ | kerberoasting, as-rep-roasting, unsecured-credentials |
| 7. השתלטות מלאה | ✅ | ✅ | ✅ | dcsync-golden-silver-ticket, credential-dumping |
| 8. Post-Exploitation והתמדה | 🟡 | 🟡 | 🟡 | scheduled-tasks; התמדה ברג'יסטרי מעבר ל-Run חסרה (ראו הערה) |
| 9. תקיפת Trusts בין דומיינים | ❌ | ❌ | ❌ | — |
| 10. OSINT ו-Passive Enum | 🟡 | 🟡 | 🟡 | תלוי בפער OSINT לעיל |

**מסקנה: כיסוי חזק מהזווית ההגנתית** (זיהוי, לא הרצה התקפית). חסרים: Domain Trusts, התמדה לא-Run ברג'יסטרי.
הערה: הוספת תרחישי התמדה ברג'יסטרי (Services/IFEO/Winlogon) נחסמה שוב ושוב על ידי מסנן הבטיחות (ראו זיכרון `project_soc_edr_static_analysis`).

### 11. אבטחת AI (AI Security Practitioner)

| מודול | תוכן | סרטון | מצגת | שיעור |
|---|---|---|---|---|
| 1. AI Foundations | 🟡 | 🟡 | 🟡 | רקע בתוך ai-attacks-detection |
| 2. Understanding LLMs | 🟡 | 🟡 | 🟡 | חלקי |
| 3. AI Systems & Architecture | ❌ | ❌ | ❌ | — |
| 4. Working with LLMs | ❌ | ❌ | ❌ | — |
| 5. LLM Interfaces & APIs | ❌ | ❌ | ❌ | — |
| 6. Prompt Engineering & Model Behavior | ✅ | ✅ | ✅ | ai-attacks-detection (Prompt Injection) |
| 7. The AI Attack Surface | ✅ | ✅ | ✅ | ai-attacks-detection |
| 8. AI & LLM Security Risks | ✅ | ✅ | ✅ | ai-attacks-detection + part 2 (OWASP LLM) |
| 9. AI Agents & Autonomous Systems | 🟡 | 🟡 | 🟡 | ai-attacks-detection-2 (Excessive Agency) |

**מסקנה: חזק על *תקיפות/זיהוי AI*, חלש על *יסודות AI ובניית LLM*.** ההטיה היא הגנתית, כצפוי.

---

## סיכום פערים, לפי עדיפות

**קבוצה A — פערים גדולים, תחום שונה מזהות הפלטפורמה (החלטת מוצר נדרשת):**
- **02 Linux Essentials** — כמעט ריק (מצגת אחת). CLI, מערכת קבצים, משתמשים/הרשאות, Bash, רשת.
- **03 CCNA** — תצורת ציוד (VLAN/STP/OSPF/EIGRP/HSRP/אלחוט/IPv6/אוטומציה) חסרה כמעט לגמרי.
- **07 OSINT** — אין תכנית ייעודית.
- **08 AWS Practitioner** — רוחב השירותים/הארכיטקטורה חסר (קיימות רק פרוסות האבטחה).

**קבוצה B — פערים בינוניים בתוך תחום הליבה (מומלץ להשלים):**
- **11 AI** — יסודות AI ו-LLM, ארכיטקטורה, APIs.
- **06 Malware** — הקמת-מעבדה, Sysinternals ייעודי, ניתוח התנהגותי בעומק.
- **10 AD** — Domain Trusts; התמדה לא-Run (חסום ע"י מסנן).

**קבוצה C — חורי-סרטון בלבד (התוכן והמצגת קיימים):**
- שיעורי יסוד עם מצגת בלי סרטון: linux-fundamentals, windows-internals, how-computers-and-networks-work, siem-fundamentals, mitre-attack-and-the-cyber-kill-chain, ועוד.

---

## הערת תחום (חשוב להחלטה)

חלק מהקורסים בתכנית הזו שייכים לתחום שונה מזהות הפלטפורמה כ-**סימולטור SOC / צוות כחול**:
- **CCNA ברמת תצורת ציוד** ו-**AWS Practitioner ברמת ארכיטקטורה** הם הסמכות תשתית, לא SOC.
- **תקיפות AD התקפיות** ו-חלקי **OSINT-אדם** הם תוכן התקפי; הפלטפורמה מלמדת אותם מהזווית ההגנתית בכוונה, וחלקם (למשל התמדה ברג'יסטרי) נחסם שוב ושוב ע"י מסנן הבטיחות.

לכן, לפני בנייה, צריך להכריע: האם מרחיבים את הפלטפורמה לאקדמיית סייבר מלאה (כולל תשתית ו-offensive), או משלימים רק את הפערים שבתוך זהות ה-SOC/כחול (קבוצה B + חורי-הסרטון בקבוצה C). זו החלטת מוצר, לא טכנית.

---

## תכנית בנייה מוצעת (אם מחליטים להשלים)

לכל שיעור חדש: **תוכן ברמה אקדמית** (כמו שיעור Kerberoasting הקיים) + **מצגת** + **סרטון**. לא באותו סדר/ארכיטקטורה של התכנית הזו, כדי שלא ייראה מועתק.

- **שלב 1 (הכי בטוח, בתוך הזהות):** להשלים את חורי-הסרטון (קבוצה C) + יסודות AI (קבוצה B). אלה שיעורים שהתוכן/המצגת כבר קיימים או שהם הגנתיים טהורים.
- **שלב 2:** Malware (מעבדה/Sysinternals/התנהגותי), AD Trusts.
- **שלב 3 (דורש החלטת-תחום):** Linux Essentials, OSINT, AWS Practitioner, CCNA — אם מרחיבים את הפלטפורמה מעבר ל-SOC.

הבנייה היא רב-שלבית ולא נכנסת לטורן אחד. אפשר להתחיל לפי הסדר הזה, או לפי מה שתגדיר כעדיפות.
