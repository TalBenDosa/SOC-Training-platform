# מודל איומים ייחוסי ל-SOC ארגוני (2024–2026) ומיפוי מול הארסנל של HACK THE SOC

**תאריך:** 2026-10-03
**כותב:** Threat-Intel / SOC lead (סקירה לקריאה בלבד, לא בוצע שום שינוי בריפו)
**היקף:** 82 storylines פעילים ב-`ATTACK_STORIES` (אחרי `EXCLUDED_STORIES`), 64 אירועי pool זדוניים בפולים של החברות וב-`BENIGN_EVENTS`, 65 חבילות ב-`/scenarios`, אפשרויות הסביבה (`environment.ts`) ואפשרויות המוצרים (`stack.ts` `STACK_CHOICES`).
**שיטה:** (1) בניית מודל איומים ממקורות סמכותיים, כל טענה מצוטטת עם URL. (2) חילוץ אוטומטי של כל storyline (tier, MITRE, מקורות, פלטפורמות) והרצה של `envAllowsStory` על כל צירוף סביבה בעזרת `tsx` (סקריפט זמני ב-scratchpad, נמחק). (3) מיפוי פערים. (4) המלצות.

---

## 0. תקציר מנהלים

1. **המציאות של 2025–2026 נראית כך:** ניצול חולשות (בעיקר ב-edge devices וב-VPN) הוא וקטור הכניסה מספר 1. DBIR 2026 מודד 31%, ו-M-Trends 2026 מודד 32%. אחריו באים זהות (credentials גנובים, infostealers, vishing מול ה-help desk) ו-ransomware/extortion, שמופיע ב-48% מהפריצות לפי DBIR 2026. ‏Breakout ממוצע ירד ל-29 דקות, ו-82% מהזיהויים הם malware-free.
2. **הארסנל של הפלטפורמה חזק בזהות ובפישינג:** BEC, ‏AiTM, ‏MFA fatigue, ‏OAuth consent, ‏help-desk reset, ‏ClickFix, ‏SocGholish, ‏infostealer. בתחומים האלה הכיסוי טוב ועדכני.
3. **הפער הגדול ביותר ביחס לשכיחות: ניצול edge devices.** זה הווקטור הראשון בכל הדוחות, ויש לו בפועל storyline אחד (`edge-vpn-cve-exploit`), שסומן REPLACE. אין תרחיש של PAN-OS, ‏Ivanti, ‏Citrix, ‏Cisco ASA, ‏Check Point VPN (CVE-2026-50751, עם קשר ל-Qilin), ‏SharePoint ToolShell, או אפליקציית file-transfer/ERP בסגנון Cl0p.
4. **פער שני: ה-ransomware "של היום".** Akira ו-Qilin מובילים, והכניסה אצלם היא valid account על VPN ← Impacket ‏(wmiexec/secretsdump) ← RDP פנימי ← השמדת גיבויים / ESXi ← exfil מחוץ לשעות העבודה. בפלטפורמה ה-ransomware המרכזי הוא LockBit שנכנס בפישינג. אין BYOVD/EDR-kill, אין RMM-led ransomware ואין "השמדת התאוששות".
5. **פער שלישי: social engineering שאינו אימייל.** DBIR 2026 מודד 41% מה-social engineering ב-vishing, ב-Teams ובערוצים אחרים. חסרים email-bomb ← Teams vishing ← Quick Assist (Black Basta), ‏callback phishing, ‏quishing ו-device-code phishing ‏(Storm-2372).
6. **פער רביעי: third-party / SaaS.** ‏DBIR 2026 מודד מעורבות צד שלישי ב-48% מהפריצות. חסרים גניבת OAuth tokens של אינטגרציה (Salesloft Drift), ‏vishing ל-Salesforce ‏(UNC6040), גישה דרך MSP/RMM של ספק, ו-Snowflake-style (credentials מ-infostealer בלי MFA).
7. **AI מיוצג יתר על המידה.** 13 מתוך 82 storylines (16%) הם AI-themed, ומתוכם 4 על Claude Enterprise. ‏M-Trends 2026 קובע במפורש ש-2025 "לא הייתה השנה" שבה פריצות נבעו ישירות מ-AI. מומלץ לצמצם ל-6–8 ולהשאיר את המבוססים (`ai-llmjacking-bedrock`, ‏`ai-agentic-intrusion-tempo`, ‏`ai-helpdesk-voice-reset`, ‏`ai-svg-invoice-lure`, ‏`ai-shadow-chat-upload`).
8. **ענפים: הכיסוי דק.** ל-Healthcare יש 4 storylines ענפיים, וכולם slices של 4 אירועים עם ציון e2e של 2. ל-Logistics יש 2 slices. ל-Finance יש 7, ומתוכם 2 ב-REPLACE ו-3 שדורשים AWS+CyberArk. ארגון פיננסי בסטאק Azure מקבל רק 2 תרחישים ענפיים נוספים, ואחד מהם ב-REPLACE.
9. **פלטפורמות: Azure כמעט ריק.** בחירה ב-Azure מוסיפה 3 storylines בלבד (שניים מהם AI). זה למרות ש-Azure/M365 הוא הסטאק הנפוץ ביותר בישראל. בחירה ב-K8s, ב-GitHub או ב-CyberArk בלי AWS לא מוסיפה **אף** storyline. ‏VMware מוסיף 1 ו-NDR מוסיף 2. בסטאק Okta+Google Workspace עם פלטפורמות ברירת המחדל יש רק 6 core ו-9 advanced.
10. **בחירת המוצרים:** הסט לגיטימי, ורוב המוצרים בו מובילי שוק. חסרים מוצרי ה-edge שמנוצלים הכי הרבה בפועל (Ivanti Connect Secure, ‏Citrix NetScaler, ‏SonicWall, ‏Check Point Remote Access כ-VPN). חסרים גם Cortex XDR / Trend Vision One / Check Point Harmony ב-EDR, ‏Mimecast / Check Point Harmony Email ‏(Avanan) באבטחת דוא"ל, ‏Intune/MDM, ‏GCP (יש renderer ואין פלטפורמה), ו-proxy/SSE (יש renderer ל-Zscaler ZIA ואין בחירה). כדאי להוסיף ענפים: Manufacturing/OT, ‏High-tech/SaaS (‏#1 ב-M-Trends 2026), ‏Government/Municipal, ‏Education.

**Top-10 התרחישים החסרים:** מפורטים בסעיף 4.1.

---

## 1. מקורות (ראשיים)

| מקור | גרסה | מה לקחנו |
|---|---|---|
| Verizon DBIR | [2025](https://www.verizon.com/business/resources/reports/dbir/) · [2026](https://www.verizon.com/business/resources/T343/reports/2026-dbir-data-breach-investigations-report.pdf) | וקטורי כניסה, ransomware, צד שלישי, infostealers, ערוצי SE |
| Mandiant M-Trends | [2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025) · [2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) | Initial infection vectors, ‏dwell time, ענפים, recovery denial |
| CrowdStrike GTR | [2025](https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-global-threat-report-findings/) · [2026](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) | ‏breakout, ‏malware-free, ‏vishing, ‏cloud, ‏zero-day |
| Microsoft MDDR | [2025](https://blogs.microsoft.com/on-the-issues/2025/10/16/mddr-2025/) | מניעים, זהות, infostealers, ClickFix |
| ENISA ETL | [2025](https://www.enisa.europa.eu/sites/default/files/2026-01/ENISA%20Threat%20Landscape%202025_v1.2.pdf) | ‏phishing 60% / ‏exploitation 21.3% (EU), תחבורה כענף מותקף |
| Sophos Active Adversary | [2025](https://www.sophos.com/en-us/blog/2025-sophos-active-adversary-report) · [2026](https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report) | ‏root causes, ‏Impacket, ‏RDP, ‏Akira/Qilin, זמן ל-AD |
| Red Canary TDR | [2025/2026](https://redcanary.com/threat-detection-report/) · [2026 summary](https://www.zscaler.com/blogs/cybersecurity-best-practices/2026-threat-detection-report) | ‏Top techniques |
| CISA | [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) · [AA25-163A](https://www.attackiq.com/2025/06/16/response-to-cisa-advisory-aa25-163a/) · [ED 25-03](https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices) | ‏edge, ‏RMM, ‏Scattered Spider |
| ענפים | [DBIR 2026 Healthcare](https://www.verizon.com/business/resources/reports/2026-dbir-healthcare-snapshot.pdf) · [HC3 help-desk note](https://www.aha.org/cybersecurity-government-intelligence-reports/2024-04-03-hc3-tlp-clear-analyst-note-social-engineering-attacks-targeting-it) · [FS-ISAC Navigating Cyber 2025](https://www.fsisac.com/navigatingcyber2025) · [Proofpoint cargo theft](https://www.proofpoint.com/us/blog/threat-insight/beyond-breach-inside-cargo-theft-actors-post-compromise-playbook) | איומים ענפיים |
| ישראל | [Times of Israel / INCD](https://www.timesofisrael.com/iranian-cyberattacks-on-israel-surged-in-2026-cyber-chief-says/) · [Unit 42 Handala](https://unit42.paloaltonetworks.com/handala-hack-wiper-attacks/) · [MuddyWater](https://thehackernews.com/2025/12/iran-linked-hackers-hits-israeli_2.html) | ‏wipers, ‏RMM, ‏Intune abuse |

> **הערת כיול:** כל דוח מודד אוכלוסייה אחרת. DBIR מודד פריצות מאומתות, M-Trends מודד חקירות IR, ‏Sophos מודד IR+MDR (שם הרוב SMB), ו-ENISA מודד אירועים פומביים ב-EU (וכולל DDoS). לכן המספרים לא אמורים להתלכד. מה שחשוב הוא **הסדר היחסי** והמגמה, ואלה עקביים בין הדוחות.

---

## 2. מודל האיומים הייחוסי

### 2.1 וקטורי גישה ראשונית: השכיחות בפועל

| וקטור | DBIR 2025 | DBIR 2026 | M-Trends 2025 | M-Trends 2026 | Sophos 2025 / 2026 (root cause) | ENISA 2025 |
|---|---|---|---|---|---|---|
| ניצול חולשה (exploit) | 20% ([src](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025)) | **31%** ([src](https://pushsecurity.com/blog/verizon-dbir-2026-review)) | **33%** | **32%** | 22% / 16% | 21.3% |
| Credential abuse / stolen creds | 22% | 13% (16% מתוקנן) | 16% | – | **41% / 42%** | – |
| Phishing (email) | 16% | 16% | 14% | 6% | – / 6.35% | **60%** |
| Voice phishing / pretexting | – | 6% pretexting | – | **11%** (#2) | – | – |
| Prior compromise (handoff) | – | – | – | 10% (30% ב-ransomware) | – | – |
| Brute force | – | – | – | – | 21% / 15.6% | – |

מקורות: [M-Trends 2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025), ‏[M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026), ‏[Sophos 2025](https://www.sophos.com/en-us/blog/2025-sophos-active-adversary-report), ‏[Sophos 2026](https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report), ‏[ENISA via SecurityAffairs](https://securityaffairs.com/182978/security/reading-the-enisa-threat-landscape-2025-report.html).

**הקשרים חשובים:**
- **Edge/VPN:** ב-DBIR 2025, ‏edge devices ו-VPN עלו מ-3% ל-22% מיעדי הניצול ([Tenable](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025)).
- **Zero-day:** לפי CrowdStrike 2026, ‏42% מהחולשות נוצלו לפני חשיפה. ‏40% מתקיפות China-nexus כוונו ל-edge devices ([CrowdStrike 2026](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/)). ‏M-Trends 2026 מודד mean time-to-exploit של **‎-7 ימים**.
- **Sophos:** ב-2025, ‏External Remote Services הופיעו ב-71% מהמקרים, ו-Valid Accounts ב-78%. ‏RDP חשוף היה 18% ו-VPN פגיע 12%. ‏MFA חסר היה ב-63% מהמקרים, וב-2026 ב-59% חסר או מוגדר לא נכון.
- **Credential כמבשר ל-ransomware:** לפי DBIR 2026, ל-50% מקורבנות ה-ransomware היה אירוע credential או infostealer ב-95 הימים שלפני ([Push Security](https://pushsecurity.com/blog/verizon-dbir-2026-review)).
- **ClickFix:** לפי MDDR 2025, ‏ClickFix היה 47% ממקרי ה-initial access שטיפל בהם Defender Experts ב-2025, יותר מפישינג קלאסי ([דיווח](https://www.intel471.com/blog/clickfix-tricking-users-into-installing-infostealers); המספר מצוטט בדיווחים על MDDR).

**מסקנה למודל:** משקל ההדרכה צריך להיות בערך **שליש ניצול public-facing/edge, שליש זהות (creds / infostealer / vishing / AiTM / help-desk), שליש פישינג ו-SE מגוון**. בתוך הזהות, ה-vishing וה-help desk הם הצומחים ביותר.

### 2.2 קצב ועומק

| מדד | ערך | מקור |
|---|---|---|
| eCrime breakout ממוצע | 48 דק' (2024) ← **29 דק'** (2025). המהיר ביותר 27 שניות | [CS 2025](https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-global-threat-report-findings/), ‏[CS 2026](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/) |
| Malware-free detections | 79% ← **82%** | שם |
| Median dwell | 11 ← **14 ימים**. ‏espionage ו-DPRK IT workers: ‏122 ימים | M-Trends 2025/2026 |
| Hand-off מ-access broker | 8 שעות (2022) ← **22 שניות** (2025) | [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| זמן לניסיון גישה ל-AD | **3.4 שעות** (‎-70% לעומת השנה הקודמת) | [Sophos 2026](https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report) |
| Exfil מחוץ לשעות עבודה | 78.85%. ‏ransomware נפרס מחוץ לשעות ב-88% | שם |
| Akira VPN ← הצפנה | פחות מ-4 שעות, לעתים 55 דק' | [Help Net Security](https://www.helpnetsecurity.com/2025/09/29/akira-ransomware-sonicwall-vpn/) |

**משמעות להדרכה:** תרחישי advanced צריכים לכלול **לחץ זמן אמיתי**. התוקף מגיע ל-DC תוך שעות, ולכן containment מוקדם (בידוד host, ‏revoke session) צריך להשפיע על התוצאה. מנגנון ה-EDR isolation שקיים במשחק הקבוצתי מתאים לזה.

### 2.3 טכניקות וכלים מובילים

- **Red Canary 2025 Top-10:** ‏Cloud Accounts ‏(T1078.004) במקום 1, ‏Windows Command Shell, ‏**Email Forwarding Rule** ‏(T1114.003), ‏PowerShell, ‏**Email Hiding Rules** ‏(T1564.008), ‏Service Execution, ‏Modify Registry, ‏WMI, ‏Mshta, ‏Ingress Tool Transfer ([Red Canary](https://redcanary.com/threat-detection-report/)).
- **Red Canary 2026:** ‏Cloud Accounts שוב במקום 1. נכנסו לראשונה **Data from Cloud Storage** ו-**Malicious Copy and Paste (ClickFix)**. לפחות חצי מ-top-10 האיומים פועלים מהדפדפן או גונבים ממנו ([Zscaler/Red Canary](https://www.zscaler.com/blogs/cybersecurity-best-practices/2026-threat-detection-report)).
- **Sophos 2025/2026, כלים:** ‏**Impacket** הוא הכלי המוביל, ‏21.43% ← 36.01%, כש-`wmiexec.py` ו-`secretsdump.py` הם הנפוצים. ‏Cobalt Strike בירידה. ‏Mimikatz ב-15%. ‏RDP פנימי ב-66%, ‏WMI ב-24%, ‏vssadmin ב-10%.
- **MDDR 2025:** יותר מ-97% מתקיפות הזהות הן password spray / brute force. תקיפות זהות עלו ב-32% ב-H1 2025 ([Microsoft](https://blogs.microsoft.com/on-the-issues/2025/10/16/mddr-2025/)).

### 2.4 קטגוריות האיום: מה רואים ראשון ואילו לוגים מוכיחים

> בכל קטגוריה: **שכיחות/עוגן**, **ההתראה הראשונה** שאנליסט T1 פוגש, ו**מקורות ההוכחה** (בסוגריים: ה-native renderer בפלטפורמה, אם יש).

#### A. Ransomware ו-extortion

- **שכיחות:**
  - לפי DBIR 2026, ‏ransomware מופיע ב-48% מהפריצות (2025: ‏44%).
  - לפי MDDR 2025, ‏52% מהתקיפות שהמניע שלהן ידוע הן extortion/ransom, ובערך 80% מהן כוללות גניבת נתונים.
  - לפי Sophos 2026, ‏Akira הוא 22.6% ו-Qilin ‏11.1%, וחמשת המותגים המובילים הם 51% מהמקרים.
- **מגמות:**
  - **(1) "Recovery denial":** השמדת גיבויים, ניצול ADCS templates, תקיפת hypervisor ומחיקת backups בענן ([M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)).
  - **(2) ESXi:** מספר החקירות של Microsoft IR שכללו ESXi הוכפל בשלוש שנים. ‏CVE-2024-37085 (קבוצת "ESX Admins") נוצל בידי Storm-0506, ‏Octo Tempest ואחרים, עם פריסת Akira ו-Black Basta ([Microsoft](https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/)).
  - **(3) RMM:** לפי DBIR 2026, ניצול RMM עלה ב-240%. דוגמה: ‏DragonForce דרך SimpleHelp, ‏CVE-2024-57727 ([CISA AA25-163A](https://www.attackiq.com/2025/06/16/response-to-cisa-advisory-aa25-163a/)).
  - **(4) BYOVD / EDR killers:** ‏EDRKillShifter של RansomHub משמש גם את Play, ‏Medusa ו-BianLian ([ESET](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/)).
  - **(5) Data-theft-only:** ‏Cl0p ב-Oracle EBS, ‏CVE-2025-61882. ההתראה הראשונה של הקורבן הייתה **מייל סחיטה למנהלים** ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation)).
- **מה רואים ראשון:**
  - EDR: ‏Impacket/wmiexec ‏(`cmd.exe /Q /c … 1> \\127.0.0.1\ADMIN$\__…`), ‏secretsdump / גישה ל-NTDS, ‏`vssadmin delete shadows`, או sensor שמפסיק לדווח.
  - ספירת התחברויות RDP פנימיות חריגה.
  - Egress גדול בלילה (rclone/MEGA).
  - ESXi: ‏SSH שהופעל, ‏`esxcli vm process kill`.
- **מקורות הוכחה:**
  - VPN ‏(`globalprotect` / `anyconnect` / `fortigate_sslvpn`)
  - `windows_security`: ‏4624 type 3/10, ‏4672, ‏7045/4697, ‏4728/4732, ‏5136
  - EDR ‏(`mde` / `crowdstrike` / `sentinelone`), ‏`sysmon`
  - firewall ‏egress, ‏DNS
  - vCenter/ESXi syslog (אין native)
  - backup console (אין native)

#### B. זהות: AiTM, ‏MFA fatigue, ‏help desk, ‏token theft, ‏OAuth consent, ‏device code

- **שכיחות:**
  - Vishing: ‏CrowdStrike 2025 מדד זינוק של 442% ב-vishing. ‏M-Trends 2026 מודד voice phishing כ-11% מהכניסות, הווקטור השני בשכיחותו, שמכוון בעיקר ל-help desk לעקיפת MFA.
  - Scattered Spider: ‏CISA עדכנה את AA23-320A ב-29 ביולי 2025 עם TTPs חדשים ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)). ב-M&S מספיקה הייתה שיחה ל-help desk של צד שלישי (TCS), אחריה הוצא NTDS.dit, ונפרס DragonForce: ‏46 יום בלי הזמנות אונליין ונזק של כ-300 מיליון ליש"ט ([THN](https://thehackernews.com/2025/06/scattered-spider-behind-cyberattacks-on.html)).
  - AiTM: ‏Tycoon 2FA היה ה-PhaaS הדומיננטי ב-AiTM עד הפירוק ב-2026 ([Trend Micro](https://www.trendmicro.com/en_us/research/26/c/tycoon2fa-takedown.html)).
  - Device code: ‏Storm-2372 הוביל קמפיין device-code phishing דרך הזמנות Teams, ועבר ל-client ID של Microsoft Authentication Broker כדי לרשום device ולקבל **PRT** ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)).
  - Data theft: ‏Red Canary 2026 מודד Steal Application Access Token ו-Data from Cloud Storage בעלייה.
- **מה רואים ראשון:**
  - Entra ID Protection או Okta: ‏risky sign-in, ‏unfamiliar properties, ‏anomalous token.
  - רישום MFA method חדש מיד אחרי איפוס.
  - Sign-in עם `authenticationProtocol = deviceCode`.
  - הוספת device חדש.
  - Inbox rule שמעבירה מייל החוצה או מסתירה אותו.
  - Consent לאפליקציה עם `Mail.Read` / `offline_access`.
- **מקורות הוכחה:**
  - `entra` (sign-in + audit), ‏`okta`
  - `m365` UAL: ‏New-InboxRule, ‏MailItemsAccessed, ‏Consent to application
  - `servicenow`: ה-ticket של ה-help desk
  - `defender_o365` / `proofpoint` ‏(lure)
  - `zscaler_zia` או firewall: הגישה לדומיין ה-AiTM

#### C. Infostealers

- **שכיחות:**
  - לפי DBIR 2026, ל-54% מהמכשירים בלוגים של Initial Access Brokers היה infostealer.
  - פירוק Lumma: כ-394,000 מחשבים נגועים במרץ–מאי 2025 ([Microsoft](https://blogs.microsoft.com/on-the-issues/2025/05/21/microsoft-leads-global-action-against-favored-cybercrime-tool/)).
  - Snowflake ‏(UNC5537): כ-165 ארגונים נפרצו עם credentials מ-infostealers ישנים (חלקם מ-2020), בחשבונות **ללא MFA** ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion)).
- **מה רואים ראשון:**
  - EDR: גישה של תהליך לא-דפדפן ל-`Login Data` / `Cookies`.
  - הרצה מ-ClickFix ‏(`powershell -w h -c iwr … | iex` מתוך RunMRU).
  - אחר כך sign-in מ-ASN של VPS עם session קיים (cookie replay).
- **מקורות הוכחה:**
  - EDR file/process, ‏`sysmon` 1/11/22
  - proxy/firewall
  - `entra` / `okta` ‏sign-in (אותו session ID מ-IP אחר)
  - `m365` / `google_workspace`

#### D. ניצול Edge devices ו-public-facing applications

- **שכיחות:** הווקטור מספר 1 (סעיף 2.1).
- **CISA KEV:** ב-2025 נוספו 245 רשומות KEV (2024: ‏185), ו-24 מהן מסומנות כמנוצלות ע"י ransomware ([Cyber Express](https://thecyberexpress.com/cisa-known-exploited-vulnerabilities-kev-2025/)).
- **עוגנים:**
  - Cisco ASA/FTD: ‏ArcaneDoor, ‏CVE-2025-20333/20362, ‏ED 25-03 ([CISA](https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices)).
  - SonicWall: ‏CVE-2024-40766 ← Akira, כולל עקיפת OTP ([BleepingComputer](https://www.bleepingcomputer.com/news/security/akira-ransomware-breaching-mfa-protected-sonicwall-vpn-accounts/)).
  - Check Point:
    - CVE-2024-24919: קריאת קבצים וגניבת hash-ים של חשבונות מקומיים, ב-KEV ([Tenable](https://www.tenable.com/blog/cve-2024-24919-check-point-security-gateway-information-disclosure-zero-day-exploited-in-the)).
    - **CVE-2026-50751:** ‏auth bypass ב-Remote Access VPN, מנוצל מ-7 במאי 2026, עם קשר ל-Qilin ([Rapid7](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/)).
  - SharePoint on-prem ‏**ToolShell**: ‏CVE-2025-53770, ‏Storm-2603 ← Warlock ransomware ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)).
  - Oracle EBS ‏(Cl0p).
- **מה רואים ראשון:**
  - Firewall/IPS: ‏threat log עם חתימת CVE.
  - Login לממשק הניהול מ-IP חיצוני.
  - Config export או יצירת local admin על ה-appliance.
  - EDR על שרת ה-app: ‏`w3wp.exe` / `java` שמריצים `cmd` / `powershell` / `sh`, או קובץ `.aspx` חדש.
  - VPN session של משתמש מקומי ישן.
- **מקורות הוכחה:**
  - Firewall threat + system logs ‏(`paloalto` / `fortigate` / `checkpoint` / `cisco_asa` / `cisco_ftd`)
  - VPN
  - EDR על השרת, ‏`windows_security`, ‏`linux_auditd`
  - WAF ו-IIS logs (אין native)

#### E. ענן ו-SaaS

- **שכיחות:**
  - לפי CrowdStrike 2026, ‏cloud-conscious intrusions עלו ב-37%, ואצל state-nexus ב-266%.
  - Red Canary: ‏Cloud Accounts הוא מקום 1, שנתיים ברציפות.
- **עוגנים:**
  - Salesloft Drift ‏(UNC6395, אוגוסט 2025): ‏OAuth tokens גנובים של האינטגרציה שימשו לשאילתות על Salesforce ביותר מ-700 ארגונים. התוקפים חיפשו AWS keys וטוקנים בתוך Cases, ו-Drift Email tokens נתנו גישה ל-Google Workspace ([Arctic Wolf](https://arcticwolf.com/resources/blog/widespread-salesforce-data-theft-via-compromised-salesloft-drift-oauth-tokens/), ‏[Astrix](https://astrix.security/learn/blog/critical-update-astrix-research-team-discovers-unc6395-oauth-compromise-spanning-salesforce-google-workspace-and-aws/)).
  - UNC6040 / ShinyHunters: שיחת vishing ← אישור של Data Loader מזויף כ-connected app ← exfil ← lateral ל-Okta/M365 ([THN](https://thehackernews.com/2025/06/google-exposes-vishing-group-unc6040.html)).
  - LLMjacking.
- **מה רואים ראשון:**
  - GuardDuty: ‏`InstanceCredentialExfiltration`, ‏anomalous API.
  - Volume חריג של API מ-connected app.
  - `ListBuckets` / `GetObject` בכמויות.
  - Access key בשימוש מ-ASN חדש.
- **מקורות הוכחה:**
  - `aws_cloudtrail`, ‏`aws_guardduty`, ‏`aws_vpcflow`
  - `azure_activity`, ‏`gcp_audit`
  - `okta` / `entra` (federation)
  - `google_workspace` ‏(token audit, ‏drive)
  - Salesforce Event Monitoring (אין native)

#### F. Supply chain ו-third-party

- **שכיחות:** לפי DBIR 2026, ‏48% מעורבות צד שלישי (2025: ‏30%).
- **עוגנים:**
  - tj-actions/changed-files, ‏CVE-2025-30066: ‏secrets של CI דלפו לתוך build logs ב-23,000 repos ([Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)).
  - Shai-Hulud: תולעת npm שפגעה ביותר מ-500 חבילות וגנבה PATs ומפתחות AWS/GCP/Azure ([CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)).
  - Blue Yonder (Termite) השבית WMS אצל 3,000 לקוחות. ‏CDK Global ‏(BlackSuit) השבית 15,000 סוכנויות רכב ([BleepingComputer](https://www.bleepingcomputer.com/news/security/blue-yonder-saas-giant-breached-by-termite-ransomware-gang/)).
  - help desk חיצוני (M&S/TCS).
- **מה רואים ראשון:**
  - Workflow שרץ עם step לא מוכר.
  - Token של GitHub בשימוש מ-IP חיצוני.
  - Process של `node` / `npm` שקורא `~/.aws/credentials`.
  - חיבור RMM של ה-MSP בשעה חריגה.
- **מקורות הוכחה:**
  - GitHub audit (אין native)
  - EDR על ה-dev endpoint או ה-runner
  - `aws_cloudtrail`
  - firewall

#### G. Insider (כולל DPRK IT workers)

- **שכיחות ועוגנים:**
  - FBI: הונאת IT workers מניבה לצפון קוריאה עד כ-800 מיליון דולר בשנה. ‏operatives גנבו קוד, ביצעו סחיטה וגנבו session cookies ([FBI](https://www.fbi.gov/wanted/cyber/fraudulent-remote-it-workers-from-dprk), ‏[ASIS](https://www.asisonline.org/security-management-magazine/latest-news/today-in-security/2025/may/recruitment-red-flags/)).
  - M-Trends 2026 מודד dwell של 122 יום לתקיפות האלה.
- **מה רואים ראשון:**
  - DLP / USB / העלאה לענן אישי.
  - Forwarding rule.
  - כלי remote admin לא מאושר על laptop תאגידי (IP-KVM, ‏AnyDesk).
  - התחברויות דרך residential proxy.
- **מקורות הוכחה:**
  - EDR (device control)
  - `m365` / `google_workspace`
  - `okta` / `entra`
  - Purview DLP (אין native)
  - HR feed (אין native)

#### H. BEC והונאות תשלום

- **שכיחות:** לפי IC3 2025, ‏BEC גרם להפסדים של 3.05 מיליארד דולר מ-24,768 תלונות, ו-86% מההפסדים עברו ב-wire/ACH ([SpyCloud on IC3](https://spycloud.com/blog/fbi-internet-crime-report-2025/)).
- **עוגן deepfake:** ‏Arup, ‏25 מיליון דולר בשיחת וידאו מזויפת ([CNN](https://www.cnn.com/2024/05/16/tech/arup-deepfake-scam-loss-hong-kong-intl-hnk)).
- **מה רואים ראשון:**
  - Inbox rule.
  - Sign-in חריג.
  - דומיין lookalike.
  - בקשה לשינוי פרטי בנק של ספק.
- **מקורות הוכחה:**
  - `m365`, ‏`entra`, ‏`defender_o365`
  - **מערכת התשלומים / ERP** (אין native; ראו ממצא F ב-STORYLINE-REVIEW)

#### I. Social engineering: ערוצי מסירה

- **שכיחות:** לפי DBIR 2026:
  - 41% מה-SE breaches לא עברו באימייל.
  - ל-vishing יש success rate גבוה ב-40%.
  - מתוך המתקפות שנחסמו באימייל: ‏80% credential/session phishing, ‏10% malware, ‏5% callback ([Push](https://pushsecurity.com/blog/verizon-dbir-2026-review)).
- **עוגנים:**
  - Storm-1811: ‏email bombing ← Teams "help desk" ← Quick Assist ← Black Basta ([SC Media](https://www.scworld.com/news/microsofts-quick-assist-used-in-scam-to-drop-black-basta-ransomware)).
  - ClickFix ‏(MDDR, Red Canary 2026).
  - Quishing: עלייה חדה ב-2025, ומיקוד ב-M365 ([Barracuda via SecurityBrief](https://securitybrief.co.nz/story/microsoft-reports-8-3bn-phishing-threats-as-qr-codes-surge)).
  - ENISA: מעל 80% מהפישינג בספטמבר 2024 עד פברואר 2025 השתמש ב-AI במידה כלשהי.

#### J. LOTL ו-hands-on-keyboard

- **עוגן:** כלים לגיטימיים מובילים (סעיף 2.3).
- **עוד מגמה:** לפי Sophos 2025, מגוון ה-LOLBins עלה ב-126%.
- **מה רואים ראשון:** ‏process lineage חריג (wmiprvse ← cmd), ‏`4624` type 3 רבים מ-host אחד, ‏`7045` של PSEXESVC.
- **מקורות הוכחה:** ‏`windows_security`, ‏`sysmon`, ‏EDR, ‏Zeek (NDR).

#### K. התקפות שמשולב בהן AI

- **מה מתועד בפועל:**
  - GTG-1002: קמפיין ריגול סיני שבו Claude Code ביצע 80–90% מהפעולות מול כ-30 ארגונים ([Paul Weiss](https://www.paulweiss.com/insights/client-memos/anthropic-disrupts-first-documented-case-of-large-scale-ai-orchestrated-cyberattack)).
  - PROMPTFLUX / PROMPTSTEAL / QUIETVAULT ‏(M-Trends 2026).
  - AI-enabled adversaries עלו ב-89% ‏(CrowdStrike 2026).
  - Shadow AI ‏(DBIR 2026): ‏45% מהעובדים משתמשים ב-AI באופן קבוע, ‏67% מהם בחשבונות לא תאגידיים, ול-15% הותקנו AI browser extensions לא מאושרים.
- **אבל:** ‏M-Trends 2026 קובע ש-2025 **לא** הייתה השנה שבה פריצות נבעו ישירות מ-AI, ושהכשלים הבסיסיים נשארים הסיבה העיקרית.
- **מסקנה:** ‏AI הוא בעיקר **מאיץ** של אותן תקיפות (פישינג, voice clone, אוטומציה), ולא קטגוריה עצמאית גדולה. האיומים ה-AI-native שכן רלוונטיים ל-SOC הם LLMjacking, ‏shadow AI ‏(DLP) ו-agentic intrusion tempo.

#### L. Destructive, ‏wipers וחקטיביזם (קריטי ללקוחות ישראלים)

- **ישראל:**
  - ה-INCD טיפל ביותר מ-26,000 אירועים ב-2025, עלייה של 55%.
  - ביוני 2026 נרשמו כ-4,800 אירועים, לעומת כ-1,600 ביוני 2025.
  - "חברות שהיה קל לחדור אליהן מצאו את המערכות שלהן מחוקות" ([Times of Israel](https://www.timesofisrael.com/iranian-cyberattacks-on-israel-surged-in-2026-cyber-chief-says/)).
- **עוגנים:**
  - **Handala / Void Manticore** (MOIS): ‏phishing ו-**ניצול Microsoft Intune** לפקודות RemoteWipe/FactoryReset המוניות, כולל Stryker במרץ 2026. ההנחיה: להזרים Intune audit ל-SIEM ולהתריע על 5 wipes ומעלה בחלון קצר ([Unit 42](https://unit42.paloaltonetworks.com/handala-hack-wiper-attacks/)).
  - **MuddyWater:** ‏spearphishing שמוביל להתקנת RMM (Atera, ‏SimpleHelp ועוד) מאתרי שיתוף קבצים, נגד רשויות מקומיות, תעופה, בריאות, טלקום ו-SMB ([THN](https://thehackernews.com/2025/12/iran-linked-hackers-hits-israeli_2.html), ‏[Dark Reading](https://www.darkreading.com/threat-intelligence/iran-mois-criminals-cyberattacks)).
  - M-Trends 2025 מציין הסלמה של Iran-nexus מול ישראל.
- **EU:** חקטיביסטים ו-DDoS הם כמעט 80% מהאירועים ([ENISA](https://securityaffairs.com/182978/security/reading-the-enisa-threat-landscape-2025-report.html)). ערך ההדרכה של DDoS ל-SOC נמוך, כי ה-SOC בעיקר מקבל התראת ספק.

### 2.5 איומים ענפיים (רק התעשיות שהפלטפורמה תומכת בהן)

| ענף | מה דומיננטי | עוגנים | מה ה-SOC רואה |
|---|---|---|---|
| **Healthcare** | ‏System Intrusion: ‏60% מהפריצות. ‏ransomware ב-77% מה-intrusions. ‏exploit ‏20%, ‏phishing ‏14%, ‏stolen creds ‏11% ([DBIR 2026 HC](https://www.hipaajournal.com/verizon-dbir-2026-healthcare/)) | Change Healthcare: גישה מרחוק בלי MFA, ‏9 ימי lateral ו-exfil, ‏190 מיליון רשומות ([The Record](https://therecord.media/unitedhealth-updates-change-healthcare-data-breach-190-million)) · Ascension: עובד הוריד קובץ זדוני ← Black Basta ([Bleeping](https://www.bleepingcomputer.com/news/security/ascension-hacked-after-employee-downloaded-malicious-file/)) · Kettering: ‏Interlock, ‏dwell של 41 יום ([HIPAA Journal](https://www.hipaajournal.com/kettering-health-ransomware-attack/)) · HC3: ‏help desk SE ← שינוי MFA ← **הסטת תשלומים** ([HC3](https://www.aha.org/cybersecurity-government-intelligence-reports/2024-04-03-hc3-tlp-clear-analyst-note-social-engineering-attacks-targeting-it)) | VPN/Citrix sign-in, ‏EDR על שרתי EMR/PACS, ‏egress של DICOM/HL7, שינוי direct deposit ב-HR/payroll |
| **Finance** | הונאה מונעת GenAI, תקיפות ספקים, DDoS ו-ransomware עם double/triple extortion ([FS-ISAC](https://www.fsisac.com/navigatingcyber2025)). ‏M-Trends 2026: פיננסים 14.6% מהחקירות (ירדו מהמקום הראשון) | BEC ו-wire fraud, ‏deepfake CFO (Arup), ‏AiTM על בנקאות ארגונית, ספקי IT/SaaS | sign-in חריג ← שינוי מוטב ← העברה. דורש **לוג מערכת תשלומים** |
| **Logistics / Transport** | ENISA: תחבורה, ימאות ולוגיסטיקה בין הענפים המותקפים ביותר. ‏CrowdStrike 2026: ‏China-nexus הגדילו מיקוד בלוגיסטיקה ב-85% | Cargo theft: ‏RMM (ScreenConnect, ‏SimpleHelp, ‏PDQ…) מקישורי load-board מזויפים ← גניבת credentials ← הצעה על משלוחים וגנבתם ([Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/beyond-breach-inside-cargo-theft-actors-post-compromise-playbook)) · Blue Yonder (WMS SaaS) · CDK Global | התקנת RMM לא מאושר, sign-in ל-TMS או load-board מ-host חדש, שינויי פרטי תשלום של carrier |

---

## 3. מיפוי הארסנל הנוכחי

### 3.1 מלאי

- **82 storylines פעילים:** ‏20 foundation, ‏27 core, ‏35 advanced.
- **לפי ענף:** ‏69 general, ‏7 finance, ‏4 healthcare, ‏2 logistics.
- **הוצאו:** ‏`bundled-cryptominer`, ‏`drive-by-browser-miner`, ‏`clipboard-clipper`, ‏`rocketstack-chain-c`, ‏`ai-bedrock-key-abuse`.
- **ה-`cryptomining` המקורי** הוחלף ב-`aws-key-leak-s3-exfil`, וזה תואם להמלצת הסקירה.
- **Pool attacks** (64 אירועים, בערך 45 incidents):
  - forwarding rules ‏(T1114.003): ‏8
  - העתקה ל-USB או לענן ‏(T1052/T1530/T1048): ‏8
  - brute force / spray: ‏5 incidents
  - הרשאות "unverified": ‏6
  - AV detections: ‏7
  - WAF blocks: ‏3
  - UEBA: ‏3
  - email: ‏4
- **חבילות `/scenarios` שעדיין לא חוברו ל-live:** ‏emailBombHelpdesk, ‏vishingRmm, ‏goldenSaml, ‏lateralMovementPth, ‏windowsPrivescToken, ‏destructiveWiper, ‏sqliDbExfil, ‏becWireFraud, ‏macosStealerDmg, ‏azureManagedIdentityAbuse, ‏gcpSaKeyTheft, ‏gwsOauthMarketplace, ‏pamVaultAbuse, ‏insiderDlpUsbCloud, ‏s3ExfilExposure, ‏cicdSupplyChain, ‏uebaCompromisedAccount, ‏multiHostIntrusion, ‏otNetworkAnomaly ועוד. **זה מאגר של quick wins**, כי חלק גדול מהפערים שלהלן כבר כתוב שם (לגבי `.events.ts` ראו 4.3).

### 3.2 כיסוי לפי קטגוריה ו-tier

מקרא: ✅ טוב · 🟡 חלקי · ❌ חסר · ⬆ מיוצג יתר על המידה

| קטגוריה (משקל אמיתי) | foundation | core | advanced | הערכה | storylines קיימים / הערה |
|---|---|---|---|---|---|
| **D. Edge / public-facing exploit** (גבוה מאוד) | – | ❌ | 🟡 | **❌ הפער הגדול** | `edge-vpn-cve-exploit` (REPLACE) · `webshell-rce` (SQLi לאפליקציה) · `ai-agentic-intrusion-tempo` (SSRF). אין PAN-OS / Ivanti / Citrix / ASA / Check Point VPN, ‏ToolShell או file-transfer. ב-pool יש רק 3 WAF blocks |
| **A. Ransomware / extortion** (גבוה מאוד) | – | 🟡 | 🟡 | **🟡** | `ransomware` (LockBit, פישינג; KEEP) · `esxi-ransomware` · `exfil-first-extortion` · `medcore-chain-a`. חסרים VPN valid-account ← Impacket (Akira/Qilin), ‏RMM-led, ‏BYOVD, ‏recovery denial (גיבויים), ו-data-theft-only מ-zero-day |
| **B. זהות** (גבוה מאוד) | ✅ | ✅ | ✅ | **✅** | `bec` · `mfa-fatigue` · `aitm-token-theft` · `impossible-travel(-basic)` · `helpdesk-mfa-reset` · `ai-helpdesk-voice-reset` · `oauth` · `oauth-consent` · `okta-password-burst` · `rocketstack-cred-stuffing`. חסרים **device-code phishing**, ‏device registration ← PRT, ‏SSPR abuse, ‏federation/IdP admin abuse (ה-Golden SAML קיים ב-/scenarios), ו-Entra Connect |
| **C. Infostealers** (גבוה) | ✅ | ✅ | 🟡 | **✅/🟡** | `infostealer-session-theft` · `seo-poisoned-installer` · `clickfix-fake-captcha` · `gws-phish-attachment`. חסר "stealer log ← SSO/VPN בלי MFA ← data warehouse" (Snowflake) |
| **I. SE delivery** (גבוה) | 🟡 | ❌ | – | **🟡** | הרבה ווריאציות של קובץ/קישור (zip, ‏macro, ‏iso, ‏svg, ‏fake update, ‏cracked, ‏SEO, ‏ClickFix). **חסרים כל הערוצים הלא-אימייליים:** ‏Teams vishing, ‏email bombing, ‏callback/TOAD, ‏quishing. ‏`malicious-macro` מבוסס על הנחת יסוד מיושנת (Microsoft חוסמת macros מהאינטרנט כברירת מחדל מ-2022) |
| **E. Cloud / SaaS** (גבוה) | 🟡 | 🟡 | ✅ (AWS) | **🟡** | AWS עשיר: ‏`aws-key-leak` · `phishing` · `k8s` · `rs-*` · `ai-llmjacking` · `ai-agentic`. ‏**Azure דל:** ‏`nexacorp-chain-a` ושניים של AOAI. ‏**GCP: אפס.** אין SaaS-to-SaaS token theft (Drift) ואין Salesforce |
| **F. Supply chain / 3rd-party** (גבוה ועולה) | – | 🟡 | 🟡 | **🟡** | `supply-chain` · `rocketstack-chain-b` (npm) · `rs-cicd-pipeline-poisoning` · `rs-terraform-iac-backdoor`. חסרים MSP/RMM של ספק (רלוונטי מאוד בישראל), ‏help desk חיצוני ו-SaaS vendor |
| **J. LOTL / lateral** (גבוה) | – | 🟡 | 🟡 | **🟡** | `lolbins` · `dcsync` · `kerberoasting` · `ntlm-relay` · `asrep-roasting` · `rogue-admin`. **אין storyline ש-Impacket או RDP פנימי במרכזו** (הכלי והתנועה הנפוצים ביותר לפי Sophos). ‏PsExec ו-PtH קיימים ב-/scenarios (`lateral-movement-pth`) ולא ב-live |
| **H. BEC / payment fraud** (גבוה) | ✅ | ✅ | ✅ | **✅** | `bec` · `nexacorp-chain-b` · `impossible-travel-basic` · `ai-svg-invoice-lure` · `qb-swift-wire-fraud`. חסרה ראיה ממערכת התשלומים, ואין שינוי פרטי ספק ב-ERP |
| **G. Insider** (בינוני) | 🟡 | ✅ | 🟡 | **✅⬆** | `insider` · `nexacorp-chain-c` · `medcore-chain-b` · `globallogis-chain-c` · `ai-claude-enterprise-departure` · `ai-shadow-chat-upload`, ועוד כ-16 pool events. חסר DPRK IT worker |
| **K. AI-enabled** (נמוך–בינוני) | ⬆ | ⬆ | ⬆ | **⬆** | 13 storylines (16%), מהם 4 על Claude Enterprise ו-2 על Copilot |
| **L. Destructive / wiper** (בינוני; **גבוה בישראל**) | – | ❌ | ❌ | **❌** | אין ב-live (`destructive-wiper` קיים ב-/scenarios). אין Intune/MDM mass-wipe |
| **macOS / mobile** (בינוני) | 🟡 | – | – | **🟡** | `gws-phish-attachment` (AMOS-like). ב-/scenarios יש `macos-stealer-dmg`, ‏`macos-tcc-pkg` ו-`mobile-mdm-compromise` |

### 3.3 פערי MITRE (תדירות ה-technique על פני כל האירועים בתרחישים)

- **מיוצג היטב:** T1078 (27), ‏T1530 (21), ‏T1071.001 (20), ‏T1566.001 (19), ‏T1110.003 (17), ‏T1114.003 (12), ‏T1114.002 (11).
- **כמעט חסר, ושכיח בעולם:**
  - **T1047** WMI: אפס. מקום 8 ב-Red Canary 2025, ‏24% ב-Sophos.
  - **T1219** RMM: ‏4 הופעות, כולן ב-tech-support-scam.
  - **T1190** Exploit Public-Facing App: ‏4.
  - **T1133** External Remote Services: ‏2.
  - **T1068** Exploitation for PrivEsc / BYOVD: אפס.
  - **T1562.001** בהקשר של EDR-kill: הופעות קיימות, אבל לא כ-BYOVD.
  - **T1490** Inhibit System Recovery: ‏1.
  - **T1485** Data Destruction: ‏1.
  - **T1484.001** GPO modification לפריסת ransomware: אפס.
  - **T1649** ADCS (Steal or Forge Authentication Certificates): אפס.
  - **T1606.002** Golden SAML: אפס ב-live.
  - **T1566.004** Spearphishing Voice: אפס. ה-vishing מתויג T1656 בלבד.
  - **T1204.004** Malicious Copy-Paste: ‏1.
  - **T1572** / **T1090** (tunneling / proxy, ‏ngrok/cloudflared): אפס.
  - **T1021.001** RDP: ‏2.

### 3.4 כיסוי לפי בחירת סביבה (חושב בהרצה של `envAllowsStory` על הרשימה הפעילה)

**מספר ה-storylines הזמינים, foundation / core / advanced:**

| פלטפורמות ↓ \ ענף → | general | healthcare | finance | logistics |
|---|---|---|---|---|
| none (Microsoft workplace בלבד) | 18 / 13 / 14 | 18 / 16 / 15 | 18 / 15 / 14 | 18 / 15 / 14 |
| **default (azure+linux)** | 19 / 14 / 17 | 19 / 17 / 18 | 19 / 16 / 17 | 19 / 16 / 17 |
| azure בלבד | 19 / 14 / 15 | 19 / 17 / 16 | 19 / 16 / 15 | 19 / 16 / 15 |
| aws בלבד | 19 / 17 / 19 | 19 / 20 / 20 | 19 / 20 / 19 | 19 / 19 / 19 |
| k8s / github / cyberark בלבד | 18 / 13 / 14 (**+0**) | אותו דבר | אותו דבר | אותו דבר |
| vmware בלבד | 18 / 13 / 15 (+1) | | | |
| ndr בלבד | 18 / 13 / 16 (+2) | | | |
| linux בלבד | 18 / 13 / 16 (+2) | | | |
| הכול | 20 / 19 / 31 | 20 / 22 / 32 | 20 / 22 / 34 | 20 / 21 / 31 |

**עם `teamStoryFilter` ‏(stack)**, ברירת מחדל azure+linux, ‏general:

| Stack | f / c / a |
|---|---|
| MDE + PAN + Entra + M365 | 17 / 13 / 14 |
| SentinelOne + Check Point + Entra + M365 | 17 / 13 / 14 |
| CrowdStrike + PAN + **Okta** + M365 + Proofpoint | 15 / **10 / 10** |
| CrowdStrike + FortiGate + **Okta + Google Workspace** + Proofpoint | 16 / **6 / 9** |

**ממצאים:**

1. **K8s, ‏GitHub ו-CyberArk הם בחירות "ריקות" בלי AWS.** כל ה-storylines שלהן (`k8s-pod-escape`, ‏`rs-*`, ‏`qb-*`, ‏`quantumbank-chain-b`) דורשים גם AWS. מדריך שבוחר "K8s" לארגון Azure (AKS) לא יקבל אף תרחיש K8s. זו בעיה של ריאליזם וגם של UX: הבחירה נראית משמעותית ואינה כזו.
2. **Azure, שהוא ה-cloud הנפוץ בקרב הלקוחות הישראלים, מוסיף 3 storylines בלבד:** ‏1 foundation (`ai-aoai-support-bot-jailbreak`), ‏1 core (`nexacorp-chain-a`, ‏FIX עם logs=2) ו-1 advanced (`ai-aoai-key-capacity-abuse`). אין תרחיש Azure control-plane אמיתי: הוספת secret ל-service principal, ‏role assignment, ‏Key Vault, ‏Storage SAS או managed identity. ‏`azureManagedIdentityAbuse` כבר קיים ב-/scenarios.
3. **VMware מוסיף רק `esxi-ransomware`,** ו-vCenter עדיין בלי native card. **NDR** מוסיף `asrep-roasting` ו-`ntlm-relay`, ששניהם קיבלו logs=2 בסקירה, ול-Zeek אין native card.
4. **Finance:** בלי AWS ו-CyberArk מתווספים רק `quantumbank-chain-a` (REPLACE) ו-`quantumbank-chain-d`. כל שלושת ה-advanced הפיננסיים דורשים AWS+CyberArk, ובנק ישראלי טיפוסי (on-prem + Azure) לא יקבל אותם.
5. **Healthcare:** ארבעה slices של 4 אירועים (`medcore-chain-a..d`), כולם עם e2e=2. אין את התבנית של Change Healthcare (remote access בלי MFA) ואין הסטת תשלומים דרך help desk.
6. **Logistics:** שני slices (`globallogis-chain-a/b`) בלבד. אין cargo-theft RMM ואין WMS/SaaS outage.
7. **Okta + Google Workspace:** ‏6 core ו-9 advanced. זה סביב חלון ה-anti-repeat של 8 שקיים ב-feed הבודד, ולכן כיתה שמתאמנת שבוע תפגוש חזרות. הסיבה: ‏GWS חוסם את כל תרחישי ה-Exchange (inbox rule, ‏delegation), ואין להם מקבילה ב-GWS.
8. **Foundation לא מושפע מהסביבה** (18–20 בכל צירוף), כי הוא בנוי על EDR+firewall בלבד. זה טוב לגיוון, אבל המשמעות היא שבחירת הסביבה לא משנה דבר לכיתת מתחילים.

### 3.5 Pool attacks: ממצאים

- **הטייה חזקה:** כ-16 מתוך 64 הם forwarding rule או העתקת קבצים (insider/BEC). אין pool attack של edge exploit (מלבד 3 WAF blocks שכבר נחסמו), אין RMM install, אין OAuth consent, אין התחברות מ-infostealer, אין device-code ואין התקנת RMM מ-ClickFix.
- **נעדרת כמעט לגמרי "הצלחה שקטה":** רוב ה-pool attacks נחסמו (blocked / quarantined / denied). ב-SOC אמיתי התראות T1 רבות הן "allowed but suspicious". מומלץ להוסיף pool events של הצלחה, למשל `ScreenConnect.ClientService.exe` installed, sign-in מוצלח מ-ASN של VPS עם אותו SessionId, או Consent granted.
- **ה-IP-ים חוזרים:** ‏`185.220.101.x` משמש גם ב-pool (`b_bf_*`, ‏`mc_dns_*`) וגם ב-storylines, כפי שמתואר בסקירה בסעיף H.

### 3.6 Storylines בשכיחות נמוכה או אקזוטיים ביחס למודל

| storyline | למה | המלצה |
|---|---|---|
| `quantumbank-chain-c` (Rogue Trading) | מניפולציית שוק היא תחום של trade surveillance, לא של SOC. היא כבר ב-REPLACE | להחליף ב-"help desk ← שינוי מוטב" או ב-"AiTM על treasury" |
| `qb-fraud-monitoring-tampering`, ‏`qb-cyberark-mule-payout` | insider fraud קיים, אבל ה-SOC רואה רק חלק קטן ממנו, והשרשרת מחייבת AWS+CyberArk | לאחד לאחד, ולהוסיף לוג תשלומים |
| `tech-support-scam` | זה פורמט צרכני. הגרסה הארגונית היא callback phishing או Teams vishing ← RMM | למסגר מחדש כ-callback/TOAD (יש `vishingRmm` ב-/scenarios) |
| `usb-malware` | ‏USB כווקטור ארגוני נדיר יחסית ב-2024–2026 | להשאיר foundation אחד, לא יותר |
| `browser-extension` (sideload עם NativeMessagingHosts) | נישה | למסגר כ-extension מ-Chrome Web Store שנחטף (תבנית Cyberhaven, דצמבר 2024) |
| `iso-container-smuggling` | ההנחה על MOTW מיושנת (מופיע בסקירה) | להחליף ב-quishing או ב-ClickFix-to-RMM |
| `malicious-macro` | macros מהאינטרנט חסומים כברירת מחדל | להשאיר כתרחיש של "macro נחסם / ניסיון", או להחליף ב-SVG/HTML smuggling (כבר קיים) |
| `dns-tunneling` (dnscat2) | נדיר ב-eCrime, ומתאים יותר ל-threat hunting | להשאיר advanced, אבל לא לתת לו משקל |
| `ntlm-relay` (Responder) | פופולרי בעיקר ב-pentest. בתקיפות אמיתיות רואים relay עם coercion ל-ADCS (ESC8) | לעדכן ל-PetitPotam ← ADCS |
| `k8s-pod-escape` | שכיחות נמוכה ביחס לזהות בענן | לא דחוף |
| `ai-copilot-indirect-injection` (EchoLeak) | חולשה שתוקנה, ולא דווח על ניצול in-the-wild | להוריד ל-/scenarios |
| `ai-chat-harvest-extension`, ‏`ai-aoai-support-bot-jailbreak`, ‏`ai-gemini-drive-sweep`, ‏`ai-claude-shared-secret` (REPLACE), ‏`ai-claude-compliance-key-harvest` | יש 4 תרחישים על מוצר AI אחד (Claude Enterprise), יותר מהמשקל שלו בשוק. ה-jailbreak של בוט חיצוני הוא בעיקר בעיה של AppSec | לצמצם את ה-AI ל-6–8 storylines |

---

## 4. תרחישי ייחוס חסרים: המלצות מתועדפות

**שיטת התעדוף:** שכיחות בעולם (1–5) × ערך הדרכתי (1–5), עם בונוס על התאמה ללקוח ישראלי ועל השלמת חור בסביבה/ענף. אין בשום תרחיש קריפטו.

### 4.1 Top-10

#### 1. ‏Edge VPN zero-day ← valid foothold ← AD: "Check Point / PAN-OS / Cisco ASA" (מחליף את `edge-vpn-cve-exploit`)
- **עוגן:**
  - Check Point CVE-2026-50751 (auth bypass, ‏Qilin) ו-CVE-2024-24919 (גניבת hash-ים של חשבונות מקומיים).
  - Cisco ASA ArcaneDoor (ED 25-03).
  - DBIR 2026: ‏exploit ב-31%. ‏M-Trends 2026: ‏32%.
- **שרשרת:**
  1. סריקה ו-threat log של החתימה.
  2. VPN session של **חשבון מקומי ישן** (לא AD) מ-VPS.
  3. Pivot ל-jump host דרך RDP: ‏`4624` type 10 עם ה-IP מה-tunnel pool.
  4. `nltest` / `AdFind`.
  5. Impacket `secretsdump` מול DC.
  6. הסלמה ל-Domain Admin, ‏staging, ‏exfil.
- **לוגים (native):**
  - Firewall threat log + system/admin log: ‏`checkpoint` / `paloalto` / `cisco_asa` / `cisco_ftd`, וכל firewall צריך את ה-CVE שלו.
  - VPN: ‏`globalprotect` / `anyconnect` / `fortigate_sslvpn`.
  - `windows_security`, ‏EDR, ‏`sysmon`.
- **התראה ראשונה:** ‏IPS/threat log של חתימת ה-CVE מול ה-gateway, ‏**ו**-VPN login מוצלח של `vpn_local_admin` מ-ASN של אירוח.
- **Tier:** advanced. גרסת core אפשרית: לעצור אחרי ה-RDP ל-jump host.
- **למה ראשון:** הווקטור מספר 1 בעולם, והפער הגדול בפלטפורמה. ‏Check Point נפוץ מאוד בישראל, ויש native card ל-5 ה-firewalls.

#### 2. ‏Akira-style: ‏VPN ‏valid account ← Impacket ← גיבויים ← ESXi
- **עוגן:**
  - Sophos 2026: ‏Akira ‏22.6%, ‏Impacket ‏36%, ‏AD תוך 3.4 שעות, ‏88% מהפריסות מחוץ לשעות.
  - Akira/SonicWall: מ-VPN להצפנה בפחות מ-4 שעות.
  - M-Trends 2026: ‏recovery denial.
- **שרשרת:**
  1. VPN login עם credential ממאגר infostealer, בלי MFA, בשעה 01:10.
  2. `wmiexec.py` אל file server: ‏`wmiprvse.exe` ← `cmd.exe /Q /c … 1> \\127.0.0.1\ADMIN$\__<epoch>`.
  3. `secretsdump` מול DC (‏4662 עם DS-Replication GUIDs).
  4. RDP פנימי לשרת הגיבויים ומחיקת jobs ו-repositories.
  5. `rclone` ל-MEGA.
  6. SSH ל-ESXi והצפנה.
- **לוגים:** VPN, ‏`windows_security` (‏4624 type 3/10, ‏4662, ‏7045), ‏EDR/`sysmon`, ‏firewall egress, ‏`linux_auditd` (אם ESXi מוצג כ-Linux; אחרת vCenter legacy).
- **התראה ראשונה:** ‏EDR "Impacket wmiexec-style remote execution" על FS01 בשעה 01:30.
- **Tier:** advanced.
- **למה:** מחליף את מקומו של LockBit-בפישינג כתבנית ה-ransomware העדכנית, ומכסה את פער ה-lateral/LOTL (T1047, ‏T1021.001, ‏T1490).

#### 3. ‏Email-bomb ← Teams "IT support" ← Quick Assist ← RMM ← hands-on-keyboard (Storm-1811 / Black Basta)
- **עוגן:** Microsoft Storm-1811. ‏DBIR 2026: ‏41% מה-SE לא באימייל, ‏RMM עלה ב-240%. ‏M-Trends 2026: ‏vishing ב-11%.
- **שרשרת:**
  1. 2,000+ הודעות newsletter בתוך 30 דקות.
  2. צ'אט Teams חיצוני מ-`helpdesk@<tenant>.onmicrosoft.com`.
  3. `quickassist.exe`.
  4. הורדת AnyDesk / ScreenConnect.
  5. `whoami /groups`, ‏`net group "domain admins"`.
  6. כלי tunneling.
- **לוגים:** ‏`defender_o365` / `proofpoint` (bulk/spam surge), ‏`m365` (Teams external chat: ‏ChatCreated / MessageSent), ‏EDR, ‏firewall (relay domains של RMM), ‏`servicenow` (אין ticket פתוח: ראיה שלילית), ‏`entra`.
- **התראה ראשונה:** ‏EDR "Remote access tool installed by user" אחרי session של Quick Assist. אפשר גם להתחיל מ-"user reports spam flood" ב-ServiceNow.
- **Tier:** core. יש גרסת foundation אם עוצרים לפני ה-recon.
- **Quick win:** ‏`emailBombHelpdesk` ו-`vishingRmm` כבר קיימים ב-/scenarios.

#### 4. ‏MuddyWater-style: ‏spearphish ← RMM מאתר שיתוף ← גישה מתמשכת (לקוח ישראלי)
- **עוגן:** ‏INCD ו-THN על MuddyWater נגד רשויות, בריאות ו-SMB בישראל. ‏Proofpoint על RMM בלוגיסטיקה.
- **שרשרת:**
  1. מייל בעברית "עדכון נוהל / הזמנה" עם קישור ל-Egnyte / OneHub / Dropbox.
  2. הורדת `Atera_Agent.msi` או `SimpleHelp`.
  3. `msiexec` בהקשר של המשתמש.
  4. Agent שמתחבר ל-tenant זר.
  5. איסוף credentials מהדפדפן.
- **לוגים:** ‏`defender_o365` / `proofpoint`, ‏`zscaler_zia` / firewall URL log, ‏EDR, ‏DNS ‏(`windows_dns` / `infoblox`).
- **התראה ראשונה:** ‏EDR "New remote management software installed (AteraAgent.exe)", או URL click ב-email security.
- **Tier:** **foundation**: host אחד, משתמש אחד, בלי lateral. זה מוסיף גיוון אמיתי ל-easy.
- **ווריאנט לוגיסטיקה:** ‏cargo theft. אותה שרשרת, עם load-board מזויף, ואחריה sign-in ל-TMS מה-host. מחובר לענף `logistics`.

#### 5. ‏Device-code phishing ← token ← device registration ← PRT ← mailbox (Storm-2372)
- **עוגן:** ‏Microsoft, פברואר 2025. ‏Red Canary 2026 מציין את Steal Application Access Token. לפי Microsoft, ב-2026 כבר יש קמפיינים מבוססי AI.
- **שרשרת:**
  1. הזמנת Teams עם "קוד הצטרפות".
  2. משתמש מזין את הקוד ב-`microsoft.com/devicelogin`.
  3. Sign-in עם `authenticationProtocol=deviceCode` ו-client "Microsoft Authentication Broker" מ-IP של התוקף.
  4. "Register device" באודיט.
  5. Sign-in עם PRT מה-device החדש.
  6. MailItemsAccessed / Graph search ל-"password", "wire".
- **לוגים:** ‏`entra` (sign-in + audit; **צריך להוסיף ל-renderer** את `authenticationProtocol` / `originalTransferMethod`), ‏`m365`, ‏`defender_o365`.
- **התראה ראשונה:** ‏Entra ID Protection "Anomalous token" / "Unfamiliar sign-in properties", או custom rule "deviceCode sign-in by non-shared-device user".
- **Tier:** core.

#### 6. ‏SaaS integration token theft ← mass export ← secrets ← AWS (Salesloft Drift / UNC6395)
- **עוגן:** ‏GTIG, ‏Arctic Wolf, ‏Astrix. ‏DBIR 2026: מעורבות צד שלישי 48%.
- **שרשרת:**
  1. OAuth token של אפליקציה צד-