# פירוק הנושאים המומלצים ל-Tier 1/2 — תתי-נושאים לבניית חדרים

> המשך ישיר ל-[PLATFORM-SYLLABUS.md](PLATFORM-SYLLABUS.md), סעיף "פערים ידועים". כל נושא כאן מפורק לתתי-נושאים ברמת דיוק שמאפשרת לבנות חדר לימוד ישירות ממנו. נבנה מתוך קוד המקור (כולל הרצת `scripts/coverage-report.mjs` בפועל). עודכן 2026-08-12.

---

## 1. Regex + כתיבת שאילתות SIEM (KQL/SPL) — Tier 1→2 bridge

הכי גבוה בהחזר: משרת *כל* חקירה עתידית.

**1.1 יסודות Regex**
- תווים ליטרליים, מחלקות תווים (`[a-z]`, `\d`, `\w`), כמתים (`*`, `+`, `?`, `{n,m}`)
- עוגנים (`^`, `$`), קבוצות (`()`), אלטרנציה (`|`)
- Greedy מול Lazy matching — המלכודת הקלאסית

**1.2 דפוסי Regex של אנליסט**
- חילוץ כתובת IP, אימייל, hash (MD5/SHA1/SHA256), URL/domain מתוך טקסט חופשי
- זיהוי תבניות timestamp
- שימוש ב-`grep -E`, `Select-String` (PowerShell) בהשוואה לשפת שאילתות SIEM

**1.3 KQL (Kusto Query Language) — Sentinel/Defender**
- מבנה בסיסי: `table | where | project | extend | summarize`
- אופרטורי מחרוזת: `has`, `contains`, `startswith`, `matches regex`
- אגרגציה: `summarize count() by`, `bin()`, `make-set()`
- `join` בין טבלאות — מתאם DeviceProcessEvents↔DeviceNetworkEvents

**1.4 SPL (Splunk Search Processing Language)**
- `search | stats | table | eval | rex`
- ההבדל התחבירי מול KQL על אותם מושגים בדיוק

**1.5 בניית שאילתת זיהוי מהשערה**
- זרימה מלאה: "אני חושד ב-X" → שאילתה שמוכיחה/שוללת
- מודעות לביצועים — למה `search *` איטי, שימוש באינדקסים/זמן

---

## 2. Sigma Rules + YARA Rules — כתיבת חתימות זיהוי

הופך תלמיד מ"קורא alerts" ל"כותב detections" — ההבדל המרכזי בין Tier 1 ל-Tier 2.

**2.1 Sigma — כללי זיהוי אגנוסטיים לספק**
- מבנה YAML: `title / logsource / detection / condition / level / falsepositives`
- כתיבת כלל Sigma מ-TTP ידוע (למשל PowerShell מקודד)
- ממיר Sigma→KQL/SPL/ES (sigmac / pySigma) — כלל אחד, פלטפורמה אחת
- מאגר SigmaHQ כמשאב קהילתי

**2.2 YARA — זיהוי מבוסס-דפוס לקבצים**
- מבנה כלל: `meta / strings / condition`
- סוגי strings: טקסט, hex, regex
- כתיבת כלל YARA למשפחת malware לפי מחרוזות ייחודיות
- YARA בפועל: סריקת קבצים, YARA hunting ב-VirusTotal

**2.3 ההבדל המושגי**
- Sigma = זיהוי בלוגים (מה קרה); YARA = זיהוי בקבצים (מה זה)
- כיוונון False Positive — בדיקת כלל מול תעבורה שפירה לפני production

---

## 3. PowerShell להגנה + Python לאנליסט

כבר מסומן ב-roadmap (SEV-3.x) כפער אוטומציה.

**3.1 PowerShell — הצד ההגנתי** (בניגוד לתפקיד ה-LOLBin ההתקפי שכבר נלמד)
- 7 הפקודות הליבה: `Get-Process, Get-Service, Get-WinEvent, Get-ChildItem, Select-Object, Where-Object, Export-Csv`
- מושג ה-pipeline — העברת אובייקטים, לא טקסט
- סינון event logs עם `Get-WinEvent -FilterHashtable`
- חקירת תהליכים: `Get-Process | Where-Object`
- ייצוא ממצאים ל-CSV לצורך דו״ח
- זיהוי ההבדל בלוגים בין PowerShell הגנתי להתקפי (גשר לתוכן קיים)

**3.2 Python לאנליסט SOC**
- למה Python לאוטומציה — משימות חוזרות שאין טעם לעשות ידנית
- משתנים, רשימות, dicts — מודלים לרשומת IOC
- לולאות ופונקציות — עיבוד רשימת hashes
- קריאה/כתיבה של JSON — פרסינג לוגים מיוצאים
- מודול `re` — חילוץ IOCs מטקסט
- ספריית `requests` — קריאה ל-API להעשרה (VirusTotal, AbuseIPDB)
- **פרויקט מעשי 1:** סקריפט לבדיקת reputation גורפת ל-hashes
- **פרויקט מעשי 2:** סקריפט להעשרת IP + הפקת דו״ח

---

## 4. ניתוח PCAP (Wireshark/Zeek)

**4.1 יסודות**
- מהו PCAP, איך packet capture עובד, promiscuous mode
- ממשק Wireshark: packet list / details / bytes panes
- Capture filters מול Display filters

**4.2 שחזור שיחה**
- Follow TCP Stream — קריאת שיחה שלמה
- זיהוי פרוטוקול לפי תוכן ולא רק לפי port (protocol on non-standard port)
- חילוץ קבצים מתוך HTTP/SMB streams (Export Objects)

**4.3 זיהוי תקיפה ב-PCAP**
- דפוס beaconing — חיבורים קבועים למרווח זמן
- ניתוח DNS חשוד ב-PCAP
- TLS handshake — SNI ומידע תעודה גלוי גם בלי לפענח

**4.4 Zeek/Bro כחלופה**
- `conn.log, dns.log, http.log, files.log` — מתי logs עדיפים על PCAP גולמי
- מתי בכלל למשוך PCAP מול מתי EDR/SIEM מספיקים

---

## 5. חקירת IR בענן (מעבר לניטור בלבד)

הפלטפורמה כבר מלמדת **ניטור** ענן (AWS/Azure/GCP) — זה החלק החסר: **חקירה פעילה** של אירוע ענן.

**5.1 CloudTrail כמסלול ביקורת**
- מבנה אירוע CloudTrail
- זיהוי פריצת IAM: `GetCallerIdentity, CreateAccessKey, AttachUserPolicy`
- חקירת מפתח גישה שנפרץ — היסטוריית CloudTrail למפתח בודד

**5.2 הכלה בענן**
- ביטול מפתח/session, בידוד instance/security group
- Azure Activity Log — חקירת service principal שנפרץ
- GCP Audit Logs — המקבילה

**5.3 תנועה בענן**
- pivoting בין חשבונות/regions — מה תוקף עושה אחרי כניסה
- Playbook הענן המקביל ל-IR מסורתי (Contain/Eradicate/Recover) — אך עבור IAM/משאבי ענן
- שימור ראיות — snapshot למכונה שנפרצה לפני termination

---

## 6. Capstone Exam ("Final Shift") — מפרט פיצ'ר, לא נושא ידע

**6.1 מבנה הסשן**
- חלון זמן מוגבל (60-90 דק'), 10-15 התראות מגוונות חומרה/סוג, לוקח מכל הקטגוריות שכבר נלמדו

**6.2 אפשרויות החלטה לכל התראה**
- Close (שפיר) / Investigate further / Escalate / Report (כתיבת דו״ח אירוע)

**6.3 רובריקת ניקוד משולבת**
- סיווג נכון + ציטוט ראיות + מהירות תגובה + הימנעות מ-false positive

**6.4 פלט**
- תעודה/הסמכה על ציון עובר
- דו״ח debrief מסכם — "רדאר מיומנויות" לפי קטגוריה

---

## 7. 18 הטכניקות המלומדות-בתרגול-אך-לא-בתיאוריה (מדויק, מ-`coverage-report.mjs`)

הרצתי את הסקריפט בפועל (לא ניחוש) — 111 טכניקות מתורגלות ב-Dashboard/EDR/Scenarios, 93 מהן (84%) מלומדות בחדר כלשהו. הפער בפועל:

| Technique ID | שם | קטגוריית ATT&CK |
|---|---|---|
| T1033 | System Owner/User Discovery | Discovery |
| T1039 | Data from Network Shared Drive | Collection |
| T1056.001 | Input Capture: Keylogging | Collection |
| T1057 | Process Discovery | Discovery |
| T1133 | External Remote Services | Initial Access / Persistence |
| T1176 | Browser Extensions | Persistence |
| T1189 | Drive-by Compromise | Initial Access |
| T1219 | Remote Access Software | Command and Control |
| T1485 | Data Destruction | Impact |
| T1534 | Internal Spearphishing | Lateral Movement |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1563 | Remote Service Session Hijacking | Lateral Movement |
| T1565.001 | Data Manipulation: Stored Data Manipulation | Impact |
| T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | Defense Evasion |
| T1580 | Cloud Infrastructure Discovery | Discovery |
| T1609 | Container Administration Command | Execution |
| T1619 | Cloud Storage Object Discovery | Discovery |
| T1657 | Financial Theft | Impact |

**תצפית:** רוב הפער מרוכז ב-3 אשכולות טבעיים — אפשר לבנות תוסף אחד לכל אשכול ולסגור את רובם יחד:
1. **Discovery כללי** (T1033, T1057, T1580, T1619) — "מה תוקף בודק אחרי שנכנס", יכול להתאחד לתוסף אחד בחדר Discovery/Lateral Movement קיים
2. **Session/Cookie theft + Remote access abuse** (T1539, T1563, T1133, T1219) — מתקשר ישירות לחדר Kerberos/Windows Auth ול-Identity הקיימים
3. **Cloud-specific** (T1578.002, T1580, T1619) — נכנס טבעי לנושא 5 (חקירת IR בענן) למעלה

---

## המלצת סדר בנייה (החזר-על-מאמץ)

1. **Regex + KQL/SPL** — התשתית שהכל נשען עליה
2. **Sigma + YARA** — מסיים את מעבר Tier1→Tier2
3. **סגירת אשכולות ה-Discovery/Session** מתוך הפער — משלב תוכן חדש עם סגירת גאפ קיים
4. **PowerShell + Python** — האוטומציה
5. **Cloud IR** — סוגר גם 3 מתוך 18 הטכניקות החסרות
6. **PCAP** — עומק נוסף
7. **Capstone** — הכתר, אחרי שהיסודות בפנים
