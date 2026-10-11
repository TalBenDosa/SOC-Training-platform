# חוות דעת מקצועית: היתכנות תרגיל Team-SOC לפני מכירה לארגונים ולמכללות

**כותב:** מנהל SOC / ראש צוות IR (15 שנות ניסיון). סקירה לקריאה בלבד, לא שיניתי שום קובץ בריפו.
**תאריך:** 2026-10-03
**חומר שנבדק:** שלושה סשנים שנוצרו במלואם עבור contoso-labs.io:
- S1: easy, ברירת מחדל (azure+linux), ‏89 שורות חיות, ‏10 שורות בונוס, אין injects.
- S2: medium, ענף healthcare, ‏CrowdStrike + FortiGate + FortiGate SSL-VPN, ‏149 שורות, ‏9 בונוס, ‏7 injects.
- S3: hard, ‏AWS/K8s/GitHub, ‏Okta + Google Workspace + SentinelOne + PAN, ‏207 שורות, ‏12 בונוס, ‏7 injects.

בנוסף עברתי על `ENV-MATRIX.md`, על `STORIES.md` (82 storylines) ועל `THREAT-LANDSCAPE.md`. את הטענות המרכזיות במסמך האחרון אימתתי מול מקורות פתוחים (סעיף 7.3).

**מגבלה:** ב-dump שקיבלתי כל native record נחתך אחרי כ-1.5KB. לכן לא קבעתי ששדה "חסר" אם הוא היה אמור להופיע אחרי נקודת החיתוך.

**הנחת עבודה לסימולציה:** צוות של 5 אנשים: ‏2×T1, ‏T2, ‏T3 ו-SOC Manager. בצוות של 3 (T1, ‏T2/T3, ‏Manager) העומס ב-S3 גבוה בערך פי 2.

---

## 0. תקציר ופסק דין

**פסק דין: מוכן עם תיקונים (Ready with fixes).** תיקוני P0 חוסמים מכירה. אפשר להריץ פיילוט מודרך במכללה עוד לפני שהם נסגרים, בתנאי שהמדריך מתודרך על הבעיות הידועות. לא הייתי מוכר את המוצר לארגון כ"כלי למדידת ביצועי צוות" לפני סגירת כל ה-P0.

**מה טוב, ובאמת ברמה גבוהה:**
- **שרשראות התקיפה אמינות ועדכניות:** ClickFix עם RunMRU, ‏CI/CD poisoning שממשיך ל-IMDS ← GuardDuty ← CreateAccessKey ← S3, ‏Okta credential stuffing עם רישום factor חדש, ‏shadow-AI אחרי חסימת DLP, ‏keylogger בתוכנת PDF מזויפת, ו-supply chain של vendor update.
- **רוב ה-native records נכונים לסכמה של המוצר:** Windows 4625/4624 עם SubStatus נכונים, ‏CrowdStrike FDR ‏(`event_simpleName`, ‏`aid`/`cid`), ‏Okta System Log עם `behaviors`, ‏CloudTrail 1.11 עם `tlsDetails`, ‏k8s audit, ‏Zscaler NSS, ו-GWS Reports.
- **ההזרקות (false lead, ‏ITSM, ‏Legal) מייצרות דינמיקה צוותית אמיתית.** בעיקר ה-false lead של Mixpanel, שמגיע עם ticket אישור, ו-FP שמגיע עם ticket שינוי.

**מה שובר את המדידה, וזה הליבה של המכירה:**
1. **ה-severity הוא כמעט אורקל.** ‏100% משורות ה-high/critical ב-S1 הן תקיפה, ‏17 מתוך 18 ב-S2 ו-29 מתוך 31 ב-S3. אף שורת רעש "רגילה" לא מגיעה ל-high.
2. **טקסט השורה מסגיר את התשובה.** שורות תקיפה ארוכות פי 1.7–3.3 משורות רעש, כתובות כנרטיב ("The first logon failure…", ‏"the poisoned deploy.yml", ‏"The stolen instance-role credentials", ‏"check whether it was opened"), ולעתים מכילות את הניתוח עצמו.
3. **הרעש מייצר "אירועי רפאים" שהצוות ייענש על זיהויים.** דוגמאות: ‏SSN ל-gmail שמסומן benign, ‏outbound ל-4444 שמסומן benign, ו-Nmap פנימה ל-workstation מאותו IP שאליו host אחר מנסה להתחבר ב-4444. רעש גם משתמש בזהות של הקורבן בזמן אמת (g.lopez ב-S2).
4. **שבירות סיבתיות:** ה-twist inject מגיע לפני שהאירוע טופל. שורות ה-C2 של ה-twist מופיעות לפני שה-malware בכלל ירד לדיסק (S2). ה-bonus נוחת על host שהצוות כבר בודד (S2). חותמות הזמן של ה-bonus "חוזרות" ל-08:00.

---

## 1. ממצאים כמותיים רוחביים

### 1.1 Severity: אורקל כמעט מושלם

| סשן | שורות high/critical | מהן תקיפה | רעש לא-FP ב-high/critical | התפלגות רעש רגיל |
|---|---|---|---|---|
| S1 | 10 | **10 (100%)** | 0 | ‏68 info, ‏7 low, ‏2 medium |
| S2 | 18 | **17 (94%)** | 0 (היחיד: FP של encoded PS, ‏@17.5m) | ‏99 info, ‏12 low, ‏4 medium |
| S3 | 31 | **29 (94%)** | 0 (השניים: FP של certutil @10.8m ושל encoded PS @11.2m) | ‏142 info, ‏18 low, ‏9 medium |

**המשמעות:** אסטרטגיית T1 של "high ומעלה מסלים, info מסמן benign" תקבל ציון כמעט מושלם בלי לפתוח אף record. ב-SOC אמיתי רוב ההתראות ה-high הן benign-positive: סורק פגיעויות, pentest, כלי admin, ‏AV quarantine שהצליח, ‏break-glass מאושר. גם הכיוון ההפוך חסר: רוב השלבים המוקדמים של תקיפה אמיתית נראים low או info.

**ה-FP היחידים ב-high חוזרים על אותה תבנית:** ‏IT admin, כלי LOLBin ו-ticket ITSM שקדם לאירוע (S2 @17.0m←17.5m, ‏S3 @10.2m/10.4m←10.8m/11.2m). צוות לומד את התבנית אחרי סשן אחד.

### 1.2 אורך וסגנון טקסט השורה

| סשן | אורך ממוצע, רעש | אורך ממוצע, תקיפה | אורך ממוצע, בונוס |
|---|---|---|---|
| S1 | 56 תווים | **187** | 134 |
| S2 | 59 | **117** | 161 |
| S3 | 58 | **97** | 145 |

שורות רעש קצרות וטלגרפיות ("i.levi launched Chrome on WS-FIN-2847"). שורות תקיפה הן פסקאות הסבר. מספיק להעיף מבט בעמודה.

### 1.3 שורות שלא ב-native ‏(legacy raw)

‏7/99 ב-S1, ‏21/158 ב-S2 ו-29/219 ב-S3. זה תואם ל-82–93% native ב-ENV-MATRIX. הבעיה היא שמשפחות מקור שלמות אף פעם לא מגיעות ב-native:
- Purview DLP (‏`data.office365.*`)
- כל ה-WAFs ‏(Cloudflare, ‏Azure AppGW, ‏F5)
- כל ה-DAM ‏(MSSQL Audit, ‏Guardium, ‏Imperva)
- התראות Sentinel
- GitHub audit
- 4663 ב-S2 @13.0m, שמגיע כ-`winlog.*` בסגנון ECS

ההתראה המרכזית של אירוע הבונוס ב-S1 (@BONUS Sentinel) והשלב הראשון של ה-CI/CD ב-S3 (@24.7m GitHub) מוצגים כ-legacy. זה סותר את הכלל "כל לוג בפורמט ה-native של המקור".

---

## 2. S1: ‏easy, ברירת מחדל (30 דק', ‏3 שורות לדקה, בלי injects)

### 2.1 ריצה לפי תפקיד

| זמן | מה עולה | T1 | T2 | T3 | Manager |
|---|---|---|---|---|---|
| 0–6.7m | חימום: Kerberos, ‏DNS, ‏Chrome, ‏Zscaler, ‏PAN, ‏Entra | מסמן benign בקצב גבוה. מתלבט ב-@1.1m (חסימת USB של קובץ payroll, מסומן benign) | – | – | אין injects, ולכן אין לו תפקיד |
| 1.8m→2.9m | ticket ‏INC-10447, ואחריו הוספה ל-Backup Operators | מתאים ticket לאירוע ומסמן FP. **תרגול מצוין** | – | – | – |
| 6.7–14.0m | **Shadow AI:** ייצוא Salesforce ← login ל-DeepSeek ← חסימת DLP של upload ← 3 POST-ים של prompt שעוברים | @7.8m נראה benign (ייצוא Salesforce של איש מכירות) ונספר כ-tp. @8.7m הטקסט עצמו אומר "company has no DeepSeek tenant, so any account… is a personal one". ב-@9.8m (medium) וב-@12.1m (high) מסלים | מקשר לפי host/user ולפי ה-md5 (הטקסט ב-@9.8m כבר אומר "The md5 in the record is the md5 of Customer_Contacts…"). ‏Containment: חסימת DeepSeek ב-ZIA, ‏HR/Legal, שימור ראיות | אין לו מה לעשות. אי אפשר לראות את תוכן ה-prompt, וזה ריאלי | – |
| 10.1m | Cloudflare rate-limit מסין עם python-requests, ‏benign + ‏T1499 | בלבול: benign עם MITRE | – | – | – |
| 18.3m | **Inbox rule forward** ל-contoso-labs-secure.info, ‏**critical** (היחיד בפיד) | מסלים מיד בגלל ה-severity | מנסה לבנות scope: אין sign-in של n.cohen מ-91.108.4.222, אין MailItemsAccessed, ‏n.cohen לא מופיע בשום מקום אחר. סוגר על remove rule, ‏revoke sessions, ‏reset ו-block domain בלי לדעת איך החשבון נפרץ | – | – |
| 18.3–30m | **12 דקות של רעש בלבד** | שעמום | – | – | – |
| BONUS | keylogger ב-SwiftPDF | מסלים לפי high/critical | Run key, ‏hook, ‏cache.dat, ‏beacon. ‏Containment: ‏isolate WS-HR-1182, ‏reset ל-c.cohen | ‏PIDs בטקסט לא תואמים ל-record (ראו 6.2) | – |

### 2.2 איפה צוות טוב ייתקע או יוטעה

- **@7.8m ו-@11.0m (MDE):** הורדת קובץ מ-Salesforce ופתיחה שלו ב-Excel מסומנות tp. ‏T1 שמסמן אותן benign בזמן אמת צודק מקצועית, ובכל זאת נענש. אלה שורות הקשר שמתבררות רק בדיעבד. צריך מחלקה נפרדת של "evidence/context" (ראו P0-6).
- **@18.3m (M365):** אירוע של שורה אחת, בלי שום telemetry תומך. אין sign-in חריג ואין session. ‏T2 לא יכול לענות לשאלה "איך זה קרה ומה עוד נגנב". גם ה-record מוזר: `ObjectId` ‏`n.cohen@…\MobileSync`, כלומר שם תיקיית ActiveSync במקום שם של rule.
- **@1.1m (Purview):** ניסיון להעתיק payroll ל-USB, נחסם, ומסומן benign בלי ticket או הקשר. ב-SOC אמיתי זה "TP – blocked, notify manager". שורה שמלמדת הרגל שגוי.
- **@BONUS (PAN, MDE):** כל חותמות הזמן הן 08:00–08:05, אבל הבונוס משתחרר אחרי דקה 30. ‏T3 שבונה timeline יראה את הבונוס *לפני* תחילת המשמרת.

### 2.3 תזמון ורעש

- החימום של 6.7 דקות סביר.
- אחרי 18.3m אין שום אירוע מתוכנן במשך 12 דקות. בצוות, ה-Manager ו-T3 פשוט מובטלים לאורך כל הסשן, כי אין injects ב-easy.
- הרעש מגוון, ויש בו מבלבלים טובים: ‏`rclone` ל-SharePoint ב-@14.4m, ‏`ntdsutil` על DC ב-@16.6m, ו-PowerShell של SYSTEM ב-@13.4m.
- אבל ב-@16.6m (Sysmon) ה-User הוא `CONTOSOLABS\Domain Admins`, כלומר קבוצה במקום משתמש, ו-CurrentDirectory הוא `C:\Users\Domain Admins\`.

---

## 3. S2: ‏medium, ‏healthcare, ‏CrowdStrike/FortiGate (36 דק', ‏4.1 שורות לדקה, ‏7 injects)

### 3.1 ריצה לפי תפקיד

| זמן | מה עולה | T1 | T2 | T3 | Manager |
|---|---|---|---|---|---|
| 3.8m | FortiGate: ‏inbound RDP מרוסיה, ‏allowed ‏(medium) | מסמן ושם בצד | – | – | – |
| 4.8–7.1m | ‏4625: קודם `glopez` ‏(0xC0000064), אחר כך `g.lopez` ‏(0xC000006A), ‏`WorkstationName=WORKSTATION` | **ריאליזם מעולה** (כלי brute-force, ניחוש פורמט שם). אבל הטקסט "a representative 4625 of the burst" ו-"The final 4625" מסגיר | – | – | – |
| 8.4m, 9.4m | ‏4624 type 3 ‏(NTLM), ואחריו type 10 ‏(Negotiate) מאותו IP ‏(high) | מסלים | פותח case. ‏Scope: ‏BACKUP01 | – | – |
| 10.7m | Falcon: ‏`net use Z: \\SRV-FILE01\HR-Confidential` | – | מוסיף FILE01 ל-scope | – | **CISO inject (10.7m):** תזמון טוב, הצוות באמצע ה-scope |
| 11.7m→13.0m | ‏4624 Kerberos ב-FILE01 עם TargetLogonId ‏0x74C2E19, ואחריו 4663 עם אותו SubjectLogonId | – | **pivot מצוין** של LogonId בין שני records | – | – |
| 13.9m | Sentinel alert: ‏214 failures ואחריהם 1 success | אחרי כל זה | – | שם מלא בהעשרה: "J Chen, Accounts Payable" עבור g.lopez | – |
| 13.2m, 29.3m, 30.8m+31.6m, 31.3m | **רעש על g.lopez:** "risk score returned to normal after analyst confirmed legitimate travel", ‏reset סיסמה מאושר, "g.lopez emailed SSN data to external@gmail.com" ‏(benign) | יסלים את ה-SSN, ובצדק | יכניס לתוך ה-scope של bf (התוקף שולח SSN!), וייענש | – | – |
| 7.9m→14.8/16.8m→16.1m | false lead של Mixpanel: ‏ticket אישור, ‏upload גדול, ‏inject | – | בודק ticket ויעד, מסמן FP | – | **אחת ההזרקות הטובות במוצר.** אבל 1.87GB ל-`/batch` של Mixpanel ב-@14.8m חשוד בפני עצמו |
| 17.0m | ticket ‏CHG-9914 שהטקסט שלו הוא ה-FP rationale: "PowerShell -EncodedCommand fired because…" | – | – | – | ‏ticket שינוי לא יכול לתאר התראה שעוד לא קרתה. זה דליפה ואנכרוניזם |
| 19.8–31.8m | **ClickFix:** דף invoice ← captcha.js ← RunMRU ← powershell iwr\|iex ← init.ps1 ← base64 child ← sysupd32.exe ← NRD block ← Falcon kill | ‏@22.1m RunMRU ‏(medium) הוא אחד הארטיפקטים הכי טובים שראיתי בסימולטור | ‏isolate WS-OPS-2214 | ‏timeline | **Legal inject (22.2m):** רלוונטי ל-payroll של bf |
| 24.3m | **Twist inject:** "a host you already worked is now beaconing to a NEW C2" | – | מחפש host *שכבר טופל*. ‏SRV-CON-BACKUP01 הוא המועמד הטבעי, ולא ימצא שם כלום | **שבירה סיבתית:** שורות ה-support (DNS ‏cdn-edge-metrics.com ב-@24.8m, חיבור ב-@25.5m, ו-"sysupd32.exe… connected to 45.61.137.212" ב-@26.2m) קודמות להורדת sysupd32.exe ‏(@27.0m), לכתיבה שלו לדיסק (@27.9m) ולהרצה שלו (@29.1m) | – |
| 22.9m | FortiGate: ‏WS-ENG-3301 ← 91.108.56.199:4444 ‏blocked, ‏**benign** | יסלים (4444 הוא ברירת המחדל של Metasploit) וייענש | – | – | – |
| 25.0, 26.3, 30.0m | Solos: ‏PUP keygen, ‏inbox forward (אותה תבנית כמו ב-S1: אותו IP ואותו דומיין), ‏WAF block | – | – | – | – |
| 32.2m | Exec inject | – | – | – | ‏SITREP |
| BONUS | ISO ← LNK ← rundll32 ← PS ← core.dll, על **WS-OPS-2214** של משתמש "dba" | – | **ה-host כבר מבודד** אחרי ה-ClickFix. ‏host אחד, שני קורבנות שונים ("She") | – | – |

### 3.2 הערכה

- **אירוע ה-bf ניתן לזיהוי, ל-scope ול-containment מלאים מתוך המסך.** ‏Containment: ‏block IP, סגירת policy ‏`RDS-PUBLISHED-INBOUND`, ‏disable/reset ל-g.lopez, ‏isolate BACKUP01, ‏Legal על payroll. זה לימודי מאוד.
- **ההתראה המתואמת (Sentinel @13.9m) מגיעה 5.5 דקות אחרי ה-success וה-lateral.** ‏SIEM אמיתי היה מתריע סמוך ל-@8.4m. כרגע ה-T1 נדרש "לצוד" 4625 בודדים, וזה יותר משימת hunt מאשר triage.
- **ClickFix מצוין טכנית ועדכני (ראו 7.1).** הוא נהרס על ידי ה-twist שמוקדם מדי.
- **הענף healthcare לא מורגש בכלל.** אין EMR/PACS/HL7 ואין PHI. דווקא יש רעש של "svc-tradingapp positions-report" (@5.8m) ושל WS-TRADE-DESK4 (@21.9m), שמגיע מפרופיל פיננסי.
- **קצב:** ‏4.1 שורות לדקה ו-7 injects ב-22 דקות. מתאים ל-medium עם 5 אנשים. החפיפה בין bf, ‏ClickFix ו-solos יוצרת תיעדוף אמיתי, וזה טוב.

---

## 4. S3: ‏hard, ‏AWS/Okta/GWS/SentinelOne/PAN (40 דק', ‏5.2 שורות לדקה, ‏7 injects)

### 4.1 ריצה לפי תפקיד

| זמן | מה עולה | T1 | T2 | T3 | Manager |
|---|---|---|---|---|---|
| 7.7–11.0m | Okta: ‏63 failures, ‏21 users, ‏ThreatInsight deny, ‏lockout ל-j.vogel | מסלים (high) | פותח case | – | – |
| 12.3m | PAN IPS ‏"Web.Login.Credential.Stuffing" מול 217.177.80.60 | – | **סתירה ארכיטקטונית:** ‏Okta הוא SaaS, והתעבורה של התוקף אליו לא עוברת ב-firewall הארגוני. גם שם החתימה מומצא | – | ‏CISO inject (11.9m) |
| 13.7m | ‏v.rossi success מ-89.248.171.44 עם python-requests | – | **סתירה:** ‏ThreatInsight חסם את ה-IP ב-@9.0m | – | – |
| 15.2m | Okta Verify factor חדש נרשם מה-IP של התוקף ‏(critical) | – | ‏Containment: ‏clear sessions, ‏reset factors, ‏suspend | – | – |
| 16.8m | CloudTrail: ‏IAMUser `v.rossi` עם מפתח AKIA קורא ListRoles | – | **שבירת מודל זהות:** משתמש Okta מפודרל אמור להופיע כ-`AssumeRoleWithSAML`/AssumedRole. מאיפה לתוקף מפתח סטטי? ה-clone של ה-repo, שאולי מכיל secrets, מגיע רק אחר כך (@18.2m) | – | – |
| 18.2m | GitHub: ‏clone של `contoso-labs/platform-core` דרך OAuth app של okta-sso | – | ‏revoke tokens | שם ה-org לא עקבי: ‏`contoso-labs` כאן, ו-`contoso-labs-io` ב-@24.7m | ‏false lead (17.9m) |
| 24.7–36.6m | **CI/CD poisoning:** ‏PR merge ← workflow על runner ‏self-hosted ‏(srv-linux-web01) ← curl\|bash ← IMDS ← GuardDuty ← GetCallerIdentity ← CreateAccessKey ← GetSecretValue ← GetObject customers_full.csv ← PAN block ← S1 quarantine | high/critical, מסלים | ‏disable runner, ‏revert workflow, ‏revoke ל-PR author | ראו את השבירות למטה | **Legal (24.7m):** מגיע לפני הגניבה של customers_full.csv ב-@34.2m |
| 27.0m | Twist inject | – | **שוב:** srv-linux-web01 הופיע רק ב-@25.9m ואיש עוד לא "עבד" עליו | – | – |
| 34.7m + 38.4m | Nmap OS scan **מ-91.108.56.199 פנימה ל-10.10.20.14** ‏(benign), ו-WS-ENG-3301 ← **91.108.56.199**:4444 ‏(benign) | צוות טוב יחבר: סריקה מבחוץ, ו-host פנימי מנסה reverse shell לאותו IP | יפתח אירוע | ייענשו על זיהוי נכון | – |
| BONUS | supply chain של NetPulse על srv-linux-app01 ← secrets ← AssumeRole מסינגפור ← 2.3GB מ-backups ← SSH ל-db/jenkins | – | – | **הבונוס הכי טוב בשלושת הסשנים.** ‏precursors מסומנים fp, וזה רעיון נכון. אבל t.larsen הוא "Senior Analyst" בפיננסים (@39.4m) שיש לו `/home/t.larsen/.ssh/id_rsa` על שרת אפליקציה ומשתמש IAM בשם "t.larsen-ci" | – |

### 4.2 השבירות בשרשרת ה-CI/CD, שבה T3 ייתקע

- **@27.5m (Sysmon על srv-linux-web01, host לינוקס):** ‏record של Windows Sysmon עם `"Image":"C:\\Windows\\System32\\bootstrap.sh"`, ‏`UserID S-1-5-18` ו-`CONTOSOLABS\ci-pipeline`. זה record שבור לגמרי.
- **חשבונות AWS לא מתחברים:**
  - ב-@31.0m ה-GetCallerIdentity הוא של `contoso-labs-ci-deploy-role` בחשבון **247316892041**, עם instance id ‏`i-0abc123def456789`, שנראה כמו placeholder.
  - ב-@32.0m וב-@33.1m ה-CreateAccessKey וה-GetSecretValue רצים כ-`IAMUser` בשם `"unknown"` בחשבון **128434854045**.
  - ה-GuardDuty ב-@29.8m מציג principal `unknown-role`.
  - ‏T3 לא יכול לקשור את ה-access key החדש ל-role של ה-runner. ערכי placeholder דולפים ל-native.
- **@24.7m (GitHub):** ה-PR מוזג על ידי d.haddad. זה אותו משתמש פיננסי מהרעש: ‏WS-FIN-2847, העתקת 9.3GB ל-USB ב-@5.8m. אין PR reviewer ואין approval. בנוסף, השדה `github.workflow.diff_added_lines` לא קיים ב-GitHub audit log, כי audit log לא מכיל diff.
- **@28.5m (IMDS):** אין שום אינדיקציה ל-IMDSv2 ‏(PUT token). זו נקודת לימוד שהולכת לאיבוד.

### 4.3 הערכה

- **שני הסיפורים המרכזיים הם בדיוק מה שרואים ב-2025–2026** (סעיף 7.1). הם בנויים כך שכל תפקיד מקבל עבודה: T1 על Okta, ‏T2 על containment בשלושה מישורים (IdP, ‏AWS ו-GitHub), ‏T3 על reconstruction מ-PR ועד S3, וה-Manager על Legal.
- **ארבעה solos של שורה אחת:** ‏WAF block, ‏22 failures ב-VPN, ‏MFA denied ו-phish delivered. כולם "תופסים" ב-severity בלבד, בלי שום שורה המשך ל-scope.
  - ב-@25.3m הטקסט אומר "SentinelOne pulled it 4 minutes later (ZAP); check whether it was opened". ‏ZAP הוא מנגנון של Defender for O365, ‏SentinelOne לא מושך מיילים, וחלק המשפט "check whether…" הוא הוראה לאנליסט שמופיעה בתוך הלוג.
- **בחירת Okta+GWS לא ניקתה את המותג של Microsoft מהרעש:**
  - ב-@11.9m: ‏"A Google Workspace update wrote a registry value", כשה-record הוא `OfficeClickToRun.exe`.
  - ב-@14.5m: ‏"Microsoft Defender Antivirus scan" שמגיע מ-SentinelOne.
  - ב-@23.7m: ‏"Google Drive /sites/HR", שהוא נתיב SharePoint.
  - ב-@28.8m: ‏"quarantined by SentinelOne for Google Workspace".
  - ‏Purview DLP על "email" בארגון GWS (@2.8m, ‏@15.5m, ‏@29.2m).
  - זה חיפוש-והחלפה של שמות מותג, וכל מתרגל שעבד עם GWS יזהה את זה מיד.
- **"vendor sprawl" לא ריאלי:** שלושה WAFs על אותו `app.contoso-labs.io` ‏(Cloudflare @4.5m, ‏F5 @18.4m, ‏Azure AppGW @20.1m), שלושה מוצרי UEBA (‏Sentinel UEBA, ‏Exabeam @30.8m, ו-Securonix ב-S2), וארבעה DAM. לארגון אמיתי יש אחד מכל סוג.

---

## 5. האם הרעש ריאלי, והאם קשה להפריד אותו מהתקיפה?

**בהיקף ובגיוון, כן.** הרעש מכסה 20+ מקורות, יש בו מבלבלים אינטליגנטיים (rclone, ‏ntdsutil, ‏kubectl exec, ‏MFA בניסיון שני, ‏home sign-in, ‏DLP USB מאושר), ויש בו correlation ל-ITSM.

**בהפרדה, לא.** התקיפה מסגירה את עצמה בכמה ערוצים במקביל:
- severity (סעיף 1.1)
- אורך וסגנון הטקסט (1.2)
- מילים טעונות בטקסט: "poisoned", ‏"stolen", ‏"phishing email", ‏"the burst"
- ה-severity ‏critical הוא כמעט תמיד תקיפה
- ה-FP-ים בנויים כולם מאותה תבנית (ticket שקודם לאירוע)

**הבעיה ההפוכה חמורה לא פחות:** יש "benign" שהוא בעצם זדוני או מחשיד, ומלמד הרגל שגוי:
- S2 @31.3m ו-S3 @29.2m: "emailed SSN data to external@gmail.com", ‏benign.
- S2 @22.9m ו-S3 @38.4m: ‏outbound ל-91.108.56.199:4444, ‏benign.
- S3 @34.7m: ‏Nmap OS scan מהאינטרנט ל-10.10.20.14. אם הוא הגיע, ה-host חשוף. ה-record גם ממקם workstation פיננסי בזון `dmz`.
- S1 @1.1m: חסימת USB של payroll, בלי ticket.
- S2 @13.2m: "risk score returned to normal after the analyst confirmed legitimate travel" על הקורבן הפעיל.

---

## 6. מקצועיות הלוגים

### 6.1 חוזקות (עם דוגמאות)

| נושא | דוגמה |
|---|---|
| Windows auth אמיתי | S2 @4.8m 4625 עם `SubStatus 0xc0000064` ו-`TargetUserName glopez`, ‏@6.1m ‏0xC000006A, ‏@8.4m 4624 עם `LmPackageName NTLM V2`, ‏`WorkstationName WORKSTATION`, ‏`LogonGuid` אפסים. ‏S1 @17.0m 4720 עם `NewUacValue 0x15` (הערך הסטנדרטי). ‏S1 @28.2m 4771 עם `Status 0x18` |
| Pivot של LogonId | S2 @11.7m `TargetLogonId 0x74C2E19` ← @13.0m 4663 `SubjectLogonId 0x74C2E19` |
| CrowdStrike FDR | S2 @22.1m `RegGenericValueUpdate` על RunMRU עם `\1`, ‏@26.2m `NetworkConnectIP4` עם `ContextProcessId`, ‏@25.0m detection עם `composite_id`/`aggregate_id` |
| FortiGate | S2 @3.8m traffic/forward עם `policyname`, ‏`srccountry`, ‏`appcat Remote.Access`. ‏@14.8m utm/webfilter עם FSSO user |
| Okta | S3 @13.7m `debugContext.debugData.behaviors` ‏(New Geo-Location=POSITIVE…), ‏@9.0m `threatSuspected:true` |
| AWS | S3 @34.2m CloudTrail data event (`eventCategory Data`, ‏`managementEvent false`), ‏@31.0m `ec2RoleDelivery 2.0`, ‏@29.8m סוג finding נכון ב-GuardDuty |
| K8s / GWS / Zscaler | S3 @10.0m exec subresource עם `code 101`. ‏S3 @23.7m `admin#reports#activity` עם shared drive. ‏S1 @9.8m NSS עם `dlpengine`/`filetype`/`status 403` |
| ITSM correlation | S1 @1.8m←@2.9m. ‏S2 @22.6m←@23.1m (תרגול FP אמיתי) |

### 6.2 ליקויים (כל אחד עם offset)

**א. דליפת תשובה בטקסט השורה (P0):**
- S1 @6.7m "This is the user's usual AI traffic before the later sessions"
- S1 @8.7m "the company has no DeepSeek tenant, so any account signed in here is a personal one"
- S1 @9.8m "The md5 in the record is the md5 of Customer_Contacts_Q3_Master.xlsx"
- S1 @12.1m "the rule that blocked the file does not cover prompt text"
- S2 @6.1m "a representative 4625 of the burst", ‏@7.1m "The final 4625 of the burst"
- S2 @23.6m "consistent with a pasted command run from the Windows Run dialog"
- S2 @27.0m "the file named in its decoded Base64 command line"
- S2 BONUS "She chose Run anyway" (‏EDR לא רושם לחיצה על אזהרת MOTW)
- S3 @25.9m "the **poisoned** deploy.yml"
- S3 @31.0m "The **stolen** instance-role credentials"
- S3 @25.3m "check whether it was opened"

**ב. סתירות בין טקסט השורה ל-record:**
- S1 @4.3m: הטקסט אומר "used a YubiKey to complete MFA", וה-record הוא `ProcessCreated ssh` ב-MDE.
- S1 @8.4m: הטקסט אומר "Outlook mobile on iPhone", וה-record הוא Windows Chrome עם `clientAppUsed Browser`.
- S1 @14.0m: הטקסט אומר "Between 09:36 and 09:40", וה-records הם 08:12–08:14.
- S1 BONUS: הטקסט נותן pid 15192 ו-15244 ו-chrome pid 5012, וה-records נותנים 19988 ו-9404 ו-18452. הטקסט אומר "SetWindowsHookExW", וה-ActionType ב-record הוא `OpenProcessApiCall`. ל-keylogging ב-MDE היה מתאים יותר `GetAsyncKeyStateApiCall`.
- S1 BONUS: הטקסט אומר "61 KB over 34 minutes", כשכל האירועים בתוך 2 דקות.
- S3 @39.4m: ה-FP מתאר "The 22:15 login", והאירוע בשעה 08:39.

**ג. records שבורים או placeholders:**
- S3 @27.5m: ‏Sysmon של Windows על host לינוקס.
- S1 @9.4m: ‏MDE על runner לינוקס עם `FolderPath "/usr/bin\\node"`.
- S3 @31.0m–34.2m: ‏`user/unknown`, ‏`unknown-role` ו-`i-0abc123def456789`.
- S1 @15.6m: IP פרטי (10.20.30.10) עם geo "Tel Aviv".
- S1 @22.0m: ‏SQL Agent עם `event.code 33205` (קוד של SQL Audit) וקובץ `FinanceDB_20260510` בתאריך 2026-01-01.
- S3 @25.3m: ‏Proofpoint עם `messageID 20260512…`.
- S3 @7.7m: ‏`externalSessionId "idx4xfg7haKimShenzhen8823"`, שם עיר בתוך session id.

**ד. קוהרנטיות זהויות ונכסים (P1, ושובר pivoting):**
- שני SIDs של domain לאותו CONTOSOLABS: ‏`S-1-5-21-2661191538-…` ‏(S1 @0.0m) ו-`S-1-5-21-3421479547-…` ‏(S1 @28.6m).
- אותו משתמש בשני פורמטים: `ilevi` ו-`i.levi`.
- ה-domain מופיע בשלוש צורות: `CONTOSOLABS.COM`, ‏`DC=contoso-labs,DC=com` ו-contoso-labs.io.
- WS-FIN-2847 משמש לפחות 6 משתמשים בסשנים השונים (i.levi, ‏v.ahmed, ‏g.lopez, ‏i.bauer, ‏z.kowalski, ‏d.haddad).
- j.moreau מופיע על 4 hosts ב-S1.
- S2 @18.8m: ‏`LocalAddressIP4 10.45.164.165` עבור LT-ENG-4400, שה-IP שלו 10.100.50.41.
- S1 @17.7m: ‏WS-HR-1142 כותב ל-`C:\Users\edahl\` (‏e.dahl הוא איש מכירות על WS-SALES-1876).
- העשרת Sentinel עם שם שגוי: S1 BONUS ‏"T Harris, Legal" עבור c.cohen, ו-S2 @13.9m ‏"J Chen, Accounts Payable" עבור g.lopez.
- c.cohen ב-S1 הוא בו-זמנית HR (WS-HR-1182), ‏IT שיוצר חשבונות (@16.3m) ו-Ops (‏LT-OPS-4503).

**ה. חיפוש-והחלפה של מותגים:** ראו 4.3 (S3 @11.9m, ‏@14.5m, ‏@23.7m, ‏@25.3m, ‏@28.8m).

**ו. ארכיטקטורה:**
- S3 @12.3m: ‏PAN רואה cred-stuffing מול Okta.
- S3 @16.8m: משתמש Okta מופיע כ-IAM user.
- S2 @3.8m: שרת גיבוי מוגדר כ-RDS מפורסם לאינטרנט. זה אפשרי כ-misconfig, אבל שווה לציין במפורש.

**ז. חתימות וכותרות מומצאות:** ‏PAN ‏"Web.Login.Credential.Stuffing(51234)" ו-"SCAN-Nmap-OS-Detection(40000)", ‏MDE Title ‏"UnsignedUserlandKeyboardHook". כותרות התראה ב-MDE הן משפטים בשפה טבעית ולא CamelCase.

**ח. ServiceNow:**
- שינויים נרשמים כ-`incident` ‏(INC-10447 "approved") או כ-`sc_req_item` עם קידומת CHG. בפועל שינוי נרשם ב-`change_request` עם CHG.
- ‏`resolved_at` של INC-10447 (08:01:48) קודם לשינוי עצמו (08:02:51).
- ה-short_description של CHG-9914 הוא ה-rationale של ה-FP.

**ט. בסיס זמן:**
- כל הסשנים מתוארכים ל-**2026-01-01 08:00**, שהוא חג. ובכל זאת יש רעש של "quarter-end crunch", ‏payroll ו-Q3 budget.
- הבונוסים מתוארכים ל-08:00–08:05.

**י. חזרתיות בין סשנים:** אותם INC-10447, ‏ONB-0388, ‏CHG-9914, ‏RITM0048213 ("1,842 files (9.3 GB)"), אותו Mixpanel, אותו "SSN to gmail", אותו 91.108.56.199:4444, אותו 122.114.88.45, אותו 91.108.4.222 עם contoso-labs-secure.info, ואותם 7 injects מילה במילה ב-S2 וב-S3. כיתה שמשחקת שלושה סשנים תלמד את התבניות בעל פה.

**יא. דליפת ענף:** רעש פיננסי (svc-tradingapp, ‏TradeFlow, ‏WS-TRADE-DESK4, ‏WS-RISK-3311) ב-healthcare וב-general. ‏RemotePort 104 ‏(DICOM) עבור "document archive" בסשן general (S1 @27.5m).

---

## 7. ריאליזם של תרחישי הייחוס

### 7.1 האם התקריות בסשנים תואמות את 2024–2026?

| תקרית | ריאליזם | הערה |
|---|---|---|
| ‏Shadow AI ‏(S1) | ✅ גבוה | ‏DLP חוסם קובץ, המשתמש עוקף דרך prompt. זה בדיוק מה שרואים מאז 2025. מתאים כ-insider/policy, לא כתקיפה |
| ‏Inbox forward ‏(S1, ‏S2) | ✅ תבנית נכונה | T1114.003 נמצא ב-top-10 של Red Canary. חסר ה-sign-in שקדם לו, וזה הופך את התרגיל ל"טריגר בלבד" |
| ‏Keylogger ב-PDF tool ‏(S1) | ✅ | תואם לקמפייני "free PDF editor" של 2025 |
| ‏RDP brute-force ל-RDS מפורסם ‏(S2) | 🟡 | ריאלי (‏Sophos מודד RDP חשוף ב-18%). ב-2025–2026 שכיח יותר valid account מ-infostealer מאשר 214 failures. טוב ל-medium |
| ‏ClickFix ‏(S2) | ✅ מאוד | לפי MDDR 2025, ‏47% מה-initial access. ‏T1204.004 נוסף ב-ATT&CK v17 |
| ‏ISO/LNK ‏(S2 bonus) | 🟡 | המכניקה נכונה ל-post-Nov-2022: ה-MOTW מתפשט. השכיחות ירדה מאז 2023 |
| ‏Okta credential stuffing ← factor חדש ‏(S3) | ✅ | תואם לאזהרות Okta מ-2024 ולתבנית Snowflake. השבירה היחידה היא ב-AWS (4.1) |
| ‏CI/CD poisoning ‏(S3) | ✅ מאוד | ‏tj-actions (CVE-2025-30066), ‏Ultralytics, ‏Shai-Hulud |
| ‏Vendor supply chain ‏(S3 bonus) | ✅/נדיר | בסגנון 3CX/SolarWinds. טוב כבונוס |
| ‏Solos חסומים (WAF, ‏PUP) | 🟡 | ב-SOC אמיתי WAF block בודד הוא benign/informational, לא incident. ניקוד שלו כ-TP מלמד הסלמת-יתר |

### 7.2 מה חסר בארסנל (מעבר לסשנים, לפי STORIES.md)

את הספירה וידאתי ב-`STORIES.md`: ‏82 storylines (20 foundation, ‏27 core, ‏35 advanced). ‏T1190 מופיע ב-3 storylines בלבד. ‏T1047, ‏T1649, ‏T1606 ו-T1068 לא מופיעים בכלל. ‏T1219 מופיע רק ב-`tech-support-scam`, ‏T1490 רק ב-`ransomware`, ו-T1485 רק ב-`globallogis-chain-c`.

1. **ניצול edge/public-facing (וקטור מספר 1 בעולם).** יש רק `edge-vpn-cve-exploit` ‏(FortiOS) ו-`webshell-rce`. חסרים PAN-OS GlobalProtect ‏(CVE-2024-3400), ‏Ivanti Connect Secure, ‏Citrix NetScaler, ‏Cisco ASA/FTD ‏(CVE-2025-20333/20362, ‏ED 25-03), ‏Check Point ‏(CVE-2024-24919, ‏CVE-2026-50751), ‏SharePoint ToolShell ‏(CVE-2025-53770) ו-Oracle EBS ‏(CVE-2025-61882, ‏Cl0p).
2. **ransomware מודרני בסגנון Akira/Qilin:** ‏VPN valid account ← Impacket wmiexec/secretsdump ← RDP פנימי ← מחיקת גיבויים ← ESXi. ה-ransomware המרכזי במוצר הוא LockBit שנכנס בפישינג. אין BYOVD/EDR-kill ואין recovery denial.
3. **SE שאינו אימייל:** ‏email bombing ← Teams "IT" ← Quick Assist ← RMM ‏(Storm-1811), ‏callback/TOAD, ‏quishing, ו-device-code phishing ‏(Storm-2372).
4. **RMM abuse:** ‏ScreenConnect, ‏SimpleHelp ו-Atera. בפרט MuddyWater מול ארגונים ישראליים.
5. **SaaS-to-SaaS:** גניבת OAuth tokens של אינטגרציה (Salesloft Drift, ‏UNC6395), ‏vishing ל-Salesforce ‏(UNC6040), ומחסן נתונים בלי MFA בסגנון Snowflake.
6. **Wiper דרך MDM:** ‏Handala ← Intune ‏RemoteWipe (Stryker, ‏11 במרץ 2026). קריטי ללקוחות ישראליים.
7. **זהות מתקדמת:** ‏ADCS (ESC1/ESC8 ‏/ T1649), ‏Golden SAML, ‏Entra Connect, הוספת secret ל-service principal ‏(Azure control-plane).
8. **Cloud ransomware:** הצפנת S3 עם SSE-C בסגנון Codefinger (2025).
9. **DPRK IT workers** כ-insider.
10. **ייצוג-יתר של AI:** יש 14 storylines עם `ai-*`. ‏M-Trends 2026 קובע ש-2025 לא הייתה השנה של פריצות שנבעו מ-AI. הייתי מצמצם ל-6–8.

### 7.3 אימות `THREAT-LANDSCAPE.md`

| טענה | סטטוס |
|---|---|
| CVE-2026-50751, ‏Check Point Remote Access VPN, מנוצל מ-7.5.2026, קשר ל-Qilin | **אומת** (Rapid7, ‏Check Point, ‏Qualys, ‏BSI). **הסתייגות:** החולשה היא לוגיקה של אימות תעודות ב-**IKEv1** והיא רלוונטית רק בקונפיגורציה עם legacy clients ובלי machine certificate. הגילוי הפומבי היה ב-8.6.2026. בתרחיש צריך לבנות את התנאים האלה, לא "auth bypass" גנרי |
| DBIR 2026: ‏exploit ב-31%, ‏ransomware ב-48%, צד שלישי ב-48% | אומת. **הסתייגות:** Verizon מציינים שחלק מהירידה ב-credential abuse (ל-13%) נובע משינוי מתודולוגי, כי נוספה קטגוריית pretexting. כש-credential abuse נספר בכל שלב של התקיפה, הוא מופיע ב-39% מהפריצות |
| M-Trends 2026: ‏exploit ב-32%, ‏vishing ב-11% (מקום שני), ‏email phishing ב-6% | אומת |
| CrowdStrike 2026: ‏breakout של 29 דק', המהיר ביותר 27 שניות, ‏82% malware-free | אומת |
| Sophos 2026: ‏Akira ‏22.6%, ‏Qilin ‏11.1%, ‏top-5 ‏51% | אומת (22.58% / 11.06%) |
| MDDR 2025: ‏ClickFix ב-47% מה-initial access | אומת, דרך דיווחים משניים |
| Tycoon 2FA: פירוק ב-2026 | אומת (Europol ו-Trend Micro, מרץ 2026) |
| Handala / Stryker / Intune, מרץ 2026 | אומת |
| Sophos: ‏Impacket עלה מ-21.43% ל-36.01% | **לא אומת.** לא מצאתי את המספר בתקצירים הפומביים. צריך לבדוק ב-PDF לפני שמשתמשים בו |
| "13 מתוך 82 storylines הם AI, מהם 4 על Claude Enterprise" | **לא תואם ל-STORIES.md:** יש 14 עם `ai-*` ו-3 עם Claude בכותרת. כנראה הבדל בהגדרה. לתקן לפני שמצטטים מול לקוח |
| "`iso-container-smuggling`: הנחת ה-MOTW מיושנת" | **מדויק בחלקו.** הרינדור ב-S2 משקף נכון את ההתנהגות שאחרי 2022: ה-MOTW מתפשט והמשתמש לוחץ "Run anyway". מה שהתיישן הוא השכיחות, לא המכניקה |
| "`malicious-macro` מבוסס על הנחה מיושנת" | **חלש.** הכותרת של ה-storyline היא "…Download **Blocked**", כלומר הוא כבר ממדל את החסימה. מתאים להשאיר אותו כ-foundation |
| "VMware מוסיף 1" | מודד מול "none". ב-ENV-MATRIX, הוספת vmware על גבי ברירת המחדל מוסיפה **0** (44 = 44). שני המסמכים נכונים, כל אחד מול baseline אחר |

---

## 8. בחירות הסביבה ‏(ENV-MATRIX)

**לגיטימי ומגובה היטב:**
- **AWS:** מ-44 ל-52 storylines שונים (hard מ-14 ל-18), ו-AWS noise אמיתי (8 שורות ב-medium).
- **all platforms:** ‏60 storylines שונים.
- **EDR, ‏firewall ו-VPN:** מחליפים בפועל את המקור בשורות. ב-S2 כל ה-EDR הוא CrowdStrike וכל ה-firewall הוא FortiGate, ב-S3 כל ה-EDR הוא SentinelOne וכל ה-firewall הוא PAN. ה-native share של PAN, ‏Proofpoint ו-CrowdStrike הוא 90–93%.

**כמעט לא משנה דבר, או לא משנה בכלל:**

| בחירה | storylines שונים | noise של הפלטפורמה ב-medium | מה המדריך יצפה לקבל ולא יקבל |
|---|---|---|---|
| +k8s | 44 (‏+0) | k8s:2 | תרחישי AKS/EKS, ‏pod escape (דורש AWS) |
| +github | 44 (‏+0) | **0** | תרחישי repo/Actions/PAT בלי AWS |
| +cyberark | 44 (‏+0) | **0** | ‏PAM vault abuse |
| +vmware | 44 (‏+0) | **0** (גם ב-S2, שנבחר בו vmware) | לוגים של ESXi/vCenter ו-ESXi ransomware |
| +ndr | 46 (‏+2, ב-hard בלבד) | **0** | לוגים של Zeek/NDR |
| +azure / +linux | זהה לברירת המחדל | – | שתיהן כבר כלולות בברירת המחדל, ולכן אין שינוי |
| industry=healthcare | ‏+4 (64 לעומת 60) | – | ‏EMR/PACS/HL7 ו-PHI. ב-S2 לא הופיע שום דבר ענפי, ודווקא הופיע רעש של trading |

**בחירות ש*מקטינות* את הארסנל, בלי שהמדריך יודע:**
- collab=google_workspace: מ-60 ל-**47** (‏-13; ‏medium מ-35 ל-27).
- email=proofpoint: ‏-6.
- firewall=cisco_asa: ‏-5.
- idp=okta: ‏-3.
- infoblox: ‏-1.
- **idp=entra מוריד את ה-native share ל-75%,** הנמוך בטבלה. זה עבור ה-IdP הנפוץ ביותר בישראל.

**גודל הארסנל לפי רמה:** ב-hard יש 14 storylines בלבד בברירת המחדל, פחות משיש ב-medium (30). כיתה מתקדמת שמתאמנת שבוע תפגוש חזרות.

**הדינמיקה המוסתרת:** המדריך בוחר "GWS + Okta" כדי שהתרגול ירגיש כמו הסביבה של הלקוח. בפועל הוא מקבל פחות תרחישים, רעש עם מותגי Microsoft, ו-Purview DLP על Gmail.

---

## 9. מכניקת צוות

**Bonus attack:**
- **הרעיון טוב:** פרס לצוות שתפס הכול, ובידול ברור בין צוותים.
- **בעיות:**
  1. השער הוא "תפסו כל התקפה מתוכננת", כולל solos טריוויאליים כמו WAF block. צוות שמסלים הכול עובר את השער בזכות הסלמת-יתר.
  2. חותמות הזמן חוזרות ל-08:00.
  3. ב-S2 הבונוס נוחת על host מבודד.
  4. persona: ‏t.larsen ב-S3 ו-c.cohen ב-S1 משמשים גם ברעש עם תפקידים סותרים.

**Injects:**
- **טובים:**
  - ה-CISO ב-S2 @10.7m מגיע באמצע ה-scope, בתזמון נכון.
  - ה-Legal ב-S2 רלוונטי ל-payroll.
  - ה-false lead של Mixpanel עם ticket מקדים הוא תרגול מצוין של "don't over-escalate".
  - ה-ticket של ה-help desk (MFA code vishing) בודק תגובה של T1.
- **בעיות:**
  1. ה-MSEL קבוע ושווה מילה במילה בין S2 ל-S3. הטקסט גנרי ("the suspicious activity") ולא מזכיר hosts או users של התקרית בפועל.
  2. ה-twist מתוזמן לפי שעון ולא לפי מצב הצוות. הוא מגיע לפני שה-incident טופל, ושורות ה-support שלו קודמות ל-malware.
  3. ב-easy אין injects בכלל, וה-Manager מובטל.
  4. ה-announcement לא דורש שום פעולה.
  5. חסרים injects שיוצרים מתח אמיתי:
     - בעל המערכת מסרב לבודד שרת production. ב-S3, ‏srv-linux-web01 הוא שרת web, ובידוד שלו הוא החלטה עסקית שמחייבת אישור Manager.
     - ‏shift handover.
     - פנייה חיצונית (AWS abuse report, ‏GitHub).
     - רגולטור או משרד הבריאות ב-healthcare.

**חלוקת תפקידים ומדידות:**
- **T1:** נדרש לתת disposition לכל שורה, כולל "launched Chrome" ו-DNS. ב-SOC אמיתי T1 ממיין *התראות*, ו-telemetry משמש לחקירה. בקצב של 5.2 שורות לדקה (S3) זה עומס של מקלדת ולא של חשיבה.
- **T3:** כמעט אין לו משטח עבודה ייחודי. אין שורות "hunt" (hosts נוספים עם אותו IOC, ראיה שלילית), ואין דרך למדוד כתיבת detection rule.
- **בעיות בניקוד:**
  - precursors ללא סימן חשד מסומנים tp ב-S1 (@7.8m ו-@11.0m), אבל fp ב-S3 (בונוס). חוסר עקביות.
  - FP לעומת benign לא מוגדרים באופן עקבי: ב-S1, ‏group add עם ticket הוא fp ב-@2.9m, ו-account delete בלי ticket הוא benign ב-@5.3m.
  - "אירועי רפאים" מעונשים זיהוי נכון (סעיף 5).

**השורה התחתונה למכניקה:** יש דינמיקה צוותית אמיתית ב-S2 וב-S3: חפיפת תקריות, תיעדוף, false lead ו-Legal. המדידה עדיין לא אמינה, מהסיבות בסעיפים 1, ‏5 ו-6.

---

## 10. פסק דין ורשימת תיקונים מתועדפת

**פסק דין: מוכן עם תיקונים.** חובה לסגור את כל ה-P0 לפני מכירה לארגונים. אפשר להריץ פיילוט במכללה עם מדריך מתודרך כבר עכשיו.

### P0: חוסם מכירה

1. **לבטל את ה-severity כאורקל.**
   - להוסיף לרעש התראות benign-positive ב-high/critical: סורק פגיעויות, pentest מתואם, ‏AV quarantine שהצליח, ‏break-glass מאושר, ‏admin tooling.
   - להוריד שלבים מוקדמים של תקיפה ל-low/info.
   - **יעד מדיד:** לכל היותר 60% מה-high/critical הם TP, ולפחות 30% משורות ה-TP הן low/info.
   - להוסיף lint שנכשל אם היעדים לא מתקיימים.
2. **לנטרל את טקסט השורה.**
   - פורמט אחיד בסגנון כותרת התראה של ספק + שדות מפתח, עם אורך דומה לשורות רעש (הפער כרגע: 56 מול 187).
   - רשימת מילים אסורות: poisoned, ‏stolen, ‏phishing, ‏representative, ‏first/final, ‏"check whether", ‏"consistent with", ‏She/He.
   - כל הניתוח עובר למפתח התשובה.
   - **lint:** היחס בין אורך שורת תקיפה לאורך שורת רעש קטן מ-1.2.
3. **שומר התנגשויות ברעש.**
   - הרעש לא משתמש ב-users, ב-hosts או ב-IPs של storylines פעילים (כרגע: g.lopez ב-S2 @13.2m/29.3m/31.3m, ו-z.kowalski ב-S3 @29.2m).
   - לא ליצור זוגות מחשידים מקריים (כרגע: 91.108.56.199 ב-S3 @34.7m+@38.4m).
   - לסווג מחדש או להסיר תבניות "benign" שהן מחשידות במהותן: ‏SSN ל-gmail, ‏outbound ל-4444, ‏Nmap פנימה ל-workstation, חסימת USB של payroll בלי ticket.
4. **בדיקות סיבתיות וזמן.**
   - ה-twist מופעל לפי מצב הצוות (רק אחרי escalation או containment של האירוע שאליו הוא מתייחס), ושורות ה-support שלו נוצרות אחרי ה-artifact (S2 @24.3m–26.2m).
   - חותמות הזמן של הבונוס ממשיכות את שעון הסשן.
   - אין שימוש חוזר ב-host בין תקריות (S2: ‏WS-OPS-2214).
   - **lint:** זמנים, ‏PIDs ושמות שמופיעים בטקסט השורה תואמים ל-record (S1 @14.0m, ‏S1 BONUS, ‏S3 @39.4m).
5. **לתקן records שבורים.**
   - Sysmon על לינוקס (S3 @27.5m), נתיב MDE בלינוקס (S1 @9.4m).
   - placeholders ב-AWS (‏`unknown`, ‏`i-0abc123…`) ושני חשבונות שלא מתחברים (S3 @31.0m–34.2m).
   - geo על IP פרטי (S1 @15.6m).
   - PAN שרואה תעבורה ל-SaaS (S3 @12.3m).
   - משתמש Okta כ-IAM user (S3 @16.8m).
   - חיפוש-והחלפה של מותגים (S3 @11.9m, ‏@14.5m, ‏@23.7m, ‏@25.3m, ‏@28.8m).
   - ‏ticket שינוי שמכיל FP rationale (S2 @17.0m, ‏S3 @10.2m).
6. **סמנטיקת ניקוד.**
   - מחלקה נפרדת "context/evidence" ל-precursors שלא נראים חשודים: לא מעונשים T1 על benign, ונספרים ל-T2/T3 כראיה. עקבי בין כל הסשנים.
   - solos חסומים (WAF block) נספרים כ-"benign/blocked, log only".
   - שער הבונוס מבוסס על לכידה ברמת incident, עם קנס על FP, כך שאי אפשר לעבור אותו בהסלמת-יתר.

### P1: לפני הרחבה מסחרית

7. **מודל זהויות ונכסים מרכזי (CMDB) לכל org:** ‏user ← host ← IP ← SID ← מחלקה ← שם מלא, עם domain SID יחיד ופורמט שם יחיד. אכיפה בכל ה-renderers, כולל העשרת Sentinel (שמות שגויים כרגע ב-S1 BONUS וב-S2 @13.9m).
8. **שקיפות בבחירות הסביבה.**
   - github, ‏cyberark, ‏k8s, ‏vmware ו-ndr לא מוסיפים כמעט כלום. צריך להוסיף להם תוכן ו-noise native, או לסמן אותם ב-UI כ"קוסמטי".
   - להציג למדריך את מספר ה-storylines לכל צירוף לפני תחילת התרגיל, כי GWS, ‏Proofpoint, ‏ASA ו-Okta מקטינים את הארסנל.
   - industry צריך לשלוט באוצר המילים של הרעש: ‏EMR/PACS/HL7 ב-healthcare, ובלי trading מחוץ ל-finance.
9. **native לכל משפחות המקור שעדיין legacy:** ‏Purview DLP, ‏WAFs, ‏DAM, ‏Sentinel alerts, ‏GitHub audit, ‏4663. להעלות את ה-native share של idp=entra (כרגע 75%).
10. **לבטל vendor sprawl:** ‏WAF אחד, ‏UEBA אחד ו-DAM אחד לכל org, בהתאם ל-stack שנבחר.
11. **לפצל את הפיד ל-Alert Queue ול-Telemetry search.**
    - T1 נותן disposition רק להתראות.
    - telemetry משמש ל-pivot של T2/T3.
    - להוסיף ל-T3 משטח hunt: ‏hosts נוספים עם אותו IOC, וראיה שלילית שמוכיחה containment.
12. **מנוע injects שמחובר לתקריות.**
    - הטקסט מתייחס ל-host/user אמיתי מהתקרית, וה-MSEL משתנה בין סשנים.
    - להוסיף inject של קונפליקט אישור (בעלים של שרת prod מסרב לבידוד), ‏shift handover, ותקשורת חיצונית.
    - ב-easy: לפחות inject אחד של Manager, ולמלא את "הזנב המת" של 12 הדקות.
13. **להסיר חזרתיות:** מספרי ticket, ‏IPs, דומיינים מתחזים וניסוחים אקראיים. ‏anti-repeat בין סשנים של אותה כיתה. להגדיל את ארסנל ה-hard (14 storylines בברירת המחדל).
14. **תזמון התראות ריאלי:** התראה מתואמת צריכה להגיע סמוך לאירוע המכריע (S2: ‏Sentinel מגיע 5.5 דקות אחרי ה-success). תאריך סשן שאינו חג, עם דפוס שעות עבודה.
15. **להוסיף שלושה storylines מודרניים בעדיפות עליונה:**
    - ניצול edge, למשל Check Point CVE-2026-50751 בקונפיגורציית IKEv1 legacy, או PAN-OS/Ivanti, שממשיך ל-AD.
    - ‏Akira-style: ‏VPN valid account ← Impacket ← מחיקת גיבויים ← ESXi.
    - Storm-1811: ‏email bomb ← Teams ← Quick Assist ← RMM.

### P2: ליטוש והעמקה

16. **שאר פערי הארסנל:** ‏device-code phishing, ‏Drift/UNC6395, ‏UNC6040 Salesforce vishing, ‏Handala Intune mass-wipe, ‏DPRK IT worker, ‏ADCS ESC1/ESC8, ‏BYOVD, ‏Codefinger S3 SSE-C, ו-MuddyWater RMM מול ארגונים ישראליים. במקביל, לצמצם את AI ל-6–8 storylines.
17. **שמות אמיתיים:** חתימות PAN וכותרות התראה של MDE (משפטים). ‏ServiceNow ‏`change_request` עם CHG, ו-resolved אחרי השינוי.
18. **MITRE ו-artifacts קטנים:**
    - T1005 על פתיחת Excel (S1 @11.0m) הוא מיפוי חלש.
    - MITRE על benign (S1 @10.1m ‏T1499).
    - 1.87GB ל-Mixpanel (S2 @14.8m).
    - ‏`ObjectId \MobileSync` ב-inbox rule (S1 @18.3m).
    - ‏ntdsutil שמורץ כ-"Domain Admins" (S1 @16.6m).
    - IMDSv2 ‏(S3 @28.5m).
19. **שורות המשך ל-solos כדי שיהיה מה לבנות ממנו scope:** ‏sign-in לפני inbox rule. אחרי MFA denied, הוכחה שהסיסמה דלפה. אחרי phish delivered, ‏click/no-click.

---

### מקורות שאומתו
- [Rapid7: CVE-2026-50751](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/) · [Check Point blog](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/) · [Qualys](https://threatprotect.qualys.com/2026/06/10/cve-2026-50751-defending-against-the-check-point-ikev1-vpn-authentication-bypass/)
- [Descope on DBIR 2026](https://www.descope.com/blog/post/verizon-dbir-2026) · [Push Security on DBIR 2026](https://pushsecurity.com/blog/verizon-dbir-2026-review)
- [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)
- [CrowdStrike 2026 GTR](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/)
- [Sophos Active Adversary 2026](https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report)
- [MDDR 2025 / ClickFix (Flare)](https://flare.io/learn/resources/blog/2025-microsoft-digital-defense-report/)
- [Trend Micro: Tycoon 2FA takedown](https://www.trendmicro.com/en_us/research/26/c/tycoon2fa-takedown.html)
- [Cybersecurity Dive: Stryker / Intune](https://www.cybersecuritydive.com/news/stryker-attack-device-management-microsoft-iran/814816/)
