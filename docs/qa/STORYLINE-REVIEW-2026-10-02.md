# בחינת כל תרחישי התקיפה (Storylines) — 2026-10-02

**היקף:** כל 87 התרחישים, כל אירוע, כולל הרשומה כפי שהפלטפורמה מרנדרת אותה בפורמט הנייטיב.
**מי בדק:** שישה בודקים במקביל, בפרספקטיבה של Tier-3 / IR lead. הקריטריונים: [RUBRIC.md](storyline-review/RUBRIC.md).
**דוחות מפורטים לכל תרחיש:** [storyline-review/batch-1..6.md](storyline-review/).
- batch-3 כולל טבלת ציונים מלאה, אבל פירוט רק ל-2 מתוך 18 התרחישים (הפלט נקטע).
- את asrep-roasting בדקתי בעצמי.

**ארבעה קריטריונים:**
1. אירוע סייבר מוכר שאנליסטים פוגשים ב-SOC אמיתי.
2. בלי קריפטו.
3. אפשר לזהות ולתחקר אותו מקצה לקצה מתוך הלוגים בלבד.
4. כל לוג הוא ראיה אמינה לתקיפה.

---

## בשורה התחתונה

| החלטה | מספר | מה זה אומר |
|---|---|---|
| **KEEP** | 6 | תקין, לכל היותר תיקון קטן |
| **FIX** | 70 | הקונספט נכון ומוכר, הביצוע דורש תיקונים |
| **REPLACE** | 5 | הקונספט סביר, הביצוע חלש מדי וצריך לכתוב מחדש |
| **REMOVE** | 6 | כולם בגלל קריפטו |

**ממוצע ציונים (1–5):** אירוע מוכר **4.2** · יש התראה ראשונה **3.7** · תחקור מקצה לקצה **3.1** · אמינות הלוגים **2.7**.

**הקונספטים חזקים, הביצוע חלש.**
- בקריטריון "אירוע מוכר" ציון הממוצע גבוה: רוב התרחישים קיבלו 4–5, ומעוגנים ב-ATT&CK ובקמפיינים אמיתיים. ביניהם SocGholish, ‏ClickFix, ‏Scattered Spider, ‏Storm-2139, ‏EchoLeak, ‏Capital One SSRF ו-LockBit.
- החולשה נמצאת בשני קריטריונים:
  - **תחקור מקצה לקצה:** שרשראות שבהן חסרה החוליה שמחברת בין שלבים.
  - **אמינות הלוגים:** ראיות שקיימות רק בתיאור, ורשומות נייטיב שסותרות זו את זו.

### המובילים, לשמור כדוגמה
`bec` · `oauth` · `ransomware` (LockBit) · `dcsync` · `ai-agentic-intrusion-tempo` · `ai-llmjacking-bedrock`
קרובים מאוד לרמה הזו: `fake-browser-update` · `clickfix-fake-captcha` · `impossible-travel-basic` · `aitm-token-theft` · `ai-svg-invoice-lure` · `ai-aoai-key-capacity-abuse`

---

## 1. קריפטו: 6 להסרה

| תרחיש | מה הוא | ממה אפשר להציל |
|---|---|---|
| `bundled-cryptominer` | כורה בתוך ממיר וידאו | אין צורך, יש תרחישי Trojanized installer אחרים |
| `drive-by-browser-miner` | כרייה בדפדפן | — |
| `clipboard-clipper` | החלפת כתובת ארנק | — |
| `cryptomining` | מפתח AWS שדלף ושימש לכרייה ב-GPU | **החצי הלא-קריפטו טוב:** מפתח שדלף ב-GitHub ← IAM backdoor ← bucket ציבורי ← הוצאת נתונים מ-S3. כדאי לשכתב כ"דליפת מפתח → גניבת נתונים" |
| `linux-cryptominer` | SSH חשוף ← cron ← XMRig | השלד (Brute Force ל-SSH ← root ← cron) טוב. להחליף את המטען בבוטנט או דלת אחורית, או לוותר כי `globallogis-chain-d` מכסה את זה |
| `rocketstack-chain-c` | בריחה מקונטיינר ← XMRig | הנחת היסוד חלשה ממילא (משתמש מריץ קונטיינר privileged על הלפטופ שלו) |

**מקרים גבוליים שנבדקו ואינם קריפטו:**
- Bitcoin בדרישת הכופר של תרחישי הכופרה הוא חלק טבעי מהאירוע.
- ההתראה "wallet attack" ב-`ai-aoai-key-capacity-abuse` עוסקת במיצוי עלויות ולא במטבע.

**קריפטו קיים גם מחוץ לתרחישי התקיפה:**
- בעמוד ה-Scenarios: אותן חבילות תוכן, וגם `linuxPrivescSuid`.
- בשלושה כללי זיהוי של AWS בכרטיסי הנייטיב: `aws_cloudtrail.cryptomining_gpu`, ‏`aws_guardduty.cryptomining`, ‏`aws_vpcflow.cryptomining_pool`.
- בכמה שיעורים וחדרים: `pathLessons-c/e/h`, ‏`newTopicLessons`, ‏`rooms-batch-14/22/32/46/49`.
- בלוגי הרקע של החברות **אין** תוכן קריפטו.

## 2. לכתוב מחדש (REPLACE): 5

| תרחיש | הבעיה |
|---|---|
| `edge-vpn-cve-exploit` | ה-"WAF" של FortiGate מתעד בקשות לממשק הניהול שלו עצמו, מנגנון ה-web shell מומצא, אין חיבור מה-VPN לשרת הקפיצה, והתראת Sentinel מצטלבת על IP שלא מופיע בנתונים |
| `nexacorp-chain-d` | Spray על DC ב-SMB ישירות מהאינטרנט אינו מציאותי, שום ניסיון לא מצליח, ונעילות החשבון סותרות את הגדרת ה-Spray |
| `quantumbank-chain-a` | ה-MFA fatigue (בענן) וה-beacon שיוצא מ-Outlook (בתחנה) לא קשורים סיבתית. אותו IP ממוקם במולדובה ובציריך |
| `quantumbank-chain-c` | הכותרת "מסחר פרוע", אבל הלוגים מראים חטיפת session חיצונית. Zscaler מתעד IP של תוקף חיצוני, וגדלי הבתים בלתי אפשריים |
| `ai-claude-shared-secret` | אין התראה, אין הוכחה שהארטיפקט מכיל סודות, ואין תיעוד של מי ראה אותו או של שימוש בסודות |

**לאחד:** `ai-bedrock-key-abuse` ו-`ai-llmjacking-bedrock` הם אותו אירוע. להשאיר את השני, שהוא הטוב מביניהם, או לבדל ביניהם.
**הנחת יסוד מיושנת:** `iso-container-smuggling`. מאז נובמבר 2022, Mark-of-the-Web כן עובר לקבצים בתוך ISO, ולכן הדרך לעקוף אותו השתנתה.

---

## 3. ממצאים רוחביים לפי השפעה

> **תיקון כיול:** כמה בודקים דיווחו ש"התווית אומרת CrowdStrike והרשומה היא Defender". **זה תוצר של הייצוא, לא באג.** הייצוא רינדר את האירועים בלי שלב ההתאמה למוצרי הארגון. בהרצה אמיתית בדקתי את `ntlm-relay` ואת `ransomware`: התווית, התיאור והרשומה מצביעים כולם על אותו מוצר (Defender / Palo Alto). הממצא הזה הוצא מהרשימה.

### A. ראיות שקיימות רק בתיאור (השכיח והחמור ביותר)
- **מה זה:** עובדות מכריעות שמופיעות בשורת התיאור ולא בשדה של הרשומה. דוגמאות:
  - "94 קבצים", "78 כישלונות", "1.2M שורות"
  - גיל הדומיין, "Tor exit node", "elevated to High integrity"
  - נושא המייל, ספירת בתים על אירוע תחנה שבכלל לא נושא שדה בתים
- **למה זה חמור:** אנליסט אמיתי מבסס החלטה על שדות. כאן אפשר "לפתור" מקריאת התיאור בלבד.
- **כלל לתיקון:** כל טענה בתיאור חייבת להופיע בשדה של הרשומה. ספירות מגיעות מרשומת אגרגציה או מכמה אירועים.

### B. חוליה חסרה: Initial Access ו-Root cause
- **מה זה:** רוב התרחישים מתחילים באמצע, כך שהתחקור לא נסגר. דוגמאות:
  - **המייל או ההורדה שהביאו את הקובץ:** אין hash לקובץ המצורף, ואין שורת יצירת קובץ (phishing-malware, malicious-macro, iso).
  - **איך נגנבו פרטי ההזדהות:** k8s-pod-escape, kerberoasting, rogue-admin, compliance-key, gemini.
  - **ההתחברות שיצרה את ה-session שנגנב:** impossible-travel-basic, aitm.
  - **חיבורים שלא קיימים במציאות:** ‏Okta session לא מניב מפתחות AKIA של משתמש IAM (rocketstack-a/d), ותחנה שנפרצה בפישינג מגיעה לכופרה בשרת בלי תנועה רוחבית (medcore-a).
- **כלל לתיקון:** בכל תרחיש חייבת להיות שורה שמראה את נקודת הכניסה, ושרשרת של מזהים שאפשר לעקוב אחריהם (host ↔ IP ↔ user ↔ hash ↔ domain ↔ key) עד ההשפעה.

### C. מחולל רשומות הנייטיב: ליקויים שחוזרים בכל התרחישים
תיקון אחד בקוד המחולל יפתור עשרות תרחישים.
1. **Windows Security בלי כרטיס נייטיב:** כ-61 אירועים (4624, ‏4625, ‏4768, ‏4769, ‏4720, ‏4728…) מוצגים בתצוגה הישנה. אומת בהרצה: `ad` → legacy. זו המשפחה הכי חשובה לתחקור AD.
2. **מזהים שנוצרים מחדש ולא נלקחים מהאירוע:**
   - **מזהי משתמשים:** Entra user ID, ‏tenant ID, ‏subscription ID ו-session ID משתנים בין שורות של אותו סיפור.
   - **PID, ‏SID ו-LogonId:** משתנים בין שורות.
   - **hash:** של תהליך כשהוא מופיע בעצמו מול כשהוא מופיע כתהליך אב (דיווח של שלושה בודקים, עוד לא אומת בהרצה).
3. **שדות מכריעים שנשמטים מהכרטיס:**
   - שיטת ה-MFA החדשה ב-"registered security info".
   - ה-work notes של ServiceNow.
   - URL ו-user בשורות חומת האש (נהפכות לשורות traffic רגילות).
   - initiating-process באירועי file ו-registry.
4. **מיקום גאוגרפי של Okta לא עקבי** (אומת): אותו IP ‏89.248.171.44 מוצג פעם בשנג'ן, סין ופעם בלונדון, BT. ה-behaviors תמיד NEGATIVE.
5. **AWS:**
   - ברירות מחדל גנריות: `user/unknown`, ‏session issuer "service-role", ‏responseElements ריק, כך שאי אפשר לעקוב אחרי מפתח שנוצר ב-CreateAccessKey או ב-AssumeRole.
   - ממצאי GuardDuty עם משאב קבוע (svc-account / ListBuckets).
   - "GovCloud" שמוצג עם partition מסחרי.
   - (דיווח של בודק אחד, אומת חלקית.)
6. **מקורות שלמים בלי כרטיס:** Purview DLP, ‏Workday, ‏Claude Enterprise, ‏Copilot, ‏Azure OpenAI, ‏AWS WAF, ‏GitHub, ‏CyberArk ו-Zeek.

### D. אין התראה ראשונה אמיתית
- **בלי התראה בכלל:** impossible-travel (סיכון Entra = none), ‏chat-harvest-extension, ‏claude-shared-secret, ‏copilot-indirect-injection, ‏gemini-drive-sweep ו-aitm. המתאמנים מונחים רק לפי חומרה שאנחנו קבענו.
- **התראה שמגיעה רק בסוף**, אחרי הנזק ("malware prevented" אחרי שההוצאה כבר הושלמה): רוב תרחישי הבסיס.
- **התראה לפני האירוע שהיא מצטטת:**
  - kerberoasting: התראת MDI לפני השאילתה.
  - copilot-oversharing: התראת UEBA בשעה 13:36 על הורדה מ-13:41.
  - rs-cicd: ‏GuardDuty לפני השימוש הראשון.
  - helpdesk-voice: ה-ticket נסגר לפני האיפוס.

### E. תיאורים ושורות SIEM שמסגירים את המסקנה
- שורות SIEM / Sentinel שכתוב בהן את הלקח ("זו תקיפת X").
- בכמה מקומות עדיין מופיעים "malicious", ‏"C2" ו-"attacker".
- **כלל לתיקון:** התראה מציגה ישויות וסימנים, לא verdict.

### F. מוצרים שלא היו יכולים לראות את האירוע
- Zscaler ZIA מתעד תוקף חיצוני ותעבורת core-banking / SWIFT.
- חומת אש on-prem מתעדת תעבורת SaaS או S3 שלא עוברת דרכה.
- CloudTrail של חשבון חיצוני גלוי לחברה.
- כתובות IP פרטיות כמקור באירועי ענן (nexacorp-c1, ‏rocketstack-c3).
- שמות איום מומצאים ב-Palo Alto ("Generic-Wire-Fraud-C2").
- **QuantumBank:** תרחישי ההונאה צריכים מקור נייטיב של מערכת תשלומים / core-banking (מי יזם, סכום, מוטב) במקום Zscaler.

### G. סתירות זמן ולוגיקה
- **שעון ותהליך:**
  - קובץ HR שהועתק ל-USB לפני שנפתח (insider).
  - session של חומת אש שמתחיל לפני שאילתת ה-DNS.
  - התחברות של "למחרת" עם אותו LogonId.
- **הרשאות:**
  - Scheduled Task שרץ כ-SYSTEM נוצר מתהליך לא מורם (cracked-software).
  - כתיבה ל-Program Files ב-Medium integrity (trojanized-keylogger).
- **כמויות:**
  - העלאה בודדת של 11GB ל-S3 (globallogis-c).
  - `vim-cmd` על מארח אחד שעוצר 96 מכונות וירטואליות של cluster שלם (esxi).
- **מנגנון:**
  - מייל עם verdict של Malware שנמסר בכל זאת (MDO לא עושה את זה).
  - Mimikatz בהסגר, ובכל זאת פרטי ההזדהות שלו משמשים (globallogis-b).

### H. תשתית תוקף ותבניות שחוזרות
- 185.220.101.x מופיע כתוקף בחמישה תרחישים או יותר. אותם 45.148.10.x, אותו rule ואותו serial, ואותו נתיב C2.
- חמישה תרחישי בסיס כמעט זהים: "משתמש מריץ קובץ ← דומיין חדש ← האנטי-וירוס עוצר".
- שלושה תרחישי QuantumBank מסתיימים באותה דרך: wevtutil על SRV-QB-ADMIN01.
- **התוצאה:** המתאמנים יכולים לזהות לפי תבנית במקום לנתח.

---

## 4. תוכנית תיקון מומלצת לפי סדר

1. **הסרת קריפטו** (6 תרחישים) והחלטה לגבי הקריפטו בעמוד ה-Scenarios, בכללי הזיהוי ובשיעורים. שכתוב `cryptomining` ל"דליפת מפתח AWS → גניבת נתונים מ-S3".
2. **תיקון המחולל** (סעיף C), עם הכי הרבה השפעה:
   - כרטיס נייטיב ל-Windows Security.
   - מזהים שנלקחים מהאירוע במקום להיווצר מחדש.
   - שדות מכריעים על הכרטיס.
   - מיקום גאוגרפי עקבי ב-Okta.
   - זהויות ו-responseElements של AWS.
3. **הרחבת שער השלמות ל"תחקור מקצה לקצה"**, כבדיקות אוטומטיות:
   - כל טענה בתיאור מופיעה ברשומה.
   - הסיבה קודמת לתוצאה.
   - hash עקבי לאורך השרשרת.
   - דומיין בפקודה מפוענחת = דומיין ב-DNS ובחומת האש.
   - יש שורת התראה ראשונה.
   - אין IP של תוקף שחוזר בין סיפורים.
4. **REPLACE** לחמשת החלשים, ואיחוד תרחישי ה-Bedrock.
5. **FIX לפי סדר עדיפות:** קודם התרחישים שמגיעים הכי הרבה למתאמנים (Easy/Medium בסביבת ברירת המחדל), ובכל תרחיש לפי רשימת התיקונים בדוח המפורט שלו.

---

## 5. טבלה מלאה (87)
ציונים 1–5: recognised = אירוע מוכר · detect = יש התראה ראשונה · e2e = תחקור מקצה לקצה · logs = אמינות הלוגים.

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| phishing-malware | FIX | 5 | no | 4 | 3 | 4 | Sound commodity chain. Nothing in the logs ties the email attachment to the exe (no file-create / attachment hash), and a description leaks "C2". |
| usb-malware | FIX | 3 | no | 4 | 3 | 3 | The USB origin appears only in raw and prose. The native MDE card has no removable-media field or device event. No C2 or impact. |
| browser-extension | FIX | 3 | no | 4 | 3 | 4 | The chain is coherent and the decoded cradle matches the PAN domain. Nothing shows how the unpacked extension or its NativeMessagingHosts registration arrived. |
| tech-support-scam | FIX | 4 | no | 3 | 2 | 3 | No lure, no remote-peer ID and no post-session actions. SHA1 mismatch on the network row. The key facts ("caller's instruction", "caller now has control") exist only in prose. |
| cracked-software | FIX | 4 | no | 4 | 2 | 2 | Impossible: a `/ru SYSTEM` task is created from a Limited token. The svchelper.exe drop is missing. The download filename appears only in prose. |
| malicious-macro | FIX | 4 | no | 4 | 2 | 2 | The decoded payload is `http://…/inv.exe` but PAN logs ssl/443. MDO shows a Malware verdict yet Delivered. The inv.exe outcome is never shown. |
| insider | FIX | 5 | no | 4 | 3 | 2 | Strong concept (departing-employee theft), but 11/15 rows have null native. Counts live only in prose. The HR file is copied before it is accessed. |
| impossible-travel | FIX | 5 | no | 2 | 3 | 4 | Good native records but no alert row at all (Entra risk = none). No credential-origin event and no VPN-tunnel activity. |
| phishing | FIX (major) | 4 | no | 4 | 2 | 2 | Too many techniques at once. The decoded C2 domain ≠ the DNS/FW domain. Sysmon/MDE/AD IDs contradict each other (PID, SID, LogonId, hash, sAMAccountName). The credential dump leads nowhere. |
| bec | KEEP | 5 | no | 5 | 4 | 4 | Classic password-spray→BEC; solid evidence; minor ADFS-vs-DC 4625 realism nit |
| ransomware | KEEP (fix) | 5 | no | 5 | 5 | 3 | Textbook LockBit chain; CrowdStrike events render as MDE native |
| oauth | KEEP | 5 | no | 5 | 5 | 4 | Illicit-consent cloud APT, great "reset doesn't revoke token" lesson; minor vendor-label errors |
| cryptomining | REMOVE | 4 | **YES** | 5 | 5 | 4 | Cryptojacking (XMRig/Monero) is the central incident — prohibited |
| dcsync | KEEP (fix) | 5 | no | 5 | 5 | 4 | DCSync→forged-ticket domain dominance; only defect is CrowdStrike→MDE native on NTDS event |
| supply-chain | FIX | 5 | no | 4 | 4 | 3 | Solid vendor-update compromise; AWS region + account-id contradictions break the native pivot |
| mfa-fatigue | FIX | 5 | no | 5 | 5 | 2 | Excellent MFA-fatigue narrative, but every Okta event renders as Microsoft Entra native |
| ntlm-relay | FIX | 5 | no | 4 | 5 | 2 | Great relay fingerprint, but FortiGate renders as Palo Alto and CrowdStrike as MDE; lsass evidence lost in native |
| k8s-pod-escape | FIX | 5 | no | 3 | 3 | 2 | The SCARLETEEL-style chain is sound, but the identity and account IDs contradict each other. No GuardDuty or Falcon detection is present, there is no initial token theft, and nothing links the pod to the node. |
| oauth-consent | FIX | 5 | no | 3 | 3 | 2 | A textbook illicit consent grant, but it confuses delegated identity with app identity, uses invented Graph "operations" and a Microsoft-owned IP as the attacker, has 4 null natives and no lure email. |
| kerberoasting | FIX | 5 | no | 4 | 3 | 2 | The 4769/RC4 core is right, but all 11 native records are null, 4662 is misused as an LDAP log, the MDI alert fires before its query, there is no endpoint evidence and the payload is a dead end. |
| dns-tunneling | FIX | 4 | no | 4 | 3 | 3 | The Sysmon 22 core is good. The PAN log contradicts the resolver path, the update.exe hash and PID differ between records, update.exe is never executed, the root cause is missing and "dnscat2" appears only in prose. |
| lolbins | FIX | 4 | no | 4 | 3 | 3 | A kitchen-sink of 6 LOLBins and 5 payloads, mostly never executed. srvhost.dll has no origin, and a systemic initiating-process hash mismatch breaks pivots. |
| bruteforce-single | FIX | 5 | no | 4 | 4 | 3 | A solid exposed-RDP brute-force chain. The firewall zones and rule contradict each other, 8 of 10 natives are null, and the CrowdStrike row renders as MDE with a different SID and LogonId. |
| okta-password-burst | FIX | 5 | no | 4 | 4 | 3 | Good teaching ("password guessed, MFA held"). But behaviors show NEGATIVE for a first-seen Iceland IP, and two descriptions don't match the native eventType. |
| gws-phish-attachment | FIX | 4 | no | 5 | 4 | 3 | An AMOS-style HTML-smuggled DMG. osascript is killed at :24, yet a POST that needs a typed password goes out at :25. The two detections conflict and the HTML-open step is missing. |
| fake-browser-update | FIX | 5 | no | 5 | 4 | 4 | A faithful SocGholish chain. Minor issues: CrowdStrike rows render as MDE, FileOriginUrl is null and the initiating-process hash doesn't match. |
| trojanized-keylogger | FIX | 4 | no | 4 | 3 | 2 | The description says "elevated", but the records show Medium integrity and no admin rights while Program Files is written. Installer→file and process→POST attribution is missing from the native records, and the keylogger alert appears twice. |
| bundled-cryptominer | REMOVE | 4 | yes | 4 | 4 | 3 | Crypto-themed: the incident is a coinminer (T1496, stratum pool, wallet in the command line). |
| seo-poisoned-installer | FIX | 5 | no | 4 | 4 | 3 | A Nitrogen/Rhadamanthys-style malvertising case. The referer is not an ad click, explorer runs at High integrity, and the "prevented" alert contradicts exfiltration that already completed. |
| iso-container-smuggling | FIX | 4 | no | 4 | 3 | 2 | The core premise ("MOTW doesn't propagate into an ISO") has been outdated since the Nov-2022 patch. FortiGate and CrowdStrike rows render as PAN and MDE, the delivery vector is missing and update.dat is unused. |
| drive-by-browser-miner | REMOVE | 3 | yes | 3 | 3 | 2 | Crypto-themed: in-browser cryptojacking. |
| clickfix-fake-captcha | FIX | 5 | no | 5 | 4 | 3 | Strong and current. Bugs: a process is its own parent in evt_cfc_05, the RunMRU event and the sysupd32 download are missing, and some attribution exists only in prose. |
| clipboard-clipper | REMOVE | 3 | yes | 4 | 3 | 3 | Crypto-themed: a crypto-wallet clipper delivered through "CryptoTrackerLite". |
| scheduled-task-persistence | FIX | 3 | no | 3 | 4 | 4 | A clean Sysmon GUID chain. The next-day "logon" reuses the same LogonId and LogonGuid, there is no 4698 or TaskScheduler 106 event, and the payload's origin is missing. |
| impossible-travel-basic | FIX | 5 | no | 5 | 4 | 3 | An excellent AiTM→BEC story. It lacks the proxy sign-in that created the stolen session, uses the wrong token type (PRT), the VPN vendor doesn't match its native card, and the Zscaler and VPN IPs disagree. |
| rogue-admin | FIX | 4 | no | 4 | 3 | 3 | A textbook "new account → Domain Admins" chain, but nothing explains how the Service Desk credential was misused from WS-ENG-2208, and the Sentinel alert hands the trainee the conclusion |
| esxi-ransomware | FIX | 5 | no | 3 | 4 | 3 | A strong Akira-style VPN → vCenter → ESXi chain. The scan, spray and rename evidence lives only in prose; vim-cmd on one host cannot stop 96 cluster VMs; the encryptor's transfer has no log |
| webshell-rce | FIX | 5 | no | 4 | 4 | 3 | Solid SQLi → web shell → PrintSpoofer chain. The native CrowdStrike cards carry inconsistent IPs, SIDs and PIDs; ib.dat has no origin; the exfil byte count is not in any record |
| linux-cryptominer | REMOVE | 4 | **yes** | 4 | 4 | 3 | XMRig / Monero is the incident. Keep the SSH brute-force → cron skeleton and give it a non-crypto payload |
| aitm-token-theft | FIX | 5 | no | 3 | 4 | 3 | An excellent AiTM design (the sign-in IP equals the phishing domain's A record; the SessionId is shared). There is no alert row, native IDs / UA / AADSessionId break pivots, and the native cards drop key evidence |
| infostealer-session-theft | FIX | 5 | no | 4 | 4 | 2 | A good stealer → cookie-replay chain. Native hash and path of the stealer contradict the download; the token type (PRT) is wrong; the replay gets a new SessionId; descriptions leak conclusions |
| helpdesk-mfa-reset | FIX | 5 | no | 3 | 3 | 3 | Scattered Spider pattern. The MFA registration has no preceding sign-in; a Tor IP shows no risk; the VDI session is not linked; the story ends before any impact |
| edge-vpn-cve-exploit | REPLACE | 5 | no | 3 | 2 | 2 | A FortiGate "WAF" logs its own admin API; the web-shell mechanism is invented; native cards drop URL and user; no VPN → jump-host link; Sentinel joins on an IP that is not in the data |
| exfil-first-extortion | FIX | 5 | no | 4 | 2 | 3 | rclone → MEGA data-theft extortion is very recognisable. There is no initial access and no tool drop; the extortion email exists only in prose; the SIEM rows state the lesson |
| nexacorp-chain-a | FIX | 3 | no | 3 | 2 | 2 | A credential phish with UrlCount 0 and no click. Key Vault secrets/list is logged in the wrong log with the wrong resource provider, and "list" is not "exfil" |
| nexacorp-chain-b | FIX | 5 | no | 3 | 2 | 3 | CEO BEC is very recognisable. No initial access; the token IssuedAtTime predates the sign-in; the 23 files and the recipient appear only in raw |
| nexacorp-chain-c | FIX | 4 | no | 3 | 3 | 2 | Insider theft. SharePoint ClientIP is RFC1918; the MDE native cards drop the user; bytes, DLP and recipient are missing from the native cards |
| nexacorp-chain-d | REPLACE | 3 | no | 4 | 1 | 2 | Internet → DC SMB spraying is not realistic, the story has no outcome, there are 3 thin legacy rows, and the lockouts contradict "spray" |
| rocketstack-chain-a | FIX | 4 | no | 3 | 2 | 2 | The Okta → AWS link is impossible (an Okta session does not yield IAM-user AKIA keys). Native Okta geo and behaviors contradict Tor / impossible travel. PutEventSelectors schema is wrong |
| rocketstack-chain-b | FIX | 5 | no | 4 | 3 | 3 | npm dependency confusion → reverse shell → AWS key abuse. The key-theft and CreateUser events are missing, and the reverse-shell command line is not on any native card |
| rocketstack-chain-c | REMOVE | 2 | **yes** | 3 | 2 | 2 | xmrig is in the title and is a central event. A user running a privileged container on his own laptop is not an attack path. CloudTrail shows a private source IP |
| rocketstack-chain-d | FIX | 4 | no | 4 | 2 | 2 | Okta credential stuffing → AWS. The same IP is geolocated to China and to Tel Aviv; an Okta login yields no IAM keys; "read from bucket" has no GetObject |
| medcore-chain-a | FIX | 4 | no | 4 | 2 | 3 | Phish → macro → ransomware. No WINWORD parent; the PowerShell payload domain differs from the DNS query; no lateral path to the EMR server; the docm hash equals the powershell.exe hash |
| medcore-chain-b | FIX | 4 | no | 2 | 2 | 2 | Insider-theft concept is fine, but 2/4 natives are null and the core evidence (94 files, USB, 3,800 records, no SNI) exists only in prose. No DLP/USB alert. |
| medcore-chain-c | FIX | 4 | no | 3 | 2 | 2 | The VPN fail→success opener is good. Nothing ties the VPN session to 192.168.10.67, there's no logon to PACS, and the "exfil" in the title has no egress event. |
| medcore-chain-d | FIX | 5 | no | 4 | 2 | 2 | Recognised ASA brute-force pattern. But the RDP record shows the public attacker IP inside the LAN, lockouts exist only in prose, and the chain stops at RDP. |
| globallogis-chain-a | FIX | 4 | no | 3 | 2 | 2 | Good macro-phish opener. The xlsm hash equals the powershell hash, Excel is missing from the lineage, the PtH claim has no evidence and the WMS IP is never tied to the host. |
| globallogis-chain-b | FIX | 4 | no | 4 | 2 | 3 | The Mimikatz alert is a real opener, but the tool was quarantined and its creds are still used. No initial access, a session/logon-type mismatch, and no process→upload link. |
| globallogis-chain-c | FIX | 4 | no | 3 | 2 | 1 | Sysmon card is empty. An 11 GB single PutObject is impossible and the external-account CloudTrail would not be visible to the org. Logon type 2 is paired with a remote IP. |
| globallogis-chain-d | FIX | 5 | no | 3 | 3 | 3 | Clean IP pivot (brute force→root→dropper). No host-side failures and no IPS alert. Stops at the download, which is thin for "advanced". |
| quantumbank-chain-a | REPLACE | 3 | no | 3 | 1 | 2 | The MFA fatigue (cloud) and the Outlook-spawned beacon (endpoint) are causally unlinked. The same IP is geolocated to Moldova, then Zurich. The "existing session" has a different session id. |
| quantumbank-chain-b | FIX | 3 | no | 3 | 2 | 2 | The PAM checkout is never used. ModifyDBInstance cannot disable RDS encryption, and eventSource=ec2 is wrong. No logon to ADMIN01. |
| quantumbank-chain-c | REPLACE | 2 | no | 2 | 1 | 1 | Titled "rogue trading" but the story is an external hijack, and no log shows the shared session. ZIA logs the attacker's internet IP, byte sizes are impossible, and an AWS key appears from nowhere. |
| quantumbank-chain-d | FIX | 4 | no | 4 | 3 | 2 | Spray→ATO→wire is recognised. Geo contradictions in the Okta records. ZIA cannot log an external attacker. No SSO, MFA or payment-system evidence. |
| rocketstack-cred-stuffing | FIX | 5 | no | 4 | 3 | 3 | Strong Okta stuffing→MFA-enrol chain. The ThreatInsight block contradicts later successes from the same IP. AWS is reached as an IAMUser with an AKIA key with no explanation. The FortiGate record "sees" SaaS traffic. GitHub native is null. |
| qb-swift-wire-fraud | FIX | 4 | no | 3 | 2 | 2 | Recognised concept. WINWORD opens an .xlsm, a self-describing stealer cmdline, a Tor IP geolocated to Zurich, no path to ADMIN01, GovCloud contradictions, 11 techniques. |
| qb-fraud-monitoring-tampering | FIX | 3 | no | 3 | 2 | 2 | Insider disables fraud alarms. CloudTrail account/region/session contradictions, no AssumeRole tying CyberArk to AWS, duplicate PIDs, 3 null natives. |
| qb-cyberark-mule-payout | FIX | 3 | no | 3 | 2 | 2 | Beneficiary injection plus structuring. Account takeover vs insider is ambiguous. The Data API record logs SQL text as a management event. A single batch POST contradicts "over 40 min". Invented PAN threat. |
| rs-cicd-pipeline-poisoning | FIX | 5 | no | 4 | 3 | 2 | Strong poisoned-pipeline/IMDS story. GuardDuty fires before first use with the wrong principal. CreateAccessKey actor is "unknown" and the new key id is missing. The workflow "completes" before its steps. |
| rs-terraform-iac-backdoor | FIX | 4 | no | 3 | 2 | 2 | Recognised trust-policy backdoor. The GuardDuty finding type is wrong. Post-AssumeRole identities sit in the attacker's account. The FortiGate egress record makes no sense. |
| rs-oauth-consent-chaining | FIX | 4 | no | 3 | 2 | 2 | Recognised consent phishing. client_id differs between events, the credential evidence is prose-only, there's a gap from Okta API token to SAML, and the AssumeRoleWithSAML identity is wrong. |
| ai-shadow-chat-upload | FIX | 4 | no | 4 | 3 | 3 | Real DLP-block opener, but the xlsx-to-CSV bypass works the wrong way round. The Sanctioned/Unsanctioned flag and the prompt text appear only in raw, not in the native card. |
| ai-chat-harvest-extension | FIX | 4 | no | 2 | 4 | 3 | The extension ID and the byte sizes give clean pivots, but nothing fires an alert. The DNS row is labelled Infoblox while its native record is Windows DNS on DC01. |
| ai-svg-invoice-lure | FIX | 5 | no | 4 | 4 | 3 | Strong VEC-plus-SVG chain. The native email card lacks the attachment hash and the originating IP. IsFirstContact contradicts itself. The second recipient's scope is never followed up. |
| ai-helpdesk-voice-reset | FIX | 5 | no | 4 | 4 | 3 | Scattered Spider help-desk pattern. The ticket is resolved before the reset happens. The key work-notes are empty in the native record. Raw and native IDs disagree. |
| ai-claude-enterprise-departure | FIX | 3 | no | 3 | 3 | 3 | The data never leaves the corporate tenant. The device story contradicts itself (unmanaged Edge vs Endpoint DLP on corporate WS-SALES-1876 with Chrome). All AI, HR and DLP rows have null native. |
| ai-copilot-oversharing-probe | FIX | 3 | no | 4 | 3 | 3 | The UEBA alert at 13:36 cites a download that happens at 13:41. No evidence shows why a Marketing user can read HR, IT and Finance files. Copilot rows have null native. |
| ai-claude-shared-secret | REPLACE | 3 | no | 2 | 2 | 3 | No alert, no proof the artifact holds secrets, no record of the sharing scope or of anyone viewing it, and no use of the secrets afterwards. |
| ai-claude-compliance-key-harvest | FIX | 4 | no | 4 | 3 | 2 | The IP allow-list should have blocked the attacker's admin actions it later deletes. Okta native records contradict the anomaly. The new key ID is missing from api_key_created. |
| ai-aoai-support-bot-jailbreak | FIX | 3 | no | 5 | 3 | 3 | An external caller IP in the AOAI logs means someone is calling the endpoint directly, i.e. key exposure, and the story ignores it. The recon alert covers a window with no logs. |
| ai-aoai-key-capacity-abuse | FIX | 5 | no* | 5 | 4 | 3 | Storm-2139 Azure OpenAI key abuse, well built. The volume alert starts before gpt-4o-2 existed. Subscription IDs disagree inside the native records. |
| ai-gemini-drive-sweep | FIX | 4 | no | 3 | 3 | 3 | Okta native records contradict the story (Tel Aviv geo, all behaviours NEGATIVE). No alert. Gemini rows carry no doc IDs, so the "sweep" cannot be pivoted to files. |
| ai-bedrock-key-abuse | FIX (merge) | 5 | no | 5 | 4 | 4 | Accurate Sysdig LLMjacking sequence. Entitlement and logging changes happen in us-east-1 but the abuse runs in eu-central-1. Near-duplicate of ai-llmjacking-bedrock. |
| ai-agentic-intrusion-tempo | KEEP | 5 | no | 5 | 4 | 4 | Capital One-style SSRF → IMDSv1 → off-instance credentials chain. The access key links every step. Only minor realism nits. |
| ai-copilot-indirect-injection | FIX | 4 | no | 2 | 4 | 3 | EchoLeak (CVE-2025-32711) modelled correctly. Nothing triggers the response. The injected text, which is the root cause, exists only in prose. |
| ai-llmjacking-bedrock | KEEP | 5 | no | 5 | 4 | 4 | Best in the batch: FP control with a change ticket, invocation-log content, GuardDuty and Cost Anomaly evidence. Small native mismatches. Overlaps ai-bedrock-key-abuse. |
| asrep-roasting | FIX | 5 | no | 4 | 4 | 2 | Correct 4768 PreAuthType=0/RC4 core, but every Windows Security row renders in the legacy view, 'LDAP query' is logged as if a DC records it (it doesn't by default), and the description gives the conclusion away ('no credentials were required') |