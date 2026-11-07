# תסריט חדר 59: IOC Analysis & Threat Pivoting

**שם המבצע:** Operation Breadcrumb
**רמה:** בינוני
**העולם:** Kestrel Vale Insurance (חברת ביטוח בדויה): כותבת ביטוח סייבר ל-3,100 עסקים קטנים, ומרשם הפוליסות שלה מראה בדיוק כמה כל לקוח יכול לתבוע.
**המנטור:** Bao Lindgren, Threat Intel Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
מרשם הפוליסות הוא מחירון מוכן לצוות כופר: הוא מראה כמה כל קורבן יכול לשלם. ביום שלישי ב-08:14 ה-EDR הכניס להסגר קובץ אחד בלפטופ של מחלקת התביעות, ו-hash אחד הוא כל מה שיש ל-Bao ביד. מה-hash הזה נחשף צוות שלם, שרתים שכורים, דומיינים אחים וארבעה מחשבים בשלוש מחלקות.

## המכניקה הייחודית של החדר
- **The Pivot Board:** מעבדת `trace` שמתחילה ב-hash אחד ועוברת דרך מקורות העשרה: דוח sandbox, passive DNS, WHOIS, passive DNS הפוך, אינדקס סריקה בסגנון Shodan, מוניטין IP ו-Communicating Files. כל שלב הוא טבלת מקור ריאליסטית, וכל שורה נכונה מוסיפה עובדה ללוח החקירה.
- **מה זה עולה לתוקף:** ה-worksheet מציג את פנקס ההוצאות של הצוות עצמו, וה-spotdiff משווה שני בילדים, וכך רואים במספרים ובשורות מה משתנה בזול ומה לא. זה הלקח של ה-Pyramid of Pain.
- **Find Every Host That Touched the Crew:** מעבדת `hunt` ב-KQL על טבלאות משלה, שעונה על שאלה אחת: אילו מחשבים נגעו בצוות. שורה שגויה מראה מה היא באמת מחזירה.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) בשם Pivot Hall, עם גלובוס במרכז. קלף לכל תחנה.

## סדר המשימות
r1, q1, q5 | r2, q3 | r3, q2, q4 | la1, flag1

(הסדר הוחלף: בחדר המקורי כל הקריאות באות קודם, ולכן הוא לא מתחלק לתחנות.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Hash | r1, q1, q5 | **Put Each Clue on the Pyramid** (sort), **What a Block Really Costs the Crew** (worksheet), **What Did the Crew Bother to Change?** (spotdiff), **Is This Indicator Still True?** (evidence, לפני q5) |
| 2 | The Sources | r2, q3 | **Quiet or Loud?** (sort), **Which Source Answers This Question?** (match), **How to Read a Multi-Engine IP Report** (anatomy) |
| 3 | The Pivot Board | r3, q2, q4 | **The Pivot Board** (trace), **Find Every Host That Touched the Crew** (hunt), **Crack the Sharing Terms** (codebreak), **Where Does Each Indicator Go?** (sort) |
| 4 (בוס) | The Last Crumb | la1, flag1 | **Anatomy of a Threat Intel Match** (anatomy), **Whose Address Is This?** (evidence), ואז המשימה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **q1 (הזיהוי שהכי קשה לעקוף):** נלמד ב-Put Each Clue on the Pyramid, ב-What a Block Really Costs the Crew וב-spotdiff. הדוגמה ברמת TTP היא חשבון שירות שמכווץ share ומעלה אותו, ובהתנהגות קריאת סיסמאות מדפדפן. אין Office, PowerShell או LSASS, ואין אף ניסוח מהאפשרויות.
- **שאלת הביניים של r1 (רמת Tools):** השורה של כלל YARA על קוד הפריקה של ה-loader. ההבדל מול artefact נלמד בשורה של השם rclone.exe. אין Mimikatz.
- **q5 (IOC ישן):** נלמד ב-Is This Indicator Still True?, בכרטיס של דומיין שנרשם מחדש ועכשיו מגיש ניוזלטר של מקהלה, ובכלל 3 עד 6 חודשים. בשאלה הנבחנת זה IP מדוח בן 14 חודשים.
- **שאלת הביניים של r2 (לחפש לפני שמעלים):** נלמד ב-Quiet or Loud?, על גיליון חידושים של החברה ועל קישור איפוס סיסמה. אין קובץ מצורף שנבנה נגד החברה.
- **q3 (מי עונה על פורטים פתוחים):** עובדת זיכרון, ולכן היא מופיעה רק דרך אגב, כנתונים בשלב scan של ה-Pivot Board. הטבלה שם, Shodan-style host lookup, מציגה פורטים ובאנרים של כתובת. ה-match שואל שאלה אחרת על Shodan (חיפוש באנר זהה), ומלמד מה AbuseIPDB, MXToolbox ו-OTX כן עושים. הפורט במעבדה הוא 8443, לא 50050.
- **q2 (Passive DNS):** נלמד בשלבים pdns ו-rpdns: time_first ו-time_last מכריעים, ודיירים קודמים של שרת הם לא הקורבן ולא התוקף. במעבדה יש דומיין אח אחד וחנות אופניים שעזבה ב-2024, לא שישה דומיינים, מאפייה או מרפאת שיניים. שדה ה-rrtype מראה שלא מדובר רק ב-MX.
- **q4 (הפעלת רשימת IOC):** נלמד ב-Where Does Each Indicator Go? ובשורה של כלל ה-ActionType ב-hunt (חסימה שקטה מסתירה את המחשב הנגוע). במעבדה תשעה אינדיקטורים שממיינים לפי בקרה, לא פיד של 500 כתובות.
- **la1, שאלה 1 (Tor):** נלמד בשדה threat_intel.category ב-Anatomy of a Threat Intel Match: שלושת הממסרים, ולקוח שמתחבר החוצה ל-guard. הרשומה במעבדה היא חיבור נכנס מ-exit אל פורטל, לא לפטופ שיוצא החוצה.
- **la1, שאלה 2 (פורט 443):** נלמד ב-Whose Address Is This?, על שרת שמשדר ב-TCP 80. הרעיון אותו רעיון, על פורט אחר.
- **la1, שאלה 3 (פיבוט על ממסר משותף):** נלמד ב-Whose Address Is This? על יציאת VPN מסחרית, ובשלב rep של ה-Pivot Board. אין Tor, אין 3,847 דיווחים, אין 198.51.100.45.
- **flag1 (המארח שפתח את החיבור):** השדה data.srcip ב-Anatomy of a Threat Intel Match: המקור הוא תמיד הצד שפתח את החיבור. במעבדה המקור חיצוני, ולכן הלומד לא יכול פשוט לחפש את הכתובת הפנימית.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Hash" | כניסה | תחנה 1 |
| Chapter 2: "The Price List" | אחרי The Hash | תחנה 2 |
| Chapter 3: "Ask Quietly" | אחרי The Sources | תחנה 3 |
| Finale: "Breadcrumbs" | אחרי הבוס | החדר הבא |
