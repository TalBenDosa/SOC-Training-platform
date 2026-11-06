# תסריט חדר 61: Investigation Methodology

**שם המבצע:** Operation Loose Thread
**רמה:** בינוני
**העולם:** St Aldric's Hospice Group (ארגון צדקה בדוי): שלושה הוספיסים, בבריסטול, בהליפקס ובפרת', וכל אחד מהם מארח מערכת משותפת שאף אחד מעולם לא העביר.
**המנטור:** Rafe Nakagawa, Senior Investigator. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
תורם התקשר למשרד גיוס התרומות: אדם זר ציטט לו את הסכום המדויק שהובטח להוספיס בצוואה שלו. הסכומים האלה נמצאים ב-Legacy Register, בתוך מערכת ה-CRM של התורמים. ל-Rafe יש קצה חוט אחד וכלל אחד: אף לוג לא נפתח לפני שיש שאלה לשאול אותו. ההמשך מגלה דואר התחזות, לפטופ של קצינת עיזבונות, יצוא של 2,140 רשומות ו-1.4 GB שיצאו החוצה 21 דקות לפני שההתראה הראשונה עלתה.

## המכניקה הייחודית של החדר
- **The Hypothesis Board:** הלומד מנסח השערה, בוחר את הראיה שתוכיח או תפיל אותה, ומבצע pivot. ב-`pathway` כל צומת הוא מקור ראיות, והצעד הבא חייב לנבוע מהממצא האחרון. צעד שגוי מסביר מה המקור הזה לא יכול היה להוכיח בשום מצב.
- **One Timeline in UTC:** `sequence` שבונה ציר זמן אחד ב-UTC משישה מקורות בשלושה אזורי זמן. לפי השעונים המודפסים הנתונים יוצאים עוד לפני שהנוזקה רצה, סיפור שלא קרה.
- **The SPL Ladder:** מעבדת `hunt` ב-SPL אמיתי (לא KQL), עם טבלאות משלה, שבע שורות ותוצאות מחושבות.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) עם ליבה `chain`: ארבעה קלפים לפי התחנות, ושרשרת שמרחפת מעל הכן כמו החוט שהחקירה מושכת.

## סדר המשימות
r1, q1 | r2, q2, q3 | r3, q5 | la1, flag1, q4

הסדר השתנה: בחדר המקורי שלוש הקריאות באות ראשונות, ואי אפשר לבנות מזה תחנות. q4 חייבת לבוא אחרי la1 כי היא מפנה ל"לוגון שלמעלה", לכן הבוס מחזיק את la1, flag1, q4, ו-q5 עברה ליד הקריאה שלה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The First Question | r1, q1 | **Kill the Hypotheses** (deduce), **Six Phases of One Case** (sort), **What Disappears First** (worksheet) |
| 2 | Pivot and Timeline | r2, q2, q3 | **Four Pivots** (match), **The Hypothesis Board** (pathway), **Whose Clock Is This?** (inspect), **One Timeline in UTC** (sequence) |
| 3 | SIEM and Case File | r3, q5 | **Same Rule, Different Entity** (queue), **The SPL Ladder: Where the Account Went** (hunt), **Moving or Leaving?** (sort), **Mark Up the Draft Ticket** (hotspot) |
| 4 (בוס) | Read the Logon | la1, flag1, q4 | **Anatomy of an Expected Logon** (anatomy), ואז הרשומה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (איזה שלב דולג): נלמד ב-Six Phases of One Case, בשורות של Conclude ‏(verdict, מה נעשה, אילו מערכות, אילו נתונים) ושל Scope ‏(הערכה מוקדמת). הדוגמאות הן מהתיק של ההוספיס, ואין טיקט בלי verdict.
- שאלת הביניים של r2 (לעבוד ב-UTC): נלמד ב-One Timeline in UTC. אזורי הזמן הם UTC-3, UTC+1, UTC+8, לא Eastern ו-Pacific.
- q1 (לאסוף לפני רוטציה, לא לאתחל): נלמד ב-What Disappears First ובשורה a6 ב-Six Phases. התרגול הוא חישוב על buffer של VPN, proxy וזיכרון לפטופ, לא Security log של שרת אחד.
- q2 ‏(IP אל hosts): נלמד ב-Four Pivots (שורה p4) וב-The Hypothesis Board. הכתובת מגיעה מעץ תהליכים של EDR או מדף פישינג, לא מ-beacons בלוג חומת אש. גם המסיח של VirusTotal נלמד בתור מלכודת ti.
- q3 (איזה מקור דורש המרה ידנית): נלמד ב-Whose Clock Is This?. העובדות מוצגות כשורות נתונים עם תווית ולא נשאלות, ואין מעבדה שממזגת EVTX, IIS ו-Sentinel.
- la1 שאלה 1 (השוואת WorkstationName למלאי): נלמד ב-Anatomy of an Expected Logon על רשומה תקינה של svc-crmsync: ברשומת Kerberos השדה הוא "-", ההשוואה למלאי נעשית דרך IpAddress, וההערה מלמדת שהשם מדווח בלוגון NTLM ושכשהוא מלא משווים אותו למלאי, בלי svc-backup, SRV-FINANCE-02 או WS-DEV-09.
- la1 שאלה 2 ‏(NTLM הוא סימן, לא הוכחה): נלמד בהערה על AuthenticationPackageName באנטומיה (הרשומה עצמה Kerberos), בסוף The SPL Ladder על חשבון אדמין אנושי, ובשורה s11 ב-Moving or Leaving?.
- flag1 (הערך לחיפוש): נלמד בהערה על IpAddress באנטומיה, עם כתובת אחרת. 10.0.1.45 לא מופיעה בשום מעבדה.
- q4 (אינדיקטור לתנועה רוחבית מול הוצאת מידע): נלמד ב-Moving or Leaving? עם WMI, PsExec, ADMIN$ ו-Type 3. אירוע 7045 לא נשאל: הוא מופיע רק כנתון בטבלה של ה-hunt, ובאגב ב-why של s2 ובשיעור של ה-hunt.
- q5 (ראיות שאפשר לשחזר): נלמד ב-Mark Up the Draft Ticket, בסימון שורות בטיוטה אחת, לא בבחירה בין ארבע טיוטות.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Exact Sum" | כניסה | תחנה 1 |
| Chapter 2: "What Would Prove It?" | אחרי The First Question | תחנה 2 |
| Chapter 3: "Three Clocks, One Morning" | אחרי Pivot and Timeline | תחנה 3 |
| Finale: "Tied Off" | אחרי הבוס | החדר הבא |
