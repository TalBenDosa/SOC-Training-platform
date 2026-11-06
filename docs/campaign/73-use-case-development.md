# תסריט חדר 73: Use Case Development

**שם המבצע:** Operation First Rule
**רמה:** מתקדם
**העולם:** Merrow Dock Authority (רשות נמל בדויה): שלושה טרמינלים, 410 עובדים, ולוח רציפים שלא יכול לפספס גאות.
**המנטור:** Paloma Ferreira, Detection Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ה-SIEM של Merrow רץ כבר שנתיים, מלא בחוקים, ואף אחד לא יודע לומר אילו מהם עובדים. השבוע הגיעה הודעה מהסקטור: צוותי כופרה תוקפים נמלים ומוחקים קודם את עותקי השחזור. Paloma Ferreira רוצה חוק אחד שנעשה כמו שצריך, מקצה לקצה, באוויר עד יום שישי. המטרה היא החוק הראשון שבאמת נחשב: חוק בלי בדיקה, בלי רישום כוונון ובלי בעלים הוא לא use case.

## המכניקה הייחודית של החדר
- **Ship a Rule:** רעיון אחד עובר את כל הדרך מאיום לחוק פרוס, ושלוש מעבדות ממשיכות זו את זו.
- **Build the Detection in SPL:** מעבדת `hunt` ב-SPL, על אירועי Sysmon עם שלוש תקיפות בדיקה של צוות סגול. הלומד בונה את החוק שורה אחרי שורה, והתוצאה מחושבת באמת, כולל הפער בין `search` ל-`where` והחריג שמעוור את החוק.
- **Measure It on a Real Month:** מעבדת `tune` על 30 יום של פגיעות מסומנות, עם שני מחווני נדירות. הניצחון דורש חשבון, ומשאיר החמצה אחת ידועה ואזעקת שווא אחת מקובלת, ושתיהן נרשמות.
- **Sigma Before and After Tuning:** מעבדת `spotdiff` בין גרסה 1 לגרסה 2 של אותו חוק Sigma. לוחצים רק על שורות שמשנות מה החוק תופס, ושורות שנכתבו לבני אדם עולות בחיים.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) של רשות הנמל, עם ליבת `matrix`: ארבעה קלפים לפי התחנות.

## סדר המשימות
r1, q1 | r2, q2, m1 | r3, q3 | log-1

הסדר המקורי של החדר (שלוש הקריאות ברצף, אחריהן השאלות) לא מתחלק לתחנות, ולכן הוא שונה. האינטגרטור מיישם אותו.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Threat Idea | r1, q1 | **Six Parts of a Use Case** (anatomy), **From Idea to Live Rule** (sequence), **Use Case or Just a Rule?** (sort) |
| 2 | Build the Rule | r2, q2, m1 | **Which Idea Ships First?** (worksheet), **Inside a Sigma Rule** (anatomy), **Build the Detection in SPL** (hunt), **Name the Test** (codebreak), **Read the Name, Not the Tool** (match, לפני m1) |
| 3 | Tune the Rule | r3, q3 | **Measure It on a Real Month** (tune), **Sigma Before and After Tuning** (spotdiff), **Quarterly Rule Review** (queue), **The Registry Line** (anatomy) |
| 4 (בוס) | The First Alert | log-1 | **Read Around the Match** (anatomy), **Exception or Blind Spot?** (sort), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (ששת החלקים): החלקים מופיעים כנתון עם תווית ב-Six Parts of a Use Case, על טיוטת מחיקת עותקי צל, והמעבדה לא שואלת עליהם.
- שאלת הביניים של r2 (מה Sigma פותר): מופיע בסיכום של Inside a Sigma Rule (YAML נייטרלי לספק, pySigma, ה-SIEM מריץ את השאילתה המומרת ולא את ה-YAML), בלי ניסוח האפשרויות.
- q1 (סיכון של חוק לא מתועד): השורה על השאילתה במחברת האישית ב-Use Case or Just a Rule? מלמדת שהכיסוי שווה לזיכרון של אדם אחד. שם אין אנליסט שעוזב, ואין שאלה על מה קורה ל-SIEM.
- q2 (איפה רושמים מקור שפיר בלי לשנות התאמה): ההערה על `falsepositives` ב-Inside a Sigma Rule, ומלכודת ה-decoy באותו שדה ב-spotdiff. הדוגמה היא מנהל אחסון ומחיקת עותקי צל, לא סקריפטים של IT ו-PowerShell מקודד.
- m1 (התאמת תצפית לטכניקה): Read the Name, Not the Tool מלמד לקרוא ID כהורה ועוד וריאנט, ולקרוא את השם שאחרי הנקודתיים. הזוגות הם T1490, ‏T1486, ‏T1543.003, ‏T1021.002, ‏T1547.001, ואף אחד מחמשת הזוגות הנבחנים לא מופיע.
- q3 (חוק רועש, מה קודם): Quarterly Rule Review, השורות UC-NET-0031 ו-UC-MAIL-0019, מלמדות החרגה ממוקדת ותיקון של ספירה לפי חשבון, ובשורה UC-NET-0002 הפרישה מוצגת כמקרה שונה מכיבוי חוק רועש. הדוגמאות הן העלאת CCTV וספירת הורדות דואר, לא כשלי התחברות אחרי מיזוג.
- log-1, שאלה 1 (השתקה ממוקדת): Exception or Blind Spot? מלמד לבדוק כל השתקה מול ההתראה האמיתית האחרונה. הדוגמה היא עדכון של לקוח מכס ו-mshta, לא כלי טלאים ו-PowerShell מקודד.
- log-1, שאלה 2 (ההקשר מעלה חומרה): Read Around the Match היא מעבדה ייעודית לאות המכריע. היא עוסקת ב-mshta מ-`C:\Users\Public` עם הורה wscript.exe, ולא ב-PowerShell מ-Temp עם הורה cmd.exe. הלומד שוקל צמד שדות אחר (תפקיד המשתמש מול שליפה מ-IP חשוף), ולכן הניסוח של האפשרות הנכונה לא מופיע, והמסיחים לא נפסלים במפורש.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Two Years of Rules" | כניסה | תחנה 1 |
| Chapter 2: "The Notice" | אחרי The Threat Idea | תחנה 2 |
| Chapter 3: "Did It Fire?" | אחרי Build the Rule | תחנה 3 |
| Finale: "The First That Counts" | אחרי The First Alert | החדר הבא |
