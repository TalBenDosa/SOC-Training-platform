# תסריט חדר 30: Persistence Mechanisms

**שם המבצע:** Operation Spare Key
**רמה:** בינוני
**העולם:** Wexley Biotech (חברת ביוטק בדויה): שלושה אתרי מחקר, 1,800 עובדים ונתוני ניסוי חיסון ששווים יותר מהבניינים.
**המנטור:** Ines Carvalho, ראש צוות תגובה לאירועים (Incident Response Lead).

## סיפור הרקע
בחודש שעבר IT מחקו מחשב נייד שנפל לפישינג ואיפסו את הסיסמה של המשתמש. תשעה ימים אחר כך אותו תוקף חזר. Ines לא רוצה רק לסגור את הדלת. היא רוצה למצוא כל מפתח רזרבי שהתוקף השאיר: ב-Registry, ב-Task Scheduler וב-cron, בשירותים, ב-BITS, ב-WMI ובענן. ורק אז לאפס.

## העולם התלת-ממדי: Spare Key
- ליבת מחשב (WKS-LAB14) במרכז.
- ענפי Registry עם מפתחות (HKCU\Run ו-Startup).
- שעון שמתקתק (‎*/10 * * * *‎).
- גלגל שיניים ושכבה נסתרת מתחת לרצפה (root\subscription).
- כרטיס אירוע 4698 שמסתובב אל המצלמה.
- טבעת ענן עם מפתחות שמסתובבים עד שמנעול נסגר.

## סדר המשימות
r1 | r2, q1 | r3, r4, q2 | la1, f1 | r5, r6, q3, ac1, m1, o1 (במקור f1 היה אחרון. הוא עבר אל התחנה של la1, כי הוא שואל על אותו אירוע)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Run Keys | r1 | **Hunt the Run Keys**: ‏reg query ל-HKCU ו-HKLM ו-dir לתיקיית Startup. ערך "AdobeSyncHelper" מזויף ב-HKCU וקיצור דרך שמריץ wscript |
| 2 | Tasks and Cron | r2, q1 | **The Cron Nobody Wrote**: ‏crontab של deploy (בלי sudo) שרץ כל 10 דקות, והביט setgid של ‏/usr/bin/crontab |
| 3 | Hidden Hooks | r3, r4, q2 | **Beyond the Usual Four**: שירות LocalSystem מ-C:\Users\Public, ‏BITS עם NotifyCmdLine, ו-filter, ‏consumer ו-binding ב-WMI |
| 4 | The SYSTEM Task | la1, f1 | **Anatomy of Event 4698**: משימה שנרשמה לחשבון שירות, עם ההבדל בין מי שרשם לבין מי שהמשימה רצה בשמו |
| 5 (בוס) | Close Every Door | r5, r6, q3, ac1, m1, o1 | **What the Reset Didn't Touch** (‏Entra audit: הסכמת OAuth עם offline_access וחשבון חדש) ו-**Survives the Reset?** |

**הפרדה מהשאלות הנבחנות:**
- קונסולת ה-Run לא מציגה רשומת VPN (ac1).
- ציד ה-cron הוא Linux בלבד, ולא עוסק ב-schtasks או ב-integrity level (q1).
- ה-anatomy היא 4698 של חשבון שירות, ולא המשימה של la1 או ערך ה-/ru שלה (f1).
- בגיליון ה-Entra אין חוק העברת דואר (q3).
- שום תרגול לא מסדר שלבי הכלה (o1) ולא מצמיד מנגנון למקור לוג (m1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Nine Days Later" | כניסה | תחנה 1 |
| Chapter 2: "Every Ten Minutes" | אחרי Tasks and Cron | תחנה 3 |
| Chapter 3: "Under the Floor" | אחרי Hidden Hooks | תחנה 4 |
| Finale: "Change the Lock Last" | אחרי הבוס | החדר הבא: PowerShell for SOC Analysts |
