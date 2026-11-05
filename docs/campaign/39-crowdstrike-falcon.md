# תסריט חדר 39: CrowdStrike Falcon

**שם המבצע:** Operation Talon
**רמה:** בינוני
**העולם:** Brightmoor Hotels (רשת מלונות בדויה): ‏46 מלונות, ‏3,900 עובדים, מחשבי קבלה בכל לובי, ונתוני כרטיסי אשראי על כל אחד מהם.
**המנטור:** Tobias Wren, ראש תחום EDR.

## סיפור הרקע
בכל מחשב של Brightmoor רץ ה-sensor של CrowdStrike Falcon. הלילה המחשב הנייד של מבקר הלילה בליסבון מתקשר לשרת שאף אחד לא מכיר. Tobias יושב במשרד בלונדון. הוא לא יכול ללכת עד ליסבון, וגם לא צריך.

## המכניקה הייחודית של החדר
**סימולטור מדיניות (Prevent מול Insight).** הלומד מריץ ארבעה קבצים ופעולות דרך שלוש הבדיקות של ה-sensor, ורואה מי נחסם, מי הפך לזיהוי ומי עבר.

## העולם התלת-ממדי: Talon
- צי של מחשבים ניידים עם נקודת sensor, שמזרימים טלמטריה אל גרף איומים בענן.
- מגן מדיניות (PREVENT · INSIGHT).
- מסוף RTR בלונדון עם קרן אל המחשב בליסבון.
- עץ תהליכים עם ענף אדום ולוח CREDENTIAL ACCESS.
- טבעת בידוד שנסגרת סביב המחשב.

## סדר המשימות
r1, r2, q3 | r3, q1, q2, q4 | la1, flag1 | q5, ac1 (במקור שלוש הקריאות היו לפני כל השאלות. כל שאלה עברה אל הנושא שלה)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Falcon Console | r1, r2, q3 | **Prevent or Detect?** (סימולטור) ו-**Which Screen Is This?**: מצב ה-sensor, מודיעין על כתובת והרצה אוטומטית |
| 2 | Real Time Response | r3, q1, q2, q4 | **Remote Shell to Lisbon**: ‏ps, ‏netstat, ‏reg query ו-kill |
| 3 | Memory Theft | la1, flag1 | הזיהוי הנבחן |
| 4 (בוס) | Hands on Keyboard | q5, ac1 | תנועה רוחבית והכרעה |

**הפרדה מהשאלות הנבחנות:**
- הסימולטור לא מריץ קובץ חדש לגמרי ישר אל חסימה (checkpoint של r1).
- מסכי הקונסולה לא מראים טעינת driver ולא זיהוי של OverWatch ‏(q2, ‏q3).
- ה-RTR לא משתמש ב-get ‏(q4) ולא מפענח PowerShell מקודד (q1).
- שום תרגול לא קורא את ה-dump של LSASS ‏(la1, ‏flag1), את ההתפשטות עם PsExec ‏(q5) ולא שרשרת Word אל PowerShell ‏(ac1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "A Laptop in Lisbon" | כניסה | תחנה 1 |
| Chapter 2: "Stop It or Report It" | אחרי The Falcon Console | תחנה 2 |
| Chapter 3: "From London, Through the Sensor" | אחרי Real Time Response | תחנה 3 |
| Finale: "One Host, Not Five" | אחרי הבוס | החדר הבא: SentinelOne |
