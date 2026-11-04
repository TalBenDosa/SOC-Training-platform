# תסריט חדר 17: Endpoint Security Fundamentals

**שם המבצע:** Operation Black Box
**רמה:** מתחילים
**העולם:** Kestrel Credit Union (אגודת אשראי בדויה), עם 2,400 מחשבים ניידים ו-380 שרתים. על כל אחד מהם רץ סוכן EDR.
**המנטורית:** Hana Kobayashi, מהנדסת EDR.

## סיפור הרקע
כל סוכן הוא קופסה שחורה: הוא מקליט כל תהליך, כל קובץ, כל חיבור וכל שינוי ב-registry, ומזרים הכול לענן. כשהתראה קופצת, Hana לא מנחשת. היא פותחת את ההקלטה. כאן לומדים מה כל דור של הגנת קצה תופס, מפעילים shell של live response, מחליטים מתי בידוד שווה את המחיר שלו, וקוראים התראה כמו שהיא קוראת.

## העולם התלת-ממדי: Black Box
במרכז עומד מחשב נייד, ומסביבו ארבע טבעות דורות: AV, ‏NGAV, ‏EDR ו-XDR. טבעת ה-XDR שולחת קווים אל EMAIL, ‏IDENTITY, ‏NETWORK ו-CLOUD. טלמטריה מתפתלת למעלה אל ענן RECORDER, וכיפת בידוד נסגרת על המחשב. לצדו צומח הולוגרמה של עץ תהליכים, OUTLOOK > mshta > powershell > msupdate, והענף הזדוני זוהר באדום עד שחיתוך אחד קוטע אותו.

## סדר המשימות
r1, q1, q4 | r2, q3 | r3, q2 | la1, f1 (השאלות q1 ו-q4 על הדורות הוקדמו אל r1)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Four Generations | r1, q1, q4 | **Which Generation Catches It?**: חמש תקיפות, ולכל אחת הדור המוקדם ביותר שתופס אותה |
| 2 | The Flight Recorder | r2, q3 | **Live Response**: ‏Falcon RTR עם ps, ‏netstat, ‏filehash ו-kill. **Isolate, or Something Lighter?**: ארבעה מארחים (שרת קבצים מוצפן, DC, מחשב ניטור כספומטים, מחשב נייד עם beacon) |
| 3 | Read the Tree | r3, q2 | **Who Launched What?**: שלושה עצי תהליכים: ‏SCCM, ‏Outlook > mshta > powershell, ו-scheduled task של DBA |
| 4 (בוס) | The Alert | la1, f1 | תרגול **Anatomy of a Defender Alert** (‏AlertInfo/AlertEvidence) לפי שיטת שבעת השלבים, ואחריו הזיהוי הנבחן של Falcon והדגל |

**הפרדה מהשאלות הנבחנות:**
- מיון הדורות בנוי מתקריות, ולא מהגדרות (q1, q4).
- ה-live response ותור הבידוד עוסקים במארחים אחרים מהמחשב המתפשט של q3.
- העצים לא כוללים את winword > cmd > powershell -Enc ‏(q2).
- התרגול הוא התראה של Defender, ולא דגלי ה-PowerShell של la1 (la1, f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Endpoint Is a Flight Recorder" | כניסה | תחנה 1 |
| Chapter 2: "Live Response" | אחרי Four Generations | תחנה 2 |
| Chapter 3: "The Parent Tells the Story" | אחרי The Flight Recorder | תחנה 3 |
| Finale: "Read It Like Hana" | אחרי הבוס | החדר הבא: Analyst Mindset |
