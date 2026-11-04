# תסריט חדר 29: DLP Fundamentals

**שם המבצע:** Operation Sealed Brief
**רמה:** בינוני
**העולם:** Ashby & Rowe (משרד עורכי דין בדוי): 400 עורכי דין, תיקי מיזוגים חסויים, ולקוחות שסומכים על כך שמסמך פנימי לא יוצא החוצה.
**המנטור:** Daniel Okoye, ראש תחום סיכוני פנים (Insider Risk Lead).

## סיפור הרקע
ביום שלישי בבוקר מערכת ה-DLP של Ashby & Rowe ירתה התראה: מסמך אסטרטגיית המיזוג של תיק Halbrook שותף מחוץ למשרד. Daniel לא רוצה שתמהר להאשים. הוא רוצה שתבין איפה DLP מסתכל, כמה הוא בטוח במה שראה, מה הוא עשה עם זה, ורק אז תחליט אם זו טעות תמימה או גניבה.

## העולם התלת-ממדי: Sealed Brief
- כספת של תיקי לקוחות במרכז, ושלוש עמדות תצפית סביבה: ENDPOINT, ‏NETWORK ו-CLOUD.
- מסמכים שיוצאים מהכספת לכיוון העמדות, ואחד מהם נצבע אדום.
- קרן סורקת ומד confidence שמתמלא.
- שער פעולות: AUDIT, ‏WARN, ‏BLOCK, ‏ENCRYPT.
- קו עקיבה דרך שלוש נקודות ביקורת אל חותם VERDICT.

## סדר המשימות
r1, r2, q1 | r3, r4, q2 | r5 | r6, la1, f1, la2 | ac1, ac2, q3, m1, o1 (במקור כל הקריאות היו לפני כל השאלות. כל שאלה עברה אל התחנה של הנושא שלה)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Where DLP Watches | r1, r2, q1 | **Who Sees It?**: מיון אירועי דליפה לפי הערוץ שרואה אותם (endpoint, ‏network, ‏cloud) |
| 2 | How Sure Is It? | r3, r4, q2 | **Test the Classifier**: קונסולת PowerShell עם Test-DataClassification. מספר כרטיס שעובר Luhn מקבל confidence ‏85 עם מילות הקשר ו-65 בלעדיהן; מספר שנכשל ב-Luhn לא מתאים בכלל |
| 3 | Audit, Warn, Block | r5 | **Pick the Action**: מיון מצבים לפעולה הנכונה (audit, ‏warn, ‏block, ‏encrypt) |
| 4 | Reading the Alert | r6, la1, f1, la2 | **Follow the Match** (trace של שיתוף Halbrook_Merger_Strategy.docx) ו-**Anatomy of a DlpRuleMatch** |
| 5 (בוס) | Slip or Theft? | ac1, ac2, q3, m1, o1 | **Three Overrides**: שלוש עקיפות מדיניות. אחת מהן עם נימוק "ok" לנמען שלא שייך לתיק |

**הפרדה מהשאלות הנבחנות:**
- מספרי הכרטיס בקונסולה בדויים, ואחד מהם נכשל ב-Luhn בכוונה.
- הלוג בתרגול ה-anatomy הוא שיתוף SharePoint עם co-counsel, ולא האירועים של la1 ו-la2.
- תרגול העקיפות לא נותן את ההחלטות של ac1 ו-ac2.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Brief Left the Building" | כניסה | תחנה 1 |
| Chapter 2: "Eighty-Five Percent Sure" | אחרי How Sure Is It? | תחנה 3 |
| Chapter 3: "The Reason Box" | אחרי Reading the Alert | תחנה 5 |
| Finale: "Sealed Again" | אחרי הבוס | החדר הבא: Persistence Mechanisms |
