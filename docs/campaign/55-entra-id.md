# תסריט חדר 55: Entra ID (Azure AD) Security

**שם המבצע:** Operation Tenant Zero
**רמה:** בינוני
**העולם:** Compass Rose Tours (חברת טיולים בדויה): 900 מדריכים ב-40 מדינות, ורובם מעולם לא ראו משרד.
**המנטור:** Mirela Popescu, Identity Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
לחברה כזו אין קצה רשת. החומה היחידה שנשארה היא הכניסה, וכולה יושבת ב-tenant אחד. הפה של Mirela: כאן כל מדריך נראה כמו impossible travel, אז האזעקה לא מספיקה, וצריך לקרוא מה הכניסה עשתה בפועל.

## המכניקה הייחודית של החדר
**Work the Sign-in:** קונסולה בסגנון Entra admin center, סקין חדש של `portal`: תפריט משמאל, טבלת Sign-in logs, וחלונית פרטים עם הלשוניות האמיתיות (Basic info, Location, Authentication Details, Conditional Access). הלומד הולך מכניסה אחת ללוג הביקורת ומשם ל-PIM, ומגלה ש-Not Applied הוא שאלה ולא תשובה.

## העולם התלת-ממדי: Tenant Zero
- אין בניין: ליבת tenant זוהרת עם חשבונות ואפליקציות במסלול.
- שלוש טבעות תנאים (LOCATION, DEVICE, RISK) שכניסות עוברות דרכן, וחלקן נעצרות.
- מנורת תפקיד נעולה שנדלקת על טיימר קצר.
- גלובוס עם סיכות וקשת אחת שאף אחד לא יכול לטוס.

## סדר המשימות
r1, q5 | r2, q2, q4 | r3, q1, q3 | la1, flag1

(q5 זז לתחנה 1 כי הוא על service principal. q2 ו-q4 זזו אחרי r2. הלוג הנבחן עבר לבוס.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Tenant | r1, q5 | **Which World Is It In?** (sort) |
| 2 | The Checkpoint | r2, q2, q4 | **Crack the Sign-in Codes** (codebreak) |
| 3 | Just in Time | r3, q1, q3 | **Work the Sign-in** (portal, Entra), **Tune the Spray Rule** (tune), **The Identity Duel** (duel) |
| 4 (בוס) | Failed, Not Safe | la1, flag1 | הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- ה-codebreak משתמש ב-50053, ‏50057, ‏65001, ‏70044. לא ב-50126 ‏(q2, ‏la1) ולא ב-50076 ‏(flag1), והקונסולה לא מציגה קודי שגיאה.
- אין Shanghai או New York ‏(la1), אין מלון ו-MFA מחוץ למשרד ‏(q4), ואין push bombing ‏(q3).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "No Edge" | כניסה | תחנה 1 |
| Chapter 2: "The Only Wall" | אחרי The Tenant | תחנה 2 |
| Chapter 3: "02:00 in Porto" | אחרי The Checkpoint | תחנה 3 |
| Finale: "Tenant Zero" | אחרי הבוס | החדר הבא |
