# תסריט חדר 38: Microsoft 365 Security

**שם המבצע:** Operation Inbox Zero
**רמה:** בינוני
**העולם:** Fairhaven College (מכללה בדויה): ‏14,000 סטודנטים, ‏2,100 עובדים, וכל הרצאה, ציון ומשכורת יושבים ב-tenant אחד של Microsoft 365.
**המנטורית:** Saoirse Doyle, ראש אבטחת Microsoft 365.

## סיפור הרקע
בספטמבר משרד הכספים של המכללה שילם חשבונית מזויפת על ‎£86,000‎. המייל הגיע מתוך ה-tenant עצמו, מחשבון שהשתלטו עליו בשקט. Saoirse רוצה אנליסטים שיודעים איזה מוצר Defender רואה מה, וקוראים את ה-audit log כמו הודאה. אתמול בלילה החשבון p.okoro במחלקת אחזקה התחיל להתנהג מוזר.

## העולם התלת-ממדי: Inbox Zero
- טבעת אור של ה-tenant מעל שתי שורות של ארונות שרתים (‏EXCHANGE ו-SHAREPOINT) על רצפת מעגלים.
- ארבעה צמתי Defender (‏MDO, ‏MDE, ‏MDI, ‏MDCA) שמקיפים את הטבעת.
- שער מגן שעוצר מיילים מתחזים.
- מסוף audit שמציג פעולות.
- דליפה של חבילות לצומת חיצוני (mailbox.example), עד שמנעול סוגר את ה-tenant.

## סדר המשימות
r1 | r2, q2 | r3, q1, q3 | la1, flag1 | q4, q5 (במקור שלוש הקריאות היו לפני כל השאלות. כל שאלה עברה אל התחנה של הנושא שלה)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Defender Family | r1 | **Who Sees It?**: שישה אותות וארבעה מוצרי Defender |
| 2 | Guarding the Inbox | r2, q2 | **Four Senders**: התחזות דומיין (fairhaven-ac), התחזות משתמש (המנהלת), ספק מאושר ב-spoof intelligence וזיוף שנחסם |
| 3 | The Audit Trail | r3, q1, q3 | **Search the Audit Log**: ‏Search-UnifiedAuditLog על Add member to role, ‏Set-Mailbox עם ForwardingSmtpAddress ו-642 הורדות קבצים |
| 4 | The Hidden Rule | la1, flag1 | ההתראה הנבחנת |
| 5 (בוס) | Close the Tenant | q4, q5 | consent phishing ומה לתקן קודם |

**הפרדה מהשאלות הנבחנות:**
- מיון המוצרים לא מדרג פעולות Secure Score ‏(q5).
- גיליון השולחים עוסק בהתחזות ובזיוף, ולא בהרצת קבצים מצורפים בארגז חול (q2).
- קונסולת ה-audit לא מציגה inbox rule ‏(q1, ‏la1, ‏flag1), לא MailItemsAccessed ‏(q3) ולא OAuth consent ‏(q4).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Invoice From Inside" | כניסה | תחנה 1 |
| Chapter 2: "A Hyphen, Not a Dot" | אחרי Guarding the Inbox | תחנה 3 |
| Chapter 3: "Three Operations, One Story" | אחרי The Audit Trail | תחנה 4 |
| Finale: "Close the Tenant" | אחרי הבוס | החדר הבא: CrowdStrike Falcon |
