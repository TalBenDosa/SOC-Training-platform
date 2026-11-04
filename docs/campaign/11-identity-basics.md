# תסריט חדר 11: Identity Basics

**שם המבצע:** Operation Gatekeeper
**רמה:** מתחילים
**העולם:** Caldera Health (חברה בדויה) עם 11,000 עובדים וספק זהויות אחד שדרכו נפתחת כל דלת בארגון.
**המנטורית:** Noa Peretz, ראש אבטחת זהויות. Jonas Berg (ראש מוקד השירות) מופיע בהכרעה.

## סיפור הרקע
הלילה נמצא token של סשן של רדיולוגית בתוך dump של infostealer. ה-MFA היה מופעל, ולא היה לזה שום משקל. Noa רוצה אנליסט שמבין מה כניסה למערכת מוכיחה ומה היא לא מוכיחה: הוכחה, הרשאה, הנפקה, ביטול. ואחרי זה, לקרוא את הלוגים שמראים את כל הארבעה.

## העולם התלת-ממדי: Identity Gate
טבעת סגולה בשם AUTHENTICATE עומדת מול שלוש דלתות AUTHORIZE. לידה שלושה עמודי פקטורים: KNOW, ‏HAVE ו-ARE. מטבעות token זהובים זורמים דרך השער אל האפליקציות. מטבע אדום אחד נגנב אל התוקף, עד שקרן revoke ירוקה מנפצת אותו. מעל השער טלפון שמציף התראות APPROVE?. מאחור עומדים ארבעה מגדלים לסוגי החשבונות (USER, ‏ADMIN, ‏SERVICE, ‏MACHINE), ולפניהם זרם של אירועי logon: שבעה כישלונות ואחריהם הצלחה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Prove It, Then Permit It | r1 | **Which Check Was It?**: מיון אירועים לאימות זהות (authentication) או להרשאה (authorization) |
| 2 | Three Kinds of Proof | r2, q1 | **Know, Have, Are**: מיון הוכחות לשלוש הקטגוריות. **Real MFA or Not?**: שש זרימות התחברות, ובאילו מהן זה MFA אמיתי |
| 3 | Credentials and Tokens | r3, m1, r4, q2 | **Proof or Just a Name?**: מה ב-dump הוא credential ומה רק מזהה. **Decode the Stolen Token**: פענוח JWT ב-bash עם cut, ‏base64, ‏jq ו-date |
| 4 | Shut the Door | r5, o1 | **What Did They Leave Behind?**: קונסולת PowerShell של Graph ו-Exchange על חשבון שכבר הוכל: נקודת הביטול (SignInSessionsValidFromDateTime), טלפון MFA זדוני, כלל העברה נסתר וגם הסכמה לאפליקציה |
| 5 | The Prompt Storm | r6, ac1 | **Read the Prompt Storm**: יומן System Log של Okta עם push bombing. **Relayable or Bound?**: אילו פקטורים ניתן להעביר דרך פרוקסי AitM ואילו קשורים לדומיין. אחר כך ההכרעה של Jonas |
| 6 (בוס) | Accounts and Their Logons | r7, q3, r8, la1, f1 | **Who Is This Account?**: זיהוי חשבון user, ‏admin, ‏service או machine (כולל gMSA). **Hunt the Guessed Password**: ‏Get-WinEvent עבור 4625 ו-4624 על SRV-JUMP02. תרגול **Anatomy of a 4625**, ואחריו הרשומה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- הצירופים במעבדת ה-MFA לא כוללים סיסמה עם שאלת אבטחה (q1).
- מיון ה-credentials שואל "האם זו הוכחה?" ולא "מה התוקף מרוויח" (m1).
- קונסולת ההכלה עוסקת בשלב הסקירה של חשבון שכבר נחסם, ולכן אינה מגלה את סדר הפעולות (o1).
- סערת ה-push היא תקיפה אמיתית בטננט אחר, ולא מקרה מוקד השירות המאומת של ac1.
- מיון החשבונות מסביר איך מזהים כל סוג, ולא למה תוקפים מחפשים חשבונות שירות (q3).
- הציד הוא RDP על SRV-JUMP02 מהכתובת 198.51.100.77. אין בו את b.osei, את SRV-FILE03 או את 185.220.101.47 (la1, f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Token in the Dump" | כניסה | תחנה 1 |
| Chapter 2: "What's Inside a Token" | אחרי Credentials and Tokens | תחנה 4 |
| Chapter 3: "Block, Revoke, Review" | אחרי Shut the Door | תחנה 5 |
| Finale: "Nine Failures, One Success" | אחרי הבוס | החדר הבא: Malware Types |
