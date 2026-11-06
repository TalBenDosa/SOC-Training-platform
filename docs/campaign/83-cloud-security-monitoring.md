# תסריט חדר 83: Cloud Security Monitoring

**שם המבצע:** Operation High Cloud
**רמה:** בינוני
**העולם:** Brightfeather Robotics (חברה בדויה): רובוטים לליקוט במחסנים, 2,600 רובוטים שמושכים קושחה חתומה מהענן, ו-AWS לקושחה, Azure למשרד האחורי ו-Google Cloud לאימון מודלי ראייה.
**המנטור:** Kofi Sandoval, Cloud Security Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
יום רביעי, 08:40. אדם זר כותב ל-Brightfeather שמפתח גישה של החברה יושב כבר תשע שעות ב-repository ציבורי. גרסת קושחה 7.2 אמורה לצאת ל-2,600 רובוטים ביום שישי ב-06:00. אין משרד להיכנס אליו ואין לפטופ לתפוס. כל מה שיש ל-Kofi הוא רישום של כל קריאה שנעשתה לחשבון, ושאלה אחת: מי קרא ל-API, ומה עוד נשאר בפנים?

## המכניקה הייחודית של החדר
- **From Leaked Key to New Identity:** מעבדת `trace` לאורך רשומות CloudTrail אמיתיות במבנה שלהן (eventName, userIdentity, sourceIPAddress, errorCode), מהשימוש הראשון במפתח שדלף ועד משתמש IAM חדש שממשיך לעבוד אחרי שהמפתח כובה.
- **Which Management Events Deserve a Page?:** מעבדת `tune` על 90 יום של פעולות כתיבה. שתי מידות נדירות, של הקורא ושל הכתובת, כי אף eventName לא מצדיק הקפצה לבדו.
- **רעיון משותף לשלושת העננים:** חדר 36 מכסה את Sentinel, וחדרים מאוחרים יותר מעמיקים בכל ענן, ולכן כאן מלמדים את ה-control plane: אותן ארבע שאלות בכל לוג.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) של Brightfeather Robotics עם גלובוס במרכז וארבעה קלפים לפי התחנות.

## סדר המשימות
r1, q3 | r2, q1, q2 | r3, la1, flag1 | ac1

(הסדר הוחלף: בחדר המקורי כל הקריאות באות קודם, ולכן הוא לא מתחלק לתחנות. q3 עובר אחרי r1 כי Root נלמד שם, q1 ו-q2 אחרי r2. ‏flag1 נשאר מיד אחרי la1 כי הוא קורא את רשומת ה-CreateUser שלו, ה-logTask שלו כבר מוצמד ל-cloud-la1, ובנוסח שלו אין מספר משימה. ‏ac1 עובר לסוף כבוס.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Control Plane | r1, q3 | **Control Plane or Data Plane?** (rush), **Read One CloudTrail Record** (anatomy), **Same Four Questions, Three Clouds** (worksheet), **Read a Wall of AccessDenied** (worksheet) |
| 2 | Who Called the API? | r2, q1, q2 | **From Leaked Key to New Identity** (trace), **Looking, Opening or Taking?** (sort), **What a Plain GET Gets Back** (spotdiff) |
| 3 | The Open Door | r3, la1, flag1 | **Pull One Session Out of a Role** (worksheet), **Containment Depends on the Identity** (defuse), **Which Management Events Deserve a Page?** (tune) |
| 4 (בוס) | The Last Call | ac1 | **Who Gained What?** (queue), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (הרבה AccessDenied):** נלמד ב-Read a Wall of AccessDenied ובפריימר שלו: סופרים סוגי קריאות ושירותים, לא שגיאות. במעבדה 41 קריאות, 29 eventNames ו-7 שירותים, לא 60 קריאות על IAM, S3, EC2 ו-Secrets Manager.
- **שאלת הביניים של r2 (נתיב המטא-דאטה):** עובדת זיכרון, ולכן הנתיב מופיע רק כשורת נתונים ב-What a Plain GET Gets Back. המעבדה לא שואלת עליו.
- **q3 (Root):** עובדת זיכרון. מופיע בחלוף כערך עם התווית שלו בהערה על userIdentity.type ב-Read One CloudTrail Record, ולא נשאל. אין במעבדה AdministratorAccess, ואין התייחסות ל-Lambda או ל-SSO.
- **q1 (דלת אחורית ב-IAM):** נלמד ב-From Leaked Key to New Identity ובפריימר שלו (זהות חדשה, מפתח, הרשאות, וכתובת מקור מול הרגיל, כולל תיוג Tor). במעבדה מפתח ארוך טווח של משתמש, שרת שכור ולא Tor, ו-AddUserToGroup אל platform-admins אחרי ש-AttachUserPolicy עם IAMFullAccess נדחה. דוגמת הפריימר היא Google Cloud.
- **q2 (IMDSv2):** נלמד בפריימר של What a Plain GET Gets Back ובמעבדה עצמה: השוואה בין שתי מכונות עם אותו role, בלי פגם ווב. דוגמת הפריימר היא הכותרת של Google Cloud. שום מסיח לא מוזכר (כתובת ציבורית, GuardDuty, security group).
- **la1, שאלה 1 (סשן CI מכתובת זרה):** נלמד בפריימר של Pull One Session Out of a Role ובשאלה על nightly-sync2: role אמיתי מחוץ לכתובות הרגילות, ושם הסשן הוא תווית שהקורא בוחר. ה-userAgent מוסבר כטענה ב-Read One CloudTrail Record. במעבדה fleet-ops-role ולא role של פריסה, ואין Tor.
- **la1, שאלה 2 (us-east-1):** נלמד בהערה על awsRegion ב-Read One CloudTrail Record, על Route 53 בלבד. ‏IAM מופיע רק כנתון, בעמודת awsRegion של רשומות ה-trace.
- **la1, שאלה 3 (איזה ערך לחפש):** נלמד ב-Pull One Session Out of a Role: הלומד סופר לפי ARN של סשן ורואה שחיפוש לפי sessionIssuer מחזיר הכול. responseElements מוסבר ב-Read One CloudTrail Record.
- **flag1 (שם המשתמש שנוצר):** השיטה נלמדת ב-From Leaked Key to New Identity (השם ב-requestParameters, הקורא עדיין fw-build-bot) ובהערה ב-Read One CloudTrail Record. שם המשתמש במעבדה הוא fw-sign-audit.
- **ac1 (הסלמת הרשאות):** האות המכריע נלמד במעבדה משלו, Who Gained What?: מסירת role חזק יותר למשהו שהקורא שולט בו, רצף של בדיקת הרשאות ואז שיטוט, ו-iam:PassRole כהרשאה בלי אירוע משלה. במעבדה CreateStack ו-CreateTrainingJob, בלי instance profile, בלי EC2 ובלי ListRoles. כתובת בטווח ענן ציבורי מופיעה גם באירוע אמיתי וגם באירוע תמים, והמקרה ההפוך מגיע מכתובת המשרד. ‏GetCallerIdentity מופיע כנתון בודד ב-trace, לא כחלק מהרצף של ac1.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Nine Hours" | כניסה | תחנה 1 |
| Chapter 2: "Thirty-Four Locked Doors" | אחרי The Control Plane | תחנה 2 |
| Chapter 3: "The Night Before" | אחרי The Open Door | תחנה 4 |
| Finale: "Release 7.2" | אחרי The Last Call | החדר הבא |
