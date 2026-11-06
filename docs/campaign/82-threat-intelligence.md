# תסריט חדר 82: Threat Intelligence Fundamentals

**שם המבצע:** Operation Diamond
**רמה:** בינוני
**העולם:** Penrose Energy (חברת אנרגיה בדויה): גז וחשמל ל-640,000 בתים בשלושה מחוזות, 6 שערי גישה מרחוק, ו-3 חשבונות תמיכה של ספקים שמגיעים ל-41 תחנות עבודה של מהנדסי תת-תחנות.
**המנטור:** Callista Nwosu, Threat Intel Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
הפיד שופך ל-SOC של Penrose ‏48,000 אינדיקטורים ביום, ואף אחד לא ביקש אותם. לפני חודש נפרצה Aldermoor Gas, חברה דומה מאוד. Ingrid Solheim, שמנהלת את תפעול הרשת, שואלת שאלה אחת: האם הצוות שפגע ב-Aldermoor יכול להגיע למהנדסי התת-תחנות שלנו, והאם לעצור את סשני התמיכה של הספקים לפני שיא החורף? ל-Callista יש תשעה ימים לענות. שבועיים אחרי התשובה, בגל קור, ה-SIEM מעלה את ההתאמה הראשונה.

## המכניקה הייחודית של החדר
- **Fill the Diamond:** מעבדת `sort`. דוח ספק וערימת הערות גולמיות הופכים לאירוע אחד במודל ה-Diamond: Adversary, Capability, Infrastructure, Victim, ועוד סל חמישי לכל מה שנכון אבל לא שייך לאירוע הזה. פינה ריקה היא ממצא: היא הדבר הבא שצריך לאסוף.
- **Does the Diamond Answer Ingrid?:** ה-worksheet שאחריה מניח את האירוע ליד העובדות של Penrose ומחזיר את הלומד לשאלה שנשאלה. הלקח של החדר: מודיעין עונה על שאלה שמישהו שאל, ופיד שאף אחד לא ביקש הוא דאטה.
- **מחזור המודיעין הוא מבנה החדר:** התחנות הולכות לפי המחזור: דרישה, איסוף, ניתוח, הפצה, ואז פעולה על הפגיעה הראשונה. חדר 59 מכסה pivoting על IOC, ולכן כאן אין pivoting בכלל.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Penrose Energy עם Hub בשם THREAT INTEL HUB וחמישה מבנים לפי התחנות.

## סדר המשימות
r1, q1 | r2, q4, q5 | q2 | r3, q3 | la1, flag1

(הסדר הוחלף: בחדר המקורי כל הקריאות באות קודם, ו-flag1 מופיע לפני q4 ו-q5, ולכן הוא לא מתחלק לתחנות. flag1 נשאר מיד אחרי la1 כי הוא מתייחס להתראה שמעליו.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Requirement | r1, q1 | **Data or Intelligence?** (rush), **Work One Question Round the Lifecycle** (sequence), **Which Product for Which Reader?** (duel) |
| 2 | The Collection | r2, q4, q5 | **Sort Attackers by What They Want** (lineup), **Ask the Source That Can Answer** (duel), **Anatomy of a MISP Event** (anatomy), **What the Message Says and What Carries It** (inspect) |
| 3 | The Diamond | q2 | **Decode the Vendor Names** (codebreak), **Check the Crosswalk Before You Merge** (worksheet), **Fill the Diamond** (sort), **Does the Diamond Answer Ingrid?** (worksheet) |
| 4 | The Release | r3, q3 | **Send or Hold?** (rush), **What Does This Intelligence Change?** (match) |
| 5 (בוס) | The First Hit | la1, flag1 | **Read a Threat Intel Match Field by Field** (anatomy), **Prove the Match With Your Own Logs** (queue), **Contain a Host People Depend On** (sequence), ואז המשימות הנבחנות |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (Feedback):** נלמד ב-Work One Question Round the Lifecycle, בנקודה על Feedback ובדוגמה של רשת הקמעונאות. במעבדה Ingrid מבקשת שמות ספקים בפעם הבאה, בלי כתובות IP מתות ובלי צוות detection שמתלונן.
- **q1 (מוצר אסטרטגי):** נלמד בפריימר של Which Product for Which Reader? ובמהלך m1. הקורא הוא Head of Strategy שבוחן עסקה עם מפעיל רשת בחו"ל, לא דירקטוריון שקובע תקציב. אף ניסוח של אפשרות לא מופיע. דוגמת הפריימר לא מציגה מוצר אסטרטגי בכלל.
- **שאלת הביניים של r2 (STIX ו-TAXII):** מוצג כנתונים ב-What the Message Says and What Carries It: שורות TAXII מובילות, שורות STIX הן התוכן, ושורת ה-marking היא תווית TLP ש-STIX נושא. המעבדה לא שואלת את זה, והיא משתמשת בתעבורה של Penrose.
- **q4 (מה זה MISP):** נלמד ב-Anatomy of a MISP Event (event, attribute, כותבים וגם קוראים) ובמהלך g5. במעבדה שלוש חברות שירות שכנות, לא CERT שמזמין.
- **q5 (ISAC של המגזר):** נלמד במהלך g1 ובדוגמת הבנק. המעבדה עוסקת באנרגיה ו-E-ISAC. ‏H-ISAC מופיע רק בשורה ברשימה בפריימר, כעובדה עם התווית שלה, ולא נשאל.
- **q2 (Fancy Bear מול APT29):** הרעיון נלמד ב-Decode the Vendor Names (חיה נותנת מדינה, לא קבוצה; FIN פלילי ו-APT מדינתי) וב-Check the Crosswalk Before You Merge. השאלות במעבדה עוסקות ב-Voodoo Bear מול APT44 (למזג) וב-Wicked Panda מול Vanguard Panda (לא למזג). השורות של APT28 ו-APT29 מופיעות בטבלה כנתונים בלבד, ואין עליהן שאלה.
- **q3 (TLP:AMBER רגיל):** עובדת זיכרון, ולכן היא מופיעה רק כשורה עם התווית שלה בפריימר של Send or Hold?, וכהשוואה ב-lesson. אף קלף לא שואל על AMBER רגיל. הקלפים בוחנים את RED, AMBER+STRICT, GREEN, CLEAR ו-WHITE, ואין בהם MSSP ודוח על ערכת פישינג.
- **la1, שאלה 1 (להוכיח את ההתאמה):** האות המכריע נלמד במעבדה משלו, Prove the Match With Your Own Logs: מותר או נחסם, קצב קבוע, וכיוון הבייטים. ההתאמה האמיתית היא על jump host, עם דומיין ברמת ביטחון medium, כל 15 דקות, ו-940 MB החוצה, לא domain controller, לא IP ברמת high ולא 5 דקות. ההסבר התמים במעבדה הוא משימת גיבוי של ספק, לא עדכונים. Read a Threat Intel Match Field by Field מלמד ש-TLP אומר כמה רחוק מותר לשתף ושהגיל נקרא ב-data.first_seen, בלי לדון באפשרויות של השאלה.
- **la1, שאלה 2 (פעולה ראשונה):** נלמד ב-Contain a Host People Depend On, על jump host יחיד, דרך סדר כללי: בעל המערכת ו-IR, ניתוק הערוץ, היקף, ניקוי. המעבדה לא מזכירה את האפשרויות השגויות של השאלה, ואין בה krbtgt או AD.
- **flag1 (מזהה קבוצה ב-ATT&CK):** השיטה נלמדת בשאלה lookup ב-crosswalk ובשדה data.actor בכרטיס ההתראה. השורה של APT29 מופיעה בטבלה כנתון, והמעבדה מבקשת את ה-ID של Voodoo Bear.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Question" | כניסה | תחנה 1 |
| Chapter 2: "What Happened at Aldermoor" | אחרי The Collection | תחנה 3 |
| Chapter 3: "Cold Snap" | אחרי The Release | תחנה 5 |
| Finale: "The Question Answered" | אחרי The First Hit | החדר הבא |
