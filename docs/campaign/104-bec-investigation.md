# תסריט חדר 104: Business Email Compromise (BEC): End-to-End Investigation

**שם המבצע:** Operation Wire Transfer
**רמה:** בינוני (הפריימרים פתוחים)
**העולם:** Harcourt & Vane Engineering (חברת הנדסה בדויה): 310 עובדים, גשרים וכבישים בשלוש מדינות, tenant אחד של Microsoft.
**המנטור:** Oluchi Svensson, Fraud Investigations Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שלישי ב-14:20 שעון Pittsburgh ‏(18:20 UTC) Noor Haddad מהכספים סוגרת חודש ומוצאת תשלום של $387,250 לחשבון שאף אחד לא מכיר. הכסף יצא לפני פחות משעתיים וחצי. החשבונית אמיתית, הסכום אמיתי והתיבה אמיתית: Erin Brandt, מנהלת פרויקט Kestrel Viaduct, פשוט לא כתבה את שתי השורות ששינו את פרטי הבנק של הספק Ostrander Geotechnical. מישהו ישב בתיבה חמישה ימים וחיכה לחשבונית הנכונה. דסק ההונאות הוא של Oluchi, ובנק יכול לבקש את הכסף בחזרה רק כל עוד הוא עדיין שם.

## המכניקה הייחודית של החדר
**The Money Clock.** תקיפת BEC נחקרת מול חלון ה-recall של הבנק. חדרים 56, 77 ו-87 מכסים זרימת דואר, פורנזיקה ואיסוף, וכאן זה התיק מקצה לקצה, עם כסף וכספים בחדר.
- **Walk It Backwards:** מעבדת `sequence` שרצה לאחור, מהתאמת הבנק של Noor ועד גניבת הסשן, כי כך פוגשים תיק כזה באמת. הזמנים נחשפים רק אחרי כל הקשה.
- **From the Sign-In to the Bank Details:** מעבדת `trace` על חמישה לוגים: sign-in, ‏Unified Audit Log, חיפוש תוכן, רשומות Send, ויומן השינויים של ה-vendor master.
- **Run the Money Clock:** גיליון על חמישה תיקים מהעבר, שבו כל מספר הוא שעות מרגע שהכסף יצא.
- **The First Hour:** מעבדת `defuse` עם חמישה סבבים, על מה כל תיקון מסיר בפועל ודרך איזה ערוץ פונים לגורמים בחוץ.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של החברה: חמישה מבנים לפי התחנות. ה-Hub נושא את שם החברה ואת FRAUD DESK. סצנה `facilitywiretransfer`, ערכת נושא `wiretransfer`.

## סדר המשימות
r1, r2, q1 | r3, la1, q2 | r4, la2, m1, ac1 | r5, o1, q3 | r6, q4, f1

הסדר המקורי נשמר. הדגל f1 מצביע על הלוג שלו (מוצמד ב-`event`), ואין בו נוסח "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Invoice | r1, r2, q1 | **The Email With Nothing to Sandbox** (hotspot), **Hold or Pay?** (intercept), **Which Foothold Was It?** (deduce) |
| 2 | The Second Session | r3, la1, q2 | **Two Records, One Session** (spotdiff), **Could Anyone Have Flown It?** (worksheet) |
| 3 | The Hidden Rule | r4, la2, m1, ac1 | **Anatomy of an Inbox Rule** (anatomy), **From the Sign-In to the Bank Details** (trace), **Same Operation, Different Story** (queue) |
| 4 | The Timeline | r5, o1, q3 | **Walk It Backwards** (sequence), **Run the Money Clock** (worksheet), **Who Else Did They Touch?** (deduce) |
| 5 (בוס) | The Money Clock | r6, q4, f1 | **The First Hour** (defuse), **What the Written Summary Needs** (spotdiff) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (למה EDR לא במרכז):** עובדת זיכרון. היא מופיעה בפריימר Why There Is Nothing to Sandbox, והמעבדה לא שואלת עליה. המסיחים לא מוזכרים.
- **שאלת הביניים של r2 ו-q1 (VEC):** הטבלה ב-Which Foothold Was It? מתארת את העקבות של כל דריסת רגל, וכך הלומד מכיר את שורת הספק. הפתרון של המשחק הוא thread hijacking בתוך התיבה של Erin, לא VEC, ולכן התיק הנבחן לא מופיע במעבדה. דוגמת הפריימר היא דומיין דומה של בית ספר. אין מנכ"ל פיננסים, אין תיק עם tenant נקי לגמרי.
- **שאלת הביניים של r3 (refreshToken מול PRT) ו-m1:** עובדה בפריימר Reading a Sign-In Record, כשורה עם תווית. דוגמת הפריימר היא טאבלט של קבלן, שאין לו קשר לאף מסיח.
- **la1, שאלה 1 (בלי אימות חדש):** השדות נלמדים ב-Two Records, One Session. Pittsburgh ו-Frankfurt במרחק 27 דקות, לא Denver ו-Lagos בתשע דקות. הפריימר מגדיר את `Previously satisfied` כשדה, ולא אומר מה המשמעות במקרה הנבחן. אין אזכור ללקוח Outlook בטלפון או למדיניות CA שחוסכת הזדהות.
- **la1, שאלה 2 (impossible travel):** החישוב נלמד ב-Could Anyone Have Flown It? על ארבעה משתמשים, כולל a.kowalski עם אותו sessionId בנהיגה ל-Cleveland, כדי ש-sessionId משותף לבדו לא יספיק. VPN ונדידה לא מוזכרים.
- **la1, שאלה 3 (שדות ירוקים):** נלמד ב-Two Records, One Session: מי שמקיש על `conditionalAccessStatus` או על `riskLevelDuringSignIn` מקבל שהשורה זהה בשתי הרשומות. בלקח מוסבר שהן מעריכות את הטוקן שהוצג. המשפט שהן לא סוגרות תיק לא נכתב, כדי לא להעתיק את m1.
- **q2 (על מה מסתובבים):** ההגדרות של `sessionId` ו-`correlationId` בפריימר, כשורה עם תווית, ו-decoy על `correlationId` חדש. המעבדה לא שואלת על מה לחפש.
- **שאלת הביניים של r4 ו-la2, שאלה 1 (מה הכלל עושה):** נלמד ב-Anatomy of an Inbox Rule על כלל תמים של ניוזלטר פלדה, פרמטר אחרי פרמטר, כשכל הערה מתארת מה השדה עושה בלי לשפוט. בלי RSS Feeds, בלי SubjectOrBodyContainsWords כערך, בלי מילות המפתח של הכלל הנבחן.
- **la2, שאלה 2 (ClientIP וזמן):** נלמד בשלב השני של ה-trace ובדוגמת הפריימר, שעוסקת בהורדה מ-SharePoint. הפער 20 דקות, לא תשע.
- **la2, שאלה 3 (למה זה מסוכן בלי להוציא דואר):** נלמד בשלב השלישי של ה-trace על דף חשבון של Ostrander שנשלח יום לפני ההונאה, לא על תשובה של הספק אחרי התשלום.
- **ac1 (benign true positive):** נלמד ב-Same Operation, Different Story על ארבעה כללים מהרבעון הקודם: העברה החוצה, העברה לתיבת רשומות אחרי סגירת פרויקט, RedirectTo פנימי מכתובת זרה, ותיוק אישי. אין העברה בגלל חופשה. ה-why לא חוזר על רשימת העובדות מההסבר הנבחן.
- **f1 (שם הכלל):** הערך לא מופיע בשום מעבדה. הכלל במעבדה נקרא `zz`, והאנטומיה אומרת רק ששם הוא טקסט חופשי.
- **שאלת הביניים של r5 ו-q4 (האות המכריע של הבוס):** נלמד במעבדה משלו, Run the Money Clock, על חמישה תיקים מהעבר, בלי containment ובלי שאלה מה עושים עכשיו. ב-The First Hour אף סבב לא שואל אם להתחיל recall: סבב ה-bank שואל רק באיזה מספר מתקשרים. לא מוזכרים אישור כתוב של הספק או גבול של שש שעות.
- **o1 (סדר האירועים):** Walk It Backwards רץ לאחור, מתחיל ב-infostealer ולא ב-AiTM, ומוסיף שלב קריאה ועריכה ב-vendor master. אין בו שיחת טלפון שמאשרת, ואין הודעת ספק שנקברת אחרי התשלום. התיק נתפס בהתאמה פנימית תוך שעות, לא בתלונה אחרי שבועות.
- **q3 ושאלת הביניים של r6 (scoping):** נלמד ב-Who Else Did They Touch? על r.iyer: כתובת אחרת, אותו AS64501 ואותה צורת כלל. המעבדה לא שואלת אם סוגרים את התיק. המסיחים (תדרוך הכספים, איפוס אצל הספק) לא מוזכרים.
- **m1:** ATO, דומיין דומה, hijacking ו-VEC בפריימר Four Footholds, Four Trails; ‏refreshToken ו-primaryRefreshToken בפריימר של Two Records, One Session; שדות ירוקים ב-sameLine של אותה מעבדה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Under Three Hours" | כניסה | תחנה 1 |
| Chapter 2: "Nobody Wrote It" | אחרי The Invoice | תחנה 2 |
| Chapter 3: "Five Quiet Days" | אחרי The Hidden Rule | תחנה 4 |
| Finale: "Wire Transfer" | אחרי The Money Clock | החדר הבא |

הערות לסרטונים: Intro: ‏Noor מניחה את ההדפסה על השולחן של Oluchi. Chapter 2: ‏Erin עונה לטלפון מהאתר, עם קליטה מלאה, ולא מזהה את ההודעה. Chapter 3: ‏Marek שואל מה הסיכוי, והתשובה של Oluchi היא כמה זמן מישהו ישב בתיבה, בלי לומר מה עושים עכשיו. Finale: התשובה של הבנק, ושיחת הסיכום עם Oluchi.
