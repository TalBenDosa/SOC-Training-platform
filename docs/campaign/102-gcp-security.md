# תסריט חדר 102: Google Cloud Platform (GCP) Security Essentials

**שם המבצע:** Operation Project ID
**רמה:** בינוני (הפריימרים פתוחים)
**העולם:** Fernhollow Games Studio (אולפן משחקים בדוי): 140 עובדים, ארגון Google Cloud אחד, וארבעה ימים עד ש-Thornmere עולה לאוויר.
**המנטור:** Rashid Lundqvist, GCP Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני בבוקר modder מדווח על קובץ JSON בתוך ה-Thornmere Mod Kit הציבורי. זה מפתח של חשבון השירות build-runner, ואיש באולפן לא זוכר מתי החשבון קיבל גישה לחצי מהסביבה. המפתח מנוטרל תוך דקות, ואז מתחילה העבודה האמיתית: לגלות מאיפה ההרשאה הגיעה בכלל, מה נכתב ומה לא נכתב בלוגים, ולאן המפתח הגיע. מתברר שמישהו בחוץ התחיל לבדוק אותו שעות לפני הדיווח, התחזה דרכו ל-release-bot, יצר מפתח חדש על החשבון הזה, והפעיל מכונות GPU על חשבון האולפן. בלילה, כשהסיפור בבית נרגע, NexaCorp, המוציאה לאור של המשחקים, מתקשרת: חסר להם אנליסט במשמרת, והלומד נשלח לשבת בדסק שלהם.

## המכניקה הייחודית של החדר
**Inherited, Not Granted.** ב-GCP ההרשאות הן עץ, ולכן הרשאה שלא מופיעה על פרויקט עדיין יכולה לפעול. חדר 83 מכסה את הרעיון הענני המשותף, וכאן נשארים על הצורה של GCP עצמו.
- **Where Did the Role Come From?:** מעבדת `pathway` שיורדת מהארגון דרך התיקיות והפרויקט עד ל-bucket, וקוראת allow policy בכל רמה. ההרשאה יושבת על תיקייה, לא על הפרויקט ולא על ה-bucket. בדרך יש שני פרויקטים עם אותו שם תצוגה, כך שרק ה-project ID מוביל נכון, וגם פרויקט הבית של חשבון השירות, שלא אומר כלום על המקום שבו ההרשאה ניתנה.
- **Follow the Key:** מעבדת `trace` על Cloud Audit Logs עם שדות `protoPayload` אמיתיים: `methodName`, `authenticationInfo.principalEmail`, `serviceAccountKeyName` ו-`serviceAccountDelegationInfo`. הלומד מוצא איפה המפתח נולד, מהו השימוש הראשון מבחוץ שאפשר לראות (קריאה שנדחתה עם קוד 7. חלון הבדיקה נפתח כבר כשה-kit פורסם, כי קריאה שקטה לא הייתה נרשמת כאן), איזה מפתח חדש נוצר על release-bot ונשאר בידי הפורץ, מי עמד מאחורי release-bot, ואיזו הפעלת VM שייכת לפורץ. ב-Compute Engine שם המפתח לא נרשם, אז מסתובבים על `callerIp`.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של האולפן: חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה. סצנה `facilityprojectid`, ערכת נושא `projectid`.

## סדר המשימות
r1, r2 | r3, q1 | r4, q2, q3, m1 | la1, la2, ac1 | r5, la-sakey, f1, r6, r7

**הסדר שונה.** הסדר המקורי: r1, r2, r3, r4, q1, q2, q3, la1, la2, ac1, m1, r5, la-sakey, f1, r6, r7. q1 באה עכשיו מיד אחרי r3 שמלמדת אותה, ו-m1 מסכמת את ארבע הקריאות לפני הלוגים. הזנב שומר על סדרו כי הטקסט תלוי בו: ac1 אומרת שהאירוע הקודם כבר נבלם, r5 מצטטת את ac1, f1 קוראת את האירוע "above" (la-sakey, מיד לפניה), r6 נפתחת על הדגל, ו-r7 מצטטת את r6. ב-f1 אין נוסח "Log Analysis N", והדגל נשאר צמוד ללוג שלו.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Org Tree | r1, r2 | **Where Did the Role Come From?** (pathway), **The Names on the Map** (match), **Anatomy of an Allow Policy** (anatomy), **Who Can Give Itself More?** (worksheet), **Attached Token or Key File?** (rush) |
| 2 | The Audit Trail | r3, q1 | **Anatomy of an Audit Entry** (anatomy), **Which Log Stream?** (sort), **Anatomy of a Finding** (anatomy) |
| 3 | The Mod Kit Key | r4, q2, q3, m1 | **Follow the Key** (trace), **Walk a Token Out of a VM** (sequence) |
| 4 | The Partner Desk | la1, la2, ac1 | **Stop It Moving** (outbreak), **Who Downloaded the Patch?** (worksheet), **Fired Right, Still Fine?** (queue) |
| 5 (בוס) | The Six Minutes | r5, la-sakey, f1, r6, r7 | **Pivot on the Address** (worksheet), **Whose Key Is It?** (worksheet), **Cash Out a Foothold** (pathway), **Close Each Gap** (match), **Undo or Gone?** (rush), **Hold the VM for Forensics** (sequence) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (המקבילה של project ב-AWS):** עובדת זיכרון. היא מופיעה פעם אחת בדרך אגב, בהערת מסלול של Where Did the Role Come From?, והמעבדה לא שואלת עליה. ב-The Names on the Map אין מיפוי של Compute Engine, של Organization או של חשבון שירות ל-AWS, כדי לא לשלול את המסיחים אחד אחד.
- **שאלת הביניים של r3 (איזה לוג רושם חסימה):** נלמד ב-Which Log Stream? על לפטופ של מפתח מחוץ למתחם שנדחה בבקשה לרשימת build, עם `violationReason`. אין שם תוקף, אין העתקת dataset.
- **q1 (הורדה בלי Data Access):** נלמד ב-Which Log Stream? על קריאות Secret Manager ו-Firestore, ועל שינוי מדיניות בסוד שנרשם גם כשהקריאה עצמה לא. אין במעבדה קריאת Cloud Storage. הפריימר מלמד את ברירות המחדל של כל זרם ולא עובר על האפשרויות.
- **q2 (טוקן של VM בשימוש מבחוץ):** נלמד ב-Walk a Token Out of a VM, שנעצר ברגע שהטוקן אצל מי שקרא את התשובה, וב-Attached Token or Key File? (טוקן קצר מועד ממפתח ארוך טווח). אין במעבדה כתובת זרה, אין מדינה, ואין VM שנבדק ונמצא תקין. המסקנה נשארת ללומד.
- **q3 (איזו קריאה רושמת את ההשתלטות):** הלוגיקה נלמדת ב-Who Can Give Itself More? על sso-sync עם folderIamAdmin על תיקייה, בלי שום Owner. שם המתודה מופיע בדרך אגב כשורה עם תווית: ב-Anatomy of an Audit Entry על topic של Pub/Sub, ובשורה תמימה ב-Follow the Key. המסיחים לא מוזכרים.
- **la1, שאלה 1 (למה Owner מדאיג):** הפריימר What a role reaches מתאר מה כל תפקיד בסיסי מוסיף, והטווח של הצמדה לפרויקט נלמד דרך הדוגמה בלבד: ticket-bot שמשתמש רק ב-Pub/Sub בפרויקט אחר, בלי Owner ובלי BigQuery.
- **la1, שאלה 2 (מה אומר status 0):** נלמד ב-Anatomy of an Audit Entry על מתן גישה תמים, עם הפרש בין `request` ל-`response`. דוגמת הפריימר היא קריאה שנדחתה עם קוד 7. שום דבר לא מדבר על Editor מול Owner או על הסלמה.
- **la1, שאלה 3 (סדר התגובה):** נלמד ב-Stop It Moving ובפריימר Contain first, count second, על רובוט ברג'יסטרי של חבילות. לא מוזכרים חסימת IP, מחיקת חשבון או שמות שדות מהאירוע.
- **la2, שאלה 1 (מה זה allUsers):** עובדת זיכרון. היא מופיעה כשורה עם תווית ב-Anatomy of an Allow Policy על שירות Cloud Run, והמעבדה לא שואלת עליה. `domain:` ו-`allAuthenticatedUsers` לא מופיעים בכוונה, כדי לא לשלול מסיחים.
- **la2, שאלה 2 (מה קריאה ציבורית משאירה):** נלמד במעבדה משלו, Who Downloaded the Patch?, דרך השורות ולא דרך משפט: קריאה 2 מול קריאה 3, אותה הגדרת Data Access ורק לאחת יש רשומה, על קובץ patch ו-press kit ציבוריים, עם שחקנים ועיתונאים. אין נתוני לקוחות, אין גניבה ואין חקירה: השאלה שם היא ספירת הורדות של השיווק.
- **la2, שאלה 3 (מה עושים אחרי הורדה ציבורית):** הרעיון שחסימה לא סוגרת תיק נלמד בפריימר Contain first, count second, וחלון הזמן נלמד בשלב השני של Follow the Key, על מפתח ולא על bucket: השימוש הראשון שרואים הוא לא בהכרח השימוש הראשון.
- **ac1 (פסק דין על חשבון שירות):** נלמד ב-Fired Right, Still Fine? על render-farm, release-bot, crash-reporter ועוד, ובדוגמת הפריימר על התחברות של כונן בלילה. הכלל נשען על רשימת מעקב, והמקרה המתוזמן הוא snapshot של דיסק, כלומר שינוי ולא קריאה. אין במעבדה `compute.instances.list`, GKE או בדיקת בריאות יומית. ההבדל בין benign true positive ל-false positive נלמד על רשימה מיושנת.
- **m1 (התאמת שירותים):** ההתאמה הראשונה בחדר מכילה רק שירותים שלא נמצאים ב-m1. כל שורה של m1 נלמדת במקום אחר: IAM ב-Where Did the Role Come From?, חשבון שירות ב-Attached Token or Key File?, שרת המטאדאטה ב-Walk a Token Out of a VM, allUsers ב-Anatomy of an Allow Policy, ארבעת הזרמים ב-Which Log Stream?, ממצאים ב-Anatomy of a Finding (OPEN_FIREWALL על חוק ב-QA).
- **שאלת הביניים של r5 (משמעות קוד 7):** עובדת זיכרון. היא מופיעה כשורה עם תווית ב-Pivot on the Address ובפריימר של Anatomy of an Audit Entry, והמעבדה לא שואלת עליה.
- **la-sakey (למה מפתח USER_MANAGED הוא התמדה):** אורך החיים והניידות של מפתח נלמדים ב-Attached Token or Key File?, ו-`keyType` בפריימר של Whose Key Is It?. המעבדה לא עוברת על האפשרויות.
- **f1 (מי ביקש את המפתח, האות המכריע של הבוס):** נלמד במעבדה משלו, Whose Key Is It?, על matchmaker-svc ו-payments-bot, ובדוגמת הפריימר על dana ו-reports-bot. אין שם web-frontend, svc-data או מזהה המפתח הנבחן.
- **שאלת הביניים של r7 (הפעולה הראשונה):** Undo or Gone? שואלת רק מה ניתן לביטול, לא מה בא קודם, ודוגמת הפריימר היא השעיית חשבון של קבלן. Hold the VM for Forensics עוסקת רק ב-VM. המסיחים לא מוזכרים.
- **la-sakey (הפרדה נוספת):** השלב after ב-Follow the Key מראה מפתח על release-bot שנוצר דרך התחזות, על החשבון שהקריאה רצה בשמו. אין שם מתקשר ובעלים שצריך להבדיל ביניהם, וה-`why` לא מסביר למה מפתח כזה מסוכן.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Four Days" | כניסה | תחנה 1 |
| Chapter 2: "Nobody Granted It" | אחרי The Org Tree | תחנה 2 |
| Chapter 3: "One Analyst Short" | אחרי The Mod Kit Key | תחנה 4 |
| Finale: "Project ID" | אחרי The Six Minutes | החדר הבא |
