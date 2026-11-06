# תסריט חדר 110: Cloud Attacker Actions

**שם המבצע:** Operation Last Cloud
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Aurelia Space Systems (חברה בדויה): בונה לוויני תצפית קטנים, וכל תמונה שיורדת מהם נוחתת בארגון AWS אחד.
**המנטור:** Nils Ferreira-Okoye, Cloud Threat Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום ראשון בלילה החשבון שמריץ את מקטע הקרקע של Aurelia משתתק: אין ממצאים, אין התראות, הדשבורד ירוק, ועד סקירת השיגור נשארו שנים עשר יום. Nils Ferreira-Okoye לא סומך על חשבון שקט: מי שיכול לעצור לוג לא משאיר פתק. זה החדר האחרון בקמפיין, והוא בנוי כמבחן סיכום של שיטה: לקרוא מה יש, לשאול מה חסר, ולמצוא את העותק שהתוקף לא הגיע אליו.

## המכניקה הייחודית של החדר
- **What's Missing Is the Alert:** `trace` שעובר דרך GuardDuty, מצב ה-trails והעותק של ה-organization trail, מהממצא האחרון ועד הקריאה שגרמה לשקט. הממצא של הסיפור הוא StopLogging.
- **The Copy That Still Shows It:** `duel` שבו כל מהלך התחמקות נפגש עם העותק מחוץ לחשבון שעדיין מראה אותו. קלפים שיושבים בחשבון שנפרץ הם בתוך הטווח של התוקף.
- **Find the Region Nobody Watches:** `hunt` ב-KQL של שש שורות (חמש מדרגות) שמשווה את הלוג למלאי כיסוי ומגלה עבודה ב-Region בלי detector.

חדרי הענן הקודמים מלמדים לנטר. החדר הזה מלמד מה התוקף עושה בפועל, ומסיים את הקמפיין בדרישה לכל ההרגלים יחד.

## העולם התלת-ממדי
אי קמפוס (`campus`) עם חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה. theme: `lastcloud`, scene: `facilitylastcloud`, layout: `facility`.

## סדר המשימות
r0, r1, r2, q1 | r3, q2, r4 | r5, q3, r6, o1 | r7, la1, ac1, m1 | q4, f1

הסדר המקורי של החדר נשמר. הדגל מפנה אל "the log analysis task" בלי מספר, ויש בחדר משימת log analysis אחת, כך שההפניה נשארת נכונה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Trail | r0, r1, r2, q1 | **Follow a Silence to Its Cause** (trace), **Re-Map the Rule Pack** (worksheet), **Read a Firewall Change Field by Field** (anatomy), **Tune a New-Launch Rule** (tune) |
| 2 | The Copies | r3, q2, r4 | **Read a Snapshot Share Line by Line** (inspect), **Work Through the Snapshot Ledger** (worksheet), **What Survives a Termination?** (sort), **Run a Lockout Against Three Setups** (simulate) |
| 3 | Below the Log | r5, q3, r6, o1 | **Which Identity Was Reached Through Its Host?** (deduce), **Find the Region Nobody Watches** (hunt), **One Alert, Two Directions** (worksheet) |
| 4 | The Baseline | r7, la1, ac1, m1 | **Four Checks Before You Close** (queue), **The Copy That Still Shows It** (duel) |
| 5 (בוס) | Last Cloud | q4, f1 | **Does It Reach the Cloud API?** (sort) ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r0** (פיצול Defense Evasion וההמרה של שני המזהים): **Re-Map the Rule Pack** מראה את העובדות כנתונים עם תווית ולא שואל אותן. השאלות שם הן ספירות ושיקול דעת על חבילת חוקים. שונה: אף שאלה לא מבקשת את ההמרה עצמה.
- **שאלת הביניים של r1** (EC2.13 ו-EC2.14): הערה בשדה `cidrIp` ב-**Read a Firewall Change Field by Field** מציגה את שתי הבקרות כנתון עם תווית, בלי לשאול.
- **שאלת הביניים של r2** (מה מפריד בין שתי השקות): **Tune a New-Launch Rule** מלמד היסטוריה של זהות ונתח Region דרך חוגות. שונה: סוגי g5 ו-t3, לא g4dn.xlarge, ואין השוואה בין שתי שורות זהות.
- **q1** (שתי טכניקות, הסדר, טקטיקה משותפת): ה-primers של **Read a Firewall Change Field by Field** ו-**Tune a New-Launch Rule** מציגים את T1686.001 ו-T1578.002, וטבלת **Re-Map the Rule Pack** מראה את הטקטיקה שלהם. שונה: שום מעבדה לא מראה קבוצת אבטחה שנוצרה ומיד אחריה השקה, ו-ap-southeast-1 לא מופיע.
- **שאלת הביניים של r3** (מה createVolumePermission קובע): **Read a Snapshot Share Line by Line** מראה את העובדה כנתון בשורה שלה. שונה: שיתוף לילי לחשבון ה-DR של Aurelia עצמה, בלי פסק דין.
- **q2** (איזו פעילות היא דפוס ה-T1578.001): **Work Through the Snapshot Ledger** מלמד לעקוב אחרי ה-grant לאן שהוא מצביע. שונה: שש תמונות שנבחרו מתוך שבוע, מזהה מוכר ולא חדש, בלי 30 שניות, ומספר חשבון אחר.
- **שאלת הביניים של r4** (למה נעילה בענן טוטאלית): **Run a Lockout Against Three Setups** מריץ את אותה נעילה על שלושה מערכים. שונה: המערך הפיזי הוא אשכול hypervisor עם root מקומי בקונסולה, לא Active Directory, כך שהלומד מעביר את הרעיון בעצמו, ויש מערך שלישי של חשבון חירום.
- **שאלת הביניים של r5** (DirtyPipe): מוזכר בהסבר הסיום של **Which Identity Was Reached Through Its Host?** ולא נשאל. התא בטבלה מתאר רק shell של root בלי אירוע sudo.
- **q3** (הסבר לקריאות חדשות של role): **Which Identity Was Reached Through Its Host?** מלמד את ההבדל בין לתת לזהות יותר לבין להגיע לזהות קיימת. שונה: קובץ מפתח של root על שרת EC2, לא pod, לא node role ולא קריסה של container runtime. הדוגמה ב-primer היא VM ב-Azure עם טוקן של Key Vault.
- **o1** (סדר חמשת השלבים): **One Alert, Two Directions** מלמד תלות בין שלבים וציד לשני הכיוונים. שונה: קלפים לא מסודרים מתרגיל ב-Azure, בלי סידור ובלי חמשת הניסוחים הנבחנים.
- **שאלת הביניים של r7** (למה GuardDuty יכול לפספס): השורה של DeleteDetector ב-**Follow a Silence to Its Cause**, מהלך m2 ב-**The Copy That Still Shows It** וההתראה הבודדת על שיתוף ב-**Four Checks Before You Close**.
- **la1** (איזה שדה מראה היקף, ולמה זה חלק מתקרית): **Read a Firewall Change Field by Field** מתאר כל שדה בלי לשפוט. **Four Checks Before You Close** מלמד קישור לפי session. שונה: Terraform על פורט 5432 מ-10.40.16.0/24, לא 3389 מ-0.0.0.0/0, והקישור הוא DeleteFlowLogs לפני שינוי פנימי, לא שינוי IAM.
- **ac1** (Benign True Positive): **Four Checks Before You Close** מלמד את ארבע הבדיקות ואת שלושת פסקי הדין. שונה: Terraform ו-AWS Backup, בלי RunInstances ובלי Auto Scaling, ודוגמת ה-primer היא PutKeyPolicy.
- **m1** (התאמת פעולה ל-eventName): כל ששת השמות מופיעים כנתונים (tune, inspect, sort, trace, duel) ואף מעבדה לא שואלת את ההתאמה. התשובה ב-trace היא StopLogging, שלא נמצא ב-m1.
- **q4** (הבוס: מה מסביר את אירוע 09:14 ולמה קשה לתפוס אותו): האות המכריע נלמד במעבדה משלו, **Does It Reach the Cloud API?**, ובנוסף ב-**Which Identity Was Reached Through Its Host?**. שונה: פעולות בודדות על EC2 בלי קונטיינר ובלי ציר זמן.
- **f1** (מזהה הכלל): השדה `securityGroupRuleId` ב-**Read a Firewall Change Field by Field** מלמד איפה המזהה יושב ומה הוא מאפשר. שונה: אירוע אחר ומזהה אחר.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Quiet Account" | כניסה | תחנה 1 |
| Chapter 2: "Twelve Days" | אחרי The Trail | תחנה 2 |
| Chapter 3: "Out of Reach" | אחרי The Copies | תחנה 3 |
| Finale: "Last Cloud" | אחרי Last Cloud | סוף הקמפיין |
