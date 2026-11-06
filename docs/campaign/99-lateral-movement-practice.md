# תסריט חדר 99: Tracing Lateral Movement

**שם המבצע:** Operation Sidestep
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Corvid Cold Chain (חברה בדויה): שלושה מתחמים, שלושה שעונים, ורישום טמפרטורה לכל משטח חיסונים שעובר בהם.
**המנטור:** Tamsin Oyelowo, Threat Hunter. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
בשבת ב-02:14 UTC השרת CC-TEMPLOG-01 מדווח על קובץ טמפרטורה ששונה, שבוע לפני ביקורת של הרגולטור. ההתראה מצביעה על קובץ אחד בשרת אחד, ולא אומרת כלום על הדרך לשם. בשביל Tamsin Oyelowo ציד לא מתחיל מהתחנה האחרונה: המשימה היא לשחזר את כל המסלול, מארח אחרי מארח.

## המכניקה הייחודית של החדר
- **Rebuild the Graph:** התחברויות מכמה מארחים הופכות למפה של מי הגיע לאן. `pathway` של המסלול האמיתי: ארבע קפיצות, ארבע טכניקות, שלושה היסטי שעון. מי שלא ממיר ל-UTC נופל במלכודת.
- **Find the Pivot Host:** `hunt` ב-KQL של שבע שורות (שש מדרגות) שמחבר את הדרך החוצה של מארח לדרך פנימה שלו, על אותו מכשיר ואותו חשבון, ומוצא את מארח הציר.
- **Same Mechanism, Different Story:** `intercept` שבו כל מנגנון מופיע פעמיים ומסתיים פעם כך ופעם אחרת.

חדר 76 מלמד את הפרוטוקולים. החדר הזה הוא התרגול של מעקב אחרי מסלול שלם בין מארחים.

## העולם התלת-ממדי
אולם (`hall`) עם ליבת `chain`, ארבעה קלפי תחנה. theme: `sidestep`, scene: `facilitysidestep`, layout: `facility`.

## סדר המשימות
r1, r2, q1 | la1, la2, q2 | ac1, m1 | o1, qf1, f1

הסדר המקורי של החדר נשמר, ולכן ההפניות "Log Analysis 1" ו-"Log Analysis 2" ב-la2, ב-qf1 ובדגל נשארות נכונות.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The First Hop | r1, r2, q1 | **Which Host Holds Which Half?** (sort), **Read One Logon on the Target** (anatomy), **Where Did This Right Come From?** (worksheet) |
| 2 | What the Session Did | la1, la2, q2 | **Collect What the Record Leaves Out** (trace), **The Shape of a Remote Service** (sequence), **Read a New Service Record** (anatomy), **Same Mechanism, Different Story** (intercept) |
| 3 | Name the Move | ac1, m1 | **Name the Verdict** (sort), **Six Doors, Six Footprints** (inspect) |
| 4 (בוס) | Rebuild the Graph | o1, qf1, f1 | **Put Every Clock on UTC** (worksheet), **Rebuild the Graph** (pathway), **Find the Pivot Host** (hunt) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1** (למה רשומת המארח היעד לא מכריעה): **Read One Logon on the Target** מלמד שסיסמה נכונה כותבת את אותם ערכים בלי קשר למי שהקליד אותה. **Which Host Holds Which Half?** מלמד מה כל מארח רושם. שונה: רשומה רגילה של יום שישי בין שני שרתים, בלי פסק דין ובלי jump host.
- **q1** (מה הוכחה התקנת שירות): ה-primer של **Where Did This Right Come From?** מלמד שהזכות היא על היעד הספציפי, והטבלה מראה חמש הענקות מקומיות בלי Domain Admins. שונה: אין התקנת שירות, אין טענה של אנליסט, החשבון הוא אדמין בעל שם.
- **la1** (מה הרשומה מוכיחה, איזו ראיה חסרה, מה עושים): **Collect What the Record Leaves Out** מלמד היסטוריה, תור שינויים ומשמרות, ואז עבודה לשני הכיוונים. שונה: מקור מוכר בשעה לא נכונה ובעל חשבון בחופשה, לא מקור בלי היסטוריה. LogonType 3 מוסבר ב-anatomy הראשון.
- **la2** (קישור בין התחברות לשירות, שם ברירת מחדל, זכות מול הרשאה): **The Shape of a Remote Service** מלמד את סדר השלבים והקישור לפי מארח וזמן. **Read a New Service Record** מלמד את שדות 7045 ושמות ברירת מחדל. שונה: PAExec על מארח בדיקה מתרגיל purple team, לעולם לא PSEXESVC, והדוגמה ב-primer היא משימה מתוזמנת.
- **q2** (מה הבדיל בין שני מקרים זהים): **Same Mechanism, Different Story** מציג חמישה מנגנונים, כל אחד פעמיים, וכל זוג נושא אותה חבילת אימות, כך שההבדל יושב רק בהקשר. שונה: WMI, WinRM, RDP, משימות מתוזמנות ו-C$, בלי התקנת שירות.
- **ac1** (Benign True Positive): **Name the Verdict** מלמד את שלוש המילים, ו-**Same Mechanism, Different Story** מלמד את האות המכריע במעבדה משלו. שונה: חוקים אחרים לגמרי, בלי שירות מרוחק, בלי jump host ובלי פריסת סוכן.
- **m1** (התאמת טכניקה לעקבה): **Six Doors, Six Footprints** מציג את העובדות כנתונים עם תווית ולא שואל אותן. שונה: שש טכניקות במקום ארבע, ורשומות מתרגיל על CC-LAB-07.
- **o1** (סידור לפי UTC): **Put Every Clock on UTC** מלמד המרה, סדר הגעה מול סדר אירוע, ובדיקת סיבתיות. **Rebuild the Graph** מתרגל את אותו כלל על מפה. שונה: +02:00 ו-‎-05:00, לא +03:00, על עבודת patch, ומסלול של ארבע קפיצות ולא שתיים.
- **qf1** (KQL של התחברות ואחריה שירות): **Read One Logon on the Target** ו-**Read a New Service Record** מראים את מזהי האירועים ואת NtLmSsp כנתונים עם תווית. **Find the Pivot Host** מלמד חיבור בין טבלאות על אותו מכשיר. שונה: טבלאות Defender ולא SecurityEvent, חיבור בין יציאה להתחברות, בלי 7045, בלי allowlist ובלי חלון זמן.
- **f1** (כתובת המקור): השדה `IpAddress` ב-**Read One Logon on the Target** מלמד איפה יושבת כתובת המקור. שונה: רשומה אחרת, מארחים אחרים, כתובת 10.44.x.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Cold Record" | כניסה | תחנה 1 |
| Chapter 2: "Half a Story" | אחרי The First Hop | תחנה 2 |
| Chapter 3: "A Familiar Name" | אחרי What the Session Did | תחנה 3 |
| Finale: "Every Hop" | אחרי Rebuild the Graph | החדר הבא |
