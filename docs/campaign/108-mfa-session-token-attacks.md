# תסריט חדר 108: MFA Attacks & Session/Token Theft

**שם המבצע:** Operation Stolen Session
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Kingsmere Private Hospital (בית חולים פרטי בדוי): 92 מיטות, ארבעה חדרי ניתוח ו-tenant אחד שכולם מתחברים אליו, מהמנתחים ועד המטבח.
**המנטור:** Hyun-woo Salazar, Identity Threat Hunter. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שלישי ב-09:40 ביקשה תיבת הדואר של Maeve Tierney, מנהלת חדרי הניתוח, מהנהלת החשבונות לשנות את פרטי הבנק של ספק שתלים. באותה שעה Maeve הייתה בחדר ניתוח 2. ה-MFA עבר, הסיכון none, ו-Conditional Access מראה success, ולכן Hyun-woo רוצה לדעת מי באמת ישב בתוך הסשן. בהמשך השבוע מתברר שאותה חבורה ניסתה דרך נוספת דרך משמרות הלילה, ושבארגון יש עוד שכבות של tokens שהמילה "גניבת token" מכסה.

## המכניקה הייחודית של החדר
- **After MFA Passed:** החתימה של החדר היא מה שקורה אחרי שה-MFA עבר, בשני חלקים.
- **One Session, Two Places:** פורטל בסגנון Entra מעל יומני sign-in, עם הלשוניות interactive ו-non-interactive. הלומד עוקב אחרי Session ID אחד שמופיע משני מקומות, משווה מכשיר ודפדפן, רואה שורה ירוקה לגמרי על סשן שנגנב, ומסיים ב-Revoke sessions.
- **Follow the Relay + Where the Replay Stops:** זוג `pathway`. הראשון הולך דרך AiTM, העוגייה שהועתקה וה-replay. השני לוקח token מועתק דרך הבקרות בטננט עד לבקרה שעוצרת אותו באמת.
- **Tune:** שני כיוונונים: חוק לסופת דחיפות על לוגי Okta, וערך sign-in frequency שמראה מה הוא משיג ומה לא.

## העולם התלת-ממדי
אי קמפוס (`facility`) של בית החולים: חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם בית החולים.

## סדר המשימות
r1, r4, o1 | r5, la1 | r2, q1, r3, q2, ac1 | r6, q3, r7 | r8, q4, f1

הסדר המקורי פתח ב-fatigue והשאיר את ac1 ו-o1 רחוק מהנושא שלהם, ואילו התחנה הראשונה, The Cookie, צריכה ללמד את העוגייה. עכשיו כל משימה יושבת ליד הקריאה שלה: AiTM ו-o1 יחד, fatigue ו-ac1 יחד. אין דגל או שאלה שמפנים למספר משימה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Cookie | r1, r4, o1 | **Anatomy of a Session Cookie** (anatomy), **Tricked, Stolen or No Login at All?** (sort), **Follow the Relay** (pathway) |
| 2 | Two Places | r5, la1 | **One Session, Two Places** (portal), **Trip, Roam or Replay?** (worksheet) |
| 3 | The Push | r2, q1, r3, q2, ac1 | **A Push Storm, From the Attacker's Chair** (sequence), **Read the Okta Trail** (worksheet), **Tune the Push-Storm Rule** (tune), **How Does It Close?** (queue) |
| 4 | Other Tokens | r6, q3, r7 | **Which Log Holds It?** (sort), **The Sign-In Nobody Issued** (worksheet) |
| 5 (בוס) | After MFA Passed | r8, q4, f1 | **How Short a Session?** (tune), **Where the Replay Stops** (pathway), **Does the Attack Cross That Gate?** (locks) |

**הפרדה מהשאלות הנבחנות:**
- **o1 (סדר שרשרת AiTM):** הרעיון נלמד ב-Follow the Relay, שורות ה-notes של הצמתים proxy עד exo. השוני: QR ב-PDF וקוד OATH מוקלד, בלי קישור ובלי push, והמסלול נגמר בתיבת דואר. שלב ההתמדה (רישום method חדש) מופיע רק כשורת audit בפורטל, בשעה 09:36.
- **la1 שאלה 1 (מה מוכיח שזה אותו סשן):** נלמד בפורטל, הצעדים match ו-device, וב-worksheet Trip, Roam or Replay?. השוני: replay אחרי 38 דקות (לא 11), הכניסה הראשונה מגיעה מכתובת ה-proxy בטלפון, בוקרשט ופרנקפורט במקום אמסטרדם ושיקגו. המשחק מלמד גם הפוך: מחשב נייד שעובר ל-hotspot שומר על אותו Session ID.
- **la1 שאלה 2 (risk none ו-CA success):** נלמד בצעד green של הפורטל, על שורה שכבר הוכחה. הטקסט מתאר מה השדות מראים ולא עובר על המסיחים.
- **r5 (נקודת ביניים):** אותו צעד, ובדיקת "Previously satisfied" בצעד claim.
- **q1 (למה רצף דחיות חשוב):** נלמד ב-doneNote של ה-sequence ובלקח של Tune the Push-Storm Rule. השוני: 5 דחיות ב-8 דקות אצל l.fenn ושישה אירועי טבלה אחרים, אף פעם לא 11 דחיות ב-12 דקות.
- **q2 (זוג השדות של אישור):** עובדה של זכירה בלבד, ולכן מופיעה רק בשורה עם תווית (שורת 02:00:06) ובנקודת primer. לא נשאלת בשום מעבדה.
- **r3 (נקודת ביניים, Number Challenge):** נלמד בנקודת primer של Read the Okta Trail, על דוגמה של מוצר אחר (Verified Duo Push), ובהמשך בדלת Number matching ובמלכודת nm של Where the Replay Stops.
- **ac1 (דחייה אחת, benign true positive):** אוצר המילים נלמד ב-How Does It Close? על רישום factor, על קובץ רוטה שנכשל ועל נסיעה. אין שם דחיית push יחידה. "דחייה אחת או שתיים לא עולות לבד" נלמד בלקח של Tune the Push-Storm Rule ובאירוע n5.
- **q3 (תווית שגויה):** נלמד ב-Which Log Holds It?. השוני: אפליקציית רוטה עם Files.ReadWrite.All וסקר עם Sites.Read.All, בלי קריאת תיבת דואר.
- **f1 (T1528):** מופיע כנתון עם תווית ב-primer וב-why של Tricked, Stolen or No Login at All? וב-Which Log Holds It?. לא נשאל.
- **q4 (בוס: מה עדיין מצליח):** האות המכריע נלמד במעבדה משלו, Does the Attack Cross That Gate?. הדוגמה המחושבת היא sandbox מול USB, והדלתות הן ארבעה זוגות אחרים: FIDO2 מול consent, number matching מול Golden SAML, sign-in frequency מול T1134.001, וגלגול תעודה מול סשן של Entra. Token Protection מול fatigue לא מופיע בשום מקום. העובדה על Token Protection עצמה נלמדת ב-Where the Replay Stops, על token מועתק של לקוח desktop.
- **נקודת הביניים של r1:** נלמדת ב-Anatomy of a Session Cookie, בניסוח אחר.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Theatre Two" | כניסה | תחנה 1 |
| Chapter 2: "Everything Was Green" | אחרי The Cookie | תחנה 2 |
| Chapter 3: "The Night Shift" | אחרי The Push | תחנה 4 |
| Finale: "What Would Have Stopped It" | אחרי After MFA Passed | החדר הבא |

**הערות לסרטונים (רקע בלבד):** Intro: המייל ב-09:40, Maeve בחדר ניתוח, הנהלת החשבונות עוצרת רגע לפני התשלום. Chapter 2: Hyun-woo מול הבורד של בית החולים, בלי תשובה עדיין. Chapter 3: משמרת לילה, טלפונים של רופאים תורנים, והמבט של Hyun-woo עובר מחשבון אחד לכל המשמרת. Finale: הבורד שואל מה נסגר ומה נשאר פתוח, בלי לומר מי מהבקרות מכסה מה.
