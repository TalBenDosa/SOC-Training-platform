# תסריט חדר 60: Incident Response Methodology

**שם המבצע:** Operation Tabletop
**רמה:** בינוני
**העולם:** Oakhollow Water Trust (תאגיד מים בדוי): שני מכוני טיהור, 210,000 תושבים על הקו, ויום אחד בשנה שבו אף אחד לא נוגע בשרת אמיתי.
**המנטור:** Imogen Achieng, Incident Manager. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
הרגולטור דורש תרגיל שולחן פעם בשנה. Imogen מפנה את חדר הישיבות, פורסת את מפת הרשת על השולחן ומניחה חפיסת קלפים הפוכה. כל קלף הוא רגע אחד בחדירה שעוד לא קרתה: חשבון קבלן בלי MFA ב-VPN, כלי מרחוק על לפטופ של מהנדס, חשבון domain admin גנוב, ודרך שמובילה למערכת שמפעילה את המשאבות. מה שנרשם ביומן לא נמחק, והקלף הבא מתחיל ממה שהשארת על השולחן. בסוף, כשהקלפים כבר נאספים, הביפר מצלצל באמת.

## המכניקה הייחודית של החדר
**תרגיל שולחן חי:** אירוע אחד רץ לאורך כל החדר בשמונה חבילות קלפים (Decks), וכל חבילה נפתחת במה שההחלטה הקודמת השאירה.
- **יומן התרגיל:** שלוש מעבדות `queue` עם שורות "Carried in" ו-"Carries forward". לוגי VPN שנשמרו בהכנה חושפים את הכניסה הראשונה, הכניסה הראשונה בוחרת את נקודת השחזור, ו-image של הזיכרון כותב את רשימת האיפוסים.
- **Contain It Before It Reaches SCADA:** מעבדת `outbreak` תחת לחץ, על רשת שנבנית מחדש בכל ריצה.
- **Run B:** מעבדת `defuse` שמשחקת את אותו אירוע כפי ששיחק אותו צוות שבחר תמיד בדרך הקצרה. כל מודול הוא החשבון שהגיע על קיצור דרך אחד.

## העולם התלת-ממדי
אי קמפוס (`facility`, סצנה `facilitytabletop`, ערכת נושא `tabletop`) של התאגיד: חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1, flag1 | r2, q3, q1 | r3, q4 | q2, q5 | la1

הסדר שונה מהסדר בחדר (r1, r2, r3, q1, q2, q3, la1, flag1, q4, q5), כדי שכל שאלה תבוא אחרי הקריאה שלה והמשימה הקשה ביותר תסגור את החדר.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The First Call | r1, flag1 | **Event, Alert or Incident?** (queue), **Which Phase Owns This Job?** (sort), **Who Takes This Card?** (duel) |
| 2 | Stop the Spread | r2, q3, q1 | **Rate the Incident Again as the Facts Arrive** (queue), **Evidence Before the Power Lead** (defuse), **Stop It Now, Hold It Stable, or Later?** (reactor), **Contain It Before It Reaches SCADA** (outbreak) |
| 3 | Clear Them Out | r3, q4 | **Read the Eradication Sheet** (inspect), **Eradicate, Then Recover: Approve, Hold or Refuse** (queue) |
| 4 | Restart and Review | q2, q5 | **Run B: What Each Shortcut Costs** (defuse), **Mark Up the Review Draft** (hotspot) |
| 5 (בוס) | Not a Drill | la1 | **Anatomy of a Disguised Process** (anatomy), ואחריה הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 ו-flag1 (Containment):** זכירה טהורה. שם השלב מופיע כסל ב-**Which Phase Owns This Job?**, והמעבדה מלמדת אותו על חסימת דומיין ועל חסימה זמנית בין רשת המשרדים לרשת המתקן. אף מעבדה לא שואלת לאיזה שלב שייך בידוד שרת נגוע.
- **שאלת הביניים של r2 ו-q1 (בידוד לפני זיכרון):** הרעיון נלמד ב-**Evidence Before the Power Lead**, מודולים spread ו-first, וב-**Run B** מודול ram. הדוגמה היא שרת שמתפשט ב-PsExec, לא תחנת עבודה שמצפינה share. אין במעבדות כופרה ואין ניסוח של האפשרויות הנבחנות.
- **q2 (גיבוי מלפני הכניסה הראשונה):** נלמד ב-**Run B** מודול date ובקלף restore של **Approve, Hold or Refuse**. אצלנו 10 ימי נוכחות ונקודת שחזור נקייה עדיין קיימת, לא 45 ימים מול retention של 30.
- **q3 (מה Identification בודק):** שלוש השאלות מופיעות כשורות נתונים בכל קלף של **Rate the Incident Again**, ובקלפים i1 עד i3 של המיון, על האירוע של המעבדה. אף מעבדה לא שואלת מה מטרת השלב.
- **q4 (KRBTGT):** זכירה טהורה. העובדה מופיעה פעם אחת כשורה עם תווית ב-**Read the Eradication Sheet**, ואף מעבדה לא שואלת אותה.
- **q5 (מטרת הישיבה והמועד):** נלמד ב-**Mark Up the Review Draft** וב-**Run B** מודול notes. דו"ח טיוטה במקום אפשרויות, והחלון של 24 עד 72 שעות מופיע פעם אחת כשורה תקינה בדו"ח, ואף מעבדה לא שואלת אותו.
- **la1 שאלה 1 (masquerading):** נלמד ב-**Anatomy of a Disguised Process** על spoolsv.exe ב-ProgramData, לא svchost.exe ב-Temp.
- **la1 שאלה 2 (scope):** אותה אנטומיה, והיקף האירוע נקרא משורת הפקודה, לא משדות volumes. אין SRV-FILE01, SRV-NAS01 או LockBit. P1 נלמד ב-**Rate the Incident Again**.
- **סדר השלבים:** אין מעבדה ששואלת על סדר השלבים. אין בחדר מעבדת `sequence`.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Face Down" | כניסה | תחנה 1 |
| Chapter 2: "The Clock Started" | אחרי The First Call | תחנה 2 |
| Chapter 3: "The Same Night, Again" | אחרי Clear Them Out | תחנה 4 |
| Finale: "Cards Down" | אחרי הבוס | החדר הבא |
