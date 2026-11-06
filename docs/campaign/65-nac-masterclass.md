# תסריט חדר 65: Network Access Control

**שם המבצע:** Operation Front Door
**רמה:** בינוני
**העולם:** Ravensford Academy Trust (רשת בתי ספר בדויה): שבעה בתי ספר, רשת אחת, ועד הקיץ כל שקע קיר בכל כיתה הגיע לתיקי התלמידים.
**המנטור:** Lwazi Petrov, Network Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
בחופש הגדול Lwazi סגר את השקעים עם 802.1X, כך שכל מכשיר צריך להוכיח את עצמו לפני שהפורט נפתח. ביום שני הראשון של הלימודים, מצלמת מסדרון ב-Hollins Vale Academy נכנסה לרשת מאגף הספרייה, מקום שבו מעולם לא הייתה מצלמה. תיעוד ה-RADIUS accounting מראה שהסשן הזה שלח הרבה יותר נתונים ממה שמצלמה שולחת. החדר הולך אחרי הדלת: איך פורט מחליט, מי באמת מחליט, מה התשובה נושאת, ואיך מרמים את הדלת.

## המכניקה הייחודית של החדר
- **Walk the 802.1X Door:** מעבדת `pathway` שמוליכה מכשיר דרך supplicant, authenticator ו-RADIUS עד Access-Accept, VLAN ותוצאת posture. כל קפיצה שגויה מלמדת למה: DHCP לפני אישור, מתג שפונה ישירות ל-AD, Access-Reject, והסגר שמגיע בתוך Access-Accept.
- **Tune the MAB Door:** מעבדת `tune` עם שני חוגים (certainty factor ופורטים לא צפויים) שמתוכננת כך שמדפסות ומצלמות עוברות וכתובת MAC משובטת לא. כל חוג לבדו נכשל.
- **Listen at the Closed Port:** לכידת תעבורה מהפורט הסגור, שבה רואים בעיניים מה עובר ומה לא.

## העולם התלת-ממדי
אולם הקלפים (`facility`, פריסת hall) עם ליבת `knot`. חמישה קלפים לפי התחנות. עולם `facilityfrontdoor`, ערכת נושא `frontdoor`.

## סדר המשימות
הסדר שונה מהסדר בחדר, כי בחדר כל הקריאות באות קודם והמשימות הנבחנות בסוף:
r1, r2, r3, q1 | r4, r7, r8, q3 | r5, r6, r9 | r10, q2 | la1, f1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Port | r1, r2, r3, q1 | **Three Questions at the Door** (sort), **Find the Missing Gate** (simulate), **Who Does This Job?** (reactor), **Listen at the Closed Port** (pcap), **Name the EAP Parts** (codebreak), **Read a Supplicant Profile** (inspect) |
| 2 | The Decision | r4, r7, r8, q3 | **Walk the 802.1X Door** (pathway), **Read the Access-Accept** (anatomy), **Who Was on That Port?** (trace), **Which ISE Node Does What?** (worksheet), **How ISE Reads a Request** (sequence), **What the Profiler Hears** (match), **Four Locks of ClearPass** (locks), **ClearPass Add-Ons** (match), **Which Leg Broke?** (simulate) |
| 3 | The Health Check | r5, r6, r9 | **Run the Posture Check** (simulate), **Who Reports Device Health?** (match), **Posture Results Are Leads** (queue), **Which VLAN for Which Device?** (sort), **Read the Session Table** (worksheet), **The Same Door in the Cloud** (match), **Who Guards This Session?** (sort) |
| 4 | The Bypass | r10, q2 | **Tune the MAB Door** (tune), **Which Bypass Left This Trace?** (lineup) |
| 5 (בוס) | The Quarantine Record | la1, f1 | **Read One ISE Record** (anatomy), **Rule or Profile?** (worksheet), ואז הרשומה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (איזה עיקרון דולג):** הרעיון נלמד ב-Find the Missing Gate, אבל שם חסרים Authenticate או Authorize, אף פעם לא Assess, ואין סוכן posture חסר או מחשב אישי עם אנטי-וירוס כבוי.
- **q1 (למה אין DHCP בזמן אימות):** העובדה שפורט UNAUTHORIZED מעביר רק EAPOL נלמדת ב-Listen at the Closed Port (מטרות o1 ו-o2). השוני: מחשב עם IP קבוע ששואל ARP, לא מחשב ששולח DHCP Discover.
- **שאלת הביניים של r3 (מי פחות חשוף ב-AP זדוני):** ההיגיון נלמד ב-Read a Supplicant Profile (שורות p3, p4: בלי אימות תעודת שרת, הצד השני של המנהרה הוא שרת RADIUS זדוני) וב-Name the EAP Parts (רמז c4 ו-why שלו: בתעודת לקוח אין סיסמה לגנוב). השוני: פרופיל קווי ב-Marsh Lane, לא AP זדוני ולא השוואה בין שתי קבוצות מחשבים.
- **q3 (היכן התקלה: RADIUS או AD):** שתי הרגליים נלמדות ב-Walk the 802.1X Door (הערות psn, ad, והמלכודת ad), ומיקום תקלה על רגל נלמד ב-Which Leg Broke?. השוני: shared secret שגוי, supplicant שהשתתק, סיסמה שגויה ו-CRL לא נגיש. אין שם נפילת directory.
- **שאלת הביניים של r5 (איזה סוכן למחשב מבקר):** העובדות מופיעות כזוגות ב-Who Reports Device Health? (h1 עד h4). אין שם מקרה של מחשב מבקר לשיבוץ.
- **שאלת הביניים של r7 (איזה צומת נפל):** ב-Which ISE Node Does What? התפקיד של PSN הוא שורה בטבלה בלבד. השאלות הן על סימפטומים של MnT ו-PAN.
- **שאלת הביניים של r9 (הגדרת SASE):** המרכיבים מופיעים רק ב-why של פריט g5 ב-Who Guards This Session?, ולא נשאלים.
- **q2 (פרופיל שהשתנה ל-Windows על אותו MAC):** הרעיון נלמד ב-Tune the MAB Door (האירועים b1 עד b4 והשיעור) וב-Which Bypass Left This Trace? (סבב r1 וסבבי ה-hub). השוני: המשובטים הם מצלמה, בקר דלת ושילוט על Linux או Mac, והמדפסות הן המכשירים הכשרים. גם ב-why של Who Was on That Port? המכשיר הוא מצלמה. הסחות הדעת (עדכון קושחה, hub) מקבלות הסבר דרך g4 וסבבי ה-hub.
- **la1 שאלה 1 (VLAN יחד עם ACL):** נלמד ב-Read One ISE Record (שדות selected_vlan ו-acl), ב-Read the Access-Accept וב-Read the Session Table (s3). השוני: VLAN 120 של קבלן ו-VLAN 199, לא VLAN 50 ו-ACL-QUARANTINE-REMEDIATION.
- **la1 שאלה 2 (הערכת סיכון של כשלי posture):** נלמד ב-Posture Results Are Leads. השוני: הצפנת דיסק, EDR שנעצר, תוכנה אסורה ואנטי-וירוס מכובה עם זיהוי EDR. אין שילוב של חתימות ישנות וטלאים חסרים.
- **la1 שאלה 3 (url-redirect):** נלמד ב-Read the Access-Accept וב-Read One ISE Record (שדה cisco_av_pair). השוני: דף תנאי שימוש לקבלן, לא פורטל תיקון אחרי הסגר.
- **f1 (שם ה-authorization rule):** האות המכריע, ההבדל בין rule ל-profile, מקבל מעבדה משלו: Rule or Profile?, וגם How ISE Reads a Request ו-Read One ISE Record. השוני: חמישה כללים אחרים, בלי Posture-NonCompliant ובלי פרופיל QUARANTINE.
- **מה משותף לכולם:** כל הנתונים הם של Ravensford ‏(ravensford.example, ‏VLAN 110/120/130/140/199), לא של corp.com, ‏SW-ACCESS-FL2-01 או ISE-PSN-01.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The First Monday" | כניסה: הקיץ שבו נסגרו השקעים, וההתראה הראשונה של הלימודים | תחנה 1 |
| Chapter 2: "That Afternoon" | אחרי The Decision: מצלמת המסדרון, סשן הספרייה ומה שהוא שלח | תחנה 3 |
| Chapter 3: "After the Last Bell" | אחרי The Health Check: Lwazi הולך לספרייה עם פנס, הסרטון מתגרה בשאלה מה יושב על הפורט ולא עונה עליה | תחנה 4 |
| Finale: "Front Door" | אחרי הבוס: מה שנמצא מאחורי הארון בספרייה, והדלת שנשארת סגורה | החדר הבא |
