# תסריט חדר 77: Email Protocols & Header Forensics

**שם המבצע:** Operation Return Path
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Saffron Road Imports (יבואנית תבלינים ותה בדויה): 64 עובדים, מחסן ערובה אחד, ומכולה של זעפרן והל שמחכה בנמל עד שהמכס ישולם.
**המנטור:** Ikaika Moretti, Email Forensics Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שלישי בבוקר מגיעה ל-Accounts Payable הודעה מ-Brightquay Customs Brokers עם חשבון בנק חדש לתשלום המכס, שלושה ימים לפני הדדליין. השם נכון והניסוח נכון, אבל הכותרות סותרות זו את זו. d.ferro משחרר את ההודעה מההסגר, והקובץ הגולמי מגיע אל Ikaika Moretti. החדר הולך אחורה: מהתיבה אל השורה האחרונה ששרת של החברה עצמה כתב, ומשם אל מה שבאמת אפשר להוכיח. ביום חמישי התוקף חוזר עם דומיין משלו, והפעם כל הבדיקות עוברות.

## המכניקה הייחודית של החדר
- **Read the Received Chain Backwards:** מעבדת `pathway`. הלומד הולך על שורות ה-Received מהתיבה אחורה, עד העובדה האחרונה ששרת שלו רשם, ועוצר שם. כל מה שמתחת לגבול הוא טקסט שהשולח יכול היה להקליד, וקפיצה לשורה התחתונה, לשם ה-EHLO או לשורת From עולה בחיים.
- **Set a Genuine Invoice Beside a Forged One:** מעבדת `spotdiff`. חשבונית אמיתית מאוקטובר ליד זיוף שמדביק את שורות ה-Received התחתונות ואת ה-DKIM-Signature שלה. הרמז הוא דווקא מה שזהה: השורות שהודבקו, והקפיצה של 29 יום בגבול של השרת שלך.
- **Work Out the SPF Result:** מעבדת `codebreak`. הלומד מחשב SPF לבד מרשומה ו-IP, כולל טווחי CIDR, ומקליד את התוצאה.
- **Which DKIM Hash Does This Break?:** מסוע (`reactor`) שמפריד בין `bh=` ל-`b=` ולמה שבכלל לא מכוסה. **What Survives Forwarding?** מריץ את אותה הודעה בחמש דרכים, ו-**Anatomy of an ARC Set** קורא את עדות החותם.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) עם ליבה מסוג `knot` וחמישה קלפים לפי התחנות. שם הסצנה `facilityreturnpath`, ערכת הנושא `returnpath`.

## סדר המשימות
r1, o1, r2, q1 | r3, q3 | r4, r5, r6, q2, m1 | la1, f1, qf1, la2 | ac1

(סדר חדש. בחדר המקורי כל הקריאות מרוכזות בהתחלה, ולכן אי אפשר לחלק אותו לתחנות. o1 אחרי קריאת SMTP, q1 אחרי envelope מול header, q3 אחרי קריאת ה-Received, q2 ו-m1 צריכים DMARC ו-ARC, f1 ו-qf1 נשענים במפורש על la1, la2 נכתבה כהמשך ל-la1, ו-ac1 הוא הבוס. האינטגרטור מיישם את הסדר.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Envelope | r1, o1, r2, q1 | **Read the SMTP Session on the Wire** (pcap), **Which Sender Field Does What?** (sort), **Does a Return-Path Mismatch Prove Anything?** (worksheet) |
| 2 | The Chain | r3, q3 | **Anatomy of One Received Line** (anatomy), **Read the Received Chain Backwards** (pathway), **Read the Clocks Down the Chain** (worksheet) |
| 3 | The Seals | r4, r5, r6, q2, m1 | **Work Out the SPF Result** (codebreak), **Count the SPF DNS Lookups** (worksheet), **Anatomy of a DKIM Signature** (anatomy), **Which DKIM Hash Does This Break?** (reactor), **What Survives Forwarding?** (simulate), **Anatomy of an ARC Set** (anatomy), **Read Policy Against Disposition** (worksheet) |
| 4 | Side by Side | la1, f1, qf1, la2 | **Set a Genuine Invoice Beside a Forged One** (spotdiff), **Scope the Response to Each Message** (queue), **What Would This KQL Return?** (worksheet), **Everything Passed. What Still Gives It Away?** (hotspot) |
| 5 (בוס) | Return Path | ac1 | **Which DKIM Failure Can You Explain?** (worksheet), **Fired Right, or Fired Wrong?** (sort), ואז ההחלטה הנבחנת |

**תמהיל המשחקים:** codebreak + pathway + spotdiff. אין מעבדת `terminal`.

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (איזו שורה נתנה ל-SPF את הדומיין):** נלמד ב-Read the SMTP Session on the Wire, במשימה על MAIL FROM. השוני: `ops@hostline.example` מ-198.51.100.44, עם שני RCPT TO, לא bounce-8841 ולא 154.16.88.201.
- **o1 (סדר שיחת SMTP):** ה-primer של אותה מעבדה וחבילות הלכידה מראים את הסדר כנתון, כולל STARTTLS ו-EHLO חוזר. אף מעבדה לא מבקשת לסדר צעדים, ואין בחדר `sequence`.
- **q1 (Return-Path מול From):** Does a Return-Path Mismatch Prove Anything?. חמש הודעות של ספקים, והדוגמה לאי-התאמה לגיטימית היא ספק דיוור. ההתאמה (alignment) נלמדת ב-primer. אין שם billing, solvix או random-marketing-relay.
- **שאלת הביניים של r3 והדגל f1 (תחתית השרשרת, השם שנטען):** Read the Clocks Down the Chain שואלת על המקרה של Kochi, והתשובה היא `pc-billing3.malabarspice.example`. Anatomy of One Received Line מלמדת שהשם אחרי `from` הוא טענה. לא mail-relay-09 ולא sv-notify-relay.
- **q3 (במי לבטוח):** האות המכריע מקבל מעבדה משלו: Read the Received Chain Backwards. חמש שורות עם גבול ב-inbound1. ESMTPS נלמד באנטומיה של שורה. ניסוחי התשובות לא מופיעים.
- **שאלת הביניים של r4 (12 בדיקות DNS):** Count the SPF DNS Lookups מגיעה ל-11 עם ספק אחד, והמילה permerror מופיעה רק כנתון ב-`why` וב-primer של Work Out the SPF Result. הקוד הנכון שם הוא SOFTFAIL, NEUTRAL, PASS, TEMPERROR, ו-PermError לא נשאל.
- **שאלת הביניים של r6 (relaxed):** ה-primer של What Survives Forwarding? ושאלת `adkim=s` ב-Read Policy Against Disposition. השוני: הדוגמה הנשאלת היא strict, ודומיינים אחרים.
- **q2 (dkim=fail לצד dmarc=pass):** What Survives Forwarding?, בתרחיש Plain forward: מספיק מעבר מיושר אחד, לא משנה איזו בדיקה סיפקה אותו. שילוב התוצאות הנבחן (SPF עובר, DKIM נכשל) לא מופיע במעבדה, והסיבה נלמדת ב-Which DKIM Hash Does This Break?. אין שם billing@solvix.
- **m1 (התאמת שדות):** כל שש השורות נלמדות במעבדות של תחנות 1 עד 3 כנתון, במילים אחרות. אין בחדר משימת `match`.
- **la1 שאלה 1 (שלושה דומיינים):** Set a Genuine Invoice Beside a Forged One. מדובר בבנק של עמיל מכס, לא בהעברה של סמנכ"ל כספים.
- **la1 שאלה 2 (p=reject עם dis=none):** Read Policy Against Disposition. השורה עם הפער היא `p=quarantine; pct=100`, ולצדה שורה עם `pct=25` שמסבירה את עצמה. הזוג p=reject עם dis=none לא מופיע בשום מעבדה.
- **la1 שאלה 3 (תגובה):** Scope the Response to Each Message. ארבע הודעות אחרות. העתק נסתר של s.haddad, Reply-To שמוביל לתוקף, וחוק allow ישן בשער.
- **qf1 (KQL):** What Would This KQL Return? סופרת שורות ביד, ומשתמשת ב-CompAuth, שלא מופיע בתבנית הנבחנת. הדומיין הוא saffronroad.example, והתבנית עצמה לא מועתקת.
- **la2 (הכול עובר, ועדיין פישינג):** Everything Passed. What Still Gives It Away?. דומיין קרוב שמוסיף מילה ומקף, `brightquay-clearance.example`, בן 6 ימים, על שינוי חשבון בנק. לא החלפת אות באפס, לא יומיים ולא משכורת.
- **ac1 (הבוס, סימן מכריע):** מקבל שתי מעבדות משלו, ובנוסף Anatomy of an ARC Set. Which DKIM Failure Can You Explain? מלמדת להפריד בין טקסט הכשל, List-Id, Subject, ARC-Authentication-Results וזהות החותם, על רשימות סחר חיצוניות, עם חותם לא מוכר ועם חתימה מודבקת. Fired Right, or Fired Wrong? מלמדת benign true positive מול false positive על התראות דואר אחרות. אין שם רשימה פנימית של מהנדסים ואין אימות של IT על אותה רשימה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Three Days to Friday" | כניסה | תחנה 1 |
| Chapter 2: "Who Wrote This?" | אחרי The Chain | תחנה 3 |
| Chapter 3: "A Quiet Thursday" | אחרי Side by Side | תחנה 5 |
| Finale: "Return Path" | אחרי Return Path | החדר הבא |

- **Three Days to Friday:** הנמל, המכולה, החשבונית שנראית נכונה. d.ferro לוחץ על Release. הסיפור מוצג דרך השעון של דמי האחסנה.
- **Who Wrote This?:** Ikaika Moretti מתקשר ל-Brightquay למספר שכבר רשום בתיק, ושם אף אחד לא שלח שום דבר. השאלה עוברת מ"מה הגיע" ל"מי ערב לזה". לא מוצגים ערכי SPF או DKIM.
- **A Quiet Thursday:** ההודעה השנייה מגיעה נקייה, ו-Accounts Payable עוצר אותה בעזרת שיחת טלפון. הכסף נשאר בחברה, והמכולה משתחררת. אחרי זה מגיע יום שישי, וכל החברה מדווחת על כל DKIM fail. הסרט לא מלמד איך מכריעים בתיק הבוס.
- **Return Path:** מתברר איך התוקף השיג חשבונית אמיתית: תיבה פרוצה אצל Brightquay. החשבון נסגר, והמכס משולם בזמן.
