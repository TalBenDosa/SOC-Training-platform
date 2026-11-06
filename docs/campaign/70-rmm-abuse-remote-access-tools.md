# תסריט חדר 70: RMM Abuse & Remote Access Tools

**שם המבצע:** Operation Helping Hand
**רמה:** בינוני
**העולם:** Brookmere Accountants (משרד רואי חשבון בדוי): 140 עובדים, שלושה סניפים, ותיקי המס של 2,100 עסקים קטנים, שבוע לפני סגירת ההגשות.
**המנטור:** Sofie Njoroge, Endpoint Security Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שלישי בבוקר מגיע לדלפק השירות מכתב תודה: "תודה שתיקנתם לי את הלפטופ כל כך מהר". אף אחד בדלפק לא נגע בלפטופ הזה. הסשן רץ ב-Quillbridge Remote, אותו כלי שהטכנאים של Brookmere משתמשים בו כל יום: חתום, מותר, ושקט בתור ההתראות. על Sofie להפריד בין העוזרים לנוסע הסמוי, ולברר אם זה הלפטופ היחיד.

## המכניקה הייחודית של החדר
**Sanctioned or Stowaway?** אותו כלי תמיכה מרחוק, חתום ולגיטימי, בידי ה-IT ובידי תוקף. הלקח: חתימה תקפה מוכיחה מי בנה את הכלי, לא מי משתמש בו.
- **Sanctioned or Stowaway? (hunt):** שאילתת KQL בת שמונה שורות שמפרידה לפי יצרן, נתיב התקנה, תהליך הורה, tenant של ה-relay והכרטיס שמאחורי הסשן. כל join כולל את המכשיר, כי PID 6044 רץ היום על שני מכשירים. כרטיס דואר פתוח מאותו בוקר ושני כרטיסים סגורים ישנים מסתירים את התוקף אם סופרים כל כרטיס.
- **Same Signature, Different Owner (spotdiff):** קובץ התצורה של הסוכן המאושר לצד העותק הזר. החתימה, המוצר וה-transport זהים, וההבדל הוא מי פרס, איך זה רץ ולאיזה tenant זה עונה.
- **Who Made It, or Who's Using It? (rush):** בליץ של ראיות: האם השורה מספרת על הכלי או על השימוש בו.

## העולם התלת-ממדי
אי קמפוס (`facility`) של המשרד: חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r0, r1, q1 | r2, r3, q2, r4, f1 | r5, q3, m1 | r6, r7, q4, o1 | la1, ac1

(סדר חדש: בחדר המקורי f1, m1 ו-o1 באים אחרי הבוס. f1 עבר ל-CVE, m1 לסימנים, o1 ל-workflow, והבוס סוגר את החדר.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Support Session | r0, r1, q1 | **Inbound Door or Outbound Call?** (sort), **One Technique, Three Flavours** (inspect), **Anatomy of a Signed Binary** (anatomy), **Build It or Borrow It?** (sort) |
| 2 | The Way In | r2, r3, q2, r4, f1 | **Which Door Did It Use?** (sort), **The Advisory's Toolbox** (inspect), **Case File: Storm-1811** (inspect), **Where Would It Leave a Trace?** (sort), **Which Consoles Were Exposed?** (worksheet) |
| 3 | The Five Signs | r5, q3, m1 | **Same Signature, Different Owner** (spotdiff), **Five Signs, Five Hosts** (worksheet), **Who Made It, or Who's Using It?** (rush) |
| 4 | The Allowlist | r6, r7, q4, o1 | **What Each Control Actually Gives You** (match), **Run the Allowlist** (simulate), **Sanctioned or Stowaway?** (hunt), **Walk One Case, Start to Finish** (trace) |
| 5 (בוס) | Close or Contain | la1, ac1 | **What Can a Firewall Record Tell You?** (anatomy), **One Rule, Four Endings** (queue), ואז ההחלטות הנבחנות |

**הפרדה מהשאלות הנבחנות:**

מה מלמד כל פריט נבחן, ובמה הוא שונה:
- **שאלת הביניים של r0 (הטקטיקה של T1219):** שורת Tactic ב-One Technique, Three Flavours מציגה את העובדה ומסבירה למה, בלי לשאול. שורת Mix-up מסבירה למה לא Persistence, Discovery או Initial Access.
- **q1 (היתרון המעשי):** Build It or Borrow It? משווה בין שתי הדרכים על Brookmere. Anatomy of a Signed Binary פוסל את המסיחים: אין פטור מבדיקת EDR, הסשן המוצפן לא מסתיר את התהליך, הכלי לא עולה ל-SYSTEM לבד.
- **שאלת הביניים של r2 (A מול C):** Which Door Did It Use? על מקרים אחרים: צוות הונאה של בנק, ספק תמיכה עם 400 לפטופים. לא הניסוח של m1.
- **q2 (הצעד הראשון של Storm-1811):** זכירה טהורה. העובדה מופיעה כשורה מתויגת ב-Case File, ו-Where Would It Leave a Trace? שואל היכן נשאר עקב, לא מה היה הסדר.
- **שאלת הביניים של r4 (היקף):** Which Consoles Were Exposed? שואל כמה נקודות קצה בקונסולה החשופה הגרועה. ספקים בדויים.
- **f1 (גרסת התיקון):** זכירה טהורה. הגרסה מופיעה כנתון בשורת Vendor bulletin, והשאלה סופרת ספקים ולא שואלת את הגרסה.
- **q3 (הסימן החזק ביותר):** Same Signature, Different Owner ו-Five Signs, Five Hosts על Quillbridge ו-Farlight, לעולם לא AnyDesk מול ScreenConnect. העותק הזר על Desktop ובשם מוחלף. עותק ה-Downloads היחיד במעבדות הוא מאושר, ולכן הנתיב לבדו לא מספיק, וה-rush מראה שחתימה ושם באדוויזורי לא מכריעים.
- **m1 (התאמה):** זכירה. התבניות ב-sort, האדוויזורי כנתון ב-inspect, Storm-1811 ב-Case File, CVE-2024-1709 ב-worksheet, וכיסוי כפול כשאלה על מארח של Brookmere. אף זוג לא מועתק.
- **שאלת הביניים של r6 (חסימת קטגוריה):** זוג ב-What Each Control Actually Gives You ופסק הדין של הסשן הראשון ב-Run the Allowlist.
- **q4 (עץ התהליכים):** שלב tree ב-trace, עם nltest ‏(`/domain_trusts`) ולא net group. ה-why מסביר מה זה מוסיף ומה לא (אין ייחוס).
- **o1 (סדר החקירה):** ה-trace עובר את שבעת השלבים על מארח אחד, בניסוח אחר ובלי לבקש מיון.
- **la1 שאלה 1 (שדה הזהות):** What Can a Firewall Record Tell You? על לוג חומת אש עם שדה `app` ומוצר בדוי, לא Zscaler ולא TeamViewer. כל שדה מסביר מה הוא לא יודע: action, פורט, קטגוריה.
- **la1 שאלה 2 (מה בודקים הלאה):** סיכום האנטומיה, הזוג של ITSM, ושלב ticket ב-trace.
- **ac1 (ההכרעה):** מעבדה נפרדת, One Rule, Four Endings. אותו כלל, ארבע תוצאות: Benign True Positive, False Positive, הסלמה, בידוד. המקרה המקביל הוא הצלת סוכן תקוע בטלפון, לא מיפוי מדפסת, והמסר על רשומת allowlist צרה מופיע ב-why.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Thank-You Note" | כניסה | תחנה 1 |
| Chapter 2: "Nobody Called" | אחרי The Way In | תחנה 3 |
| Chapter 3: "Only One?" | אחרי The Allowlist | תחנה 5 |
| Finale: "Helping Hand" | אחרי הבוס | החדר הבא |
