# תסריט חדר 57: SharePoint & Teams Security Monitoring

**שם המבצע:** Operation Shared Link
**רמה:** בינוני
**העולם:** Wrenhall Architects (משרד אדריכלים בדוי): 140 עובדים, שלוש הצעות פתוחות, וכל שרטוט יושב ב-Microsoft 365.
**המנטור:** Annika Bergström, Collaboration Security Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום חמישי האחרון דפים מהצעת האצטדיון הופיעו במצגת של מתחרה. אף אחד ב-Wrenhall כבר לא שולח קבצים, הם משתפים אותם, ולשיתוף אין קובץ מצורף שמסנן דואר יכול לבדוק. לפי Annika, אף אחד לא פרץ פנימה.

## המכניקה הייחודית של החדר
**Test the Help Desk:** צ'אט אמיתי שבו הלומד מקליד בעצמו מול "IT Help Desk" חיצוני ובודק אם הוא מי שהוא טוען: מבקש מספר פנייה, שואל מאיזה ארגון, ואומר שיתקשר בחזרה. אחר כך **Follow the Override**: מעקב מהתראת DLP אחת דרך לוג הביקורת ועד HR.

## העולם התלת-ממדי: Shared Link
- טבעת גבול של ה-tenant על הרצפה, בלי קירות.
- ארונות אתרים (BIDS, HR, LEGAL) עם מסמכים מרחפים.
- לוח צ'אט, וצומת זר מחוץ לטבעת ששולח בועות פנימה.
- מגן DLP שעוצר זרם מסמכים, ומסמך אחד שעוקף אותו.
- שרשרת מהארונות אל צומת OUTSIDE, שנשברת עם סיום הבוס.

## סדר המשימות
r1, q1 | r2, q2 | r3, q3 | la1, f1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Site | r1, q1 | **Tune the Download Alert** (tune), **What Changed in Sharing?** (spotdiff) |
| 2 | The Channel | r2, q2 | **Test the Help Desk** (chat), **What's Posting in the Channel?** (deduce) |
| 3 | The Override | r3, q3 | **Follow the Override** (trace) |
| 4 (בוס) | Last Day | la1, f1 | הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- אין עובד עוזב ואין 847 קבצים ‏(la1), אין 10.0.1.55 ‏(f1), ואין כתובת #EXT# ‏(q2).
- ה-trace עוקב אחרי הזמנת שיתוף שמית ולא אחרי קישור Anyone ‏(q1).
- המעבדות לא אומרות איפה מחפשים פעולות קבצים ‏(q3).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Page Eleven" | כניסה | תחנה 1 |
| Chapter 2: "External" | אחרי The Site | תחנה 2 |
| Chapter 3: "Access They Already Had" | אחרי The Channel | תחנה 3 |
| Finale: "Shared Link" | אחרי הבוס | החדר הבא |
