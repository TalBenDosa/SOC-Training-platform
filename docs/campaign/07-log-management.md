# תסריט חדר 7: Log Management Fundamentals

**שם המבצע:** Operation Chain of Custody
**רמה:** מתחילים (בלי ידע מוקדם)
**העולם:** Halden Retail (רשת בדויה של 400 חנויות ורשת תשלומים אחת).
**המנטורית:** Grace Liu, SIEM Engineer. Victor Sandoval (IT Finance) מופיע בשאלה על האחסון.

## סיפור הרקע
כל התחברות, כל העברת כרטיס וכל חיבור חסום כותבים שורה איפשהו, שני מיליון שורות בשעה. Grace מנהלת את הצינור שמביא את כולן למקום אחד ושומר עליהן. עוקבים אחרי לוג מהרגע שהוא נכתב ועד שהוא הופך לראיה.

## העולם התלת-ממדי: Log River
צינור לוגים בתלת-ממד:
- ארבעה עמודי מקור: Endpoint, Firewall, App ו-Cloud.
- כרטיסי לוג נוסעים על מסועים אל SYSLOG :514.
- משם עוברים דרך פריזמת נרמול (NORMALISE אל ECS) ויוצאים אחידים.
- הם נכנסים לשני גלילי אחסון (HOT ל-90 יום, ARCHIVE ל-12 חודשים) וממשיכים לעין של ה-SIEM.

התחנות מדליקות את השלבים לפי הסדר. בתחנה 4 נסגר מנעול WORM על הארכיון. בבוס, כרטיס אדום "1102 · LOG CLEARED" ניתז מהארכיון הנעול.

## סדר המשימות
סודר מחדש לפי נושא: r1 | r2, q1, q4 | q2, q3 | r3 | la1, flag1. השאלות על האחסון ועל השמירה קיבלו תחנה משלהן, עם תרגול לפני כל אחת.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Every Log Tells a Story | r1 | **Name That Format** (Syslog, JSON, CEF, LEEF משורות גולמיות). **Pull the Fields** (מקור, שחקן ופורט משורות אמיתיות). **Where Did It Come From?** (ארבעה סוגי מקורות) |
| 2 | Collect and Normalise | r2, q1, q4 | **On the Collector**: טרמינל על log-col-01, כולל ss -ulpn (UDP 514), tail ללוג חומת אש (IP שנחסם שוב ושוב), וסטטיסטיקות של אירועים שנפלו ב-UDP. **Speak ECS**: מיפוי שדות של ספקים ל-ECS. **Life of a Log**: מחזור החיים |
| 3 | Store and Retain | q2, q3 | תרגול **Storage Budget**: 2,000 EPS × 400 בתים, ל-GB ביום ואחרי דחיסה. תרגול **Retention Rules**: התאמה בין PCI, HIPAA, SOX ו-GDPR לתקופות השמירה שלהם |
| 4 | Tamper Watch | r3 | **Local vs Central**: השוואה בין auth.log המקומי שנמחק לבין העותק ב-SIEM, שעה אחרי שעה. **Aggregator or SIEM?** |
| 5 (בוס) | The Cleared Log | la1, flag1 | תרגול **Anatomy of an Audit Policy Change**: אירוע 4719, השבתת ניטור שיתופי קבצים. אחריו ההתראה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- גיליון האחסון משתמש ב-2,000 EPS ו-400 בתים (q2 שואלת על 1,000 EPS ו-500 בתים).
- אין שאלה על אירוע בן חמישה חודשים (q3).
- מעבדת המחיקה היא auth.log של לינוקס, ובשום מקום לא מוצגים 1102 או 104 של Windows (la1, flag).
- התרגול הוא אירוע 4719.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Two Million Lines an Hour" | כניסה | תחנה 1 |
| Chapter 2: "One Language" | אחרי Collect and Normalise | תחנה 3 |
| Chapter 3: "The Copy They Could Not Reach" | אחרי Tamper Watch | תחנה 5 |
| Finale: "Chain of Custody" | אחרי הבוס | החדר הבא: Encoding, Encryption and Hashing |
