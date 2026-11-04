# תסריט חדר 19: Security Products Behaviour

**שם המבצע:** Operation Line of Sight
**רמה:** מתחילים
**העולם:** Calloway Group (חברה בדויה): ארבעה עשר מוצרי אבטחה, SIEM אחד, ו-SOC ששואל כל הזמן "למה שום דבר לא התריע?"
**המנטור:** Theo Brandt, ארכיטקט אבטחה.

## סיפור הרקע
Theo תכנן את ה-stack, והתשובה שלו היא תמיד שאלה חוזרת: האם משהו היה ממוקם כך שיוכל לראות את זה? כל מוצר יושב במקום מסוים: על המארח, על הקו, לצד הקו, לפני אפליקציה אחת, או בענן. המיקום הזה קובע מה המוצר רואה ומה הוא יכול לעצור. כאן עוברים על ה-stack שכבה אחר שכבה, ולומדים מה כל מוצר מסוגל לראות.

## העולם התלת-ממדי: Lines of Sight
חתך של ה-stack. בחזית רצועת INLINE. משמאל מארחים עם הילות סוכן, ומתחתם לוח HYPERVISOR שזוהר באדום, כי אין שם סוכן. באמצע קו תקשורת שעובר דרך שער NGFW/IPS, ועותק שיורד ממנו אל חיישן IDS/NDR. אחריהם מגדל אפליקציה עם מגן WAF, שער מעטפה (EMAIL GW), וסורק ששולח בדיקות החוצה. מעל הכול ענן IDENTITY/CASB. כל זרמי הלוגים נופלים אל באר SIEM מאחור.

## סדר המשימות
r1 | r2, q1, r2b | r3, r4, q2 | r5, la1, f1 | r6, r6b, ac1 | r7, r8, q3, q4, m1, o1 (הדגל f1 עבר אל ה-log analysis שהוא מתייחס אליו)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Where It Sits | r1 | **Stop It, or Report It?**: שבעה רכיבים ב-stack, כולל EDR במצב Detect Only ו-WAF במצב COUNT |
| 2 | On the Host | r2, q1, r2b | **Is There an Agent?**: אילו מכשירים יכולים להריץ EDR. **Read the Hypervisor's Diary**: אירועי vSphere ו-ESXi (‏PermissionAddedEvent, ‏ssh.enabled, ו-T1489) |
| 3 | On the Wire | r3, r4, q2 | **What the Firewall Knew**: לוג TRAFFIC של PAN-OS בלי פענוח (‏User-ID, ‏SNI, ‏1.9GB) |
| 4 | In Front of the App | r5, la1, f1 | **Tune the WAF**: ארבע חסימות. מה שומרים ומה מכווננים בצורה צרה |
| 5 | What Users Touch | r6, r6b, ac1 | **Read the Gateway's Verdicts**: ‏SPF, ‏DKIM ו-DMARC, וגם מייל פנימי שלא עבר בשער |
| 6 (בוס) | Signals and Sinks | r7, r8, q3, q4, m1, o1 | **Signals From Three Layers**: ‏beacon של גיבוי, ‏impossible travel דרך VPN, ‏OAuth consent phishing, ו-DLP של משכורות |

**הפרדה מהשאלות הנבחנות:**
- מיון הכיסוי לא כולל hypervisor (q1).
- אין מעבדה עם זוג ערכים של alert.action ב-Suricata (q2).
- תור ה-WAF עוסק ב-false positives, ולא בגוף בקשה גדול מדי (la1, f1).
- דף המייל לא עוסק בסורק (ac1).
- תור האותות לא מציג ערוץ DLP במצב notify-only (q4) או פער ב-SIEM (q3).
- אין סידור של שלבי התקיפה (o1), ואין התאמה בין מוצרים לראות הייחודית שלהם (m1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Was Anything Positioned to See It?" | כניסה | תחנה 1 |
| Chapter 2: "Below the Agents" | אחרי On the Host | תחנה 3 |
| Chapter 3: "Inline, Beside, In Front" | אחרי In Front of the App | תחנה 5 |
| Finale: "Only What Reaches It" | אחרי הבוס | החדר הבא: Web Application Security |
