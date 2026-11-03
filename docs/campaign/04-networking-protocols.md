# תסריט חדר 4: Common Network Protocols

**שם המבצע:** Operation Open Ports
**רמה:** מתחילים (אחרי Networking Fundamentals)
**העולם:** Kestrel Media (חברה בדויה), חומת האש בקצה הרשת FW-EDGE-01.
**המנטורית:** Elif Arslan, Senior Network Analyst. Marco Ruiz (מנהל IT) מופיע בשאלה.

## סיפור הרקע
14,000 חיבורים חוצים את חומת האש בכל דקה, וכל אחד מהם מדבר בפרוטוקול שמשאיר טביעות אצבע. Elif נותנת לך שתי הקלטות תעבורה וחומת אש עם פורטים פתוחים. קודם לומדים איך נראה תקין על הקו, ורק אחר כך מחפשים את מה שלא.

## העולם התלת-ממדי: The Port Wall
חזית של חומת אש עם 12 שקעי פורטים (80, 443, 53, 67, 22, 21, 23, 445, 3389, 25, 993, ICMP). זרמי תעבורה עפים אליה מהאינטרנט: כחול לפרוטוקול מוצפן, ענבר לטקסט גלוי, אדום ל-Telnet.
1. **Web, Names, Addresses:** נדלקים פורטי הרשת והשמות.
2. **The Remote Doors:** נדלקות דלתות הגישה מרחוק.
3. **Protocols Under Abuse:** מסגרת "watch" אדומה נסגרת סביב 53, 445, 3389 ו-443, הפורטים שתוקפים מנצלים.
4. **The 03:22 Lookups:** פרץ של שמות אקראיים פוגע בפורט 53, וטבעת זיהוי תופסת אותו.

## כלי חדש: Packet Capture
תצוגת ניתוח פקטות בסגנון Wireshark: רשימת פקטות בצבעים לפי פרוטוקול, מסנן תצוגה (dns, http, ftp, ip.addr==..., מחרוזת במרכאות), עץ פרוטוקולים ו-payload. המשימות נפתרות מתוך מה שרואים בפקטות עצמן.

## סדר המשימות
סודר מחדש לפי נושא: r1 | r2, q2, q3 | r3, q1 | la1, f1. במקור q1 (מנהור DNS) ו-q3 (WannaCry) היו מופרדים מהקריאה שלהם.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Web, Names, Addresses | r1 | **Morning Capture**: הקלטה של לפטופ, כולל DHCP DORA, שאילתות DNS, לחיצת יד TCP, התחברות ב-HTTP גלוי שבה הסיסמה גלויה, ו-TLS Client Hello שבו קוראים את ה-SNI. **Ask the DNS Yourself**: nslookup עבור SPF, DMARC, PTR ו-NS. **Read the Status Code**: קודי סטטוס של HTTP ומה הם מספרים לאנליסט |
| 2 | The Remote Doors | r2, q2, q3 | **Cleartext or Not?**: הקלטה של קבלן, כולל סיסמת FTP גלויה, באנר SSH, SMB מלפטופ ללפטופ (C$) ו-ping עם מידע מוחבא (מנהור ICMP). **Encrypted or Cleartext?** (חפיסת קלפים) |
| 3 | Protocols Under Abuse | r3, q1 | **Context Calls**: תור של חמש התראות "תקינות על הנייר", ולכל אחת מחליטים לפי ההקשר. **Beacon or Not?**: גיליון שממנו מחשבים קצב שאילתות, סוג רשומה ודומיין בסיס |
| 4 (בוס) | The 03:22 Lookups | la1, f1 | תרגול **Anatomy of a DNS Log** על רשומת dns.log של Zeek (שאילתה תקינה מול השרת הפנימי), ואז ההתראה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- אין התקפת brute force על RDP (q2) ואין סיפור WannaCry (q3).
- גיליון ה-beacon שואל על תזמון ועל הדומיין, ולא על שם הטכניקה (q1).
- התרגול הוא שאילתה תקינה, בלי שם אקראי, בלי שרת ציבורי ובלי NXDOMAIN (la1, f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Protocol Leaves Fingerprints" | כניסה | תחנה 1 |
| Chapter 2: "Cleartext" | אחרי The Remote Doors | תחנה 3 |
| Chapter 3: "Wrong Place, Wrong Time" | אחרי Protocols Under Abuse | תחנה 4, ההתראה של 03:22 |
| Finale: "Caught at Port 53" | אחרי הבוס | החדר הבא: Windows Fundamentals |
