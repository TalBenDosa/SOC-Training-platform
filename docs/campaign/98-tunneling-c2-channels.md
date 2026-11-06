# תסריט חדר 98: Tunneling, Proxies & C2 Channels

**שם המבצע:** Operation Quiet Wire
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Halden Geothermal (חברה בדויה): שתי תחנות גיאותרמיות על רמה געשית, 26 בארות, ורשת בקרה שלא נועדה מעולם להגיע לאינטרנט.
**המנטור:** Jorge Mbatha, Network Threat Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני בבוקר Jorge מוצא סשן SSH אחד שיוצא מ-gateway של שדה הבארות. הוא פתוח מאז יום שישי וכמעט לא מעביר כלום. שום התראה לא נדלקה, כי חומת האש רואה חיבור יוצא מסודר. במשך שבוע החוט השקט משנה צורה, ו-Jorge צריך לברר מי באמת מדבר עם מי, מה מסתתר בתוך הפרוטוקולים המותרים, ואילו חוטים שייכים ל-Halden ואילו לא.

## המכניקה הייחודית של החדר
- **Draw the Tunnel:** הלומד מצייר מי באמת מדבר עם מי. שני `pathway`: בקשת Modbus שעוברת דרך סשן יוצא, וסריקה שעוקבים אחריה לאחור דרך שרשרת פרוקסי.
- **What Rides in the Ping? / Inside the Upgrade:** שני `pcap` שבהם התעבורה הפנימית מסתתרת בפרוטוקול חיצוני: ICMP, ו-SSH בתוך WebSocket בתוך HTTP.
- **Two Sessions, One Port:** `spotdiff` של צורת סשן SSH רגיל מול צורת טאנל.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Halden Geothermal: חמישה מבנים לפי התחנות, אף מבנה לא מאחורי מבנה אחר ולא לפני ה-Hub. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1, q1, r2 | r3, r4, q2, o1 | r5, q3, m1 | r6, la1, f1 | la2, qf1, ac1

הסדר שונה מהמקור. la1 נשאר לפני la2, והקריאות r1 עד r6 שומרות על סדרן, אז כל הפניה ל-"Log Analysis N" ול-"Reading N" עדיין נכונה. r6 מגיע עכשיו לפני la1, כי ההסבר של la1 מצטט את Reading 6. הדגל f1 ("Go back to Log Analysis 1") מגיע מיד אחרי la1 ועדיין תקף.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Forward | r1, q1, r2 | **Draw the Tunnel** (pathway), **Where Does the Listener Open?** (sort), **What the Firewall Writes Down** (worksheet), **Walk the Scan Back** (pathway), **Which Shell Gets Out?** (simulate) |
| 2 | The Inner Channel | r3, r4, q2, o1 | **What Rides in the Ping?** (pcap), **Work Out the Band** (worksheet), **Spread, Not Average** (tune), **From Gap to Owner** (trace) |
| 3 | The Signed Tool | r5, q3, m1 | **Inside the Upgrade** (pcap), **Who Left This Trace?** (sort), **Same Destination, Different Host** (sort) |
| 4 | The Long Session | r6, la1, f1 | **Two Sessions, One Port** (spotdiff), **Anatomy of a Verify Record** (anatomy), **Anatomy of a Signed Launch** (anatomy), **Stack the Facts** (simulate) |
| 5 (בוס) | The Quiet Wire | la2, qf1, ac1 | **Who Owns the Socket?** (sort), **First Hour on a Beaconing Host** (sequence), **Read a Hunt Line by Line** (inspect), **Whose Wire Is It?** (queue) |

משחקי ארקייד בחדר: pathway + spotdiff + tune בלבד.

**הפרדה מהשאלות הנבחנות:**
- **r1 (שאלת ביניים, ‎-D):** הידע ב-primer של Where Does the Listener Open? ובמיון עצמו. במעבדה הפורטים 7070, 7071 ו-6060 על מארחים של Halden, בלי 1080 ובלי jumpbox.
- **q1 (‎-R, יציאה למארח חיצוני):** הידע ב-Draw the Tunnel. שם זה ssh על gateway לינוקס אל יעד Modbus במארח שלישי, לא plink ולא RDP למארח עצמו.
- **r2 (שאלת ביניים, bind מול reverse):** Which Shell Gets Out?. ארבעה ניסיונות על HG-WEB-02 מול מדיניות אחת, בלי אף אפשרות מהשאלה.
- **r4 (שאלת ביניים, למה jitter לא מסתיר):** Work Out the Band ו-Spread, Not Average. הפס 240 עד 360 שניות, והדוגמה ב-primer היא 200 שניות ב-15%.
- **q2 (פס jitter):** Work Out the Band מלמד את החישוב על 300 שניות ו-20%, ושואל כמה פערים בפנים, לא איזה ערך בודד בחוץ. בשאלה 90 שניות ו-30%.
- **o1 (סדר ציד beacon):** From Gap to Owner עובר על ציון, נדירות, תהליך ובעלים על טבלאות, בלי נוסח השלבים של השאלה.
- **q3 (ngrok על שרת DB):** Same Destination, Different Host. היעד הוא שירות סנכרון קבצים לצרכנים, לא שירות טאנל, והמארחים של Halden.
- **m1 (התאמת מנגנונים):** Draw the Tunnel, Where Does the Listener Open?, What Rides in the Ping?, Inside the Upgrade, Who Left This Trace?. המיון שואל על עקבות, לא על ניסוחי המנגנון של השאלה.
- **r6 (שאלת ביניים, it_verify_result):** Anatomy of a Verify Record מציג את הערכים כשדה עם תווית, ולא שואל עליהם. שאלת זיכרון טהורה.
- **la1 (plink ‎-R ‎-P, ביחד, חתימה):** Anatomy of a Signed Launch היא הרצה מתוזמנת של ‎-L מתיקיית הכלים של האדמין, לא Temp ולא ‎-R. What the Firewall Writes Down מציג ‎-P בשורה. Stack the Facts מלמד שילוב עובדות חלשות על עובדות אחרות: היסטוריית החשבון, חלון תחזוקה ורשימת היעדים, על robocopy, scp ו-rclone, בלי חלון 90 ימים ובלי סשן שנשאר פתוח.
- **f1 (פורט חיצוני):** What the Firewall Writes Down. השאלה שם על `ssh -p 2200` עם ‎-D, והתשובה 2200, לא 443.
- **la2 (פס, תהליך בעלים, תגובה):** Spread, Not Average ללמידת הפיזור, Who Owns the Socket? לבעלות על החיבור, First Hour on a Beaconing Host לתגובה. אין מנוע מסד נתונים, אין ngrok, והשתל הוא קובץ שהונח על המארח.
- **qf1 (KQL):** Read a Hunt Line by Line. ציד אחר לגמרי: התחברויות מתוזמנות ב-DeviceLogonEvents, לא beacon ב-DeviceNetworkEvents. הסף מוסבר כטווח על מספרים אחרים. `stdev()` מופיע כשורה בשאילתה.
- **ac1 (ngrok מאושר):** Whose Wire Is It? בלי ngrok ובלי הדגמת ספרינט: Chisel בבדיקת חדירה, plink עם כרטיס שפג תוקפו, פגיעת מחרוזת בסקריפט, ו-appliance של ספק שפונה לכתובת אחרת מזו שבחוזה.
- קטע קצב ההעברה של DNS ב-r3 לא קיבל מעבדה: אף משימה נבחנת לא צריכה אותו, וחדר 74 מכסה DNS. גם TLS נשאר בחדר 75.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Open Since Friday" | כניסה | תחנה 1 |
| Chapter 2: "It Came Back" | אחרי The Forward | תחנה 2 |
| Chapter 3: "Nothing Here Is Malware" | אחרי The Signed Tool | תחנה 4 |
| Finale: "Whose Wire" | אחרי The Quiet Wire | החדר הבא |

הערות לסרטונים:
- **Intro:** Jorge, הרמה הגעשית והבארות, סשן אחד שפתוח יותר מדי זמן ואיש לא שם לב אליו. לא מראים פקודה.
- **Chapter 2:** Karin Ferro סוגרת את הסשן. הצוות נושם לרווחה, ואז ה-gateway מתחיל לדבר שוב. לא מראים איך.
- **Chapter 3:** שום קובץ לא נתפס כזדוני, והמשמרת מתווכחת למי שייך כל חיבור. לא מראים כלי או שדה.
- **Finale:** מנהל התחנה מקבל את התמונה המלאה של השבוע, ו-Jorge סוגר את התיק. סיפור בלבד, בלי פסק הדין של המשימה הנבחנת.
