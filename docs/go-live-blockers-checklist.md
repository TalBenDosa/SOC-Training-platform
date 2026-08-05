# Checklist — 3 החוסמים לפני מכירה למכללה משלמת

הליבה הרב-דיירית **חיה ופעילה בפרודקשן** (בידוד RLS, provisioning עם מושבים+תוקף, הרשמה עצמית, קונסולות ניהול). שלושת הפריטים כאן הם **תפעול/הקשחה** — לא פונקציונליות חסרה — אבל כל אחד מהם חשוב לפני שמכללה משלמת נכנסת.

- **פרויקט Supabase רלוונטי:** "Hack The SOC Real" — ref `wrxhxtdllbctsawvewue` (eu-west-1).
- **פרויקט Vercel:** `soc-training-platform`.

---

## 🔴 חוסם 1 — גיבויים (Supabase Pro)

**למה:** הפרויקט על תוכנית **Free = אין גיבויים כלל** (לא scheduled, לא PITR). איבוד נתונים = בלתי-הפיך. מכללה משלמת תדרוש גיבוי.

- [ ] Supabase → הארגון → **Billing** → שדרג את הפרויקט "Hack The SOC Real" ל-**Pro** (~$25/חודש).
- [ ] Database → **Backups** → ודא ש-**Scheduled backups** פעילים (גיבוי יומי), ו-**Point-in-time** זמין.
- [ ] אחרי השדרוג — **הרץ את `0015` המלא** (מחיקת טבלאות `0001` הלא-בשימוש) שנדחה:
      `https://raw.githubusercontent.com/TalBenDosa/SOC-Training-platform/main/supabase/migrations/0015_hardening.sql`
      (עכשיו יש גיבוי, אז ה-`DROP TABLE` הבלתי-הפיך בטוח.)

**אימות:** Database → Backups מציג לפחות גיבוי יומי אחד.

---

## 🔴 חוסם 2 — מסירת מייל אמיתית (דומיין ב-Resend)

**למה:** כרגע נשלח מ-`onboarding@resend.dev` — שולח הבדיקה של Resend, ש**מוסר רק לכתובת שאיתה נרשמת ל-Resend**. **תלמידים אמיתיים לא יקבלו** את קישורי ההזמנה.

- [ ] Resend → **Domains** → **Add Domain** → הזן דומיין שבבעלותך (למשל `hack-the-soc.com`).
- [ ] הוסף את רשומות ה-**DNS** ש-Resend נותן (SPF/DKIM) אצל ספק הדומיין → המתן ל-**Verified**.
- [ ] Vercel → פרויקט `soc-training-platform` → **Settings → Environment Variables** → הוסף:
      **`EMAIL_FROM`** = `HACK THE SOC <noreply@your-verified-domain>`
- [ ] **Redeploy** ב-Vercel.
- [ ] (תזכורת אבטחה) ודא שביטלת את מפתח ה-Resend הישן ששלחת בצ'אט ושהחדש מוגדר.

**אימות:** פתח סביבה חדשה עם מייל org-admin של **כתובת שאינה שלך** (למשל חבר) → הוא מקבל את המייל.

---

## 🔴 חוסם 3 — אכיפת פקיעת רישיון אוטומטית (CRON_SECRET)

**למה:** סריקת הפקיעה הלילית (`/api/cron/expire-orgs`) מסמנת מכללות שפג רישיונן כ-`expired`. בלי `CRON_SECRET` ה-cron מחזיר 401 ולא רץ.

- [ ] Vercel → פרויקט `soc-training-platform` → **Settings → Environment Variables** → הוסף:
      **`CRON_SECRET`** = מחרוזת אקראית חזקה (למשל פלט של מחולל סיסמאות, 32+ תווים).
- [ ] ודא ש-`vercel.json` מכיל את ה-cron (כבר קיים: `/api/cron/expire-orgs`, 03:00 יומי).
- [ ] **Redeploy** ב-Vercel.

**אימות:** Vercel → הפרויקט → **Cron Jobs** → ה-job מופיע. הרצה ידנית לבדיקה:
`curl -H "Authorization: Bearer <CRON_SECRET>" https://soc-training-platform-jade.vercel.app/api/cron/expire-orgs`
→ מחזיר `{"expired": N}` (לא 401).

---

## סדר מומלץ
1. **חוסם 2 (דומיין מייל)** — הכי חשוב לחוויית התלמיד; ה-DNS לוקח זמן להתפשט, אז התחל ממנו.
2. **חוסם 3 (CRON_SECRET)** — 2 דקות.
3. **חוסם 1 (Pro + 0015)** — כשמתקרבים ללקוח משלם ראשון.

## אחרי 3 החוסמים — מומלץ (לא חוסם)
- מבדק חדירות חיצוני עם דגש tenant-isolation.
- DPA + מדיניות פרטיות מול המכללה הראשונה (§13 באפיון).
- CSP: התרת host ללוגו מכללה (`img-src`) אם רוצים מיתוג עם לוגו.

---

*נכון ל-05.08.2026. הליבה הרב-דיירית חיה; אלה צעדי go-live מסחרי.*
