# Runbook — Phases 1–5 (Super-admin, Enrollment, Org-admin, Branding, Hardening)

הפעלה ותפעול מלא של שכבת ה-B2B הרב-דיירית מעבר ל-Phase 0. **כל הקוד כבר deployed** (commits עד `018bee6`) אך **רדום** עד שמריצים את המיגרציות ומפעילים את ה-hook. עבוד **תמיד ב-Staging קודם**.

- **קדם-דרישה:** Phase 0 מובן ומוכן (ר' [phase-0-plan.md](phase-0-plan.md)). ה-runbook הזה ממשיך אותו.
- **אילוץ:** Claude לא מריץ migrations — הקבצים מסופקים להרצה ע"י Tal (SQL editor / `supabase db push`).
- **קבצי מקור:** `supabase/migrations/0010–0015`, `scripts/test-tenant-isolation.mjs`, `vercel.json`.

---

## 0. תמונת-על — מה מפעילים

| רכיב | היכן | פעולה חד-פעמית |
|------|------|-----------------|
| מיגרציות 0010–0015 | Supabase SQL | הרצה לפי סדר |
| Custom Access Token Hook | Supabase Dashboard | הפעלה + בחירת הפונקציה |
| `SUPABASE_SERVICE_ROLE_KEY` | Vercel env | הגדרה |
| `CRON_SECRET` | Vercel env | הגדרה (ל-cron הפקיעה) |
| `UPSTASH_REDIS_REST_URL/TOKEN` | Vercel env | הגדרה (rate-limit עמיד, כולל פר-org) |
| Vercel Cron | `vercel.json` (כבר קיים) | נכנס לתוקף עם ה-deploy |

---

## 1. סדר הרצת המיגרציות

הרץ **בסדר הזה בדיוק**. 0010 אדיטיבי (בטוח); 0011 הוא ה-RLS cut-over (ר' סדר בטוח ב-phase-0-plan). 0012–0015 אדיטיביים.

```
0010_multitenancy_foundations.sql   -- טבלאות ארגון, org_id+backfill, hook v1, trigger
0011_multitenancy_rls.sql           -- RLS cut-over + RLS על טבלאות הארגון (סגירת דליפה)
0012_multitenancy_phase1.sql        -- hook +org_active, attach_member_if_seat_available, expire_due_orgs, find_user_id_by_email
0013_enrollment.sql                 -- allowed_domains, resolve_invitation, handle_new_user (invite/domain)
0014_branding.sql                   -- hook +org_name (גרסת ה-hook הסופית)
0015_hardening.sql                  -- מחיקת טבלאות 0001, purge_org()
```

> **ה-hook מוגדר-מחדש ב-0010 → 0012 → 0014.** אחרי הרצת כולם, הגרסה הפעילה היא של 0014 (כוללת `org_id`,`org_name`,`org_role`,`org_active`,`is_platform_admin`). מריצים את כולם ברצף — אין צורך להפעיל את ה-hook מחדש בין לבין (זו אותה פונקציה, רק הגוף מתעדכן).

**נקודת עצירה קריטית (בין 0010 ל-0011):** אחרי 0010 + הפעלת ה-hook (סעיף 3) — התחבר מחדש ובדוק `select auth.jwt() ->> 'org_id';`. **רק אם חוזר uuid** המשך ל-0011. אחרת ה-RLS ינעל את כולם.

---

## 2. הגדרות סביבה (Vercel → Settings → Environment Variables)

| משתנה | חובה? | למה |
|-------|-------|-----|
| `NEXT_PUBLIC_SUPABASE_URL` / `NEXT_PUBLIC_SUPABASE_ANON_KEY` | ✅ (כבר) | חיבור Supabase |
| `SUPABASE_SERVICE_ROLE_KEY` | ✅ | קונסולת מנהל-על, audit, branding, purge, resolve — כולן service-role |
| `CRON_SECRET` | ✅ (ל-Phase 1) | מאבטח את `/api/cron/expire-orgs`. Vercel שולח אוטומטית `Authorization: Bearer <CRON_SECRET>` בהרצות ה-cron |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | מומלץ | rate-limit עמיד חוצה-instances, כולל **rate-limit פר-org**. בלעדיו — מונה בזיכרון שמתאפס |

אחרי הגדרת env — **Redeploy** ב-Vercel כדי שייכנסו לתוקף.

**Vercel Cron:** כבר מוגדר ב-`vercel.json` (`/api/cron/expire-orgs`, 03:00 יומי). נכנס לתוקף אוטומטית ב-deploy הבא. בתוכנית Hobby — cron יומי נתמך.

---

## 3. הפעלת ה-Custom Access Token Hook

זה הלב של הבידוד — בלעדיו אין claims ו-RLS ננעל.

**דרך הדשבורד:** Supabase → **Authentication → Hooks (Beta) → Customize Access Token** → Enable → בחר את `public.custom_access_token_hook` → Save.

**או דרך config.toml:**
```toml
[auth.hook.custom_access_token]
enabled = true
uri = "pg-functions://postgres/public/custom_access_token_hook"
```

ה-grants ל-`supabase_auth_admin` כבר בתוך המיגרציה. אחרי ההפעלה — **התנתק והתחבר מחדש** כדי לקבל token עם ה-claims.

---

## 4. אימות מקצה-לקצה (אחרי כל המיגרציות + ה-hook)

הרץ כמשתמש מחובר (Tal):
```sql
select auth.jwt() ->> 'org_id';            -- uuid של ארגון ה-Internal
select auth.jwt() ->> 'org_name';          -- 'Internal / Default'
select auth.jwt() ->> 'is_platform_admin'; -- 'true' (Tal)
select auth.jwt() ->> 'org_active';        -- 'true'
```

**טסט הבידוד (חובה לפני מכירה):**
```
node scripts/test-tenant-isolation.mjs      # דורש env של Staging → 6/6 PASS
```

**נגישות הקונסולה:** התחבר כ-Tal → אמור להופיע קישור **Super Admin** בסיידבר → `/superadmin` נטען.

---

## 5. תפעול לפי שלב

### Phase 1 — פתיחת וניהול סביבות (`/superadmin`)
1. **New organization** → שם, slug, **מספר מושבים**, **תאריך פקיעה**, ואופציונלי מייל org-admin (נוצרת לו הזמנה).
2. **כניסה לארגון** → טאבים:
   - **Licence:** ערוך מושבים/תאריכים/סטטוס; **Suspend/Reactivate** בלחיצה.
   - **Usage:** חברים, XP, sessions, תרחישים, חדרים.
   - **Members:** צירוף חשבון קיים במייל (עם אכיפת מושבים), הסרה.
3. **אכיפת תוקף אוטומטית:** ה-cron היומי (`expire_due_orgs`) מסמן ארגונים שפגו כ-`expired`; משתמש של ארגון פג → מופנה ל-`/license`.
4. **בדיקת ה-cron ידנית:** `curl -H "Authorization: Bearer $CRON_SECRET" https://<site>/api/cron/expire-orgs` → `{"expired": N}`.

### Phase 2 — הרשמה עצמית של סטודנטים
- **קישור כיתה:** בכרטיס Enrollment → **Generate link** → שתף. הסטודנט פותח `/join?token=…` → "Accept" → signup עם הטוקן → נכנס לארגון הנכון אוטומטית.
- **לפי דומיין:** בכרטיס Enrollment → **Allowed email domains** (למשל `sapir.ac.il`) → כל מי שנרשם עם דומיין כזה משויך אוטומטית (עד מכסת המושבים).
- **סדר עדיפות בטריגר:** invitation_token → דומיין → ארגון ברירת מחדל. מכסה מלאה עם token → ההרשמה נכשלת; מכסה מלאה עם דומיין → נופל ל-internal.

### Phase 3 — קונסולת org-admin (`/manage`)
- משתמש עם `org_role='org_admin'` רואה קישור **Manage Class** בסיידבר.
- מנהל **רק את הארגון שלו** (מזוהה מה-JWT): roster מדורג לפי XP, יצירת קישור הזמנה, צירוף/הסרת סטודנטים (עד המכסה), סטטיסטיקות כיתה.
- להפוך מישהו ל-org_admin: ב-`/superadmin` → הארגון → Members → הוסף עם role `org_admin`.

### Phase 4 — מיתוג ותעודות
- **מיתוג:** `/superadmin` → הארגון → **Branding** → צבע accent + Logo URL. מופיע כ-badge ב-Topbar של הסטודנטים ובתעודות ("Issued by <College>").
- ⚠️ **לוגו חיצוני:** ה-CSP חוסם תמונות מהוסטים חיצוניים כברירת מחדל. כדי שלוגו URL ייטען — יש להוסיף את ההוסט ל-`img-src` ב-CSP (`next.config`), או להעלות ל-Supabase Storage של הפרויקט. שם-המכללה וה-accent עובדים בלי קשר.

### Phase 5 — הקשחה ותפעול
- **Rate-limit פר-org:** מסלולי LLM מוגבלים ל-60/דקה לכל ארגון (בנוסף ל-per-IP) — הגנה על התקציב. דורש Upstash לעמידות.
- **Offboarding מכללה:** `/superadmin` → הארגון → **Offboarding**:
  1. **Export data (JSON)** — הורד ומסור למכללה.
  2. **Delete** — הקלד את שם הארגון לאישור → `purge_org()` מוחק את דאטת הלמידה, מחזיר את החשבונות ל-internal (הכניסה נשמרת), ומוחק את הארגון.

---

## 6. Rollback

| מיגרציה | rollback |
|---------|----------|
| 0010 (אדיטיבי) | drop של הטבלאות/עמודות החדשות + שחזור `handle_new_user` מ-0009. אין איבוד נתונים קיימים |
| 0011 (RLS) | migration הפוך שמשחזר `"<t> own select/write"` + `unique(handle)` + מסיר RLS מטבלאות הארגון. **snapshot/PITR לפני** בפרודקשן |
| 0012–0014 | drop/כיבוי ה-hook (Dashboard) + drop הפונקציות. ה-hook ניתן לכיבוי מיידי בלי איבוד נתונים |
| 0015 | **בלתי-הפיך** (מחיקת טבלאות 0001 שלא היו בשימוש) — ודא backup לפני. `purge_org` הוא drop-function פשוט |

**כלל אצבע:** PITR/snapshot ב-Supabase לפני 0011 ו-0015 בפרודקשן.

---

## 7. Checklist ל-Go-Live מסחרי

- [ ] 0010–0015 הורצו ב-Staging, בסדר, ללא שגיאות
- [ ] ה-hook פעיל; JWT מכיל org_id/org_name/org_active/is_platform_admin
- [ ] `test-tenant-isolation.mjs` → 6/6 ב-Staging
- [ ] env: SERVICE_ROLE_KEY, CRON_SECRET, UPSTASH_* מוגדרים; Redeploy בוצע
- [ ] `/superadmin` נגיש ל-Tal; פתיחת ארגון + קישור הזמנה + הרשמת סטודנט-בדיקה עובדים מקצה-לקצה
- [ ] בדיקת מושבים (הרשמה מעל המכסה נחסמת) + פקיעה (ארגון פג → `/license`)
- [ ] חזרה על כל הנ"ל ב-Production (חלון תחזוקה; snapshot לפני 0011/0015)
- [ ] **מבדק חדירות חיצוני בדגש tenant-isolation** — הפריט היחיד שמחוץ לקוד
- [ ] DPA מול המכללה הראשונה + תת-מעבדים (Supabase/Vercel/Upstash/LLM) — ר' §13 באפיון

---

## 8. Troubleshooting

| תסמין | סיבה סבירה | פתרון |
|-------|-------------|--------|
| משתמשים רואים 0 שורות אחרי 0011 | RLS פעיל אך ה-claim חסר | ודא שה-hook פעיל; force re-login |
| `select auth.jwt()->>'org_id'` ריק | ה-hook לא הופעל / לא נבחר | Dashboard → Hooks → בחר `custom_access_token_hook` |
| `/superadmin` מפנה ל-`/` | ה-JWT בלי `is_platform_admin` | ודא `profiles.is_platform_admin=true` ל-Tal + re-login |
| קונסולה מחזירה 503 | `SUPABASE_SERVICE_ROLE_KEY` חסר | הגדר ב-Vercel + Redeploy |
| cron מחזיר 401 | `CRON_SECRET` לא תואם | הגדר את אותו הערך ב-Vercel env |
| לוגו מכללה לא נטען | CSP חוסם הוסט חיצוני | הוסף ל-`img-src` ב-`next.config` או העלה ל-Storage |
| הרשמה עם token נכשלת "seat_limit" | מכסת המושבים מלאה | הגדל מושבים ב-Licence או הסר חברים |

---

*כל השרשרת מתוכננת להיות no-op עד שמפעילים את ה-hook — אז כל הפאזות "מתעוררות" יחד. עבוד ב-Staging, אמת עם טסט הבידוד, ורק אז Production.*
