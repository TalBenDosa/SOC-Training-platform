# Custom domain + Resend email — setup playbook (hackthesoc.app)

## Current DNS state (checked live)

- Nameservers: `ns1/ns2.vercel-dns.com` → DNS is **Vercel-managed**.
- Apex `hackthesoc.app`: A records `64.29.17.65` / `64.29.17.1` → already
  points at **Vercel's servers**.
- `https://hackthesoc.app` returns 000 → the domain is **not yet attached to
  the project**, so no cert is issued. Fixing that is Part A (one click, no DNS
  values — Vercel already owns the DNS).
- No MX / SPF / DKIM yet → email is Part B.

The one value nobody can pre-fill is the **DKIM key** in Part B — Resend
generates it uniquely when you add the domain. Copy it from Resend's screen.

---


**Why this is a manual playbook, not code:** connecting a domain and verifying
it for email are dashboard operations across Vercel, Resend, and DNS. They need
your authenticated login to each service, so they can't be automated from the
codebase. The code side needs **no changes** — invite links already use the
request's own origin (`new URL(req.url).origin`), auth redirects use
`window.location.origin`, and the email sender is read from `EMAIL_FROM`. So the
moment the site serves from your domain and `EMAIL_FROM` points at it, everything
adopts the new domain on its own.

Replace `hackthesoc.app` below with the domain you bought.

---

## Part A — Point the website at your domain (Vercel)

1. **Vercel → your project (`soc-training-platform`) → Settings → Domains**.
2. If the domain you bought through Vercel isn't already listed, click **Add**
   and enter `hackthesoc.app` (and `www.hackthesoc.app` if you want both).
3. Vercel assigns it automatically (you bought it there, so DNS is already
   Vercel-managed — no records to add for the website itself). Wait for the
   status to go **Valid / Active**.
4. Optional but recommended: set `hackthesoc.app` as the **primary** domain so
   the `…-jade.vercel.app` address redirects to it.

Nothing in the app needs editing — all internal links are origin-relative.

---

## Part B — Verify the domain in Resend (this is what unblocks email)

The current blocker: with the default `onboarding@resend.dev` sender, Resend
only lets you email your **own** Resend-account address. Verifying a domain
lifts that — you can then send to anyone.

1. **Resend → Domains → Add Domain** → enter `hackthesoc.app`.
2. Resend shows a set of **DNS records** — typically:
   - one **MX** record on a send subdomain (e.g. `send.hackthesoc.app`),
   - a **TXT** record for **SPF** (`send` subdomain, value like `v=spf1 include:amazonses.com ~all`),
   - a **TXT** record for **DKIM** (a `resend._domainkey` name with a long key value),
   - optionally a **TXT** for **DMARC** (`_dmarc`, e.g. `v=DMARC1; p=none;`).
   Copy each one exactly — name, type, and value.

3. **Add those records in Vercel DNS** (because the domain lives in Vercel):
   **Vercel → Domains → `hackthesoc.app` → DNS Records → Add**. Add each record
   Resend gave you, matching **type**, **name**, and **value** precisely.
   - Vercel sometimes appends the domain to the name automatically — if Resend
     says `resend._domainkey`, enter just `resend._domainkey`, not the full
     `resend._domainkey.hackthesoc.app`.

4. Back in **Resend → Domains → Verify**. DNS can take a few minutes to a couple
   of hours to propagate; Resend re-checks until every record is **Verified** (green).

---

## Part C — Tell the platform to send from the verified domain (Vercel env)

1. **Vercel → project → Settings → Environment Variables**, scope **Production**:
   - `EMAIL_FROM` = `HACK THE SOC <noreply@hackthesoc.app>`
     (the address MUST be at the verified domain — that's the whole point).
   - `RESEND_API_KEY` is already set and working (leave it).
2. **Redeploy** (Deployments → latest → Redeploy). Env vars bind at deploy time,
   so nothing changes until you redeploy — same gotcha we hit before.

---

## Part D — Verify it actually works (I can run this for you)

Once C is redeployed, the `send-test-email` endpoint confirms delivery to ANY
address (not just yours). Signed in as the super-admin, open in the browser:

```
https://hackthesoc.app/api/admin/send-test-email?to=talmaxima1@gmail.com
```

Expect `{"ok": true, "skipped": false}`. A real email lands in that inbox.
Tell me when B + C are done and I'll drive this end-to-end against production
(the way I sent the earlier test) and confirm delivery to a non-owner address.

---

## What changes for users after this

- Students and admins see `hackthesoc.app` instead of the `.vercel.app` URL.
- Org-admin invitations and their class codes are **emailed automatically** to
  any recipient — no more copy-the-link-and-send-it-yourself.
- Cross-border-transfer note (docs/CROSS-BORDER-DATA-TRANSFER.md) gains a fourth
  processor path only if you route mail elsewhere; Resend was already listed.
