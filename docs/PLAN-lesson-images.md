# Plan — real images in lessons and rooms

Written 2026-08-12. Grounded in the current codebase, not in assumptions — every
"already exists" line below was verified by reading the file named next to it.

## Why this plan exists

The platform currently has **no real image support in lessons**. What looks like
a cover image at the top of every lesson section is a decorative gradient:

- `SectionImage` (`src/app/(app)/learn/page.tsx:87`) hashes a string into a hue
  and renders a 64px-tall CSS gradient with stripes. It takes a `query` prop and
  ignores it apart from hashing. There is no `<img>` anywhere in it.
- `section.imageQuery` is read at `learn/page.tsx:272` and fed to that gradient.
  So the field exists in the data shape but has never mapped to a picture.

The genuine illustration mechanism that *does* work today is **Mermaid**: both
lesson readers detect Mermaid source inside `codeExample` and render a real
diagram (`src/lib/lessons/mermaid.ts:14`, used at `learn/page.tsx:299` and
`learn/[slug]/[lesson]/page.tsx:218`). That covers flows, hierarchies and
sequences well, and it is what the current curriculum work is using.

Images are still worth adding for the things Mermaid genuinely cannot express:
annotated console screenshots, log-line anatomy call-outs, packet/header
layouts, and topology art.

## What already exists (no work needed)

| Capability | Status | Evidence |
|---|---|---|
| CSP allows remote images | **Already open** — `img-src 'self' data: blob: https:` | `next.config` csp array |
| Supabase-hosted images allowed by `next/image` | **Already whitelisted** — `**.supabase.co` | `next.config` `images.remotePatterns` |
| Admin-only write path for content | **Exists** — `requireAdmin()` | `src/lib/auth/apiGuard.ts:85` |
| Rate limiting on admin APIs | **Exists** — `/api/admin/` is in the tight 10/min tier | `src/middleware.ts:38` |
| DB table for admin-authored lessons | **Exists** — `content_lessons(content jsonb)` | `supabase/migrations/0019_admin_generated_content.sql:57` |
| RLS pattern to copy | **Exists** — published-read only, writes via service role | same migration, lines 85-107 |

So CSP and image-host config are **not** blockers. That removes the two things
that usually make this expensive.

## The one thing that is missing structurally

There is **no `public/` directory in this repo at all** (verified: `ls public/`
fails). Static assets are currently not served from the app origin. That is
significant, because it decides the cheapest path below.

## Two content sources, two different answers

This is the key architectural point, and it is why this should not be built as
one uniform "upload images" feature.

**1. Curriculum content authored in the repo** — `BUILTIN_LESSONS`
(`src/data/pathLessons-*.ts`) and `ROOMS` (`src/data/rooms-batch-*.ts`). This is
~34 lessons and 90 rooms, all version-controlled TypeScript, reviewed in PRs.
For these, images should live in the repo too, served from `public/`. They
version with the content that references them, they are reviewable in a diff,
they need no database, no bucket, no upload UI, and no runtime auth. They also
cannot break at runtime because a bucket policy changed.

**2. Admin/instructor-authored lessons** — rows in `content_lessons`, created
through `/api/admin/content/*`. These are authored at runtime by a human in the
Admin panel, so their images genuinely need upload + storage: Supabase Storage,
an upload endpoint behind `requireAdmin()`, and a URL written into the lesson's
jsonb.

Path 1 covers everything the curriculum work needs. Path 2 is only required if
you want instructors to add their own images. **Recommend building Path 1 first
and treating Path 2 as optional/later** — it is roughly a fifth of the work and
delivers the actual requested outcome.

## Phase A — repo-hosted images (the recommended first step)

### A1. Data model
Add an optional `image` to the lesson section shape and to `ReadingTask`:

```ts
image?: {
  src: string;      // "/lesson-images/cloud/shared-responsibility.svg"
  alt: string;      // REQUIRED — accessibility + it forces the author to say what it shows
  caption?: string;
  credit?: string;  // source/licence line, rendered under the image
};
```

`alt` is deliberately non-optional inside the object. A decorative-only image
should not be added at all.

### A2. Asset location and format
`public/lesson-images/<topic>/<name>.svg`.

Prefer **SVG** for diagrams and annotated figures: it is text, so it diffs in
git, stays crisp at any zoom, and stays small. Use WebP/PNG only for genuine
raster content (a real screenshot). Add a size guard in the content gate
(see A5) so a 4MB PNG cannot be committed unnoticed.

### A3. Rendering — both readers, not one
There are **two** lesson readers and they have drifted before. The comment at
`learn/page.tsx:285-297` documents exactly this: `codeExample` was rendered in
one reader and silently dropped in the other, so the same lesson taught
different material depending on the route used to reach it.

So: render the image in **both**
- `src/app/(app)/learn/page.tsx` (`SectionPageContent`)
- `src/app/(app)/learn/[slug]/[lesson]/page.tsx`

Replace the `SectionImage` gradient call with: if `section.image` exists render
a real `<figure>` (image + caption + credit); otherwise keep the existing
gradient as the fallback so the 30 lessons without images look unchanged.

Use `next/image` with explicit width/height to avoid layout shift, and
`loading="lazy"` for anything below the first section.

For rooms, render `task.image` in `ReadingPlayer`
(`src/components/rooms/TaskPlayer.tsx:379`), next to the existing `diagram`
handling.

### A4. Where images actually come from — decide this before authoring
Three options, and they are not equally safe:

- **Self-authored SVG diagrams** — safe, accurate, versioned. Best for the
  packet/header layouts, log-line anatomy, topology and architecture figures.
- **Synthetic console mockups we draw ourselves** — a stylised "Falcon-like"
  detection view built as SVG, clearly ours. Safe, and good enough to teach the
  shape of a console.
- **Real vendor console screenshots (CrowdStrike, SentinelOne, Microsoft)** —
  **flagging this as a genuine risk, not a formality.** This platform is being
  sold to colleges (`docs/b2b-multitenancy-spec.md`), which makes it commercial
  use of another company's UI and trademarks. Vendor screenshots also date fast
  as consoles get redesigned. Recommend **not** shipping real vendor
  screenshots without checking each vendor's brand/press terms, and preferring
  our own mockups. If you do want real screenshots, that is a decision to take
  deliberately with the licence terms in hand — I should not make it silently.

### A5. Content gate
Extend `scripts/validate-content.mjs` with:
- every `image` has a non-empty `alt`;
- `src` starts with `/lesson-images/` and the file exists on disk (catches typos
  and deleted assets at CI time, not in the browser);
- file size under a threshold (e.g. 500KB) so a huge asset fails the gate;
- `credit` present when the image is not self-authored.

This matches how the gate already protects other content invariants.

### A6. Verification
Drive both readers in the browser and confirm a real `<img>` renders with the
right `src`, plus check `read_console_messages` for 404s on the asset. A missing
image is silent in the DOM otherwise.

## Phase B — uploads for admin-authored lessons (optional, later)

Only needed if instructors must add their own images.

- **B1. Storage**: Supabase Storage bucket `lesson-images`, **private**, with
  signed URLs — or public-read if these are never sensitive. Mirror the RLS
  stance of `0019`: no client-side write policy; writes go through the service
  role only.
- **B2. Migration** `0034_lesson_images.sql`: bucket + policies. Next free
  number — current head is `0033_org_members_profiles_fk.sql`.
- **B3. Upload API**: `POST /api/admin/content/images`, gated by
  `requireAdmin()`. Must validate **content type by magic bytes, not by the
  filename or the client-sent MIME type**, cap size server-side, strip EXIF,
  and generate its own storage key rather than trusting the uploaded filename
  (path traversal). Already inherits the 10/min admin rate limit.
- **B4. Admin UI**: a file picker in the lesson editor that uploads and writes
  the returned URL into the section's `image.src`. This would be the first
  file-upload UI in the app — there is currently no `type="file"` anywhere.
- **B5. Note**: `**.supabase.co` is already whitelisted in `next.config`, so no
  config change is needed for rendering these.

## Effort and sequencing

| Step | Scope | Notes |
|---|---|---|
| A1 data model | small | two type additions |
| A3 renderers | small-medium | **two** readers + rooms; the drift risk is the real cost |
| A5 content gate | small | mirrors existing checks |
| A2/A4 authoring assets | **this is the bulk** | drawing the actual SVGs is the real work |
| B1-B4 uploads | medium | only if instructors need it |

The engineering is genuinely small. The expensive part is authoring good
figures — which is a content task, not a code task, and can be done
incrementally: ship the mechanism, then add figures lesson by lesson.

## Recommendation

1. Do **Phase A** (repo-hosted images, both readers, gate check). It delivers
   real images with no database, no bucket, no upload surface, and no new auth
   path.
2. Author figures **only where Mermaid genuinely falls short**. Most process and
   hierarchy content is better served by the Mermaid diagrams already being
   added — a diagram whose labels are exact, diffable text beats a picture of
   the same thing.
3. Decide the vendor-screenshot question explicitly (A4) before authoring any
   console figures.
4. Treat **Phase B** as a separate, later decision driven by whether instructors
   actually need to upload their own images.
