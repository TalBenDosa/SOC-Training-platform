# FTK Imager: image acquisition log (`<image>.txt`)

Category: Digital forensics, evidence acquisition · Vendor: Exterro (formerly AccessData) · Product: FTK Imager · Card version: 2026-11-15

This is a tool report, not a telemetry stream. No registry entry: a lab shows it as text lines, and a builder checks the lines against this card.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| SANS DFIR, "Forensics 101: Acquiring an Image with FTK Imager": https://www.sans.org/blog/forensics-101-acquiring-an-image-with-ftk-imager/ (checked 2026-11-15) | A full sample log from FTK Imager 2.6.0.49. FTK Imager writes the log next to the image as `<image name>.txt`. Line labels and their order (see §3), timestamp format `Fri Jun 12 07:39:02 2009`, and the verification line format `MD5 checksum: <hash> : verified`. |
| HaystackID note on FTK Imager and USB serial numbers (search result, 2026-11-15) and the FTK Imager User Guide reproduced on Scribd | Newer builds also record the drive's serial number; FTK Imager reports the first of two serials some USB devices carry, while EnCase may report the second. The exact label in 4.x builds was not confirmed (see §7). |

No official Exterro specification of the log layout was found. The layout below is the SANS sample; later versions keep the same sections.

## 2. Native format and delivery

A plain-text file written by FTK Imager when an image is created (`Create Disk Image`), saved beside the first segment: `D:\Cases\ASH-2026-0117\0117-01.E01` → `D:\Cases\ASH-2026-0117\0117-01.E01.txt`. Every line is `Label: value`, flush left, with section headers in square brackets or ending in a colon. Times are the examiner workstation's **local** time, written `Ddd Mmm DD HH:MM:SS YYYY` with no time zone. The file goes into the case with the chain-of-custody form.

## 3. Core field reference (in file order, SANS sample)

| Line label (exact) | Meaning |
|---|---|
| `Created By AccessData® FTK® Imager <version>` | First line. Newer builds may say Exterro (UNVERIFIED) |
| `Case Information:` | Section header |
| `Case Number:` | Typed by the examiner in the wizard |
| `Evidence Number:` | Typed by the examiner |
| `Unique description:` | Typed by the examiner (lower-case `d` in the 2.6 sample) |
| `Examiner:` | Typed by the examiner |
| `Notes:` | Free text typed by the examiner. Anything here (seal number, "powered off by IT") is the examiner's statement, not something the tool measured |
| `Information for <image path>:` | Section header naming the image |
| `Physical Evidentiary Item (Source) Information:` | Section header |
| `[Drive Geometry]` | `Cylinders:`, `Tracks per Cylinder:`, `Sectors per Track:`, `Bytes per Sector:`, `Sector Count:` |
| `[Physical Drive Information]` | `Drive Model:`, `Drive Interface Type:` (and a drive serial number line in newer builds, label UNVERIFIED) |
| `Source data size:` | e.g. `488386 MB` |
| `Sector count:` | Lower-case `c` here, unlike `Sector Count:` above |
| `[Computed Hashes]` | `MD5 checksum:`, `SHA1 checksum:`: hashes computed over the **source** while reading it |
| `Image Information:` | `Acquisition started:`, `Acquisition finished:`, `Segment list:` (image segment paths) |
| `Image Verification Results:` | `Verification started:`, `Verification finished:`, then `MD5 checksum: <hash> : verified` and `SHA1 checksum: <hash> : verified` |

Verification line: the hash, a space, a colon, a space, then `verified`. A mismatch is reported in place of `verified` (exact failure wording UNVERIFIED).

## 4. Samples

SANS's own sample (FTK Imager 2.6), abridged to the labels and value shapes:

```text
Created By AccessData® FTK® Imager 2.6.0.49 090505

Case Information:
Case Number: Case-20090611-001
...
[Computed Hashes]
 MD5 checksum:    d116ed8d064ea3939ba650d6beca6efd
...
Image Verification Results:
Verification started: Fri Jun 12 07:39:02 2009
...
 MD5 checksum: d116ed8d064ea3939ba650d6beca6efd : verified
```

Platform sample (fictitious case, documentation-style values):

```text
Created By AccessData® FTK® Imager 4.7.1.2

Case Information:
Case Number: ASH-2026-0117
Evidence Number: 0117-01
Unique description: Dell Latitude 7440 SN 7K2M9Q3, bidding desk 2, internal NVMe
Examiner: R. Achebe
Notes: Seal #448120 intact on receipt. Unit powered off by IT before collection: no memory image exists. Drive connected through a hardware write blocker.

--------------------------------------------------------------

Information for D:\Cases\ASH-2026-0117\0117-01:

Physical Evidentiary Item (Source) Information:
[Drive Geometry]
 Bytes per Sector: 512
 Sector Count: 1,000,215,216
[Physical Drive Information]
 Drive Model: SAMSUNG MZVL2512HCJQ-00BL7
Source data size: 488386 MB
Sector count:    1000215216
[Computed Hashes]
 MD5 checksum:    184aa077df08b90ac9fe282cceaa325e
 SHA1 checksum:   a64c89f2592b4dcccad86640cb7e063cc91e171e

Image Information:
 Acquisition started:   Sun Oct 25 09:52:14 2026
 Acquisition finished:  Sun Oct 25 11:18:40 2026
 Segment list:
  D:\Cases\ASH-2026-0117\0117-01.E01

Image Verification Results:
 Verification started:  Sun Oct 25 11:18:41 2026
 Verification finished: Sun Oct 25 11:41:02 2026
 MD5 checksum:    184aa077df08b90ac9fe282cceaa325e : verified
 SHA1 checksum:   a64c89f2592b4dcccad86640cb7e063cc91e171e : verified
```

The separator line, the indentation and the thousands separator in `Sector Count` are illustrative (SANS reports the labels flush left); keep the labels exact and do not build a graded answer on whitespace.

## 5. Investigation notes

- **What proves integrity:** the `[Computed Hashes]` (taken from the source while imaging) and the `: verified` lines (the image re-read and matched). Copy both hashes to the custody form; anyone who opens the image later re-checks against them (FTK Imager "Verify Drive/Image", or `ewfverify`, see [forensics-libewf](forensics-libewf.md)).
- **What ties the image to the physical drive:** drive model and drive serial number, not the computer's service tag typed in `Unique description`.
- **Timeline of custody:** `Acquisition started` after the lab's receipt time on the custody form shows nobody imaged it earlier; the gap between `Acquisition finished` and `Verification started` should be seconds.
- **Missing memory image:** FTK Imager logs only what it imaged. Why there is no RAM capture is only in the examiner's `Notes`, and the form.
- **Time zone:** the times are the imaging workstation's local clock. Record the zone in the case notes before comparing with UTC sources.

## 6. Common mistakes

- Treating `Notes`, `Unique description` or `Examiner` as tool-measured facts. They are typed by a person.
- Expecting one hash line: the 2.6 sample has two hash blocks (computed, then verified), each with MD5 and SHA1.
- Writing the verification line as `MD5 verified: <hash>` or `<hash> verified`: the form is `<hash> : verified`.
- Adding a time zone or ISO timestamps (`2026-10-25T09:52:14Z`): FTK Imager writes `Sun Oct 25 09:52:14 2026`.
- Calling `Acquisition finished` the end of verification: verification has its own start and finish lines.
- Confusing this log with the E01's internal header (what `ewfinfo` prints: `Acquiry information`, `Acquisition date`): different tool, different labels.

## 7. UNVERIFIED

- Exact labels and branding in FTK Imager 4.x (e.g. whether the first line says Exterro, the exact label of the drive serial number line, a `Source Type:` / `[Device Info]` block). Only the 2.6 layout was read in full.
- The wording printed when a hash does **not** verify.
- Indentation and separator lines.
