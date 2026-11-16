# libewf tools (`ewfinfo`, `ewfverify`) and coreutils hash output

Category: Digital forensics, evidence integrity · Vendor: libyal (Joachim Metz), open source; GNU coreutils · Card version: 2026-11-15

Command-line output on an analysis workstation. No registry entry; a builder checks terminal output against this card.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| `ewfverify(1)` man page: https://man.archlinux.org/man/ewfverify.1.en.raw (checked 2026-11-15) | Example run and output: banner `ewfverify <version>`, `Verify started at: …`, `This could take a while.`, `Status: at N%.` progress blocks, `Verify completed at: …`, `Read: …`, then the hash lines and `ewfverify: SUCCESS`. Options: `-d sha1|sha256` (extra digests), `-f` format, `-l` log file, `-q` quiet, `-w` zero sectors on checksum error. |
| libewf source `ewftools/verification_handle.c` (main branch): https://raw.githubusercontent.com/libyal/libewf/main/ewftools/verification_handle.c (checked 2026-11-15) | Exact format strings: `MD5 hash stored in file:\t\t%s`, `MD5 hash calculated over data:\t\t%s`, `MD5 hash stored in file:\t\tN/A` when the image holds no hash; the same for `SHA1` and `SHA256` (`SHA256 hash calculated over data:\t%s`, one tab). |
| libewf source `ewftools/ewfverify.c` | Final status line `ewfverify: SUCCESS`, `ewfverify: FAILURE` or `ewfverify: ABORTED`. |
| `ewfinfo(1)` man page: https://man.archlinux.org/man/ewfinfo.1.en.raw and libewf source `ewftools/info_handle.c` (checked 2026-11-15) | Sections `Acquiry information`, `EWF information`, `Media information`, `Digest hash information`. Header labels in current source: `Case number`, `Description`, `Examiner name`, `Evidence number`, `Notes`, `Acquisition date`, `System date`, `Operating system used`, `Software version used`, `Password` (`N/A` when none), `Model`, `Serial number`, `Device label`. Digest line `\tMD5:\t\t\t<hash>`. (The older man page example prints `Acquiry date`; current source prints `Acquisition date`.) |
| GNU coreutils `md5sum` / `sha256sum` (manual) | Output `<hex digest><two spaces><file name>`, lower-case hex; `*` instead of the second space in binary mode. |

## 2. Native format and delivery

- `ewfinfo <image>.E01`: reads the metadata the imaging tool stored inside the EWF (EnCase) container: case fields typed at acquisition, media geometry, and the hash computed at acquisition time. It does **not** re-hash anything.
- `ewfverify <image>.E01`: re-reads every chunk, recomputes the hash over the media data, compares it with the hash stored in the file, prints both and a verdict. Exit status 0 on success. Takes minutes on a real disk.
- `md5sum <file>` / `sha256sum <file>`: hash a raw file (`.raw`, `.dd`, `.mem`, a working copy) or the E01 segment file itself (which is **not** the same as the media hash inside it).

## 3. Core field reference

| Output line | Meaning |
|---|---|
| `MD5 hash stored in file:` | Hash recorded inside the E01 at acquisition |
| `MD5 hash calculated over data:` | Hash just recomputed over the media data |
| `ewfverify: SUCCESS` | Recomputed hash(es) match and no chunk checksum errors |
| `ewfverify: FAILURE` | Mismatch or read/checksum errors: the image cannot be trusted as is |
| `N/A` after `stored in file:` | The image holds no hash of that type (nothing to compare) |
| `Acquiry information:` → `Case number`, `Examiner name`, `Evidence number`, `Notes`, `Acquisition date`, `Software version used` … | Typed or recorded at acquisition by the imaging tool |
| `Digest hash information:` → `MD5` | The stored acquisition hash, as `ewfinfo` reads it |

## 4. Samples

`ewfverify` (lines from the man page format, platform values):

```text
ewfverify 20140814

Verify started at: Tue Oct 27 13:02:11 2026
This could take a while.

Verify completed at: Tue Oct 27 13:19:40 2026

Read: 476 GiB (511101108224 bytes) in 17 minute(s) and 29 second(s) with 465 MiB/s (487632000 bytes/second).

MD5 hash stored in file:		1e62745e8d86c8249029c5342444f7bf
MD5 hash calculated over data:		1e62745e8d86c8249029c5342444f7bf

ewfverify: SUCCESS
```

`ewfinfo` (abridged; tabs as in the source):

```text
ewfinfo 20140814

Acquiry information:
	Case number:		ASH-2026-0121
	Examiner name:		R. Achebe
	Evidence number:	0121-01
	Notes:			SSD removed from laptop, connected via hardware write blocker
	Acquisition date:	Tue Oct 27 09:31:07 2026
	Software version used:	20140814

Digest hash information:
	MD5:			1e62745e8d86c8249029c5342444f7bf
```

`md5sum` over two working copies:

```text
1e62745e8d86c8249029c5342444f7bf  working/0121-work-A.raw
11bd512aff19f9b23d48166646dae191  working/0121-work-B.raw
```

## 5. Investigation notes

- Integrity is proven by **recomputed = stored** (`ewfverify`), not by the stored hash alone (`ewfinfo`), which only shows what was recorded.
- A raw working copy exported from the E01 must hash to the E01's media hash; the `.E01` file's own `md5sum` differs (it includes the container and compression), so never compare those two.
- A working copy whose hash differs was changed (mounted read-write, opened by a tool that writes metadata). Discard it and export a new copy from the E01; record the new hash on the custody form.
- `Acquisition date` and the custody form's receipt time should agree with the imaging log (FTK Imager: [forensics-ftk-imager](forensics-ftk-imager.md)).
- `-d sha256` adds a SHA-256 comparison when the image stores one.

## 6. Common mistakes

- `ewfverify: OK`, `PASS` or `VERIFIED`: the verdict word is `SUCCESS` (or `FAILURE` / `ABORTED`).
- `MD5 stored:` / `MD5 computed:` labels: they are `MD5 hash stored in file:` and `MD5 hash calculated over data:`.
- Upper-case hex from `md5sum` (`1E62…`), or one space before the file name: coreutils prints lower-case and two spaces.
- Showing `ewfverify` output that lists case fields (examiner, notes): that is `ewfinfo`.
- Expecting `ewfinfo` to say whether the image is intact. It cannot: it reads, it does not verify.

## 7. UNVERIFIED

- The date format of `Verify started at:` in current builds (the sample follows the man page example, `Tue Jan 11 19:21:51 2011`).
- The exact layout of the `Read:` summary line.
- The value format of `Acquisition date` printed by `ewfinfo` (depends on the `-d` date format option).
