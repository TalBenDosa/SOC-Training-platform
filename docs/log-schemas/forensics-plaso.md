# Plaso (log2timeline / psort): supertimeline output, `dynamic` CSV

Category: Digital forensics, timeline analysis · Vendor: log2timeline project (open source) · Product: Plaso · Card version: 2026-11-15

Tool output (a CSV file written by `psort.py`), read in Timesketch, Timeline Explorer or a spreadsheet. No registry entry; a builder checks rows against this card.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| "Using psort": https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html (checked 2026-11-15) | `dynamic` is the default output format; psort writes **UTC** unless `--output-time-zone` is given; example header `datetime,timestamp_desc,source,source_long,message,parser,display_name,tag,store_number,store_index` (older release) and rows such as `2004-09-20T16:13:02+00:00,Expiration Time,WEBHIST,MSIE Cache File URL record,…`; `--slice` and date-filter examples |
| `plaso.output.dynamic` source: https://plaso.readthedocs.io/en/latest/_modules/plaso/output/dynamic.html | Current default columns, in order: `datetime, timestamp_desc, source, source_long, message, parser, display_name, tag` |
| "Output and formatting": https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html | `datetime` is ISO 8601 with microseconds (`--dynamic-time` changes precision to the source's own); other selectable fields: `date, time, timezone, zone, filename, inode, host, hostname, macb, message_short, sourcetype, type, user, username, values` |
| Formatter definitions `plaso/data/formatters/windows.yaml`, `browser.yaml`, `generic.yaml` (GitHub main, checked 2026-11-15) | `source` (short) / `source_long` / message templates per data type, listed in §3 |
| `plaso/lib/definitions.py` (GitHub main) | `timestamp_desc` strings: `Creation Time`, `Content Modification Time`, `Last Access Time`, `Metadata Modification Time`, `Last Time Executed`, `Last Visited Time`, `File Downloaded Time`, `Content Deletion Time` |

## 2. Native format and delivery

```text
log2timeline.py --storage-file case.plaso image.E01
psort.py -o dynamic -w timeline.csv case.plaso "date > '2026-10-23 21:00:00' and date < '2026-10-23 22:30:00'"
```

One CSV row per timestamp per artifact (a file with four NTFS times gives four rows). Comma-delimited, fields containing commas quoted. Empty values print `-`. Times are UTC by default.

## 3. Core field reference

| Column | Meaning |
|---|---|
| `datetime` | ISO 8601, e.g. `2026-10-23T21:46:12.000000+00:00` |
| `timestamp_desc` | Which time of the artifact this row is (`Creation Time`, `Last Time Executed` …) |
| `source` | Short source (`FILE`, `REG`, `EVT`, `LNK`, `WEBHIST`, `RECBIN`, `AMCACHE`, `LOG`) |
| `source_long` | Long source from the formatter |
| `message` | Formatter text built from the event's values |
| `parser` | Parser chain that produced it (`mft`, `winevtx`, `lnk`, `amcache`, `winreg/…` plugin names) |
| `display_name` | Where the artifact came from, `TYPE:path` (e.g. `OS:/…`, `TSK:/…`, `NTFS:\…`) |
| `tag` | Analyst or tagging-file labels; often `-` |

Formatter values for the artifacts a SOC case uses (from the formatter YAML):

| Data type | `source` | `source_long` | `message` template (start) |
|---|---|---|---|
| NTFS $MFT entry (`fs:stat:ntfs`) | `FILE` | `NTFS file stat` | `{display_name} File reference: … Attribute name: … Name: … Parent file reference: …` |
| Windows EVTX record | `EVT` | `WinEVTX` | `[{event_identifier} / 0x{hex}] Provider identifier: … Source Name: … Strings: [...] Hostname: … Record Number: … Event Level: …` |
| LNK shortcut | `LNK` | `Windows Shortcut` | `[{description}] File size: … File attribute flags: 0x… Drive type: … Local path: … Network path: … Relative path: …` |
| Chrome download | `WEBHIST` | `Chrome History` | `{url} ({full_path}). State: …. Received {n} of {total} bytes. …` |
| AppCompatCache (ShimCache) | `REG` | `AppCompatCache Registry Key` | `[{key_path}] Cached entry: {n} Path: {path}` |
| BAM | `REG` | `Background Activity Moderator Registry Key` | `{path} [{user SID}]` |
| Amcache file entry | `AMCACHE` | `Amcache Registry Entry` | `path: … sha1: … product_name: …` |
| Recycle Bin item | `RECBIN` | `Recycle Bin` | `DC{n} -> {original_filename} … (from drive: {letter})` |
| Prefetch | `LOG` | `WinPrefetch` | `Prefetch [{executable}] was executed - run count {n} path hints: …` |

## 4. Samples

Platform rows (illustrative values; `tag` column `-`):

```text
datetime,timestamp_desc,source,source_long,message,parser,display_name,tag
2026-10-23T21:46:12.000000+00:00,Creation Time,FILE,NTFS file stat,"NTFS:\Users\Public\Music\lsasss.exe File reference: 104233-3 Attribute name: $STANDARD_INFORMATION Name: lsasss.exe",mft,NTFS:\$MFT,-
2026-10-23T21:46:12.000000+00:00,Content Modification Time,REG,AppCompatCache Registry Key,"[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Session Manager\AppCompatCache] Cached entry: 7 Path: C:\Users\Public\Music\lsasss.exe",winreg/appcompatcache,OS:C:\Windows\System32\config\SYSTEM,-
2026-10-23T21:47:03.000000+00:00,Last Time Executed,REG,Background Activity Moderator Registry Key,"\Device\HarddiskVolume3\Users\Public\Music\lsasss.exe [S-1-5-21-3021547218-1820935716-2470558912-1187]",winreg/bam,OS:C:\Windows\System32\config\SYSTEM,-
```

## 5. Investigation notes

- Separate **presence** from **execution**: MFT, ShimCache (Windows 10/11) and Amcache show a file existed; BAM `Last Time Executed`, Prefetch and process events show it ran.
- ShimCache's time is the file's last-modification time, not a run time.
- Filter on the incident window, then sort by `datetime`; read `timestamp_desc` before reading the time.
- Correct for any recorded device clock skew before mixing host times with network logs (Plaso converts to UTC; it cannot know the clock was wrong).
- Pivots: an Amcache `sha1` to threat intel and to the Amcache of other hosts; a download URL to proxy logs.

## 6. Common mistakes

- `source_long` `NTFS $MFT` or `Registry Key : BAM`: the formatter strings are `NTFS file stat` and `Background Activity Moderator Registry Key`. (`NTFS $MFT metadata file` is the **parser's** description, not an output value.)
- EVTX message `Computer Name:`: the current template says `Hostname:`.
- Chrome download message `Received: N bytes out of: N bytes`: the current template is `Received N of N bytes.`.
- `File Downloaded` as `timestamp_desc`: the constant is `File Downloaded Time` (which description a given browser parser emits for a download row is UNVERIFIED; check the parser before writing a graded answer on it).
- Local times in a psort CSV without `--output-time-zone`: default output is UTC.
- Dropping the `tag` column from a default-format header.

## 7. UNVERIFIED

- Exact `display_name` prefixes for each path-spec type and the exact `parser` chain strings (`winreg/bam` vs `windows_registry:bam`) in the current release.
- Which `timestamp_desc` the Chrome downloads parser uses for start and end times.
