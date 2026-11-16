# Volatility 3: Windows memory-analysis plugin output

Category: Digital forensics, memory analysis · Vendor: Volatility Foundation (open source) · Product: Volatility 3 Framework 2.x · Card version: 2026-11-15

Command-line output read on an analysis workstation (SIFT, REMnux, an IR laptop), never live telemetry. No registry entry for labs; the existing graded raw block that declares `vendor: "Volatility 3"` uses the plugin's own column names, which this card lists.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| `volatility3/framework/plugins/windows/pslist.py` at tag `v2.7.0`: https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.7.0/volatility3/framework/plugins/windows/pslist.py (checked 2026-11-15) | `windows.pslist` columns: `PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime, File output`. `Offset(P)` when `--physical`. `File output` = `Disabled` unless `--dump`. |
| `…/plugins/windows/pstree.py` at `v2.7.0` | `windows.pstree` columns: `PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime, Audit, Cmd, Path` |
| `…/plugins/windows/netscan.py` at `v2.7.0` | `windows.netscan` columns: `Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created`. TCP listeners `LISTENING`; UDP state blank; unreadable owner/state render as `-` |
| `…/plugins/windows/cmdline.py` at `v2.7.0` | `windows.cmdline` columns: `PID, Process, Args`; unreadable PEB prints `Required memory at 0x… is inaccessible (swapped)` or `… is not valid (process exited?)` |
| `…/plugins/windows/dlllist.py` at `v2.7.0` | `windows.dlllist` columns: `PID, Process, Base, Size, Name, Path, LoadTime, File output` |
| `volatility3/cli/text_renderer.py` at `v2.7.0` | Datetimes printed with `%Y-%m-%d %H:%M:%S.%f %Z` (Windows times are UTC, so `2026-10-23 21:50:09.000000 UTC`); `NotApplicableValue` → `N/A`; unreadable / not-available → `-`; tree depth in the quick renderer: no marker at the top level, `* ` at depth 2, `** ` at depth 3 |

## 2. Native format and delivery

`vol -f <image> windows.<plugin> [options]` (or `vol.py`, or `python3 vol.py`). Output goes to stdout: first the banner `Volatility 3 Framework <version>`, a progress line while symbols load, then a tab-separated table with a header row of the column names above. Renderers: `quick` (default, TSV), `pretty`, `csv`, `json`, `jsonl` (`-r <renderer>`). Hex columns (`Offset(V)`, `Base`, `Size`) print as `0x…`. Booleans print `True` / `False`.

Plugins most used in a SOC case: `windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan` (finds unlinked / exited processes), `windows.cmdline`, `windows.netscan` (`windows.netstat` walks live structures), `windows.dlllist`, `windows.malfind`, `windows.handles`, `windows.svcscan`, `windows.dumpfiles --pid <pid>`.

## 3. Core field reference

| Column | Plugins | Meaning |
|---|---|---|
| `PID`, `PPID` | pslist, pstree, psscan | Process and parent process ID. A PPID is a number only: the parent may have exited and the number been reused |
| `ImageFileName` | pslist, pstree | Name from `EPROCESS`, **truncated to 14 characters** |
| `Offset(V)` / `Offset(P)` | pslist, pstree | Address of the `EPROCESS` structure |
| `Threads`, `Handles` | pslist, pstree | Counts; `Handles` often prints `-` |
| `SessionId` | pslist, pstree | 0 = services; ≥1 = interactive logon sessions |
| `Wow64` | pslist, pstree | 32-bit process on 64-bit Windows |
| `CreateTime`, `ExitTime` | pslist, pstree | UTC; `ExitTime` `N/A` while running |
| `Audit` | pstree | Full kernel path, `\Device\HarddiskVolumeN\…` |
| `Cmd` | pstree | Command line from the PEB |
| `Path` | pstree | Image path from the PEB (`C:\…`) |
| `Args` | cmdline | Command line from the PEB |
| `Proto`, `LocalAddr`, `LocalPort`, `ForeignAddr`, `ForeignPort`, `State`, `Owner`, `Created` | netscan | `Proto` `TCPv4`/`TCPv6`/`UDPv4`/`UDPv6`; `State` e.g. `ESTABLISHED`, `LISTENING`, `CLOSED`; `Owner` = process name |
| `Base`, `Size`, `Name`, `Path`, `LoadTime` | dlllist | Module loaded into the process; a "DLL" can have any extension |
| `File output` | pslist, dlllist | `Disabled`, or the dumped file name with `--dump` |

## 4. Samples

`windows.pstree` (quick renderer, columns tab-separated; shown here with tabs):

```text
Volatility 3 Framework 2.7.0

PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	Audit	Cmd	Path
668	520	services.exe	0xd30c2b8a1080	7	-	0	False	2026-10-23 06:02:02.000000 UTC	N/A	\Device\HarddiskVolume3\Windows\System32\services.exe	C:\Windows\system32\services.exe	C:\Windows\system32\services.exe
* 2240	668	BidEngine.exe	0xd30c2d1f2080	24	-	0	False	2026-10-23 06:03:14.000000 UTC	N/A	\Device\HarddiskVolume4\Ashcombe\Bid\BidEngine.exe	"D:\Ashcombe\Bid\BidEngine.exe" --site ASH-BID-02	D:\Ashcombe\Bid\BidEngine.exe
5120	5096	explorer.exe	0xd30c2e4a3080	61	-	2	False	2026-10-23 21:41:07.000000 UTC	N/A	\Device\HarddiskVolume3\Windows\explorer.exe	C:\Windows\Explorer.EXE	C:\Windows\Explorer.EXE
* 7412	5120	rundll32.exe	0xd30c2f3c1080	4	-	2	False	2026-10-23 21:50:09.000000 UTC	N/A	\Device\HarddiskVolume3\Windows\System32\rundll32.exe	"C:\Windows\System32\rundll32.exe" C:\ProgramData\Intel\cache\cache.dat,Start	C:\Windows\System32\rundll32.exe
```

`windows.netscan`:

```text
Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created
0xd30c2e117a20	TCPv4	10.20.4.21	49702	10.20.4.12	1433	ESTABLISHED	2240	BidEngine.exe	2026-10-23 06:03:20.000000 UTC
0xd30c2f6c2d30	TCPv4	10.20.4.21	50412	203.0.113.71	443	ESTABLISHED	7412	rundll32.exe	2026-10-23 21:50:14.000000 UTC
```

`windows.dlllist --pid 7412`:

```text
PID	Process	Base	Size	Name	Path	LoadTime	File output
7412	rundll32.exe	0x7ff6d1a20000	0x17000	rundll32.exe	C:\Windows\System32\rundll32.exe	2026-10-23 21:50:09.000000 UTC	Disabled
7412	rundll32.exe	0x7ffb3c210000	0x5e000	cache.dat	C:\ProgramData\Intel\cache\cache.dat	2026-10-23 21:50:11.000000 UTC	Disabled
```

As the existing graded raw block renders one `windows.pslist` row (flat object keyed by the column names):

```json
{"PID": 4892, "PPID": 4, "ImageFileName": "svchost.exe", "Offset(V)": "0xbe8f2a006080", "Threads": 7, "Handles": "-", "SessionId": 0, "Wow64": "False", "CreateTime": "2025-06-24 14:31:55.000000 UTC", "ExitTime": "N/A", "File output": "Disabled"}
```

## 5. Investigation notes

- Judge a process by **path, parent, session, start time and network**, never by name alone: `svchost.exe` is legitimate only from `C:\Windows\System32\` under `services.exe` in session 0; `lsass.exe` exactly one, under `wininit.exe`.
- A user-session parent (`explorer.exe`, session ≥1) for something that should be a service on a server is an interactive operator.
- `rundll32.exe <file>,<export>` with a non-`.dll` file in `ProgramData` / `AppData` / `Temp`, plus a `dlllist` entry for that file and a `netscan` row to an outside address, is the classic proxy-execution picture (T1218.011).
- Next steps: `windows.dumpfiles --pid <pid>` (or `--virtaddr`) to extract the module, hash it, then search the hash and the foreign address across the fleet. `windows.malfind --pid <pid>` for injected code.
- `psscan` vs `pslist`: a process in `psscan` but not `pslist` is unlinked or exited.
- Memory reflects one moment: a closed connection or exited process can be missing.

## 6. Common mistakes

- Volatility 2 names and plugins (`pslist` without `windows.`, `--profile=Win10x64`, `connscan`, `Name` instead of `ImageFileName`, `PPid`). Volatility 3 needs no profile.
- Inventing columns: there is no `User`, `Parent`, `Hash`, `Signed`, `CommandLine` column in pslist/pstree (pstree's command line is `Cmd`; cmdline's is `Args`).
- ISO timestamps (`2026-10-23T21:50:09Z`): the renderer prints `2026-10-23 21:50:09.000000 UTC`.
- Treating Volatility output as live EDR telemetry or giving it an alert severity.
- Expecting the full image name in `ImageFileName`: it is cut at 14 characters (`SearchProtocol` for `SearchProtocolHost.exe`); the full name is in `Path` / `Audit` / `Args`.
- `PPID 4` for a user process is not "spawned by the kernel"; it is an anomaly to explain (or a reused PID).

## 7. UNVERIFIED

- The exact progress line between the banner and the table, and blank lines, for 2.7.0.
- Whether the quick renderer's `Handles` value prints `-` for every Windows build (it is commonly seen; the plugin defines it as `int`).
