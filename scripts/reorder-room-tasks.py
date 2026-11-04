"""Reorder a room's task blocks in a rooms-batch file (blocks keep their
comment headers). Usage:
  python scripts/reorder-room-tasks.py <file> <room-id> <task-id> <task-id> ...
Every task of the room must be listed exactly once."""
import re, sys

path, room_id, *order = sys.argv[1:]
src = open(path, encoding="utf-8").read()
nl = "\r\n" if "\r\n" in src else "\n"
lines = src.split(nl)

start = next(i for i, l in enumerate(lines) if l.strip() == f'id: "{room_id}",')
t0 = next(i for i in range(start, len(lines)) if lines[i].strip() == "tasks: [") + 1
depth, t1 = 0, None
for i in range(t0, len(lines)):
    depth += lines[i].count("[") - lines[i].count("]")
    if depth < 0:
        t1 = i  # the line holding the closing "],"
        break

body = lines[t0:t1]
# A header is a "// -----" rule, one or more comment lines, then the same rule again.
is_rule = lambda l: re.fullmatch(r"\s*// -{20,}", l) is not None
cuts, i = [], 0
while i < len(body):
    if is_rule(body[i]):
        j = i + 1
        while j < len(body) and body[j].strip().startswith("//") and body[j] != body[i]:
            j += 1
        if j < len(body) and j > i + 1 and body[j] == body[i]:
            cuts.append(i)
            i = j + 1
            continue
    i += 1
if not cuts:
    # One-line headers: "// ----- Reading 1: ... -----"
    cuts = [i for i, l in enumerate(body) if re.fullmatch(r"\s*// -{3,} .+ -{3,}", l)]
if not cuts:
    # Otherwise a block starts at each opening "{" line at the tasks' indentation,
    # pulling in any "//" comment lines (e.g. "// ── Reading 1 ──") right above it.
    first = next(l for l in body if l.strip() and not l.strip().startswith("//"))
    indent = first[: -len(first.lstrip())]
    cuts = []
    for i, l in enumerate(body):
        if l == indent + "{":
            j = i
            while j > 0 and body[j - 1].strip().startswith("//"):
                j -= 1
            cuts.append(j)
cuts.append(len(body))
blocks = {}
for a, b in zip(cuts, cuts[1:]):
    blk = body[a:b]
    ids = [m.group(1) for l in blk for m in [re.match(r'\s+id: "([^"]+)",', l)] if m]
    blocks[ids[0]] = blk

assert body[:cuts[0]] == [] or all(not l.strip() for l in body[:cuts[0]]), "content before first block"
assert sorted(blocks) == sorted(order), f"ids differ: {sorted(blocks)} vs {sorted(order)}"
new = [l for tid in order for l in blocks[tid]]
lines[t0:t1] = new
open(path, "w", encoding="utf-8", newline="").write(nl.join(lines))
print("reordered", room_id, "->", " ".join(order))
