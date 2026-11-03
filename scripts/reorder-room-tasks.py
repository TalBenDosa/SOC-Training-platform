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
# A header is a "// -----" rule, a title line, then the same rule again.
is_rule = lambda l: re.fullmatch(r"\s*// -{20,}", l) is not None
cuts = [i for i, l in enumerate(body) if is_rule(l) and i + 2 < len(body) and body[i + 2] == l]
if not cuts:
    # No comment headers: a block runs from an opening "{" line to the "}," line
    # at the same indentation (the first task's indentation).
    indent = next(l for l in body if l.strip())[: -len(next(l for l in body if l.strip()).lstrip())]
    cuts = [i for i, l in enumerate(body) if l == indent + "{"]
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
