// Print a room's tasks as readable text (readings in full, graded tasks with
// their answers) for authoring work. Usage: npx tsx scripts/print-room.ts <room-id>
import { ROOMS } from "../src/data/rooms";

const id = process.argv[2];
const room = ROOMS.find(r => r.id === id);
if (!room) { console.error(`no room ${id}`); process.exit(1); }
console.log(`# ${room.title} (${room.difficulty})\n${room.description}\n`);
for (const t of room.tasks as unknown as Record<string, unknown>[]) {
  console.log(`\n===== ${t.id} [${t.type}] ${t.heading ?? ""}`);
  if (t.content) console.log(t.content);
  const keys = ["question", "prompt", "context", "instructions", "options", "answer", "pairs", "items", "correctOrder", "event", "questions", "checkpoint", "choices", "verdicts"];
  for (const k of keys) if (t[k] !== undefined && k !== "content") console.log(`-- ${k}:`, typeof t[k] === "string" ? t[k] : JSON.stringify(t[k], null, 1));
}
