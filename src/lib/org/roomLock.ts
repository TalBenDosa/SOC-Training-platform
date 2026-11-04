/**
 * Whether an organization locks its Learning Rooms behind prerequisites (migration 0102).
 * Rooms are OPEN by default; the college admin (or the super-admin) turns locking on.
 * The older super-admin bypass all_rooms_unlocked (0036) still wins: true always means open.
 * A row read before 0102 is applied has no rooms_locked column, so it reads as open.
 */
export function orgRoomsLocked(row: { rooms_locked?: unknown; all_rooms_unlocked?: unknown } | null | undefined): boolean {
  if (!row) return false;
  return row.rooms_locked === true && row.all_rooms_unlocked !== true;
}

/** Postgres/PostgREST "column does not exist", raised when 0102 is not applied yet. */
export function isMissingColumn(error: { code?: string; message?: string } | null | undefined): boolean {
  if (!error) return false;
  return error.code === "42703" || error.code === "PGRST204" || /column .* does not exist|rooms_locked/i.test(error.message ?? "");
}
