/** Shared org / tenancy types used by the super-admin console and its API. */

export type OrgStatus = "trial" | "active" | "suspended" | "expired";
export type OrgRole = "org_admin" | "instructor" | "student";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  seat_limit: number;
  starts_at: string | null;
  expires_at: string | null;
  status: OrgStatus;
  allowed_domains?: string[];
  /** Per-org accent colour + logo shown to that college's students. */
  branding?: { color?: string; logo_url?: string };
  /**
   * Commercial record (migration 0020) — what the college bought, for how much,
   * under which PO. A record only: it does not gate access (seat_limit /
   * expires_at do that) and holds no payment state.
   */
  contract?: {
    plan?: string;
    seats_purchased?: number;
    price?: number;
    currency?: string;
    po_number?: string;
    signed_at?: string;
    notes?: string;
  };
  created_at: string;
}

export interface Invite {
  id: string;
  email: string | null;
  role: OrgRole;
  token: string;
  expires_at: string;
  accepted_at?: string | null;
  link: string;
}

/** An org row enriched with the derived counters the console lists. */
export interface OrgSummary extends Organization {
  seats_used: number;
  /** Convenience flag: is the license currently valid? */
  active: boolean;
}

export interface OrgMember {
  org_id: string;
  user_id: string;
  role: OrgRole;
  status: "active" | "invited" | "removed";
  joined_at: string;
  /** Joined from profiles for display. */
  email?: string | null;
  handle?: string | null;
  display_name?: string | null;
}

/** Aggregate usage for an org's cohort (super-admin dashboards). */
export interface OrgUsage {
  members: number;
  total_xp: number;
  sessions: number;
  scenarios_completed: number;
  rooms_completed: number;
}
