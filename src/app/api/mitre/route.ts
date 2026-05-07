import { NextResponse } from "next/server";
import { TACTICS, TECHNIQUES } from "@/lib/mitre/attack";

export async function GET() {
  return NextResponse.json({ tactics: TACTICS, techniques: TECHNIQUES });
}
