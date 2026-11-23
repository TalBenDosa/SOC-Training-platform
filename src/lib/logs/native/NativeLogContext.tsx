"use client";
/**
 * Native-format rendering for the feed UI. The page that owns the feed (dashboard,
 * team room) provides a function that renders an event in its source's native
 * format under the session's stack; the feed components only consume it. The
 * function is computed at DISPLAY time, after the feed has stamped the event's
 * final time, so native timestamps always match what the analyst sees.
 *
 * The registry itself (32 source modules) is loaded lazily by the provider, so it
 * never weighs on first load.
 */
import { createContext, useContext, useMemo } from "react";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog } from "./types";
import { documentRows } from "./fieldPaths";

export interface NativeView { log: NativeLog; product: string; /** Rows of the same transaction the product writes beside this one. */ related?: NativeLog[] }
export type NativeRenderer = (ev: TelemetryEvent) => NativeView | null;

const Ctx = createContext<NativeRenderer | null>(null);
export const NativeLogProvider = Ctx.Provider;

/** The page's native renderer itself (null outside a provider): lets the feed filter on native fields. */
export function useNativeRenderer(): NativeRenderer | null {
  return useContext(Ctx);
}

/** The native view of an event, or null (no provider yet, or no native module for it). */
export function useNativeLog(ev: TelemetryEvent | null | undefined): NativeView | null {
  const render = useContext(Ctx);
  return useMemo(() => {
    if (!render || !ev) return null;
    try { return render(ev); } catch { return null; }
    // ts is part of the key: the feed re-stamps events as they stream in.
  }, [render, ev]);
}

/** A native record as the fields table shows it: Discover-style paths, no array positions (fieldPaths.ts). */
export function nativeRows(record: Record<string, unknown>): [string, string][] {
  return documentRows(record);
}
