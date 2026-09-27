"use client";
/**
 * React access to the shared notifications store (store.ts). Every consumer —
 * the Topbar bell, the plan-announcement popup — reads the SAME snapshot and
 * the store runs ONE poll between them. Signed-out users get an empty,
 * disabled snapshot and nothing is fetched.
 */
import { useEffect, useSyncExternalStore } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import {
  EMPTY_NOTIFICATIONS, attach, getServerSnapshot, getSnapshot, markAllRead, markRead, refresh, subscribe,
  type NotificationsState,
} from "./store";

export interface UseNotifications extends NotificationsState {
  refresh: typeof refresh;
  markRead: typeof markRead;
  markAllRead: typeof markAllRead;
}

export function useNotifications(): UseNotifications {
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const snap = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  useEffect(() => attach(userId), [userId]);
  const mine = snap.userId === userId ? snap : EMPTY_NOTIFICATIONS;
  return { ...mine, refresh, markRead, markAllRead };
}
