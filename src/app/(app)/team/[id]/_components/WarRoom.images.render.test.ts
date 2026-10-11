// Team chat screenshots: an image message renders through the session's signed-URL
// route (never a raw storage URL), the caption shows, the image-only placeholder text
// is hidden, and members (not observers) get the attach button.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { WarRoom } from "./WarRoom";
import type { Ev, Me } from "@/lib/team/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const SID = "42dd267e-47a2-466b-be66-119757f2bc69";
const PATH = `${SID}/b9dcb385-398a-4ddc-a457-5c3ec87b85f9.webp`;
const ev = (seq: number, actor: string, payload: Record<string, unknown>) =>
  ({ seq, type: "message.sent", actor_id: actor, role: "t1", payload, occurred_at: "2026-10-07T09:00:00Z" }) as unknown as Ev;

describe("WarRoom — screenshots", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  function mount(me: Partial<Me>, events: Ev[]) {
    el = document.createElement("div"); document.body.appendChild(el);
    root = createRoot(el);
    act(() => root!.render(React.createElement(WarRoom, { sessionId: SID, events, me: { id: "me", ...me } as Me, nameOf: () => "Dana", act: async () => true })));
    return el;
  }

  it("renders an image message through the session route, with its caption", () => {
    const c = mount({ role: "t2" }, [
      ev(1, "u1", { text: "the EDR tree for FS01", image: { path: PATH, w: 640, h: 360 } }),
      ev(2, "u1", { text: "Shared a screenshot", image: { path: PATH, w: 640, h: 360 } }),
    ]);
    const imgs = [...c.querySelectorAll("img")];
    expect(imgs).toHaveLength(2);
    for (const img of imgs) expect(img.getAttribute("src")).toBe(`/api/team/sessions/${SID}/chat-image?path=${encodeURIComponent(PATH)}`);
    expect(imgs[0].getAttribute("alt")).toBe("the EDR tree for FS01");
    expect(imgs[1].getAttribute("alt")).toBe("Screenshot shared by Dana");
    expect(c.textContent).toContain("the EDR tree for FS01");
    expect(c.textContent).not.toContain("Shared a screenshot");
  });

  it("members get the attach button; observers do not", () => {
    expect(mount({ role: "t1" }, []).querySelector('[aria-label="Attach an image or screenshot"]')).not.toBeNull();
    act(() => root?.unmount()); el?.remove();
    expect(mount({ role: "observer" }, []).querySelector('[aria-label="Attach an image or screenshot"]')).toBeNull();
  });
});
