// No HACK THE SOC flash inside a white-label environment: the (app) layout hands the
// server-resolved environment brand to AppBrandScope, which uses it from the very first
// render, before the client fetch has answered.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { AppBrandScope, useBrand, useFeatures } from "./BrandContext";
import { brandFromOrg } from "./brand";
import { parseFeatures } from "./features";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const env = brandFromOrg({ id: "o1", name: "College", branding: { white_label: true, product_name: "College SOC", logo_data: "data:image/png;base64,AAAA" } });

function Probe() {
  const b = useBrand();
  const f = useFeatures();
  return React.createElement("p", null, `${b.productName}|${b.logoSrc ?? "none"}|quizzes:${f.quizzes}`);
}

describe("AppBrandScope first paint", () => {
  let root: Root | null = null; let el: HTMLDivElement | null = null;
  afterEach(() => { act(() => root?.unmount()); el?.remove(); });
  const render = (props: Record<string, unknown>) => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    act(() => { root!.render(React.createElement(AppBrandScope, props as never, React.createElement(Probe))); });
    return el.textContent ?? "";
  };

  it("shows the environment's brand and plan on the first render", () => {
    const text = render({ initialEnvBrand: env, initialFeatures: parseFeatures({ quizzes: false }) });
    expect(text).toContain("College SOC");
    expect(text).toContain("/api/brand/logo?org=o1");
    expect(text).toContain("quizzes:false");
    expect(text).not.toContain("HACK THE SOC");
  });

  it("without a white-label environment it is the platform", () => {
    expect(render({ initialEnvBrand: null })).toContain("HACK THE SOC");
  });
});
