import * as THREE from "three";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";

/**
 * What the room theme's layouts share: status colours, line icons, canvas textures
 * and the renderer finish. The logo is never painted into a world: the board carries
 * the site's own Logo, so a white-label organization never sees the platform's mark.
 */
export type FacilityIcon = "mail" | "shield" | "filter" | "wire" | "users" | "target" | "monitor" | "siren";

export const STATUS = { cleared: "#34d399", locked: "#64748b" };
export const ICONS: Record<FacilityIcon | "lock" | "check" | "layers" | "pulse" | "bag" | "eye" | "compass", string> = {
  mail: "M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z M22 7l-10 6L2 7",
  shield: "M12 2L3 6v6c0 5 3.5 9.5 9 10 5.5-.5 9-5 9-10V6l-9-4z M9 12l2 2 4-4",
  filter: "M22 3H2l8 9.46V19l4 2v-8.54L22 3z",
  wire: "M2 6h20v12H2z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  users: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75",
  target: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12z M12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z",
  monitor: "M2 3h20v14H2z M8 21h8 M12 17v4",
  siren: "M12 3v2 M4 20h16 M7 20v-7a5 5 0 0 1 10 0v7",
  layers: "M12 2L2 7l10 5 10-5-10-5z M2 12l10 5 10-5 M2 17l10 5 10-5",
  pulse: "M22 12h-4l-3 9L9 3l-3 9H2",
  bag: "M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z M3 6h18 M16 10a4 4 0 0 1-8 0",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  compass: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M16 8l-2 6-6 2 2-6z",
  lock: "M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4",
  check: "M20 6L9 17l-5-5",
};

export function icon(g: CanvasRenderingContext2D, name: keyof typeof ICONS, cx: number, cy: number, size: number, color: string, width = 1.5) {
  g.save();
  g.translate(cx - size / 2, cy - size / 2);
  g.scale(size / 24, size / 24);
  g.strokeStyle = color; g.lineWidth = width; g.lineCap = "round"; g.lineJoin = "round";
  g.stroke(new Path2D(ICONS[name]));
  g.restore();
}

export function canvas(w: number, h: number) {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const g = c.getContext("2d")!;
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 8;
  return { c, g, tex };
}

/** The shared finish: environment reflections, and bloom on larger screens. */
export function facilityPipeline(small: boolean) {
  return (renderer: THREE.WebGLRenderer, sc: THREE.Scene, cam: THREE.PerspectiveCamera) => {
    const pmrem = new THREE.PMREMGenerator(renderer);
    const env = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
    sc.environment = env;
    sc.environmentIntensity = 0.42;
    pmrem.dispose();
    if (small) return { dispose: () => env.dispose() };
    const composer = new EffectComposer(renderer, new THREE.WebGLRenderTarget(1, 1, { type: THREE.HalfFloatType, samples: 4 }));
    composer.addPass(new RenderPass(sc, cam));
    composer.addPass(new UnrealBloomPass(new THREE.Vector2(512, 512), 0.5, 0.65, 0.82));
    composer.addPass(new OutputPass());
    return { render: () => composer.render(), setSize: (w: number, h: number) => composer.setSize(w, h), dispose: () => { composer.dispose(); env.dispose(); } };
  };
}
