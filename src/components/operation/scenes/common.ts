import * as THREE from "three";
import type { HubStation } from "../board/types";

/** What every room world receives. Worlds are decorative: no pointer events. */
export interface WorldProps {
  stations: HubStation[];
  /** The station the board has selected (highlighted in the world). */
  selected: number;
  primary: string;
  secondary: string;
  warn: string;
  dimmed: boolean;
  reducedMotion: boolean;
}

export const GREEN = new THREE.Color("#34d399");
export const LOCKED = new THREE.Color("#1e293b");

/** Status colour of a station in its world. */
export function statusColor(s: HubStation, primary: THREE.Color, warn: THREE.Color): THREE.Color {
  return s.status === "cleared" ? GREEN : s.status === "open" ? primary : warn;
}

/**
 * Shared plumbing for a world: renderer sized to its mount, a frame loop that
 * hands the elapsed time to `frame`, and full disposal on unmount.
 */
export function mountWorld(
  mount: HTMLDivElement,
  camera: THREE.PerspectiveCamera,
  scene: THREE.Scene,
  frame: (t: number, dt: number) => void,
  onResize?: (w: number, h: number) => void,
) {
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setClearColor(0x000000, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  mount.appendChild(renderer.domElement);
  const resize = () => {
    const w = mount.clientWidth, h = mount.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    onResize?.(w, h);
  };
  const ro = new ResizeObserver(resize);
  ro.observe(mount);
  resize();
  const clock = new THREE.Clock();
  let raf = 0;
  const loop = () => {
    raf = requestAnimationFrame(loop);
    const dt = Math.min(clock.getDelta(), 0.1);
    frame(clock.elapsedTime, dt);
    renderer.render(scene, camera);
  };
  loop();
  return () => {
    cancelAnimationFrame(raf);
    ro.disconnect();
    scene.traverse(obj => {
      const m = obj as THREE.Mesh;
      m.geometry?.dispose();
      const mat = m.material as THREE.Material | THREE.Material[] | undefined;
      if (Array.isArray(mat)) mat.forEach(x => { (x as THREE.MeshBasicMaterial).map?.dispose(); x.dispose(); });
      else if (mat) { (mat as THREE.MeshBasicMaterial).map?.dispose(); mat.dispose(); }
    });
    renderer.dispose();
    mount.removeChild(renderer.domElement);
  };
}

/** Moves a DOM label to a 3D point (it stays hidden when behind the camera). */
export function placeLabel(el: HTMLElement | null, p: THREE.Vector3, camera: THREE.Camera, w: number, h: number) {
  if (!el) return;
  const v = p.clone().project(camera);
  el.style.display = v.z > 1 ? "none" : "";
  el.style.transform = `translate(-50%, -100%) translate(${(v.x * 0.5 + 0.5) * w}px, ${(-v.y * 0.5 + 0.5) * h}px)`;
}

/** Soft round sprite texture for glows and particles. */
export function glowTexture(): THREE.Texture {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.45)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

export const additive = (color: THREE.ColorRepresentation, opacity = 1) =>
  new THREE.MeshBasicMaterial({ color, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false });

export const shortLabel = (label: string) => label.replace(/^The /, "");
/** The station name without a "Hop 3:" / "Ground Floor:" prefix, for tight spots. */
export const coreName = (label: string) => shortLabel(label.includes(":") ? label.slice(label.indexOf(":") + 1).trim() : label);
export const pad2 = (n: number) => String(n).padStart(2, "0");
