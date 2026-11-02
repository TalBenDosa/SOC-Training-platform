"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import type { BuildingKind } from "@/lib/rooms/experience";

/**
 * The Operation hub: an isometric street — the "mail route". Each station is
 * its own building (archive, sorting plant, lab, office, vault) on a winding
 * road, and a glowing envelope travels the road to the next open station, so
 * progress reads as a journey rather than a menu.
 *
 * Plain three.js on purpose: Next 15's app router runs React 19 internally
 * while the project declares React 18, so React Three Fiber needs peer-dep
 * overrides and its global JSX augmentation breaks unrelated `React.ElementType`
 * props. Loaded client-only (next/dynamic, ssr:false) from OperationView.
 */

export type StationStatus = "locked" | "open" | "cleared";

export interface HubStation {
  id: string;
  label: string;
  status: StationStatus;
  boss?: boolean;
  building: BuildingKind;
  stars: number;
  progress: string; // "2/3"
}

interface HubSceneProps {
  stations: HubStation[];
  focusId: string | null;
  dimmed: boolean;
  reducedMotion: boolean;
  onSelect: (id: string) => void;
}

const COLORS = { locked: 0x334155, open: 0x22d3ee, cleared: 0x34d399, boss: 0xc084fc };
const ISO_DIR = new THREE.Vector3(1, 1.15, 1).normalize();

function colorFor(s: HubStation): number {
  if (s.status === "locked") return COLORS.locked;
  if (s.status === "cleared") return COLORS.cleared;
  return s.boss ? COLORS.boss : COLORS.open;
}
const hex = (c: number) => `#${c.toString(16).padStart(6, "0")}`;

/** Stations zig-zag along the street, left to right. */
function stationPosition(i: number, n: number): THREE.Vector3 {
  const span = Math.max(1, n - 1);
  return new THREE.Vector3(-6.4 + (12.8 * i) / span, 0, i % 2 === 0 ? 1.5 : -1.5);
}

const std = (color: number, extra: Partial<THREE.MeshStandardMaterialParameters> = {}) =>
  new THREE.MeshStandardMaterial({ color, roughness: 0.7, metalness: 0.15, ...extra });

function mesh(geo: THREE.BufferGeometry, mat: THREE.Material, x = 0, y = 0, z = 0): THREE.Mesh {
  const m = new THREE.Mesh(geo, mat);
  m.position.set(x, y, z);
  m.castShadow = true;
  m.receiveShadow = true;
  return m;
}

/**
 * One building per station kind. `body` is the shell (dimmed when locked),
 * `accent` is every lit surface (windows, dome, door ring) — recoloured by status.
 */
function makeBuilding(kind: BuildingKind, body: THREE.MeshStandardMaterial, accent: THREE.MeshStandardMaterial, trim: THREE.MeshStandardMaterial): { group: THREE.Group; height: number } {
  const g = new THREE.Group();
  switch (kind) {
    case "archive": {
      g.add(mesh(new THREE.BoxGeometry(2.2, 0.18, 1.7), trim, 0, 0.09, 0));             // steps
      g.add(mesh(new THREE.BoxGeometry(1.9, 1.1, 1.3), body, 0, 0.73, -0.1));
      const roof = mesh(new THREE.ConeGeometry(1.45, 0.7, 4), trim, 0, 1.63, -0.1);
      roof.rotation.y = Math.PI / 4;
      roof.scale.set(1, 1, 0.75);
      g.add(roof);
      for (const x of [-0.7, -0.24, 0.24, 0.7]) g.add(mesh(new THREE.CylinderGeometry(0.07, 0.07, 1.0, 10), trim, x, 0.68, 0.62));
      g.add(mesh(new THREE.PlaneGeometry(0.5, 0.7), accent, 0, 0.55, 0.56));            // lit doorway
      return { group: g, height: 2.0 };
    }
    case "factory": {
      g.add(mesh(new THREE.BoxGeometry(2.2, 1.0, 1.5), body, 0, 0.5, 0));
      for (const x of [-0.72, 0, 0.72]) {
        const tooth = mesh(new THREE.CylinderGeometry(0.42, 0.42, 1.5, 3, 1), trim, x, 1.12, 0);
        tooth.rotation.set(Math.PI / 2, 0, Math.PI / 2);
        g.add(tooth);
      }
      g.add(mesh(new THREE.CylinderGeometry(0.14, 0.18, 1.3, 12), trim, 0.85, 1.55, -0.5));
      const stackGlow = mesh(new THREE.TorusGeometry(0.15, 0.03, 8, 20), accent, 0.85, 2.2, -0.5);
      stackGlow.rotation.x = Math.PI / 2;
      g.add(stackGlow);
      for (const x of [-0.7, -0.25, 0.2]) g.add(mesh(new THREE.PlaneGeometry(0.32, 0.3), accent, x, 0.62, 0.76));
      g.add(mesh(new THREE.BoxGeometry(0.6, 0.5, 0.05), trim, 0.68, 0.25, 0.76));         // loading door
      return { group: g, height: 2.3 };
    }
    case "lab": {
      g.add(mesh(new THREE.CylinderGeometry(1.0, 1.1, 0.6, 32), body, 0, 0.3, 0));
      g.add(mesh(new THREE.CylinderGeometry(1.02, 1.02, 0.06, 32), trim, 0, 0.62, 0));
      const dome = new THREE.Mesh(
        new THREE.SphereGeometry(0.9, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2),
        new THREE.MeshPhysicalMaterial({ color: 0x9be7ff, transparent: true, opacity: 0.22, roughness: 0.05, metalness: 0, depthWrite: false }),
      );
      dome.position.y = 0.64;
      g.add(dome);
      g.add(mesh(new THREE.IcosahedronGeometry(0.28, 0), accent, 0, 1.0, 0));            // specimen
      g.add(mesh(new THREE.CylinderGeometry(0.04, 0.04, 0.3, 8), trim, 0, 0.78, 0));
      return { group: g, height: 1.7 };
    }
    case "office": {
      g.add(mesh(new THREE.BoxGeometry(1.5, 2.3, 1.3), body, 0, 1.15, 0));
      g.add(mesh(new THREE.BoxGeometry(1.6, 0.1, 1.4), trim, 0, 2.35, 0));
      for (let r = 0; r < 4; r++) for (let c = 0; c < 3; c++) {
        g.add(mesh(new THREE.PlaneGeometry(0.28, 0.26), accent, -0.45 + c * 0.45, 0.55 + r * 0.45, 0.66));
      }
      g.add(mesh(new THREE.CylinderGeometry(0.02, 0.02, 0.7, 6), trim, 0.5, 2.75, -0.3));
      return { group: g, height: 3.0 };
    }
    case "vault": {
      g.add(mesh(new THREE.BoxGeometry(2.3, 1.4, 1.6), body, 0, 0.7, 0));
      g.add(mesh(new THREE.BoxGeometry(2.5, 0.16, 1.8), trim, 0, 1.48, 0));
      const pediment = mesh(new THREE.CylinderGeometry(0.9, 0.9, 1.8, 3, 1), trim, 0, 1.72, 0);
      pediment.rotation.set(Math.PI / 2, 0, Math.PI / 2);
      pediment.scale.set(1, 1, 0.35);
      g.add(pediment);
      const door = mesh(new THREE.CylinderGeometry(0.52, 0.52, 0.08, 40), trim, 0, 0.72, 0.82);
      door.rotation.x = Math.PI / 2;
      g.add(door);
      g.add(mesh(new THREE.TorusGeometry(0.52, 0.05, 10, 40), accent, 0, 0.72, 0.86));
      for (let k = 0; k < 3; k++) {
        const spoke = mesh(new THREE.BoxGeometry(0.8, 0.05, 0.05), accent, 0, 0.72, 0.88);
        spoke.rotation.z = (k * Math.PI) / 3;
        g.add(spoke);
      }
      return { group: g, height: 2.4 };
    }
  }
}

function makeEnvelope(): THREE.Group {
  const g = new THREE.Group();
  g.add(new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.04, 0.34), new THREE.MeshStandardMaterial({ color: 0xf8fafc, emissive: 0xffffff, emissiveIntensity: 0.25 })));
  const flap = new THREE.Mesh(new THREE.ConeGeometry(0.25, 0.16, 3), new THREE.MeshStandardMaterial({ color: 0xcbd5e1 }));
  flap.rotation.set(Math.PI / 2, 0, 0);
  flap.scale.set(1, 1, 0.12);
  flap.position.set(0, 0.03, -0.02);
  g.add(flap);
  const seal = new THREE.Mesh(new THREE.CircleGeometry(0.05, 16), new THREE.MeshStandardMaterial({ color: 0xef4444, emissive: 0xef4444, emissiveIntensity: 0.8 }));
  seal.rotation.x = -Math.PI / 2;
  seal.position.y = 0.025;
  g.add(seal);
  return g;
}

interface StationRig {
  body: THREE.MeshStandardMaterial;
  accent: THREE.MeshStandardMaterial;
  ring: THREE.MeshStandardMaterial;
  group: THREE.Group;
  hit: THREE.Mesh;
  pos: THREE.Vector3;
  labelAnchor: THREE.Vector3;
}

export default function HubScene({ stations, focusId, dimmed, reducedMotion, onSelect }: HubSceneProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const rigsRef = useRef<StationRig[]>([]);
  const live = useRef({ stations, focusId, reducedMotion, onSelect });
  live.current = { stations, focusId, reducedMotion, onSelect };
  const layoutKey = stations.map(s => s.building).join(",");

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const n = live.current.stations.length;

    const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setSize(mount.clientWidth, mount.clientHeight);
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    mount.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x070b16);

    // Isometric orthographic camera; zoom is fitted to the street every frame.
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0.1, 200);
    const target = new THREE.Vector3(0, 0, 0);
    const lookAt = new THREE.Vector3(0, 0, 0);
    camera.position.copy(ISO_DIR).multiplyScalar(40);
    camera.lookAt(lookAt);

    scene.add(new THREE.HemisphereLight(0xc7d2fe, 0x0b1220, 0.9));
    const sun = new THREE.DirectionalLight(0xffffff, 1.4);
    sun.position.set(-6, 14, 9);
    sun.castShadow = true;
    sun.shadow.mapSize.set(2048, 2048);
    Object.assign(sun.shadow.camera, { left: -14, right: 14, top: 10, bottom: -10, near: 1, far: 40 });
    sun.shadow.bias = -0.0004;
    scene.add(sun);

    // City block: a raised slab with a glowing kerb.
    const slab = mesh(new THREE.BoxGeometry(18, 0.5, 8.2), std(0x111a2e, { roughness: 0.9 }), 0, -0.25, 0);
    scene.add(slab);
    const kerb = new THREE.Mesh(new THREE.BoxGeometry(18.1, 0.05, 8.3), new THREE.MeshStandardMaterial({ color: 0x22d3ee, emissive: 0x22d3ee, emissiveIntensity: 0.6 }));
    kerb.position.y = -0.47;
    scene.add(kerb);

    // The road: segments through every station, plus centre dashes and lamps.
    const pts = Array.from({ length: n }, (_, i) => stationPosition(i, n));
    const roadPts = [new THREE.Vector3(-8.6, 0, 3.2), ...pts.map(p => p.clone().setZ(p.z * 0.35)), new THREE.Vector3(8.6, 0, -3.2)];
    const roadMat = std(0x1e293b, { roughness: 0.95 });
    const dashMat = new THREE.MeshStandardMaterial({ color: 0xfacc15, emissive: 0xfacc15, emissiveIntensity: 0.35 });
    const lampHeadMat = new THREE.MeshStandardMaterial({ color: 0xfef3c7, emissive: 0xfde68a, emissiveIntensity: 1.4 });
    const poleMat = std(0x475569);
    for (let i = 0; i < roadPts.length - 1; i++) {
      const a = roadPts[i], b = roadPts[i + 1];
      const len = a.distanceTo(b);
      const mid = a.clone().add(b).multiplyScalar(0.5);
      const ang = Math.atan2(b.x - a.x, b.z - a.z);
      const seg = mesh(new THREE.BoxGeometry(1.1, 0.04, len + 1.1), roadMat, mid.x, 0.02, mid.z);
      seg.rotation.y = ang;
      seg.castShadow = false;
      scene.add(seg);
      for (let d = 0.6; d < len - 0.3; d += 0.9) {
        const p = a.clone().lerp(b, d / len);
        const dash = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.02, 0.4), dashMat);
        dash.position.set(p.x, 0.05, p.z);
        dash.rotation.y = ang;
        scene.add(dash);
      }
      // a street lamp beside each segment
      const side = new THREE.Vector3(Math.cos(ang), 0, -Math.sin(ang)).multiplyScalar(0.85);
      const lp = mid.clone().add(side);
      scene.add(mesh(new THREE.CylinderGeometry(0.03, 0.04, 0.9, 6), poleMat, lp.x, 0.45, lp.z));
      scene.add(mesh(new THREE.SphereGeometry(0.08, 10, 8), lampHeadMat, lp.x, 0.93, lp.z));
    }

    // Low background blocks so the street sits in a neighbourhood.
    const fillerMat = std(0x0f172a, { roughness: 0.9 });
    const fillerWin = new THREE.MeshStandardMaterial({ color: 0x0f172a, emissive: 0x334155, emissiveIntensity: 0.5 });
    const rand = (() => { let s = 7; return () => ((s = (s * 9301 + 49297) % 233280) / 233280); })();
    for (let i = 0; i < 16; i++) {
      const x = -8 + (16 * i) / 15 + (rand() - 0.5) * 0.4;
      const z = i % 2 ? -3.4 : 3.4;
      if (pts.some(p => Math.abs(p.x - x) < 1.3 && Math.sign(p.z) === Math.sign(z))) continue;
      const h = 0.4 + rand() * 1.1;
      scene.add(mesh(new THREE.BoxGeometry(0.8 + rand() * 0.5, h, 0.8), fillerMat, x, h / 2, z));
      if (rand() > 0.4) scene.add(mesh(new THREE.PlaneGeometry(0.2, 0.15), fillerWin, x, h * 0.6, z + 0.41));
    }

    // Stations
    const rigs: StationRig[] = pts.map((pos, i) => {
      const s = live.current.stations[i];
      const body = std(0x334155, { roughness: 0.6 });
      const trim = std(0x1e293b, { metalness: 0.4, roughness: 0.4 });
      const accent = new THREE.MeshStandardMaterial({ color: 0x020617, emissive: COLORS.locked, emissiveIntensity: 0.1 });
      const { group, height } = makeBuilding(s.building, body, accent, trim);
      group.position.copy(pos);
      // Fronts face +z; the iso camera (from +x,+z) sees the front and the right side.
      scene.add(group);

      const ringMat = new THREE.MeshStandardMaterial({ color: COLORS.locked, emissive: COLORS.locked, emissiveIntensity: 0.3, transparent: true, opacity: 0.9 });
      const ring = new THREE.Mesh(new THREE.RingGeometry(1.45, 1.6, 48), ringMat);
      ring.rotation.x = -Math.PI / 2;
      ring.position.set(pos.x, 0.03, pos.z);
      scene.add(ring);

      const hit = new THREE.Mesh(new THREE.BoxGeometry(2.6, height + 0.6, 2.2), new THREE.MeshBasicMaterial({ visible: false }));
      hit.position.set(pos.x, (height + 0.6) / 2, pos.z);
      hit.userData.index = i;
      scene.add(hit);

      return { body, accent, ring: ringMat, group, hit, pos, labelAnchor: pos.clone().setY(height + 0.55) };
    });
    rigsRef.current = rigs;
    applyStatus();

    // The envelope that travels the route.
    const curve = new THREE.CatmullRomCurve3(roadPts.slice(1, -1).map(p => p.clone().setY(0.55)));
    const envelope = makeEnvelope();
    scene.add(envelope);
    const envGlow = new THREE.PointLight(0xffffff, 3, 3, 2);
    envelope.add(envGlow);
    let routeU = 0;

    // Picking
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(0, 0);
    let hovered = -1;
    let downAt: { x: number; y: number } | null = null;
    const hits = rigs.map(r => r.hit);
    function pick(cx: number, cy: number): number {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.set(((cx - rect.left) / rect.width) * 2 - 1, -((cy - rect.top) / rect.height) * 2 + 1);
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(hits, false)[0];
      return hit ? (hit.object.userData.index as number) : -1;
    }
    const onMove = (e: PointerEvent) => {
      hovered = pick(e.clientX, e.clientY);
      const s = hovered >= 0 ? live.current.stations[hovered] : null;
      renderer.domElement.style.cursor = s ? (s.status === "locked" ? "not-allowed" : "pointer") : "auto";
    };
    const onDown = (e: PointerEvent) => { downAt = { x: e.clientX, y: e.clientY }; };
    const onUp = (e: PointerEvent) => {
      if (!downAt || Math.hypot(e.clientX - downAt.x, e.clientY - downAt.y) > 6) { downAt = null; return; }
      downAt = null;
      const i = pick(e.clientX, e.clientY);
      const s = i >= 0 ? live.current.stations[i] : null;
      if (s && s.status !== "locked") live.current.onSelect(s.id);
    };
    renderer.domElement.addEventListener("pointermove", onMove);
    renderer.domElement.addEventListener("pointerdown", onDown);
    renderer.domElement.addEventListener("pointerup", onUp);

    // Fit: how much zoom shows the whole block, given the current aspect.
    const bounds = [
      new THREE.Vector3(-9, 0, -4.1), new THREE.Vector3(9, 0, -4.1), new THREE.Vector3(-9, 0, 4.1), new THREE.Vector3(9, 0, 4.1),
      new THREE.Vector3(-9, 3.4, -4.1), new THREE.Vector3(9, 3.4, -4.1),
    ];
    let fitZoom = 0.1;
    const resize = () => {
      const w = mount.clientWidth, h = mount.clientHeight;
      if (!w || !h) return;
      renderer.setSize(w, h);
      const aspect = w / h;
      Object.assign(camera, { left: -aspect, right: aspect, top: 1, bottom: -1 });
      camera.position.copy(ISO_DIR).multiplyScalar(40);
      camera.lookAt(0, 0, 0);
      camera.updateMatrixWorld();
      const inv = camera.matrixWorldInverse;
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
      for (const b of bounds) {
        const v = b.clone().applyMatrix4(inv);
        minX = Math.min(minX, v.x); maxX = Math.max(maxX, v.x); minY = Math.min(minY, v.y); maxY = Math.max(maxY, v.y);
      }
      // Leave room for the HUD on top and the station dock below.
      fitZoom = Math.min((2 * aspect) / (maxX - minX), 1.25 / (maxY - minY)) * 0.96;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    resize();
    camera.zoom = fitZoom;
    camera.updateProjectionMatrix();

    // Loop
    const clock = new THREE.Clock();
    const tmp = new THREE.Vector3();
    const offset = new THREE.Vector3();
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      const dt = Math.min(clock.getDelta(), 0.1);
      const t = clock.elapsedTime;
      const { stations: st, focusId: fid, reducedMotion: rm } = live.current;
      const k = rm ? 1 : 1 - Math.pow(0.015, dt);

      // Camera: whole street, nudged up so it sits above the dock; or zoomed onto a building.
      const fi = st.findIndex(s => s.id === fid);
      let zoomTarget = fitZoom;
      if (fi >= 0) { target.copy(rigs[fi].pos).setY(0.8); zoomTarget = fitZoom * 2.4; }
      else target.set(rm ? 0 : pointer.x * 0.4, 0, rm ? 0 : -pointer.x * 0.4).add(offset.set(0.9, 0, 0.9));
      lookAt.lerp(target, k);
      camera.position.copy(lookAt).addScaledVector(ISO_DIR, 40);
      camera.lookAt(lookAt);
      if (Math.abs(camera.zoom - zoomTarget) > 1e-4) { camera.zoom += (zoomTarget - camera.zoom) * k; camera.updateProjectionMatrix(); }

      // Envelope rides to the frontier station (first not cleared; the last one when all are).
      const front = st.findIndex(s => s.status !== "cleared");
      const goal = n <= 1 ? 0 : (front === -1 ? n - 1 : front) / (n - 1);
      routeU += (goal - routeU) * (rm ? 1 : 1 - Math.pow(0.2, dt));
      curve.getPointAt(Math.min(1, Math.max(0, routeU)), tmp);
      envelope.position.set(tmp.x, 0.6 + (rm ? 0 : Math.sin(t * 2.2) * 0.07), tmp.z);
      if (!rm) envelope.rotation.y = Math.sin(t * 0.8) * 0.3;

      rigs.forEach((r, i) => {
        const s = st[i];
        if (!s) return;
        const lift = i === hovered && s.status !== "locked" ? 1.06 : 1;
        r.group.scale.lerp(tmp.setScalar(lift), 1 - Math.pow(0.001, dt));
        if (!rm && s.status === "open") {
          r.accent.emissiveIntensity = 1.2 + Math.sin(t * 2.6) * 0.45;
          r.ring.emissiveIntensity = 1.0 + Math.sin(t * 2.6) * 0.6;
        }
        const el = labelRefs.current[i];
        if (el) {
          tmp.copy(r.labelAnchor).project(camera);
          el.style.transform = `translate(-50%, -100%) translate(${(tmp.x * 0.5 + 0.5) * mount.clientWidth}px, ${(-tmp.y * 0.5 + 0.5) * mount.clientHeight}px)`;
        }
      });
      renderer.render(scene, camera);
    };
    loop();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.domElement.removeEventListener("pointermove", onMove);
      renderer.domElement.removeEventListener("pointerdown", onDown);
      renderer.domElement.removeEventListener("pointerup", onUp);
      scene.traverse(obj => {
        const m = obj as THREE.Mesh;
        m.geometry?.dispose();
        const mat = m.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach(x => x.dispose()); else mat?.dispose();
      });
      renderer.dispose();
      mount.removeChild(renderer.domElement);
      rigsRef.current = [];
    };
    // Built once per layout; status changes go through applyStatus.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutKey]);

  function applyStatus() {
    const { stations: st } = live.current;
    rigsRef.current.forEach((r, i) => {
      const s = st[i];
      if (!s) return;
      const c = colorFor(s);
      const lit = s.status !== "locked";
      r.body.color.setHex(lit ? 0x475569 : 0x243045);
      r.accent.emissive.setHex(c);
      r.accent.emissiveIntensity = lit ? 1.3 : 0.08;
      r.ring.color.setHex(c); r.ring.emissive.setHex(c);
      r.ring.emissiveIntensity = lit ? 1.1 : 0.25;
    });
  }
  useEffect(applyStatus, [stations]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: dimmed ? "blur(6px) brightness(0.45)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 flex flex-col items-center text-center will-change-transform">
            <span
              className="whitespace-nowrap rounded-full border bg-[#070b16]/80 px-3 py-1 text-[13px] font-bold backdrop-blur"
              style={{ color: s.status === "locked" ? "#64748b" : "#f1f5f9", borderColor: hex(colorFor(s)) + "80" }}
            >
              {s.status === "locked" ? "🔒 " : ""}{s.label}
            </span>
            <span className="mt-1 font-mono text-[11px] drop-shadow-[0_1px_3px_rgba(0,0,0,0.9)]" style={{ color: hex(colorFor(s)) }}>
              {s.status === "cleared" ? "★".repeat(s.stars) + "☆".repeat(3 - s.stars) : s.status === "open" ? s.progress : ""}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
