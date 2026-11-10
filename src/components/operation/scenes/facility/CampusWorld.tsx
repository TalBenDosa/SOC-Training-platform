"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { mountWorld, type WorldProps } from "../common";
import { netNode } from "../cyberProps";
import { canvas, icon, type FacilityIcon, fitFont } from "./kit";

/**
 * The campus layout of the room theme: a dusk island seen from a hill, a security
 * hub in the middle and one neon building per station, joined by a lit path. The
 * board, status badges and the site's own logo are the same as every other layout.
 * A room varies the buildings, their colours and what shows on each sign. Nothing
 * here may name a graded answer or a lab answer.
 */
export interface CampusConfig {
  /** Plants this room's own island: trees and ridges fall differently. */
  seed?: number;
  hub: { title: string; sub: string };
  /** One per station, in station order. */
  buildings: { icon: FacilityIcon; sign: string[]; color: string; x: number; z: number; rot: number }[];
}

const DONE = "#34d399";

/** A seeded random, so a room's island never changes between visits. */
function seeded(seed: number) {
  let s = seed;
  return () => { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646; };
}

/** A rock pillar with a grass cap: the island and every plateau on it. */
function plateau(r: number, h: number, rnd: () => number, grass = 0x17523f, rock = 0x39445c) {
  const g = new THREE.Group();
  const rockGeo = new THREE.CylinderGeometry(r, r * 0.72, h, 12, 3);
  const pos = rockGeo.attributes.position;
  for (let i = 0; i < pos.count; i++) {
    const k = 1 + (rnd() - 0.5) * 0.14;
    pos.setX(i, pos.getX(i) * k); pos.setZ(i, pos.getZ(i) * k);
  }
  rockGeo.computeVertexNormals();
  const body = new THREE.Mesh(rockGeo, new THREE.MeshStandardMaterial({ color: rock, flatShading: true, roughness: 0.9 }));
  body.position.y = -h / 2;
  g.add(body);
  const cap = new THREE.Mesh(new THREE.CylinderGeometry(r * 1.02, r * 1.04, 0.3, 12), new THREE.MeshStandardMaterial({ color: grass, flatShading: true, roughness: 0.85 }));
  cap.position.y = -0.1;
  g.add(cap);
  return g;
}

function tree(rnd: () => number) {
  const g = new THREE.Group();
  const trunk = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.1, 0.5, 5), new THREE.MeshStandardMaterial({ color: 0x4a3a30 }));
  trunk.position.y = 0.25;
  g.add(trunk);
  const col = [0x1c7a5c, 0x17694f, 0x2a8a63, 0x14594a][Math.floor(rnd() * 4)];
  const leaf = new THREE.MeshStandardMaterial({ color: col, flatShading: true, roughness: 0.8 });
  [[0.6, 0.9, 0.7], [0.45, 0.8, 1.15]].forEach(([r, h, y]) => { const c = new THREE.Mesh(new THREE.ConeGeometry(r, h, 7), leaf); c.position.y = y; g.add(c); });
  g.scale.setScalar(0.8 + rnd() * 0.7);
  return g;
}

/** The stepped front of a campus building. */
function buildingShape(w: number, h: number) {
  const s = new THREE.Shape();
  const W = w / 2;
  [[-W, 0], [W, 0], [W, h * 0.56], [W * 0.72, h * 0.56], [W * 0.72, h * 0.78], [W * 0.38, h * 0.78], [W * 0.38, h], [-W * 0.38, h], [-W * 0.38, h * 0.78], [-W * 0.72, h * 0.78], [-W * 0.72, h * 0.56], [-W, h * 0.56]]
    .forEach(([x, y], i) => (i ? s.lineTo(x, y) : s.moveTo(x, y)));
  s.closePath();
  return s;
}

function building(cfg: CampusConfig["buildings"][number], rnd: () => number) {
  const g = new THREE.Group();
  const W = 5.6, H = 4.4, D = 3.2;
  const base = new THREE.Color(cfg.color).multiplyScalar(0.3);
  const bodyMat = new THREE.MeshStandardMaterial({ color: base, metalness: 0.45, roughness: 0.42 });
  const geo = new THREE.ExtrudeGeometry(buildingShape(W, H), { depth: D, bevelEnabled: false });
  geo.translate(0, 0, -D / 2);
  g.add(new THREE.Mesh(geo, bodyMat));
  const neonMat = new THREE.LineBasicMaterial({ color: cfg.color, toneMapped: false });
  g.add(new THREE.LineSegments(new THREE.EdgesGeometry(geo, 20), neonMat));

  // The sign on the front gable
  const sg = canvas(512, 300);
  sg.g.fillStyle = "rgba(4,10,20,0.78)"; sg.g.beginPath(); sg.g.roundRect(0, 0, 512, 300, 16); sg.g.fill();
  icon(sg.g, cfg.icon, 256, 84, 112, cfg.color, 1.5);
  sg.g.fillStyle = "#ffffff"; sg.g.textAlign = "center"; fitFont(sg.g, cfg.sign, 54, 470);
  cfg.sign.forEach((l, i) => sg.g.fillText(l, 256, 196 + i * 60));
  sg.tex.needsUpdate = true;
  const sign = new THREE.Mesh(new THREE.PlaneGeometry(3.3, 1.93), new THREE.MeshBasicMaterial({ map: sg.tex, transparent: true, toneMapped: false }));
  sign.position.set(0, H * 0.7, D / 2 + 0.03);
  g.add(sign);

  // The operations floor behind the glass: a row of live screens
  const win = canvas(640, 180);
  const wg = win.g.createLinearGradient(0, 0, 0, 180);
  wg.addColorStop(0, "#14233c"); wg.addColorStop(1, "#0a1424");
  win.g.fillStyle = wg; win.g.fillRect(0, 0, 640, 180);
  for (let i = 0; i < 5; i++) {
    const x = 16 + i * 124;
    win.g.fillStyle = "#050b16"; win.g.fillRect(x, 34, 112, 84);
    win.g.fillStyle = cfg.color; win.g.fillRect(x, 34, 112, 10);
    win.g.fillStyle = "#9fc4dd";
    for (let k = 0; k < 4; k++) win.g.fillRect(x + 8, 56 + k * 13, 40 + rnd() * 56, 5);
    win.g.fillStyle = "#050b16"; win.g.fillRect(x + 12, 142, 88, 12);
  }
  win.tex.needsUpdate = true;
  const windowMat = new THREE.MeshBasicMaterial({ map: win.tex, toneMapped: false });
  const glass = new THREE.Mesh(new THREE.PlaneGeometry(W - 0.8, 1.15), windowMat);
  glass.position.set(0, 0.95, D / 2 + 0.02);
  g.add(glass);
  const frame = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(W - 0.72, 1.23)), neonMat);
  frame.position.copy(glass.position);
  g.add(frame);

  // Lit apron: the ring around the building
  const apronMat = new THREE.MeshBasicMaterial({ color: cfg.color, transparent: true, opacity: 0.85, toneMapped: false });
  const apron = new THREE.Mesh(new THREE.TorusGeometry(4.2, 0.06, 6, 48), apronMat);
  apron.rotation.x = Math.PI / 2; apron.position.y = 0.09;
  g.add(apron);

  const glow = new THREE.PointLight(cfg.color, 10, 11, 1.7);
  glow.position.set(0, 1.8, D / 2 + 1.6);
  g.add(glow);

  // Status badge, the same language as the board
  const bd = canvas(160, 160);
  const badge = new THREE.Mesh(new THREE.PlaneGeometry(1.15, 1.15), new THREE.MeshBasicMaterial({ map: bd.tex, transparent: true, toneMapped: false, depthTest: false }));
  badge.renderOrder = 5;
  badge.position.set(0, -0.15, D / 2 + 1.2);
  g.add(badge);
  return { g, bodyMat, neonMat, windowMat, apronMat, glow, bd, badge, W, H, base };
}

function drawBadge(d: ReturnType<typeof canvas>, status: string, color: string) {
  const { g, tex } = d;
  g.clearRect(0, 0, 160, 160);
  g.fillStyle = "rgba(6,12,22,0.95)"; g.beginPath(); g.arc(80, 80, 68, 0, Math.PI * 2); g.fill();
  const col = status === "cleared" ? DONE : status === "locked" ? "#cbd5e1" : color;
  g.strokeStyle = col; g.lineWidth = 7; g.stroke();
  if (status === "open") { g.fillStyle = col; g.beginPath(); g.moveTo(62, 46); g.lineTo(62, 114); g.lineTo(116, 80); g.closePath(); g.fill(); }
  else icon(g, status === "cleared" ? "check" : "lock", 80, 80, 84, col, 2.4);
  tex.needsUpdate = true;
}

/** The analyst on the hill, seen from behind. */
function analyst(accent: string) {
  const g = new THREE.Group();
  const cloth = new THREE.MeshStandardMaterial({ color: 0x1b2638, roughness: 0.75 });
  const trim = new THREE.MeshBasicMaterial({ color: accent, toneMapped: false });
  const add = (geo: THREE.BufferGeometry, mat: THREE.Material, x: number, y: number, z: number, r = 0) => { const m = new THREE.Mesh(geo, mat); m.position.set(x, y, z); m.rotation.z = r; g.add(m); return m; };
  add(new THREE.CapsuleGeometry(0.2, 0.8, 4, 10), new THREE.MeshStandardMaterial({ color: 0x121a28 }), -0.24, 0.62, 0, 0.1);
  add(new THREE.CapsuleGeometry(0.2, 0.8, 4, 10), new THREE.MeshStandardMaterial({ color: 0x121a28 }), 0.24, 0.62, 0.1, -0.1);
  add(new THREE.CapsuleGeometry(0.42, 0.72, 6, 14), cloth, 0, 1.75, 0);
  add(new THREE.CapsuleGeometry(0.14, 0.7, 4, 8), cloth, -0.56, 1.72, 0, 0.16);
  add(new THREE.CapsuleGeometry(0.14, 0.7, 4, 8), cloth, 0.56, 1.72, 0, -0.16);
  add(new THREE.SphereGeometry(0.3, 16, 12), new THREE.MeshStandardMaterial({ color: 0x9a6f52, roughness: 0.6 }), 0, 2.72, -0.04);
  const hair = add(new THREE.SphereGeometry(0.33, 16, 12, 0, Math.PI * 2, 0, Math.PI * 0.62), new THREE.MeshStandardMaterial({ color: 0x111418, roughness: 0.8, flatShading: true }), 0, 2.78, 0.02);
  hair.rotation.x = 0.35;
  add(new THREE.TorusGeometry(0.34, 0.13, 8, 18), cloth, 0, 2.34, 0.04).rotation.x = Math.PI / 2;
  const pack = add(new THREE.BoxGeometry(0.82, 0.98, 0.34), new THREE.MeshStandardMaterial({ color: 0x18222f, metalness: 0.3, roughness: 0.55 }), 0, 1.78, 0.5);
  pack.geometry.translate(0, 0, 0);
  add(new THREE.BoxGeometry(0.5, 0.05, 0.02), trim, 0, 2.16, 0.68);
  const sc = canvas(128, 128);
  icon(sc.g, "shield", 64, 64, 112, accent, 1.8);
  sc.tex.needsUpdate = true;
  const mark = new THREE.Mesh(new THREE.PlaneGeometry(0.48, 0.48), new THREE.MeshBasicMaterial({ map: sc.tex, transparent: true, toneMapped: false }));
  mark.position.set(0, 1.76, 0.68);
  g.add(mark);
  return g;
}

export function CampusWorld({ cfg, props }: { cfg: CampusConfig; props: WorldProps }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const hitRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const small = window.innerWidth < 768;
    const accent = props.primary;
    const rnd = seeded(cfg.seed ?? 7741);
    const scene = new THREE.Scene();

    // ── Sky: dusk, with far ridges and a lit city, so the campus sits on the earth ──
    const sky = canvas(1024, 512);
    const sg = sky.g.createLinearGradient(0, 0, 0, 512);
    sg.addColorStop(0, "#101a3e"); sg.addColorStop(0.45, "#27407c"); sg.addColorStop(0.72, "#3f6aa6"); sg.addColorStop(1, "#21496f");
    sky.g.fillStyle = sg; sky.g.fillRect(0, 0, 1024, 512);
    sky.g.fillStyle = "#ffffff";
    for (let i = 0; i < 90; i++) { sky.g.globalAlpha = 0.25 + rnd() * 0.5; sky.g.fillRect(rnd() * 1024, rnd() * 220, 1.6, 1.6); }
    sky.g.globalAlpha = 1;
    sky.tex.needsUpdate = true;
    scene.background = sky.tex;
    scene.fog = new THREE.Fog(0x2a4a7c, 46, 110);

    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    scene.add(new THREE.HemisphereLight(0xa9c8ff, 0x25364a, 1.15));
    const moon = new THREE.DirectionalLight(0xbcd4ff, 1.6);
    moon.position.set(-14, 26, 18);
    scene.add(moon);

    // ── Water and far ranges ──
    const sea = new THREE.Mesh(new THREE.PlaneGeometry(320, 320), new THREE.MeshStandardMaterial({ color: 0x173a63, metalness: 0.6, roughness: 0.35 }));
    sea.rotation.x = -Math.PI / 2; sea.position.y = -9;
    scene.add(sea);
    const ridge = new THREE.MeshStandardMaterial({ color: 0x2c4470, flatShading: true, roughness: 1 });
    for (let i = 0; i < 26; i++) {
      const a = -1.5 + (i / 25) * 3, d = 70 + rnd() * 16;
      const h = 9 + rnd() * 15;
      const m = new THREE.Mesh(new THREE.ConeGeometry(7 + rnd() * 9, h, 5), ridge);
      m.position.set(Math.sin(a) * d, -9 + h / 2, -Math.cos(a) * d);
      m.rotation.y = rnd() * 3;
      scene.add(m);
    }
    const city = new THREE.Group();
    for (let i = 0; i < 11; i++) {
      const h = 3 + rnd() * 9;
      const t = canvas(32, 96);
      t.g.fillStyle = "#14233f"; t.g.fillRect(0, 0, 32, 96);
      for (let y = 4; y < 92; y += 8) for (let x = 4; x < 28; x += 8) { if (rnd() > 0.45) { t.g.fillStyle = rnd() > 0.5 ? "#7dd3fc" : "#fcd34d"; t.g.fillRect(x, y, 4, 4); } }
      t.tex.magFilter = THREE.NearestFilter; t.tex.needsUpdate = true;
      const b = new THREE.Mesh(new THREE.BoxGeometry(2.2, h, 2.2), new THREE.MeshBasicMaterial({ map: t.tex }));
      b.position.set(i * 2.6, h / 2, rnd() * 2);
      city.add(b);
    }
    city.position.set(14, -3.5, -30);
    scene.add(city);

    // ── The main island, and a plateau for each building ──
    const island = plateau(27, 9, rnd);
    island.scale.z = 0.72;
    scene.add(island);
    const waterfalls: THREE.CanvasTexture[] = [];
    [[-25.4, -5, 1.2], [25, -3, -1.3], [-16, 13.7, -0.5], [15, 14.2, 0.45]].forEach(([x, z, r]) => {
      const c = canvas(64, 256);
      for (let i = 0; i < 90; i++) { c.g.fillStyle = `rgba(${200 + rnd() * 55},235,255,${0.2 + rnd() * 0.5})`; c.g.fillRect(rnd() * 64, rnd() * 256, 2 + rnd() * 3, 18 + rnd() * 34); }
      c.tex.wrapT = THREE.RepeatWrapping; c.tex.needsUpdate = true;
      const f = new THREE.Mesh(new THREE.PlaneGeometry(2.2, 9.6), new THREE.MeshBasicMaterial({ map: c.tex, transparent: true, color: 0xcfeaff }));
      f.position.set(x, -4.6, z); f.rotation.y = r;
      scene.add(f);
      waterfalls.push(c.tex);
    });

    // ── The hub ──
    const hub = new THREE.Group();
    hub.position.set(0, 0, -6);
    scene.add(hub);
    const hubP = plateau(7, 1.6, rnd, 0x1d5f5a); hubP.position.y = 0.5; hub.add(hubP);
    const steel = new THREE.MeshStandardMaterial({ color: 0x3b4a66, metalness: 0.75, roughness: 0.35 });
    const drum = new THREE.Mesh(new THREE.CylinderGeometry(5, 5.3, 2.6, 8), steel); drum.position.y = 1.7; hub.add(drum);
    const dome = new THREE.Mesh(new THREE.SphereGeometry(4.8, 8, 6, 0, Math.PI * 2, 0, Math.PI / 2), new THREE.MeshStandardMaterial({ color: 0x2a3a58, metalness: 0.8, roughness: 0.3, flatShading: true }));
    dome.position.y = 3; hub.add(dome);
    const domeEdges = new THREE.LineSegments(new THREE.EdgesGeometry(dome.geometry, 10), new THREE.LineBasicMaterial({ color: accent, toneMapped: false }));
    domeEdges.position.copy(dome.position);
    hub.add(domeEdges);
    const hs = canvas(620, 300);
    hs.g.fillStyle = "rgba(5,12,24,0.86)"; hs.g.beginPath(); hs.g.roundRect(0, 0, 620, 300, 20); hs.g.fill();
    hs.g.strokeStyle = accent; hs.g.lineWidth = 5; hs.g.stroke();
    icon(hs.g, "shield", 310, 82, 118, accent, 1.5);
    hs.g.textAlign = "center"; hs.g.fillStyle = "#ffffff"; hs.g.font = `800 ${Math.min(60, Math.floor(1040 / cfg.hub.title.length))}px "Segoe UI", system-ui, sans-serif`; hs.g.fillText(cfg.hub.title, 310, 204);
    hs.g.fillStyle = accent; hs.g.font = `600 37px Consolas, monospace`; hs.g.fillText(cfg.hub.sub, 310, 262);
    hs.tex.needsUpdate = true;
    const hubSign = new THREE.Mesh(new THREE.PlaneGeometry(4.4, 2.13), new THREE.MeshBasicMaterial({ map: hs.tex, transparent: true, toneMapped: false }));
    hubSign.position.set(0, 3.45, 5.05);
    hubSign.rotation.x = -0.14;
    hub.add(hubSign);
    // Radar dish
    const dish = new THREE.Group();
    dish.position.set(3, 7.2, 0);
    const bowl = new THREE.Mesh(new THREE.SphereGeometry(1.1, 18, 8, 0, Math.PI * 2, 0, Math.PI * 0.42), new THREE.MeshStandardMaterial({ color: 0x8a99ad, metalness: 0.6, roughness: 0.45, side: THREE.DoubleSide }));
    bowl.rotation.x = 1.15;
    dish.add(bowl);
    hub.add(dish);
    const mast = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.16, 1.9, 8), steel); mast.position.set(3, 6.2, 0); hub.add(mast);
    // The world behind the hub: global threat picture
    const globe = new THREE.Mesh(new THREE.SphereGeometry(6.2, 22, 14), new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.2, toneMapped: false }));
    globe.position.set(0, 6.5, -5);
    hub.add(globe);

    // ── Buildings ──
    const blds = props.stations.map((s, i) => {
      const c = cfg.buildings[i] ?? cfg.buildings[0];
      const p = plateau(5, 2.2, rnd, 0x1b6450);
      p.position.set(c.x, 1, c.z);
      scene.add(p);
      const b = building(c, rnd);
      b.g.position.set(c.x, 1.05, c.z);
      b.g.rotation.y = c.rot;
      b.g.scale.setScalar(1.14);
      scene.add(b.g);
      return { ...b, c, key: "" };
    });

    // ── The lit path: from the hill, past the hub, building to building ──
    const hill = new THREE.Vector3(-3, 0.2, 19.5);
    const routePts = [hill, new THREE.Vector3(-1.6, 0.2, 11), new THREE.Vector3(-0.5, 0.2, 3.2), ...cfg.buildings.map(b => new THREE.Vector3(b.x, 0.2, b.z + 4.2))];
    const segs = props.stations.map((_, i) => {
      const a = i === 0 ? routePts[2] : routePts[i + 2], b = routePts[i + 3];
      const mid = a.clone().lerp(b, 0.5); mid.z += 2.4;
      const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
      const mat = new THREE.MeshBasicMaterial({ color: "#64748b", transparent: true, opacity: 0.45, toneMapped: false });
      const m = new THREE.Mesh(new THREE.TubeGeometry(curve, 36, 0.2, 6, false), mat);
      m.scale.y = 0.35; m.position.y = 0.2;
      scene.add(m);
      return { mat };
    });
    const leadMat = new THREE.MeshBasicMaterial({ color: accent, toneMapped: false });
    const lead = new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(routePts.slice(0, 3)), 40, 0.34, 6, false), leadMat);
    lead.scale.y = 0.35; lead.position.y = 0.2;
    scene.add(lead);
    const chevGeo = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-0.7, 0, 0.36), new THREE.Vector3(0, 0, -0.36), new THREE.Vector3(0.7, 0, 0.36), new THREE.Vector3(0.7, 0, 0.7), new THREE.Vector3(0, 0, -0.02), new THREE.Vector3(-0.7, 0, 0.7)]);
    chevGeo.setIndex([0, 1, 5, 1, 4, 5, 1, 2, 4, 2, 3, 4]);
    const leadCurve = new THREE.CatmullRomCurve3(routePts.slice(0, 3));
    const chevs = [0, 1, 2, 3, 4].map(i => {
      const m = new THREE.Mesh(chevGeo, new THREE.MeshBasicMaterial({ color: accent, transparent: true, toneMapped: false, side: THREE.DoubleSide }));
      const p = leadCurve.getPoint(0.12 + i * 0.17), q = leadCurve.getPoint(0.18 + i * 0.17);
      m.position.copy(p).setY(0.42);
      m.rotation.y = Math.atan2(-(q.x - p.x), -(q.z - p.z));
      scene.add(m);
      return m;
    });

    // ── Trees, kept clear of buildings, the hub and the path ──
    const keep = [{ x: 0, z: -6, r: 8.6 }, ...cfg.buildings.map(b => ({ x: b.x, z: b.z, r: 5.6 }))];
    let planted = 0;
    for (let i = 0; i < 400 && planted < (small ? 34 : 70); i++) {
      const a = rnd() * Math.PI * 2, d = Math.sqrt(rnd()) * 25;
      const x = Math.cos(a) * d, z = Math.sin(a) * d * 0.72;
      if (keep.some(k => Math.hypot(k.x - x, k.z - z) < k.r)) continue;
      if (Math.abs(x + 1.8) < 3.2 && z > 1) continue;
      const t = tree(rnd); t.position.set(x, 0.05, z); scene.add(t); planted++;
    }

    // ── A drone on patrol and a sensor node over the campus ──
    const drone = new THREE.Group();
    const droneBody = new THREE.Mesh(new THREE.BoxGeometry(0.7, 0.14, 0.4), new THREE.MeshStandardMaterial({ color: 0x1b2331, metalness: 0.7 }));
    drone.add(droneBody);
    const rotors = [[-0.6, -0.4], [0.6, -0.4], [-0.6, 0.4], [0.6, 0.4]].map(([x, z]) => { const r = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.3, 0.02, 12), new THREE.MeshBasicMaterial({ color: 0xcfe8f5, transparent: true, opacity: 0.4 })); r.position.set(x, 0.1, z); drone.add(r); return r; });
    const droneLed = new THREE.Mesh(new THREE.SphereGeometry(0.07, 8, 6), new THREE.MeshBasicMaterial({ color: "#f43f5e", toneMapped: false }));
    droneLed.position.set(0, -0.1, 0.2); drone.add(droneLed);
    drone.scale.setScalar(1.5);
    scene.add(drone);
    const node = netNode(props.secondary, 0.5);
    node.group.position.set(-3.8, 8.2, -6);
    scene.add(node.group);

    // ── The analyst on the hill ──
    const rock = plateau(5.2, 3, rnd, 0x2a3a4e, 0x2d3648);
    rock.position.set(-4, 1.2, 23.5);
    rock.scale.set(1.1, 1, 0.8);
    scene.add(rock);
    const man = analyst(accent);
    man.position.set(-3.4, 1.1, 22.6);
    man.scale.setScalar(1.24);
    scene.add(man);

    const size = { w: 1, h: 1 };
    let portrait = false, wide = false, scale = 1;
    const fit = (w: number, h: number) => {
      size.w = w; size.h = h;
      const asp = w / h;
      portrait = asp < 1;
      wide = w >= 1024;
      scale = Math.max(1, 1.6 / asp);
      camera.setViewOffset(w, h, wide ? -w * 0.075 : 0, h * (portrait ? 0.14 : 0.06), w, h);
    };
    const pick = new THREE.Vector3(), toward = new THREE.Vector3(), look = new THREE.Vector3(0, 1, -2);
    const cam = new THREE.Vector3(0, 20, 50);

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.05, dt);
      const pulse = rm ? 0.7 : 0.65 + Math.sin(t * 2.4) * 0.35;

      stations.forEach((s, i) => {
        const b = blds[i]; if (!b) return;
        if (b.key !== s.status) {
          b.key = s.status;
          drawBadge(b.bd, s.status, b.c.color);
          // Locked buildings keep their identity but go quiet, so colour still names them.
          b.bodyMat.color.copy(b.base).multiplyScalar(s.status === "locked" ? 0.6 : 1);
          b.windowMat.color.setScalar(s.status === "locked" ? 0.3 : 1);
          b.neonMat.color.set(b.c.color).multiplyScalar(s.status === "locked" ? 0.55 : 1);
        }
        const seg = segs[i];
        seg.mat.color.set(s.status === "cleared" ? DONE : s.status === "open" ? accent : "#64748b");
        seg.mat.opacity = s.status === "locked" ? 0.45 : 1;
        b.glow.intensity = s.status === "locked" ? 3 : 10 + (s.status === "open" ? pulse * 8 : 0);
        b.apronMat.opacity = i === selected ? 0.55 + pulse * 0.45 : s.status === "locked" ? 0.3 : 0.7;
        b.badge.quaternion.copy(camera.quaternion);
        const parentQ = b.g.quaternion.clone().invert();
        b.badge.quaternion.premultiply(parentQ);
      });
      chevs.forEach((c, i) => { (c.material as THREE.MeshBasicMaterial).opacity = rm ? 0.8 : 0.35 + 0.65 * ((Math.sin(t * 3 + i * 0.9) + 1) / 2); });

      if (!rm) {
        waterfalls.forEach(w => { w.offset.y = t * 0.55; });
        globe.rotation.y = t * 0.05;
        dish.rotation.y = Math.sin(t * 0.4) * 0.7;
        node.wire.rotation.y = t * 0.6;
        rotors.forEach(r => { r.rotation.y = t * 30; });
        drone.position.set(Math.cos(t * 0.16) * 19, 10 + Math.sin(t * 0.5) * 0.6, -2 + Math.sin(t * 0.16) * 10);
        drone.rotation.y = -t * 0.16;
      } else drone.position.set(-14, 10, 2);

      const target = blds[selected] ?? blds[0];
      if (portrait) { toward.set(target.c.x, 22, target.c.z + 33); look.lerp(pick.set(target.c.x, 2, target.c.z), ease); }
      else { toward.set(target.c.x * 0.05 + (rm ? 0 : Math.sin(t * 0.1) * 0.4), 20 * scale, 50 * scale); look.lerp(pick.set(0, 1, -2), ease); }
      cam.lerp(toward, ease);
      camera.position.copy(cam);
      camera.lookAt(look);
      camera.updateMatrixWorld();

      // Each building is a real hit target, sized to where it sits on screen.
      blds.forEach((b, i) => {
        const el = hitRefs.current[i]; if (!el) return;
        b.g.updateMatrixWorld();
        const toS = (x: number, y: number) => { pick.set(x, y, 1.6).applyMatrix4(b.g.matrixWorld).project(camera); return { x: (pick.x * 0.5 + 0.5) * size.w, y: (-pick.y * 0.5 + 0.5) * size.h }; };
        const p = toS(-b.W / 2, b.H), q = toS(b.W / 2, -0.4);
        el.style.transform = `translate(${Math.min(p.x, q.x)}px, ${Math.min(p.y, q.y)}px)`;
        el.style.width = `${Math.abs(q.x - p.x)}px`;
        el.style.height = `${Math.abs(q.y - p.y)}px`;
      });
    }, fit, (renderer, sc, c) => {
      const pmrem = new THREE.PMREMGenerator(renderer);
      const env = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
      sc.environment = env;
      sc.environmentIntensity = 0.3;
      pmrem.dispose();
      if (small) return { dispose: () => env.dispose() };
      const composer = new EffectComposer(renderer);
      composer.addPass(new RenderPass(sc, c));
      composer.addPass(new UnrealBloomPass(new THREE.Vector2(512, 512), 0.42, 0.6, 0.86));
      composer.addPass(new OutputPass());
      return { render: () => composer.render(), setSize: (w: number, h: number) => composer.setSize(w, h), dispose: () => { composer.dispose(); env.dispose(); } };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.primary, props.secondary, props.warn, props.stations.length]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }}>
      <div ref={mountRef} className="absolute inset-0" />
      {!props.dimmed && (
        <div className="absolute inset-0 overflow-hidden">
          {props.stations.map((s, i) => (
            <button key={s.id} ref={el => { hitRefs.current[i] = el; }} tabIndex={-1} aria-hidden
              onClick={() => { if (i === props.selected && s.status !== "locked") props.onEnter?.(s.id); else props.onPick?.(i); }}
              className={`pointer-events-auto absolute left-0 top-0 rounded-sm ${s.status === "locked" && i !== props.selected ? "cursor-default" : "cursor-pointer"}`} />
          ))}
        </div>
      )}
    </div>
  );
}
