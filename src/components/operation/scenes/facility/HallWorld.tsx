"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, coreName, mountWorld, type WorldProps } from "../common";
import { canvas, facilityPipeline, fitFont, icon, ICONS, STATUS } from "./kit";

/**
 * The hall layout of the room theme: an arc of tall glass cards around a holographic
 * globe. Each station is a card. When a learner finishes a station its card rolls out
 * of the arc, spins, shows the cleared face and goes back turned, so the arc itself is
 * the record of what is done. The board, status colours and the site's own logo are the
 * same as every other layout. Nothing here may name a graded answer or a lab answer.
 */
export type HallArt = "axes" | "tree" | "pulse" | "loot" | "lock" | "ghost";
export interface HallConfig {
  title: string;
  sub: string;
  /** One per station, in station order. */
  cards: { icon: keyof typeof ICONS; name: string[]; color: string; art: HallArt }[];
  /** Spines of the books on the desk. */
  books: string[];
  /** What floats over the pedestal. Each hall has its own. */
  core?: "globe" | "chain" | "matrix" | "knot";
}

const W = 3.3, H = 5.7, CUT = 0.46, ROLL = 4;
const ARC = { r: 11.6, cz: 7 };

function seeded(seed: number) {
  let s = seed;
  return () => { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646; };
}
const smooth = (a: number, b: number, x: number) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };

function outline(w: number, h: number, cut: number) {
  const a = w / 2;
  return [[-a, 0], [a, 0], [a, h - cut], [a - cut, h], [-a + cut, h], [-a, h - cut]].map(([x, y]) => new THREE.Vector2(x, y));
}
/** The card's face: a chamfered sheet whose UVs fill the shape. */
function faceGeo() {
  const geo = new THREE.ShapeGeometry(new THREE.Shape(outline(W, H, CUT)));
  const pos = geo.attributes.position, uv = geo.attributes.uv;
  for (let i = 0; i < pos.count; i++) uv.setXY(i, (pos.getX(i) + W / 2) / W, pos.getY(i) / H);
  return geo;
}
/** The neon rim, thick enough to read from the back of the room. */
function rimGeo() {
  const s = new THREE.Shape(outline(W + 0.16, H + 0.12, CUT + 0.04));
  s.holes.push(new THREE.Path(outline(W - 0.04, H - 0.04, CUT).map(p => new THREE.Vector2(p.x, p.y + 0.06)).reverse()));
  const g = new THREE.ExtrudeGeometry(s, { depth: 0.2, bevelEnabled: false });
  g.translate(0, -0.03, -0.1);
  return g;
}

function drawArt(g: CanvasRenderingContext2D, art: HallArt, color: string, x: number, y: number, w: number, h: number, rnd: () => number) {
  g.save();
  g.translate(x, y);
  g.strokeStyle = color; g.fillStyle = color; g.lineWidth = 3;
  const cx = w / 2, cy = h / 2;
  if (art === "axes") {
    g.globalAlpha = 0.5;
    for (let i = 1; i < 6; i++) { g.beginPath(); g.moveTo((w * i) / 6, 10); g.lineTo((w * i) / 6, h - 10); g.moveTo(10, (h * i) / 6); g.lineTo(w - 10, (h * i) / 6); g.stroke(); }
    g.globalAlpha = 1; g.lineWidth = 5;
    g.beginPath(); g.moveTo(cx, 8); g.lineTo(cx, h - 8); g.moveTo(8, cy); g.lineTo(w - 8, cy); g.stroke();
    for (let i = 0; i < 9; i++) { g.beginPath(); g.arc(30 + rnd() * (w - 60), 26 + rnd() * (h - 52), 9, 0, Math.PI * 2); g.fill(); }
  } else if (art === "tree") {
    const nodes = [[cx, 44], [cx - 112, 150], [cx + 112, 150], [cx - 170, 270], [cx - 58, 270], [cx + 112, 270]];
    [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5]].forEach(([a, b]) => { g.beginPath(); g.moveTo(nodes[a][0], nodes[a][1]); g.lineTo(nodes[a][0], (nodes[a][1] + nodes[b][1]) / 2); g.lineTo(nodes[b][0], (nodes[a][1] + nodes[b][1]) / 2); g.lineTo(nodes[b][0], nodes[b][1]); g.stroke(); });
    nodes.forEach(([a, b]) => { g.fillStyle = "#07101c"; g.fillRect(a - 44, b - 19, 88, 38); g.strokeRect(a - 44, b - 19, 88, 38); g.fillStyle = color; g.fillRect(a - 30, b - 4, 60, 8); });
  } else if (art === "pulse") {
    g.lineWidth = 5; g.beginPath(); g.moveTo(0, cy);
    for (let i = 0; i < 6; i++) { const s = 16 + (i * (w - 32)) / 6; g.lineTo(s, cy); g.lineTo(s + 14, cy - 96); g.lineTo(s + 30, cy + 74); g.lineTo(s + 42, cy); }
    g.lineTo(w, cy); g.stroke();
    g.globalAlpha = 0.25; g.lineWidth = 2;
    for (let i = 1; i < 8; i++) { g.beginPath(); g.moveTo((w * i) / 8, 6); g.lineTo((w * i) / 8, h - 6); g.stroke(); }
  } else if (art === "loot") {
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
      const px = 26 + c * 104 + r * 6, py = 26 + r * 86;
      g.globalAlpha = 1 - (c * 0.22);
      g.strokeRect(px, py + 8, 78, 54); g.beginPath(); g.moveTo(px, py + 8); g.lineTo(px + 8, py); g.lineTo(px + 34, py); g.lineTo(px + 40, py + 8); g.stroke();
    }
    g.globalAlpha = 1;
  } else if (art === "lock") {
    g.lineWidth = 8;
    for (let i = 0; i < 3; i++) { g.globalAlpha = 0.25 + i * 0.2; g.beginPath(); g.arc(cx, cy + 4, 156 - i * 34, 0, Math.PI * 2); g.stroke(); }
    g.globalAlpha = 1; g.fillRect(cx - 42, cy - 8, 84, 62);
    g.lineWidth = 12; g.beginPath(); g.arc(cx, cy - 8, 28, Math.PI, 0); g.stroke();
    g.fillStyle = "#07101c"; g.beginPath(); g.arc(cx, cy + 20, 10, 0, Math.PI * 2); g.fill();
  } else {
    // A figure that is only there as a scan line picks it out
    for (let yy = 12; yy < h - 8; yy += 11) {
      const v = (yy - 12) / (h - 20), half = v < 0.42 ? 70 * Math.sqrt(Math.max(0.02, 1 - Math.pow((v - 0.21) / 0.21, 2))) : 64 + (v - 0.42) * 170;
      g.globalAlpha = 0.25 + 0.6 * ((Math.sin(yy * 0.14) + 1) / 2);
      g.fillRect(cx - half, yy, half * 2, 5);
    }
    g.globalAlpha = 1;
  }
  g.restore();
}

function drawFront(d: ReturnType<typeof canvas>, c: HallConfig["cards"][number], locked: boolean, seed: number) {
  const { g, tex } = d, w = 640, h = 1104;
  const bg = g.createLinearGradient(0, 0, 0, h);
  bg.addColorStop(0, "#0c1a30"); bg.addColorStop(0.55, "#091424"); bg.addColorStop(1, "#050b16");
  g.globalAlpha = 1; g.fillStyle = bg; g.fillRect(0, 0, w, h);
  g.globalAlpha = 0.16; g.fillStyle = c.color; g.fillRect(0, 0, w, h); g.globalAlpha = 1;
  icon(g, c.icon, w / 2, 190, 190, c.color, 1.5);
  g.fillStyle = "#ffffff"; g.textAlign = "center"; g.textBaseline = "alphabetic"; fitFont(g, c.name, 74, w - 70);
  c.name.forEach((l, i) => g.fillText(l, w / 2, 380 + i * 84));
  g.fillStyle = "rgba(3,8,16,0.8)"; g.fillRect(44, 590, w - 88, 420);
  g.strokeStyle = c.color; g.globalAlpha = 0.6; g.lineWidth = 3; g.strokeRect(44, 590, w - 88, 420); g.globalAlpha = 1;
  drawArt(g, c.art, c.color, 64, 610, w - 128, 380, seeded(seed));
  if (locked) {
    g.fillStyle = "rgba(4,8,15,0.46)"; g.fillRect(0, 0, w, h);
    g.fillStyle = "rgba(6,12,22,0.95)"; g.beginPath(); g.arc(w / 2, 800, 84, 0, Math.PI * 2); g.fill();
    g.strokeStyle = "#cbd5e1"; g.lineWidth = 7; g.stroke();
    icon(g, "lock", w / 2, 800, 96, "#e2e8f0", 2.1);
  }
  tex.needsUpdate = true;
}

function drawBack(d: ReturnType<typeof canvas>, c: HallConfig["cards"][number], stars: number) {
  const { g, tex } = d, w = 640, h = 1104;
  const bg = g.createRadialGradient(w / 2, 400, 40, w / 2, 400, 760);
  bg.addColorStop(0, "#0d4a3a"); bg.addColorStop(1, "#04141a");
  g.fillStyle = bg; g.fillRect(0, 0, w, h);
  g.strokeStyle = STATUS.cleared; g.lineWidth = 12; g.beginPath(); g.arc(w / 2, 300, 136, 0, Math.PI * 2); g.stroke();
  icon(g, "check", w / 2, 300, 170, STATUS.cleared, 2.6);
  g.textAlign = "center"; g.textBaseline = "alphabetic";
  g.fillStyle = STATUS.cleared; g.font = `700 54px "Segoe UI", system-ui, sans-serif`; g.fillText("CLEARED", w / 2, 540);
  g.fillStyle = "#ffffff"; fitFont(g, c.name, 70, w - 70);
  c.name.forEach((l, i) => g.fillText(l, w / 2, 650 + i * 80));
  for (let i = 0; i < 3; i++) {
    const cx = w / 2 + (i - 1) * 124, cy = 930, on = i < stars;
    g.beginPath();
    for (let k = 0; k < 10; k++) { const r = k % 2 ? 22 : 52, a = -Math.PI / 2 + (k * Math.PI) / 5; g[k ? "lineTo" : "moveTo"](cx + Math.cos(a) * r, cy + Math.sin(a) * r); }
    g.closePath();
    if (on) { g.fillStyle = "#fcd34d"; g.fill(); } else { g.strokeStyle = "rgba(226,232,240,0.5)"; g.lineWidth = 4; g.stroke(); }
  }
  tex.needsUpdate = true;
}

function leaf(rnd: () => number, size: number) {
  const mat = new THREE.MeshStandardMaterial({ color: [0x2c7a4b, 0x3b8f4e, 0x21653f, 0x7a9a33][Math.floor(rnd() * 4)], roughness: 0.6 });
  const m = new THREE.Mesh(new THREE.SphereGeometry(1, 8, 6), mat);
  m.scale.set(size * 0.42, size * 0.05, size);
  return m;
}
function plant(rnd: () => number) {
  const g = new THREE.Group();
  const pot = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.38, 0.8, 18), new THREE.MeshStandardMaterial({ color: 0xcdd3dc, roughness: 0.55 }));
  pot.position.y = 0.4; g.add(pot);
  for (let i = 0; i < 16; i++) {
    const l = leaf(rnd, 0.55 + rnd() * 0.45), a = (i / 16) * Math.PI * 2 + rnd(), up = 0.35 + rnd() * 0.9;
    const holder = new THREE.Group();
    holder.position.y = 0.85; holder.rotation.order = "YXZ"; holder.rotation.y = a; holder.rotation.x = -up;
    l.position.z = 0.6;
    holder.add(l); g.add(holder);
  }
  return g;
}
function vine(rnd: () => number, n: number) {
  const g = new THREE.Group();
  for (let i = 0; i < n; i++) {
    const l = leaf(rnd, 0.2 + rnd() * 0.16);
    l.position.set((rnd() - 0.5) * 0.4, -i * 0.2, (rnd() - 0.5) * 0.3);
    l.rotation.set(rnd() * 2, rnd() * 6, rnd() * 2);
    g.add(l);
  }
  return g;
}

/** A globe of dots: enough of the continents to read as the world, no map data needed. */
function globeTexture(color: string) {
  const d = canvas(1024, 512);
  const blobs = [[160, 140, 90, 60], [230, 330, 46, 92], [500, 130, 60, 42], [520, 280, 66, 96], [700, 150, 150, 74], [840, 350, 58, 34]];
  d.g.fillStyle = color;
  for (let y = 6; y < 512; y += 11) for (let x = 6; x < 1024; x += 11) {
    if (blobs.some(([cx, cy, rx, ry]) => Math.pow((x - cx) / rx, 2) + Math.pow((y - cy) / ry, 2) < 1)) d.g.fillRect(x, y, 6, 6);
  }
  d.tex.needsUpdate = true;
  return d.tex;
}

export function HallWorld({ cfg, props }: { cfg: HallConfig; props: WorldProps }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const hitRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const small = window.innerWidth < 768;
    const accent = props.primary;
    const rnd = seeded(5521 + cfg.cards.length * 31 + cfg.title.length);
    const N = cfg.cards.length, HALF = 0.172 * (N - 1); // half the arc, in radians
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x070c16);
    scene.fog = new THREE.Fog(0x070c16, 30, 64);
    const camera = new THREE.PerspectiveCamera(36, 1.6, 0.1, 140);
    camera.position.set(0, 6.4, 27);

    scene.add(new THREE.AmbientLight(0x8fb0d8, 0.55));
    const key = new THREE.PointLight(0xffc48a, 40, 34, 1.5);
    key.position.set(0, 9.4, 1);
    scene.add(key);

    // ── The room: a floor that reflects, a glass wall, a ring of light ──
    const ft = canvas(1024, 1024);
    ft.g.fillStyle = "#0e1420"; ft.g.fillRect(0, 0, 1024, 1024);
    ft.g.strokeStyle = "#1c2534"; ft.g.lineWidth = 3;
    for (let i = 0; i <= 6; i++) { ft.g.beginPath(); ft.g.moveTo(i * 170, 0); ft.g.lineTo(i * 170, 1024); ft.g.moveTo(0, i * 170); ft.g.lineTo(1024, i * 170); ft.g.stroke(); }
    ft.tex.wrapS = ft.tex.wrapT = THREE.RepeatWrapping;
    ft.tex.repeat.set(7, 7);
    ft.tex.needsUpdate = true;
    const floor = new THREE.Mesh(new THREE.CircleGeometry(34, 64), new THREE.MeshStandardMaterial({ map: ft.tex, roughness: 0.4, metalness: 0.5, transparent: true, opacity: 0.8 }));
    floor.rotation.x = -Math.PI / 2;
    floor.renderOrder = 1;
    scene.add(floor);

    const wt = canvas(2048, 512);
    wt.g.fillStyle = "#0a1220"; wt.g.fillRect(0, 0, 2048, 512);
    for (let c = 0; c < 18; c++) for (let r = 0; r < 4; r++) {
      const x = 8 + c * 113, y = 8 + r * 125, b = rnd();
      const pane = wt.g.createLinearGradient(x, y, x, y + 118);
      pane.addColorStop(0, b > 0.5 ? "#143a63" : "#102b4c"); pane.addColorStop(1, "#0a1a30");
      wt.g.fillStyle = pane; wt.g.fillRect(x, y, 106, 118);
      if (b > 0.72) { wt.g.fillStyle = "#c9e3f5"; wt.g.fillRect(x + 8, y + 18, 60, 3); wt.g.fillRect(x + 22, y + 34, 70, 3); }
    }
    wt.tex.wrapS = THREE.RepeatWrapping; wt.tex.repeat.set(2, 1); wt.tex.needsUpdate = true;
    const wall = new THREE.Mesh(new THREE.CylinderGeometry(21, 21, 13, 64, 1, true), new THREE.MeshBasicMaterial({ map: wt.tex, side: THREE.BackSide, color: new THREE.Color(0x9fb4c8).lerp(new THREE.Color(accent), 0.3) }));
    wall.position.set(0, 6.5, ARC.cz);
    scene.add(wall);
    const ceiling = new THREE.Mesh(new THREE.CircleGeometry(22, 48), new THREE.MeshStandardMaterial({ color: 0x0b1220, roughness: 0.6 }));
    ceiling.rotation.x = Math.PI / 2; ceiling.position.set(0, 12.2, ARC.cz);
    scene.add(ceiling);
    const ringWarm = new THREE.Mesh(new THREE.TorusGeometry(8.2, 0.16, 12, 96), new THREE.MeshBasicMaterial({ color: 0xffc48a, toneMapped: false }));
    ringWarm.rotation.x = Math.PI / 2; ringWarm.position.set(0, 11.4, 2);
    scene.add(ringWarm);
    const ringCool = new THREE.Mesh(new THREE.TorusGeometry(6.3, 0.08, 10, 96), new THREE.MeshBasicMaterial({ color: accent, toneMapped: false }));
    ringCool.rotation.x = Math.PI / 2; ringCool.position.set(0, 11.2, 2);
    scene.add(ringCool);
    // Two neon arcs set into the floor, tying the cards together
    [ARC.r - 1.5, ARC.r - 2.6].forEach((r, i) => {
      const arc = new THREE.Mesh(new THREE.TorusGeometry(r, 0.035, 6, 96, HALF * 2 + 0.3), additive(i ? accent : 0xffc48a, 0.9));
      arc.rotation.x = -Math.PI / 2; arc.rotation.z = Math.PI / 2 - HALF - 0.15;
      arc.position.set(0, 0.03, ARC.cz);
      scene.add(arc);
    });

    const sg = canvas(1400, 300);
    sg.g.textAlign = "center"; sg.g.fillStyle = "#d6dde6"; sg.g.font = `700 150px "Segoe UI", system-ui, sans-serif`;
    sg.g.fillText(cfg.title, 700, 150);
    sg.g.fillStyle = "#cfe0ee"; sg.g.font = `500 60px "Segoe UI", system-ui, sans-serif`;
    sg.g.fillText(cfg.sub, 700, 244);
    sg.tex.needsUpdate = true;
    const sign = new THREE.Mesh(new THREE.PlaneGeometry(10.5, 2.25), new THREE.MeshBasicMaterial({ map: sg.tex, transparent: true, toneMapped: false, depthWrite: false }));
    sign.position.set(0, 8.1, -3.4);
    scene.add(sign);

    // ── The cards ──
    const face = faceGeo(), rim = rimGeo();
    const st = canvas(256, 442);
    const streak = st.g.createLinearGradient(0, 0, 256, 442);
    [[0, 0.1], [0.3, 0.1], [0.38, 1], [0.46, 0.1], [0.56, 0.1], [0.6, 0.7], [0.64, 0.1], [1, 0]].forEach(([at, a]) => streak.addColorStop(at, `rgba(255,255,255,${a})`));
    st.g.fillStyle = streak; st.g.fillRect(0, 0, 256, 442);
    st.tex.needsUpdate = true;
    const sheenTex = st.tex;
    const cards = cfg.cards.map((c, i) => {
      const a = N > 1 ? -HALF + (2 * HALF * i) / (N - 1) : 0;
      const slot = new THREE.Vector3(Math.sin(a) * ARC.r, 0.12, ARC.cz - Math.cos(a) * ARC.r);
      const rot = -a;
      const fd = canvas(640, 1104), bd = canvas(640, 1104);
      const front = new THREE.MeshBasicMaterial({ map: fd.tex, toneMapped: false, color: 0xcccccc });
      const back = new THREE.MeshBasicMaterial({ map: bd.tex, toneMapped: false, color: 0xd8d8d8 });
      const rimMat = new THREE.MeshBasicMaterial({ color: c.color, toneMapped: false });
      const glass = new THREE.MeshBasicMaterial({ map: sheenTex, transparent: true, opacity: 0.06, depthWrite: false, blending: THREE.AdditiveBlending });
      const handleMat = new THREE.MeshBasicMaterial({ color: c.color, toneMapped: false });
      const build = () => {
        const g = new THREE.Group();
        const f = new THREE.Mesh(face, front); f.position.z = 0.1; g.add(f);
        const b = new THREE.Mesh(face, back); b.position.z = -0.1; b.rotation.y = Math.PI; g.add(b);
        g.add(new THREE.Mesh(rim, rimMat));
        return g;
      };
      const g = build();
      const sheen = new THREE.Mesh(face, glass); sheen.position.z = 0.13; g.add(sheen);
      const handle = new THREE.Mesh(new THREE.CapsuleGeometry(0.045, 0.62, 4, 8), handleMat); handle.position.set(-W / 2 + 0.2, 2.6, 0.17); g.add(handle);
      g.position.copy(slot); g.rotation.y = rot;
      scene.add(g);
      const mirror = build();
      mirror.scale.y = -1;
      scene.add(mirror);
      const glow = new THREE.PointLight(c.color, 4, 9, 1.8);
      glow.position.set(slot.x * 0.9, 1.6, slot.z + 1.4);
      scene.add(glow);
      const pad = new THREE.Mesh(new THREE.RingGeometry(1.75, 1.84, 48), additive(c.color, 0.8));
      pad.rotation.x = -Math.PI / 2; pad.scale.y = 0.42; pad.position.set(slot.x, 0.04, slot.z);
      scene.add(pad);
      drawFront(fd, c, false, 90 + i);
      drawBack(bd, c, 0);
      return { c, g, mirror, slot, rot, fd, bd, rimMat, handleMat, glow, pad: pad.material as THREE.MeshBasicMaterial, key: "", stars: -1, lift: 0 };
    });

    // ── The globe on its pedestal ──
    const pedestal = new THREE.Group();
    pedestal.position.set(0, 0, 9.4);
    pedestal.scale.setScalar(0.62);
    const metal = new THREE.MeshStandardMaterial({ color: 0x1d2736, metalness: 0.8, roughness: 0.32 });
    const add = (m: THREE.Mesh, y: number) => { m.position.y = y; pedestal.add(m); return m; };
    add(new THREE.Mesh(new THREE.CylinderGeometry(3.3, 3.6, 0.7, 72), metal), 0.35);
    add(new THREE.Mesh(new THREE.CylinderGeometry(2.7, 3.1, 0.42, 72), metal), 0.9);
    const stripe = (r: number, y: number, col: string) => { const m = add(new THREE.Mesh(new THREE.TorusGeometry(r, 0.035, 8, 96), new THREE.MeshBasicMaterial({ color: col, toneMapped: false })), y); m.rotation.x = Math.PI / 2; return m; };
    stripe(3.42, 0.58, accent); stripe(3.61, 0.12, accent);
    const rings = [1.1, 1.7, 2.3].map((r, i) => stripe(r, 1.13, i === 1 ? props.secondary : accent));
    const em = canvas(256, 256);
    icon(em.g, "shield", 128, 128, 200, accent, 1.5);
    em.tex.needsUpdate = true;
    const emblem = new THREE.Mesh(new THREE.PlaneGeometry(0.62, 0.62), new THREE.MeshBasicMaterial({ map: em.tex, transparent: true, toneMapped: false }));
    emblem.position.set(0, 0.36, 3.5);
    pedestal.add(emblem);
    const globeWrap = new THREE.Group();
    globeWrap.position.y = 2.45;
    pedestal.add(globeWrap);
    const core = new THREE.Mesh(new THREE.SphereGeometry(1.1, 32, 22), additive(accent, 0.12));
    const dots = new THREE.Mesh(new THREE.SphereGeometry(1.14, 40, 28), new THREE.MeshBasicMaterial({ map: globeTexture(accent), transparent: true, depthWrite: false, toneMapped: false, side: THREE.DoubleSide, blending: THREE.AdditiveBlending }));
    const grid = new THREE.Mesh(new THREE.SphereGeometry(1.17, 18, 12), new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.16 }));
    const line = new THREE.MeshBasicMaterial({ color: accent, wireframe: true, toneMapped: false, transparent: true, opacity: 0.75 });
    if (cfg.core === "chain") {
      [-0.82, 0, 0.82].forEach((x, i) => { const link = new THREE.Mesh(new THREE.TorusGeometry(0.5, 0.13, 10, 28), line); link.position.x = x; link.rotation.x = i % 2 ? Math.PI / 2 : 0; globeWrap.add(link); });
    } else if (cfg.core === "matrix") {
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) { const cell = new THREE.Mesh(new THREE.BoxGeometry(0.34, 0.34, 0.06 + rnd() * 0.3), line); cell.position.set((x - 2) * 0.42, (y - 2) * 0.42, 0); globeWrap.add(cell); }
    } else if (cfg.core === "knot") {
      globeWrap.add(new THREE.Mesh(new THREE.TorusKnotGeometry(0.72, 0.2, 90, 10), line));
    } else globeWrap.add(core, dots, grid);
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(1.05, 1.5, 1.2, 40, 1, true), additive(accent, 0.1));
    beam.position.y = 1.72;
    pedestal.add(beam);
    scene.add(pedestal);

    // ── The analyst's desks in the foreground, so the hall reads as a workplace ──
    const deskMat = new THREE.MeshStandardMaterial({ color: 0x1a2230, metalness: 0.5, roughness: 0.45 });
    const desk = (x: number) => {
      const g = new THREE.Group();
      const top = new THREE.Mesh(new THREE.BoxGeometry(7.4, 0.14, 3), deskMat); top.position.y = 1.5; g.add(top);
      [[-3.4, -1.2], [3.4, -1.2], [-3.4, 1.2], [3.4, 1.2]].forEach(([a, b]) => { const l = new THREE.Mesh(new THREE.BoxGeometry(0.12, 1.5, 0.12), deskMat); l.position.set(a, 0.75, b); g.add(l); });
      g.position.set(x, 0, 13.4);
      scene.add(g);
      return g;
    };
    const left = desk(-9);
    [[-1.8, 0.34], [0, 0], [1.8, -0.34]].forEach(([x, r], i) => {
      const sc = canvas(420, 260);
      sc.g.fillStyle = "#050b16"; sc.g.fillRect(0, 0, 420, 260);
      sc.g.fillStyle = accent; sc.g.fillRect(0, 0, 420, 18);
      sc.g.fillStyle = "#9fc4dd";
      for (let k = 0; k < 9; k++) sc.g.fillRect(14, 34 + k * 24, 80 + rnd() * 280, 7);
      if (i === 1) { sc.g.fillStyle = "#f43f5e"; sc.g.fillRect(14, 106, 240, 7); }
      sc.tex.needsUpdate = true;
      const m = new THREE.Group();
      m.add(new THREE.Mesh(new THREE.BoxGeometry(1.76, 1.12, 0.06), new THREE.MeshStandardMaterial({ color: 0x0b1018 })));
      const screen = new THREE.Mesh(new THREE.PlaneGeometry(1.68, 1.04), new THREE.MeshBasicMaterial({ map: sc.tex, toneMapped: false }));
      screen.position.z = 0.04; m.add(screen);
      m.position.set(x, 2.2, -0.5); m.rotation.y = r;
      left.add(m);
    });
    const right = desk(9.6);
    cfg.books.forEach((b, i) => {
      const sp = canvas(420, 74);
      sp.g.fillStyle = ["#1e3a5f", "#27314a", "#1b3d44"][i % 3]; sp.g.fillRect(0, 0, 420, 74);
      sp.g.fillStyle = "#e6eef6"; sp.g.font = `600 40px "Segoe UI", system-ui, sans-serif`; sp.g.textBaseline = "middle"; sp.g.fillText(b, 18, 39);
      sp.tex.needsUpdate = true;
      const side = new THREE.MeshStandardMaterial({ color: 0x1b2a3f, roughness: 0.7 });
      const book = new THREE.Mesh(new THREE.BoxGeometry(1.9, 0.3, 1.3), [side, side, side, side, new THREE.MeshBasicMaterial({ map: sp.tex }), side]);
      book.position.set(-1.5 + i * 0.04, 1.73 + i * 0.3, 0.4); book.rotation.y = -0.16 + i * 0.1;
      right.add(book);
    });
    const leftPlant = plant(rnd), rightPlant = plant(rnd), rightDesk = plant(rnd);
    leftPlant.position.set(-13.5, 0, 3); leftPlant.scale.setScalar(2.2); scene.add(leftPlant);
    rightPlant.position.set(10.4, 0, 7.6); rightPlant.scale.setScalar(2.2); scene.add(rightPlant);
    rightDesk.position.set(2, 1.56, 0.1); rightDesk.scale.setScalar(0.9); right.add(rightDesk);
    for (let i = 0; i < 18; i++) {
      const side = i % 2 ? 1 : -1, v = vine(rnd, 8 + Math.floor(rnd() * 16));
      v.position.set(side * (7.6 + rnd() * 4.4) + 1.4, 11.9, 3 + rnd() * 6);
      scene.add(v);
    }

    // The moment a card turns: a ring that opens behind it
    const burst = new THREE.Mesh(new THREE.RingGeometry(0.92, 1, 64), additive(STATUS.cleared, 0));
    burst.visible = false;
    scene.add(burst);
    const SHOW = new THREE.Vector3(0, 1.5, 14);

    const size = { w: 1, h: 1 };
    let portrait = false, wide = false, scale = 1;
    const fit = (w: number, h: number) => {
      size.w = w; size.h = h;
      const asp = w / h;
      portrait = asp < 1; wide = w >= 1024;
      scale = Math.max(1, 1.6 / asp);
      camera.setViewOffset(w, h, wide ? -w * 0.1 : 0, h * (portrait ? 0 : 0.03), w, h);
      pedestal.visible = left.visible = right.visible = !portrait;
    };
    const cam = new THREE.Vector3(0, 6.4, 27), look = new THREE.Vector3(0, 3, 0), toward = new THREE.Vector3(), aim = new THREE.Vector3(), pick = new THREE.Vector3();
    let rolling: number | null = null, rollFrom = 0;

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm, dimmed } = live.current;
      const unrolled = live.current.unrolled ?? [];
      const ease = rm ? 1 : 1 - Math.pow(0.05, dt);
      const pulse = rm ? 0.7 : 0.65 + Math.sin(t * 2.4) * 0.35;
      const nextRoll = live.current.rolling ?? null;
      if (nextRoll !== rolling) { rolling = nextRoll; rollFrom = t; }
      const p = Math.min(1, (t - rollFrom) / ROLL);

      stations.forEach((s, i) => {
        const c = cards[i]; if (!c) return;
        const locked = s.status === "locked";
        const turned = s.status === "cleared" && !unrolled.includes(s.id);
        const roll = rolling === i;
        if (c.key !== `${locked}`) { c.key = `${locked}`; drawFront(c.fd, c.c, locked, 90 + i); }
        if (c.stars !== s.stars) { c.stars = s.stars; drawBack(c.bd, c.c, s.stars); }
        c.rimMat.color.set(turned || (roll && p > 0.52) ? STATUS.cleared : c.c.color).multiplyScalar(locked ? 0.45 : 1);
        c.handleMat.color.copy(c.rimMat.color);
        const out = roll ? smooth(0, 0.16, p) * (1 - smooth(0.84, 1, p)) : 0;
        const spin = roll ? smooth(0.1, 0.6, p) * Math.PI * 3 : turned ? Math.PI : 0;
        const sel = i === selected && !dimmed ? 1 : 0;
        c.lift += (sel - c.lift) * ease;
        const yaw = c.rot * (1 - out) + spin;
        // A picked card steps out of the arc towards the globe
        c.g.position.lerpVectors(c.slot, SHOW, out);
        c.g.position.x -= Math.sin(c.rot) * c.lift * 0.5 * (1 - out);
        c.g.position.z += Math.cos(c.rot) * c.lift * 0.5 * (1 - out);
        c.g.rotation.y = yaw;
        c.g.scale.setScalar(1 + out * 0.2 + c.lift * 0.04);
        c.mirror.position.set(c.g.position.x, -c.g.position.y, c.g.position.z);
        c.mirror.rotation.y = yaw;
        c.mirror.scale.set(c.g.scale.x, -c.g.scale.y, c.g.scale.z);
        c.mirror.visible = out < 0.05;
        c.glow.intensity = locked ? 1 : 4 + (s.status === "open" ? pulse * 3 : 0);
        c.pad.opacity = locked ? 0.25 : i === selected ? 0.5 + pulse * 0.5 : 0.7;
        if (roll) {
          const b = smooth(0.34, 0.8, p);
          burst.visible = b > 0 && b < 1;
          burst.position.copy(c.g.position).setY(3.9); burst.position.z -= 0.6;
          burst.scale.setScalar(2 + b * 7);
          (burst.material as THREE.MeshBasicMaterial).opacity = (1 - b) * 0.9;
        }
      });
      if (rolling === null) burst.visible = false;

      if (!rm) {
        globeWrap.rotation.y = t * 0.16;
        rings.forEach((r, i) => { r.rotation.z = t * (0.2 + i * 0.1); r.scale.setScalar(1 + Math.sin(t * 1.4 + i) * 0.02); });
        (beam.material as THREE.MeshBasicMaterial).opacity = 0.08 + Math.sin(t * 1.6) * 0.03;
      }

      const target = cards[selected] ?? cards[0];
      if (portrait) {
        // Phone: face one card square on, with room for the bottom bar under it
        const r = rolling !== null ? SHOW : target.slot, a = rolling !== null ? 0 : -target.rot, away = rolling !== null ? 25 : 15 + scale;
        toward.set(r.x - Math.sin(a) * away, 3.7, r.z + Math.cos(a) * away);
        look.lerp(aim.set(r.x, 1.3, r.z), ease);
      } else {
        toward.set(target.slot.x * 0.035 + (rm ? 0 : Math.sin(t * 0.12) * 0.25), 6.4, 27 * scale);
        look.lerp(aim.set(0, 3, 0), ease);
      }
      cam.lerp(toward, ease);
      camera.position.copy(cam);
      camera.lookAt(look);
      camera.updateMatrixWorld();

      cards.forEach((c, i) => {
        const el = hitRefs.current[i]; if (!el) return;
        c.g.updateMatrixWorld();
        const toS = (x: number, y: number) => { pick.set(x, y, 0).applyMatrix4(c.g.matrixWorld).project(camera); return { x: (pick.x * 0.5 + 0.5) * size.w, y: (-pick.y * 0.5 + 0.5) * size.h }; };
        const a = toS(-W / 2, H), b = toS(W / 2, 0);
        el.style.transform = `translate(${Math.min(a.x, b.x)}px, ${Math.min(a.y, b.y)}px)`;
        el.style.width = `${Math.abs(b.x - a.x)}px`;
        el.style.height = `${Math.abs(b.y - a.y)}px`;
      });
    }, fit, facilityPipeline(small));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.primary, props.secondary, props.warn, props.stations.length]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }}>
      <div ref={mountRef} className="absolute inset-0" />
      {!props.dimmed && (
        <div className="absolute inset-0 overflow-hidden">
          {props.stations.map((s, i) => (
            <button key={s.id} ref={el => { hitRefs.current[i] = el; }} tabIndex={-1} aria-hidden title={coreName(s.label)}
              onClick={() => { if (i === props.selected && s.status !== "locked") props.onEnter?.(s.id); else props.onPick?.(i); }}
              className={`pointer-events-auto absolute left-0 top-0 ${s.status === "locked" && i !== props.selected ? "cursor-default" : "cursor-pointer"}`} />
          ))}
        </div>
      )}
    </div>
  );
}
