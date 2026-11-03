"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, type WorldProps } from "./common";

/**
 * "First look": the city of Northport seen through the Cyber Lens. The city is
 * always there; what changes is how much of its invisible layer the learner can
 * see. Each cleared station switches on one layer, in station order:
 *   1 connections between everything, 2 three locks (C, I, A) over every
 *   landmark, 3 attackers at the city's edge with their attacks travelling in,
 *   4 the SOC tower lights up and every attack becomes an alert flying to it,
 *   5 a shield closes over the whole city.
 * The open station's layer flickers faintly as a preview. Decorative only.
 */
const LANDMARKS = ["house", "bank", "hospital", "plant", "traffic", "school"] as const;
const LOCK_COLORS = [0x2dd4bf, 0x60a5fa, 0xfbbf24];
const WATCHER_COLORS = [0xf43f5e, 0xfb7185, 0xe11d48, 0xf97316, 0xc026d3];
/** Landmark each attacker hits, matching the attack screens below. */
const ATTACK_TARGETS = [0, 1, 2, 5, 3]; // house, bank, hospital, school, plant
const ALERT_ROWS = [
  "HIGH  Phishing link clicked · house-wifi",
  "CRIT  Traffic flood · pay.northportbank",
  "CRIT  Files encrypted · hospital FIN-PC-12",
  "MED   Untrusted certificate · school Wi-Fi",
  "HIGH  Password reset by phone · power plant",
];

/** A 2D screen as a canvas texture: how each attack looks on a real screen. */
function attackScreen(kind: number): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = 256; c.height = 168;
  const g = c.getContext("2d")!;
  const frame = (bg: string, bar: string, title: string, fg = "#e2e8f0") => {
    g.fillStyle = "#1e2533"; g.fillRect(0, 0, 256, 168);
    g.fillStyle = bar; g.fillRect(4, 4, 248, 20);
    g.fillStyle = bg; g.fillRect(4, 24, 248, 140);
    g.fillStyle = fg; g.font = "bold 12px sans-serif"; g.fillText(title, 12, 18);
  };
  const text = (t: string, x: number, y: number, color: string, font = "13px sans-serif") => { g.fillStyle = color; g.font = font; g.fillText(t, x, y); };
  if (kind === 0) {
    frame("#f8fafc", "#334155", "Messages");
    g.fillStyle = "#e2e8f0"; g.fillRect(16, 40, 210, 70);
    text("Your parcel is on hold.", 24, 62, "#0f172a");
    text("Pay 1.99 today:", 24, 82, "#0f172a");
    text("np-post.parcel-fee.top", 24, 100, "#2563eb", "bold 13px sans-serif");
    text("PHISHING", 16, 148, "#e11d48", "bold 16px sans-serif");
  } else if (kind === 1) {
    frame("#0b1220", "#1e3a5f", "Requests per second");
    g.strokeStyle = "#94a3b8"; g.setLineDash([4, 4]); g.beginPath(); g.moveTo(12, 120); g.lineTo(244, 120); g.stroke(); g.setLineDash([]);
    g.strokeStyle = "#f43f5e"; g.lineWidth = 3; g.beginPath();
    [118, 120, 117, 119, 118, 60, 38, 36, 40, 37, 39].forEach((y, i) => (i ? g.lineTo(12 + i * 23, y) : g.moveTo(12, y)));
    g.stroke();
    text("DDoS", 16, 152, "#f43f5e", "bold 16px sans-serif");
  } else if (kind === 2) {
    frame("#3b0712", "#7f1d1d", "FIN-PC-12");
    text("YOUR FILES ARE", 30, 64, "#fb7185", "bold 18px sans-serif");
    text("ENCRYPTED", 30, 88, "#fb7185", "bold 18px sans-serif");
    text("budget.xlsx.locked", 30, 112, "#fecdd3");
    text("Pay 2.5 BTC in 72h", 30, 132, "#fbbf24");
    text("RANSOMWARE", 30, 156, "#f43f5e", "bold 13px sans-serif");
  } else if (kind === 3) {
    frame("#f1f3f4", "#9ca3af", "Wi-Fi: Harbour_Cafe_FREE", "#111827");
    g.fillStyle = "#dc2626"; g.beginPath(); g.moveTo(40, 44); g.lineTo(60, 80); g.lineTo(20, 80); g.closePath(); g.fill();
    text("Your connection", 72, 60, "#111827", "bold 15px sans-serif");
    text("is not private", 72, 80, "#111827", "bold 15px sans-serif");
    text("ERR_CERT_AUTHORITY_INVALID", 16, 112, "#6b7280", "11px monospace");
    text("MAN-IN-THE-MIDDLE", 16, 148, "#dc2626", "bold 15px sans-serif");
  } else {
    frame("#ffffff", "#0369a1", "Service Desk · phone call");
    text("Caller: \"Finance Director\"", 16, 52, "#0f172a");
    text("Reset my password and", 16, 76, "#0f172a");
    text("read it to me. NOW.", 16, 96, "#0f172a", "bold 13px sans-serif");
    text("SOCIAL ENGINEERING", 16, 148, "#b45309", "bold 15px sans-serif");
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

/** The SOC tower's alert queue: every attack, as an analyst sees it. */
function alertBoard(): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = 512; c.height = 236;
  const g = c.getContext("2d")!;
  g.fillStyle = "rgba(6,16,33,0.92)"; g.fillRect(0, 0, 512, 236);
  g.strokeStyle = "#2dd4bf"; g.lineWidth = 3; g.strokeRect(2, 2, 508, 232);
  g.fillStyle = "#2dd4bf"; g.font = "bold 18px monospace"; g.fillText("SOC · ALERT QUEUE", 16, 30);
  ALERT_ROWS.forEach((row, i) => {
    const sev = row.slice(0, 4);
    g.fillStyle = i % 2 ? "rgba(255,255,255,0.03)" : "rgba(255,255,255,0.07)"; g.fillRect(10, 44 + i * 37, 492, 33);
    g.fillStyle = sev === "CRIT" ? "#f43f5e" : sev === "HIGH" ? "#fb923c" : "#fbbf24";
    g.font = "bold 15px monospace"; g.fillText(sev, 20, 66 + i * 37);
    g.fillStyle = "#e2e8f0"; g.font = "15px monospace"; g.fillText(row.slice(6), 80, 66 + i * 37);
  });
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

export default function CityScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x050a16, 30, 80);
    const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 220);
    const glow = glowTexture();
    let seed = 11;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x081020, 0.9));
    const key = new THREE.DirectionalLight(0xc7d6ff, 1.4);
    key.position.set(-12, 20, 10);
    scene.add(key);

    // ── Ground: a dark street grid ──
    const ground = new THREE.Mesh(new THREE.CircleGeometry(70, 64), new THREE.MeshStandardMaterial({ color: 0x0a1120, roughness: 0.95 }));
    ground.rotation.x = -Math.PI / 2;
    scene.add(ground);
    const grid = new THREE.GridHelper(64, 32, 0x1b2a46, 0x111c31);
    grid.position.y = 0.01;
    scene.add(grid);

    // ── Filler blocks: the ordinary city ──
    const blockMat = new THREE.MeshStandardMaterial({ color: 0x1a2440, roughness: 0.8 });
    const blocks: THREE.Mesh[] = [];
    for (let i = 0; i < 70; i++) {
      const a = rnd() * Math.PI * 2, r = 4.5 + rnd() * 22;
      const x = Math.round(Math.cos(a) * r / 2) * 2, z = Math.round(Math.sin(a) * r / 2) * 2;
      if (Math.hypot(x, z) < 3.5 || LANDMARKS.some((_, k) => { const la = (k / LANDMARKS.length) * Math.PI * 2; return Math.hypot(x - Math.cos(la) * 9.5, z - Math.sin(la) * 9.5) < 2.6; })) continue;
      const h = 0.4 + rnd() * (r < 12 ? 1.6 : 3.2);
      const b = new THREE.Mesh(new THREE.BoxGeometry(1.3, h, 1.3), blockMat);
      b.position.set(x, h / 2, z);
      scene.add(b);
      blocks.push(b);
    }

    // ── Landmarks ──
    const bodyMat = new THREE.MeshStandardMaterial({ color: 0x3a4a6e, emissive: 0x0b1530, metalness: 0.2, roughness: 0.55 });
    const trimMat = new THREE.MeshStandardMaterial({ color: 0x55688f, metalness: 0.3, roughness: 0.4 });
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x8ea6d8, transparent: true, opacity: 0.35 });
    const box = (g: THREE.Group, w: number, h: number, d: number, x = 0, y = h / 2, z = 0, m: THREE.Material = bodyMat) => {
      const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), m);
      mesh.position.set(x, y, z);
      g.add(mesh);
      const e = new THREE.LineSegments(new THREE.EdgesGeometry(mesh.geometry), edgeMat);
      e.position.copy(mesh.position);
      g.add(e);
      return mesh;
    };
    type Landmark = { g: THREE.Group; top: number; pos: THREE.Vector3 };
    const marks: Landmark[] = LANDMARKS.map((kind, k) => {
      const a = (k / LANDMARKS.length) * Math.PI * 2 + Math.PI / 2;
      const g = new THREE.Group();
      g.position.set(Math.cos(a) * 9.5, 0, Math.sin(a) * 9.5);
      g.rotation.y = -a + Math.PI / 2;
      scene.add(g);
      let top = 2;
      if (kind === "house") {
        box(g, 2, 1.4, 1.8);
        const roof = new THREE.Mesh(new THREE.ConeGeometry(1.6, 1.1, 4), trimMat);
        roof.position.y = 1.95; roof.rotation.y = Math.PI / 4;
        g.add(roof);
        top = 2.6;
      } else if (kind === "bank") {
        box(g, 3, 0.3, 2.2, 0, 0.15);
        for (let c = 0; c < 5; c++) {
          const col = new THREE.Mesh(new THREE.CylinderGeometry(0.13, 0.13, 1.6, 10), trimMat);
          col.position.set(-1.1 + c * 0.55, 1.1, 0.9);
          g.add(col);
        }
        box(g, 2.6, 1.6, 1.4, 0, 1.1, -0.3);
        const ped = new THREE.Mesh(new THREE.CylinderGeometry(0, 1.9, 0.7, 3), trimMat);
        ped.rotation.z = Math.PI / 2; ped.rotation.y = Math.PI / 2; ped.scale.set(1, 1, 0.6);
        ped.position.y = 2.25;
        g.add(ped);
        top = 2.8;
      } else if (kind === "hospital") {
        box(g, 3, 3.2, 2.2);
        const cross = additive(0xf43f5e, 0.8);
        for (const [w, h] of [[0.9, 0.26], [0.26, 0.9]]) {
          const c = new THREE.Mesh(new THREE.PlaneGeometry(w, h), cross);
          c.position.set(0, 2.5, 1.12);
          g.add(c);
        }
        top = 3.4;
      } else if (kind === "plant") {
        box(g, 2.6, 1.2, 1.8, -0.5);
        for (const x of [0.9, 1.9]) {
          const t = new THREE.Mesh(new THREE.CylinderGeometry(0.45, 0.65, 2.6, 16, 1, true), trimMat);
          t.position.set(x - 0.6, 1.3, -0.2);
          g.add(t);
        }
        top = 3;
      } else if (kind === "traffic") {
        for (const [x, z] of [[-1, -1], [1, 1]]) {
          const pole = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, 2.2, 6), trimMat);
          pole.position.set(x, 1.1, z);
          g.add(pole);
          [0xef4444, 0xfbbf24, 0x22c55e].forEach((c, j) => {
            const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: c, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false }));
            s.scale.set(0.5, 0.5, 1);
            s.position.set(x, 2.15 - j * 0.28, z + 0.08);
            g.add(s);
          });
        }
        const cross = new THREE.Mesh(new THREE.PlaneGeometry(3.4, 0.9), new THREE.MeshStandardMaterial({ color: 0x1e293b }));
        cross.rotation.x = -Math.PI / 2; cross.position.y = 0.02;
        g.add(cross);
        top = 2.6;
      } else {
        box(g, 3.2, 1.6, 1.8);
        box(g, 1.2, 2.4, 1.2, 0, 1.2, 0.4);
        const flag = new THREE.Mesh(new THREE.PlaneGeometry(0.6, 0.35), new THREE.MeshBasicMaterial({ color: 0x60a5fa, side: THREE.DoubleSide }));
        flag.position.set(0.32, 2.85, 0.4);
        g.add(flag);
        top = 3;
      }
      return { g, top, pos: g.position.clone() };
    });

    // ── The SOC tower in the centre ──
    const tower = new THREE.Group();
    scene.add(tower);
    const towerMat = new THREE.MeshStandardMaterial({ color: 0x2b3a5e, emissive: 0x081226, metalness: 0.4, roughness: 0.4 });
    const shaft = new THREE.Mesh(new THREE.CylinderGeometry(1.1, 1.5, 6, 6), towerMat);
    shaft.position.y = 3;
    tower.add(shaft);
    const shaftEdges = new THREE.LineSegments(new THREE.EdgesGeometry(shaft.geometry), edgeMat);
    shaftEdges.position.y = 3;
    tower.add(shaftEdges);
    const crown = new THREE.Mesh(new THREE.TorusGeometry(1.6, 0.12, 8, 40), additive(A, 0.15));
    crown.rotation.x = Math.PI / 2; crown.position.y = 6.3;
    tower.add(crown);
    const towerBeam = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.6, 14, 16, 1, true), additive(A, 0));
    towerBeam.position.y = 13;
    tower.add(towerBeam);
    const towerGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    towerGlow.scale.set(9, 9, 1); towerGlow.position.y = 6.3;
    tower.add(towerGlow);

    // ── Layer 1: connections (light threads) with packets ──
    const lineMat = (c: THREE.ColorRepresentation) => new THREE.LineBasicMaterial({ color: c, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const threadMat = lineMat(A);
    const threads: THREE.Line[] = [];
    const routes: THREE.CatmullRomCurve3[] = [];
    const lift = (v: THREE.Vector3, y: number) => new THREE.Vector3(v.x, y, v.z);
    const addRoute = (from: THREE.Vector3, to: THREE.Vector3, h: number) => {
      const mid = from.clone().add(to).multiplyScalar(0.5);
      mid.y = h;
      const curve = new THREE.CatmullRomCurve3([lift(from, 0.3), mid, lift(to, 0.3)]);
      const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(30)), threadMat);
      scene.add(line);
      threads.push(line);
      routes.push(curve);
    };
    marks.forEach((m, k) => {
      addRoute(m.pos, new THREE.Vector3(0, 0, 0), 2.6);
      addRoute(m.pos, marks[(k + 1) % marks.length].pos, 2);
    });
    blocks.filter((_, i) => i % 3 === 0).forEach((b, i) => addRoute(b.position, marks[i % marks.length].pos, 1.2));
    const packets: { s: THREE.Sprite; c: THREE.CatmullRomCurve3; t: number; v: number }[] = [];
    for (let i = 0; i < 40; i++) {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i % 2 ? A : B, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.45, 0.45, 1);
      scene.add(s);
      packets.push({ s, c: routes[i % routes.length], t: rnd(), v: 0.15 + rnd() * 0.25 });
    }

    // ── Layer 2: three locks over every landmark ──
    const lockTex = LOCK_COLORS.map((c, i) => {
      const cv = document.createElement("canvas");
      cv.width = 128; cv.height = 160;
      const g = cv.getContext("2d")!;
      const col = `#${c.toString(16).padStart(6, "0")}`;
      g.strokeStyle = col; g.lineWidth = 12;
      g.beginPath(); g.arc(64, 58, 30, Math.PI, 0); g.lineTo(94, 76); g.moveTo(34, 58); g.lineTo(34, 76); g.stroke();
      g.fillStyle = col; g.fillRect(18, 74, 92, 74);
      g.fillStyle = "#061021"; g.font = "bold 60px sans-serif"; g.textAlign = "center"; g.textBaseline = "middle";
      g.fillText(["C", "I", "A"][i], 64, 114);
      const t = new THREE.CanvasTexture(cv);
      t.colorSpace = THREE.SRGBColorSpace;
      return t;
    });
    const locks: { s: THREE.Sprite; base: number; ph: number }[] = [];
    marks.forEach((m, k) => {
      for (let i = 0; i < 3; i++) {
        const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: lockTex[i], transparent: true, opacity: 0, depthWrite: false }));
        s.scale.set(0.7, 0.875, 1);
        const p = m.g.localToWorld(new THREE.Vector3((i - 1) * 0.85, m.top + 0.9, 0));
        s.position.copy(p);
        scene.add(s);
        locks.push({ s, base: p.y, ph: k + i * 0.7 });
      }
    });

    // ── Layer 3: attackers at the city's edge ──
    const watchers = WATCHER_COLORS.map((c, i) => {
      const g = new THREE.Group();
      const mat = new THREE.MeshBasicMaterial({ color: c, transparent: true, opacity: 0 });
      const body = new THREE.Mesh(new THREE.CapsuleGeometry(0.45, 1.1, 4, 10), mat);
      body.position.y = 1;
      g.add(body);
      const head = new THREE.Mesh(new THREE.SphereGeometry(0.38, 14, 10), mat);
      head.position.y = 2.15;
      g.add(head);
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: c, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.scale.set(3.4, 3.4, 1); halo.position.y = 1.3;
      g.add(halo);
      const a0 = Math.PI * 0.85 + (i / WATCHER_COLORS.length) * Math.PI * 1.3;
      scene.add(g);
      return { g, mat, halo, a0 };
    });

    // ── Layer 3 too: attacks travelling from the attackers to landmarks ──
    const shots = watchers.map((w, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: WATCHER_COLORS[i], transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(1.1, 1.1, 1);
      scene.add(s);
      const trail = new THREE.Line(new THREE.BufferGeometry().setFromPoints(new Array(24).fill(0).map(() => new THREE.Vector3())), lineMat(WATCHER_COLORS[i]));
      scene.add(trail);
      return { s, trail, target: marks[ATTACK_TARGETS[i]], t: i / watchers.length };
    });

    // ── Layer 3 too: how each attack looks, as a screen over its target. With
    //    layer 4 the screens fly into the tower and become the alert queue. ──
    const screens = ATTACK_TARGETS.map((ti, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: attackScreen(i), transparent: true, opacity: 0, depthWrite: false }));
      const home = marks[ti].pos.clone().setY(marks[ti].top + 4);
      s.position.copy(home);
      scene.add(s);
      return { s, home };
    });
    const board = new THREE.Sprite(new THREE.SpriteMaterial({ map: alertBoard(), transparent: true, opacity: 0, depthWrite: false }));
    board.scale.set(8.7, 4, 1);
    board.position.set(0, 9.6, 0);
    scene.add(board);

    // ── Layer 5: the shield dome ──
    const dome = new THREE.Mesh(new THREE.SphereGeometry(15, 40, 20, 0, Math.PI * 2, 0, Math.PI / 2),
      new THREE.MeshBasicMaterial({ color: A, wireframe: true, transparent: true, opacity: 0, depthWrite: false }));
    scene.add(dome);

    // ── The lens sweep: a scan ring that keeps passing over the city ──
    const sweep = new THREE.Mesh(new THREE.RingGeometry(0.96, 1, 96), additive(A, 0));
    sweep.rotation.x = -Math.PI / 2; sweep.position.y = 0.05;
    scene.add(sweep);

    const layer = [0, 0, 0, 0, 0]; // eased visibility per layer
    let dist = 34;
    const fit = (w: number, h: number) => { const asp = w / h; dist = asp < 1 ? 62 : asp < 1.5 ? 48 : 40; };
    const tmpA = new THREE.Vector3(), tmpB = new THREE.Vector3();
    const greyBody = new THREE.Color(0x3a4a6e), litBody = new THREE.Color(0x4a6b9a);

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.15, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.12 + pulse * 0.12 + (selected === k ? 0.1 : 0) : 0;
        layer[k] += (target - layer[k]) * ease;
      }
      const seen = stations.filter(s => s.status === "cleared").length / Math.max(1, stations.length);

      // camera: a slow orbit
      const yaw = rm ? 0.3 : t * 0.035;
      camera.position.set(Math.sin(yaw) * dist, dist * 0.72, Math.cos(yaw) * dist);
      camera.lookAt(0, 1.5, 0);

      // the city gains colour as the learner sees more of it
      bodyMat.color.copy(greyBody).lerp(litBody, seen);
      edgeMat.opacity = 0.3 + seen * 0.4;

      // 1 connections
      threadMat.opacity = layer[0] * 0.55;
      packets.forEach(p => {
        if (!rm) p.t = (p.t + dt * p.v) % 1;
        p.c.getPointAt(p.t, p.s.position);
        (p.s.material as THREE.SpriteMaterial).opacity = layer[0];
      });

      // 2 locks
      locks.forEach(l => {
        l.s.position.y = l.base + (rm ? 0 : Math.sin(t * 1.6 + l.ph) * 0.15);
        (l.s.material as THREE.SpriteMaterial).opacity = layer[1];
      });

      // 3 watchers pace at the edge
      watchers.forEach((w, i) => {
        const a = w.a0 + (rm ? 0 : Math.sin(t * 0.25 + i) * 0.12);
        const r = 19 - layer[2] * 2.5;
        w.g.position.set(Math.cos(a) * r, 0, Math.sin(a) * r);
        w.g.lookAt(0, 0, 0);
        w.mat.opacity = layer[2] * 0.9;
        (w.halo.material as THREE.SpriteMaterial).opacity = layer[2] * 0.5;
      });

      // 3 attacks fly in; 4 once the tower is lit they turn into alerts and fly to the tower
      shots.forEach((sh, i) => {
        if (!rm) sh.t = (sh.t + dt * 0.28) % 1;
        const from = watchers[i].g.position;
        const to = layer[3] > 0.5 ? tmpB.set(0, 6.3, 0) : tmpB.copy(sh.target.pos).setY(sh.target.top);
        const pts = (sh.trail.geometry as THREE.BufferGeometry).attributes.position as THREE.BufferAttribute;
        const at = (u: number, out: THREE.Vector3) => {
          out.lerpVectors(from, to, u);
          out.y = THREE.MathUtils.lerp(2, to.y, u) + Math.sin(u * Math.PI) * 5;
          return out;
        };
        at(rm ? 0.6 : sh.t, sh.s.position);
        for (let j = 0; j < pts.count; j++) { at(Math.max(0, (rm ? 0.6 : sh.t) - j * 0.012), tmpA); pts.setXYZ(j, tmpA.x, tmpA.y, tmpA.z); }
        pts.needsUpdate = true;
        const mat = sh.s.material as THREE.SpriteMaterial;
        mat.color.set(WATCHER_COLORS[i]).lerp(A, layer[3]);
        mat.opacity = layer[2];
        (sh.trail.material as THREE.LineBasicMaterial).opacity = layer[2] * 0.6;
        (sh.trail.material as THREE.LineBasicMaterial).color.copy(mat.color);
      });

      // attack screens: over their targets with layer 3, into the tower with layer 4
      screens.forEach((sc, i) => {
        const fly = THREE.MathUtils.smoothstep(layer[3], 0.5, 1); // the open-station preview never moves them
        sc.s.position.lerpVectors(sc.home, tmpA.set(0, 6.6, 0), fly);
        sc.s.position.y += rm ? 0 : Math.sin(t * 1.3 + i) * 0.12 * (1 - fly);
        const k = 4.4 * (1 - fly * 0.85);
        sc.s.scale.set(k, k * 0.656, 1);
        (sc.s.material as THREE.SpriteMaterial).opacity = layer[2] * (1 - fly);
      });
      (board.material as THREE.SpriteMaterial).opacity = THREE.MathUtils.clamp((layer[3] - 0.5) * 2, 0, 1);

      // 4 the tower and its beam; 5 the shield
      (crown.material as THREE.MeshBasicMaterial).opacity = 0.15 + layer[3] * 0.85;
      (towerBeam.material as THREE.MeshBasicMaterial).opacity = layer[3] * 0.35;
      (towerGlow.material as THREE.SpriteMaterial).opacity = layer[3] * 0.8;
      towerMat.emissive.setRGB(0.03, 0.07, 0.15).lerp(A, layer[3] * 0.35);
      (dome.material as THREE.MeshBasicMaterial).opacity = layer[4] * 0.12;
      if (!rm) { crown.rotation.z += dt * 0.5; dome.rotation.y += dt * 0.03; }

      // the lens sweep: an expanding ring every few seconds
      const sw = rm ? 0.5 : (t * 0.18) % 1;
      sweep.scale.setScalar(1 + sw * 26);
      (sweep.material as THREE.MeshBasicMaterial).opacity = (1 - sw) * (0.25 + seen * 0.4);
      (sweep.material as THREE.MeshBasicMaterial).color.copy(Wn).lerp(A, Math.min(1, seen * 3));
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
    </div>
  );
}
