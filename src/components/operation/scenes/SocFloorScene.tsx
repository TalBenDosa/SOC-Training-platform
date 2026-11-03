"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The floor": a SOC operations room. A curved video wall of dashboards, three
 * tiers of analyst desks (T1 in front, T2 behind, T3 on a raised dais) and a
 * row of tool towers (SIEM, EDR, SOAR, TIP, ticketing). Stations switch the
 * room on in order: the wall, the desks tier by tier, the tools (data links run
 * from each tower to the wall), and finally the night alert, which travels from
 * the wall to a T1 desk and up the escalation path. Decorative only.
 */
const TOOLS = ["SIEM", "EDR", "SOAR", "TIP", "TICKETS"];
const TOOL_COLORS = [0x22d3ee, 0xf43f5e, 0xa78bfa, 0xfbbf24, 0x34d399];
/** Towers stand along the side walls so they never hide the video wall. */
const TOOL_SPOTS: [number, number][] = [[-15, -6], [-15, -0.5], [-15, 5], [15, -6], [15, -0.5]];

function wallTexture(): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = 1536; c.height = 384;
  const g = c.getContext("2d")!;
  g.fillStyle = "#050b16"; g.fillRect(0, 0, 1536, 384);
  const panel = (x: number, w: number, title: string) => {
    g.strokeStyle = "#1e3a5f"; g.lineWidth = 3; g.strokeRect(x + 6, 10, w - 12, 364);
    g.fillStyle = "#7dd3fc"; g.font = "bold 22px monospace"; g.fillText(title, x + 20, 42);
  };
  panel(0, 384, "ALERTS / HOUR");
  [40, 55, 38, 62, 48, 120, 90, 70, 52, 44, 60, 58].forEach((v, i) => { g.fillStyle = v > 100 ? "#f43f5e" : "#38bdf8"; g.fillRect(24 + i * 28, 350 - v * 2, 18, v * 2); });
  panel(384, 384, "OPEN INCIDENTS");
  g.fillStyle = "#f8fafc"; g.font = "bold 120px monospace"; g.fillText("07", 440, 220);
  g.fillStyle = "#94a3b8"; g.font = "22px monospace"; g.fillText("2 CRIT  3 HIGH  2 MED", 410, 290);
  panel(768, 384, "MTTD / MTTR");
  g.fillStyle = "#34d399"; g.font = "bold 46px monospace"; g.fillText("4h 12m", 800, 170); g.fillText("38m", 800, 290);
  g.fillStyle = "#94a3b8"; g.font = "20px monospace"; g.fillText("mean time to detect", 800, 205); g.fillText("mean time to respond", 800, 325);
  panel(1152, 384, "THREAT MAP");
  for (let i = 0; i < 60; i++) {
    const x = 1180 + ((i * 97) % 330), y = 80 + ((i * 53) % 270);
    g.fillStyle = i % 7 === 0 ? "#f43f5e" : "#1d4ed8"; g.beginPath(); g.arc(x, y, i % 7 === 0 ? 6 : 3, 0, Math.PI * 2); g.fill();
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  // the wall is seen from inside the cylinder: flip so the text reads left to right
  t.wrapS = THREE.RepeatWrapping;
  t.repeat.x = -1; t.offset.x = 1;
  return t;
}

function towerLabel(text: string, color: string) {
  const c = document.createElement("canvas");
  c.width = 256; c.height = 64;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 34px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, 128, 32);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(2.6, 0.65, 1);
  return s;
}

export default function SocFloorScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03060d, 30, 70);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x05080f, 0.75));
    const key = new THREE.DirectionalLight(0xd6e2ff, 1.1);
    key.position.set(6, 16, 14);
    scene.add(key);

    const floor = new THREE.Mesh(new THREE.PlaneGeometry(70, 50), new THREE.MeshStandardMaterial({ color: 0x0a0f1a, roughness: 0.6, metalness: 0.3 }));
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);
    const grid = new THREE.GridHelper(70, 35, 0x14213a, 0x0e1729);
    grid.position.y = 0.01;
    scene.add(grid);

    // ── Video wall: a curved screen of dashboards ──
    const wallMat = new THREE.MeshBasicMaterial({ map: wallTexture(), transparent: true, opacity: 0.12, side: THREE.DoubleSide });
    const wall = new THREE.Mesh(new THREE.CylinderGeometry(20, 20, 6, 64, 1, true, Math.PI * 0.8, Math.PI * 0.4), wallMat);
    wall.position.set(0, 4.4, 8);
    scene.add(wall);
    const frame = new THREE.Mesh(new THREE.CylinderGeometry(20.05, 20.05, 6.4, 64, 1, true, Math.PI * 0.8, Math.PI * 0.4), new THREE.MeshStandardMaterial({ color: 0x0f172a, side: THREE.BackSide }));
    frame.position.copy(wall.position);
    scene.add(frame);
    const wallGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    wallGlow.scale.set(30, 10, 1); wallGlow.position.set(0, 4.4, -11);
    scene.add(wallGlow);
    const wallAnchor = new THREE.Vector3(-9, 7.4, -10.2);

    // ── Desks: tiers T1 (front), T2, T3 (raised) ──
    const deskMat = new THREE.MeshStandardMaterial({ color: 0x1b2333, metalness: 0.4, roughness: 0.5 });
    type Desk = { g: THREE.Group; screens: THREE.MeshBasicMaterial[]; pos: THREE.Vector3 };
    const tiers: Desk[][] = [[], [], []];
    const tierRows = [{ z: 1, n: 6, y: 0 }, { z: 5, n: 4, y: 0 }, { z: 9.5, n: 2, y: 0.8 }];
    tierRows.forEach((row, ti) => {
      if (row.y > 0) {
        const dais = new THREE.Mesh(new THREE.BoxGeometry(12, row.y, 4), new THREE.MeshStandardMaterial({ color: 0x111827 }));
        dais.position.set(0, row.y / 2, row.z);
        scene.add(dais);
      }
      for (let i = 0; i < row.n; i++) {
        const g = new THREE.Group();
        g.position.set((i - (row.n - 1) / 2) * 3.6, row.y, row.z);
        g.rotation.y = Math.PI;
        scene.add(g);
        const top = new THREE.Mesh(new THREE.BoxGeometry(3, 0.12, 1.3), deskMat);
        top.position.y = 0.9;
        g.add(top);
        const leg = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.85, 0.1), deskMat);
        leg.position.set(0, 0.45, 0.5);
        g.add(leg);
        const screens: THREE.MeshBasicMaterial[] = [];
        for (const [x, ry] of [[-0.85, 0.25], [0, 0], [0.85, -0.25]] as const) {
          const m = new THREE.MeshBasicMaterial({ color: 0x1e293b, side: THREE.DoubleSide });
          const sc = new THREE.Mesh(new THREE.PlaneGeometry(0.8, 0.5), m);
          sc.position.set(x, 1.35, 0.35); sc.rotation.y = ry;
          g.add(sc);
          screens.push(m);
        }
        const chair = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.32, 0.6, 12), new THREE.MeshStandardMaterial({ color: 0x0f172a }));
        chair.position.set(0, 0.5, -0.7);
        g.add(chair);
        tiers[ti].push({ g, screens, pos: g.position.clone() });
      }
    });

    // ── Tool towers on the right, data links to the wall ──
    const towers = TOOLS.map((name, i) => {
      const c = TOOL_COLORS[i];
      const g = new THREE.Group();
      g.position.set(TOOL_SPOTS[i][0], 0, TOOL_SPOTS[i][1]);
      scene.add(g);
      const body = new THREE.Mesh(new THREE.BoxGeometry(1.4, 3.2, 1.4), new THREE.MeshStandardMaterial({ color: 0x151d2c, metalness: 0.5, roughness: 0.4 }));
      body.position.y = 1.6;
      g.add(body);
      const stripe = additive(c, 0.1);
      for (let k = 0; k < 4; k++) {
        const sp = new THREE.Mesh(new THREE.PlaneGeometry(1.1, 0.08), stripe);
        sp.position.set(0, 0.6 + k * 0.7, 0.71);
        g.add(sp);
      }
      const label = towerLabel(name, `#${c.toString(16).padStart(6, "0")}`);
      label.position.y = 3.8;
      g.add(label);
      const linkMat = new THREE.LineBasicMaterial({ color: c, transparent: true, opacity: 0, blending: THREE.AdditiveBlending });
      const from = new THREE.Vector3(g.position.x, 3.2, g.position.z);
      const to = new THREE.Vector3(Math.sign(g.position.x) * 9, 4.4, -10.5);
      const curve = new THREE.QuadraticBezierCurve3(from, new THREE.Vector3((from.x + to.x) / 2, 7, (from.z + to.z) / 2), to);
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(30)), linkMat));
      const pulse = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: c, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      pulse.scale.set(0.9, 0.9, 1);
      scene.add(pulse);
      return { g, stripe, label: label.material as THREE.SpriteMaterial, linkMat, curve, pulse, t: i / TOOLS.length };
    });

    // ── The night alert: wall → a T1 desk → T2 → T3 ──
    const t1 = tiers[0][2], t2 = tiers[1][1], t3 = tiers[2][0];
    const escPts = [new THREE.Vector3(0, 4.4, -11), t1.pos.clone().setY(1.6), t2.pos.clone().setY(1.6), t3.pos.clone().setY(2.4)];
    const escPath = new THREE.CatmullRomCurve3(escPts);
    const escMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending });
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(escPath.getPoints(80)), escMat));
    const alertDot = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    alertDot.scale.set(1.8, 1.8, 1);
    scene.add(alertDot);
    let alertT = 0;

    // label anchors per station: wall, the T2 row, the tools, the T1 desk
    const anchors = [wallAnchor, new THREE.Vector3(0, 2.6, 5), new THREE.Vector3(-15, 4.6, -0.5), t1.pos.clone().setY(2.4)];

    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 30, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 46 : asp < 1.5 ? 34 : 29; };
    const dim = new THREE.Color(0x1e293b), side = new THREE.Color(0x60a5fa);

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.12 : 0;
        level[k] += (target - level[k]) * ease;
      }

      // the camera stands behind the T3 dais, looking over the room to the wall
      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.15;
      camera.position.set(Math.sin(yaw) * dist * 0.6, dist * (portrait ? 0.75 : 0.5), dist * 0.85 + 6);
      camera.lookAt(0, 2.2, -2);

      // 1 the wall
      wallMat.opacity = 0.12 + level[0] * 0.88;
      (wallGlow.material as THREE.SpriteMaterial).opacity = level[0] * 0.25;

      // 2 the desks, tier by tier
      tiers.forEach((row, ti) => {
        const on = THREE.MathUtils.clamp(level[1] * 3 - ti, 0, 1);
        row.forEach((d, di) => d.screens.forEach((m, si) => {
          m.color.copy(dim).lerp(si === 1 ? A : side, on);
          if (on > 0.9 && !rm && Math.sin(t * 5 + di * 3 + si) > 0.97) m.color.multiplyScalar(1.4);
        }));
      });

      // 3 the tools, linked to the wall
      towers.forEach(tw => {
        tw.stripe.opacity = 0.1 + level[2] * 0.8;
        tw.label.opacity = 0.35 + level[2] * 0.65;
        tw.linkMat.opacity = level[2] * 0.7;
        if (!rm) tw.t = (tw.t + dt * 0.35) % 1;
        tw.curve.getPoint(rm ? 0.5 : tw.t, tw.pulse.position);
        (tw.pulse.material as THREE.SpriteMaterial).opacity = level[2] > 0.5 ? 0.9 : 0;
      });

      // 4 the night alert climbs the escalation path
      escMat.opacity = level[3] * 0.8;
      if (!rm) alertT = (alertT + dt * 0.18) % 1;
      escPath.getPoint(rm ? 0.6 : alertT, alertDot.position);
      (alertDot.material as THREE.SpriteMaterial).opacity = Math.max(level[3], stations[3]?.status === "open" ? 0.6 * pulse : 0);

      anchors.forEach((p, i) => placeLabel(labelRefs.current[i], p, camera, W_, H_));
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 hidden will-change-transform sm:block">
            <span className="block whitespace-nowrap rounded-md border bg-[#071021]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
