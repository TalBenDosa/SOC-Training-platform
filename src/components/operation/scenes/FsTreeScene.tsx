"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The filesystem tree": one Linux server's directory tree grown in 3D from
 * "/" at the base. Stations light it up in turn: the branches and their
 * folders; rwx permission triplets over the sensitive files (/etc/shadow,
 * /etc/sudoers.d); the persistence spots (a cron clock over /etc/cron.d and
 * a red intruder key over /root/.ssh that gets removed); and finally an audit
 * beam that sweeps every branch. Decorative only.
 */
type Dir = { path: string; parent: number; x: number; y: number; z: number; hot?: boolean };
const DIRS: Dir[] = [
  { path: "/", parent: -1, x: 0, y: 0.8, z: 0 },
  { path: "/etc", parent: 0, x: -6, y: 3.2, z: -1 },
  { path: "/var", parent: 0, x: -2.4, y: 3.6, z: -3 },
  { path: "/tmp", parent: 0, x: 1.8, y: 3.2, z: -3.2, hot: true },
  { path: "/home", parent: 0, x: 5, y: 3.4, z: -1 },
  { path: "/proc", parent: 0, x: 6.8, y: 2.6, z: 2 },
  { path: "/root", parent: 0, x: -6.8, y: 2.4, z: 2.4 },
  { path: "/usr/bin", parent: 0, x: 2.4, y: 2.4, z: 3.4 },
  { path: "shadow", parent: 1, x: -8.4, y: 5.8, z: -1.6 },
  { path: "sudoers.d", parent: 1, x: -6.4, y: 6.4, z: -2.6 },
  { path: "cron.d", parent: 1, x: -4.2, y: 6, z: -1.2 },
  { path: "log", parent: 2, x: -2.4, y: 6.6, z: -4.2 },
  { path: ".ssh", parent: 6, x: -8.6, y: 4.8, z: 3.6 },
  { path: "/dev/shm", parent: 0, x: -1.4, y: 2.4, z: 3.6, hot: true },
];
const SHADOW = 8, SUDOERS = 9, CRON = 10, SSH = 12;

function tag(text: string, color: string, w = 256) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 30px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 110, 0.5, 1);
  return s;
}

export default function FsTreeScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x030607, 24, 64);
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xa7f3d0, 0x050a08, 0.7));
    const grid = new THREE.GridHelper(60, 60, 0x0f2a22, 0x0a1a16);
    scene.add(grid);
    // falling green terminal glyph columns in the background
    const rain = Array.from({ length: 70 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x22c55e, transparent: true, opacity: 0.15, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.25, 0.9, 1);
      s.position.set(-20 + (i * 37) % 40, (i * 13) % 14, -10 - (i % 5) * 2);
      scene.add(s);
      return s;
    });

    // ── The tree: nodes and branches ──
    const nodeMats = DIRS.map(d => new THREE.MeshBasicMaterial({ color: d.hot ? Wn : A, transparent: true, opacity: 0.2 }));
    const nodePos = DIRS.map(d => new THREE.Vector3(d.x, d.y, d.z));
    DIRS.forEach((d, i) => {
      const m = new THREE.Mesh(i === 0 ? new THREE.OctahedronGeometry(0.7) : new THREE.BoxGeometry(0.55, 0.55, 0.55), nodeMats[i]);
      m.position.copy(nodePos[i]);
      scene.add(m);
      const t = tag(d.path, d.hot ? "#fda4af" : "#d1fae5", d.path.length > 7 ? 320 : 256);
      t.position.copy(nodePos[i]).add(new THREE.Vector3(0, 0.62, 0));
      scene.add(t);
    });
    const branchMat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.15 });
    DIRS.forEach((d, i) => {
      if (d.parent < 0) return;
      const a = nodePos[d.parent], b = nodePos[i];
      const mid = a.clone().lerp(b, 0.5); mid.y = Math.max(a.y, b.y) + 0.4;
      const c = new THREE.QuadraticBezierCurve3(a, mid, b);
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(c.getPoints(20)), branchMat));
    });

    // ── 2 permission triplets over the sensitive files ──
    const perms = [
      { at: SHADOW, text: "rw- r-- ---  640" },
      { at: SUDOERS, text: "r-- r-- ---  440" },
    ].map(p => {
      const s = tag(p.text, "#fde68a", 420);
      s.position.copy(nodePos[p.at]).add(new THREE.Vector3(0, 1.25, 0));
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return s.material as THREE.SpriteMaterial;
    });

    // ── 3 persistence: a cron clock and the intruder key ──
    const clock = new THREE.Mesh(new THREE.TorusGeometry(0.75, 0.06, 8, 40), additive(0xfbbf24, 0));
    clock.position.copy(nodePos[CRON]).add(new THREE.Vector3(0, 1.4, 0));
    scene.add(clock);
    const hand = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.6, 0.06), additive(0xfbbf24, 0));
    hand.position.copy(clock.position);
    scene.add(hand);
    const key = tag("kali@kali  KEY", "#fb7185", 340);
    key.position.copy(nodePos[SSH]).add(new THREE.Vector3(0, 1.1, 0));
    scene.add(key);
    const keyMat = key.material as THREE.SpriteMaterial;

    // ── 4 the audit beam sweeping the tree ──
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 12, 8), additive(A, 0));
    scene.add(beam);
    const eye = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    eye.scale.set(3, 3, 1); eye.position.set(0, 10, 0);
    scene.add(eye);

    const anchors = [new THREE.Vector3(0, 2, 0), nodePos[SHADOW].clone().add(new THREE.Vector3(0, 2.2, 0)), nodePos[SSH].clone().add(new THREE.Vector3(0, 2, 0)), nodePos[2].clone().add(new THREE.Vector3(0, 1.4, 0))];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 22, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 38 : asp < 1.5 ? 25 : 21; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0.3 : Math.sin(t * 0.06) * 0.35 + 0.15;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 2, Math.cos(yaw) * dist);
      camera.lookAt(-0.8, 3.6, 0);

      rain.forEach((r, i) => { if (!rm) r.position.y = 14 - ((t * (0.8 + (i % 4) * 0.3) + i) % 14); });

      // 1 the tree grows: nodes light from the root outwards
      nodeMats.forEach((m, i) => {
        const depth = DIRS[i].parent < 0 ? 0 : DIRS[DIRS[i].parent].parent < 0 ? 1 : 2;
        m.opacity = 0.18 + THREE.MathUtils.clamp(level[0] * 3 - depth, 0, 1) * 0.75;
      });
      branchMat.opacity = 0.12 + level[0] * 0.6;
      // 2 permissions
      perms.forEach(m => { m.opacity = level[1]; });
      // 3 persistence found: the clock ticks, the intruder key flashes, then fades once cleared
      (clock.material as THREE.MeshBasicMaterial).opacity = level[2] * 0.9;
      (hand.material as THREE.MeshBasicMaterial).opacity = level[2] * 0.9;
      if (!rm) hand.rotation.z = -t * 1.2;
      const found = stations[2]?.status === "cleared";
      keyMat.opacity = found ? Math.max(0, 1 - level[3] * 1.2) * 0.9 : (stations[2]?.status === "open" ? 0.4 + pulse * 0.4 : 0.15);
      // 4 the audit beam sweeps
      const sweep = rm ? 0.5 : (t * 0.15) % 1;
      const target = nodePos[1 + Math.floor(sweep * (DIRS.length - 1))];
      beam.position.copy(target).add(new THREE.Vector3(0, 5, 0));
      (beam.material as THREE.MeshBasicMaterial).opacity = level[3] * 0.4;
      (eye.material as THREE.SpriteMaterial).opacity = level[3] * 0.8;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04110c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
