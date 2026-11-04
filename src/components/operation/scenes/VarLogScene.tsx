"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "/var/log": a filing cabinet whose drawers slide open one by one (auth.log,
 * syslog, audit, nginx, wtmp); a crystal for the binary journal, with query
 * beams picking lines out of it; an SSH door that a swarm of red knocks hits
 * until one gets through and a key glints in the lock; and a cron clock whose
 * hand ticks every five minutes, firing a line to a server, beside a log
 * ribbon with a red hole in it. Stations switch each part on. Decorative only.
 */
const DRAWERS = ["auth.log", "syslog", "audit.log", "nginx", "wtmp"];

function tag(text: string, color: string, w = 220) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 26px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}

export default function VarLogScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x080503, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xffedd5, 0x080503, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x431407, 0x1c0f06));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3a2e26, emissive: 0x120a05, metalness: 0.55, roughness: 0.4 });

    // ── 1 the cabinet ──
    const cab = new THREE.Mesh(new THREE.BoxGeometry(2.4, 4.2, 1.8), metal());
    cab.position.set(-11, 2.1, 0);
    scene.add(cab);
    const drawers = DRAWERS.map((n, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x4a3a2e, emissive: A, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(2.1, 0.7, 1.6), mat);
      const y = 3.75 - i * 0.8;
      m.position.set(-11, y, 0.15);
      scene.add(m);
      const l = tag(n, "#ffedd5", 200);
      l.position.set(-11, y, 1.9);
      scene.add(l);
      return { m, mat, y };
    });

    // ── 2 the journal crystal ──
    const crystalMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.35, metalness: 0.2, roughness: 0.1 });
    const crystal = new THREE.Mesh(new THREE.OctahedronGeometry(1.3, 0), crystalMat);
    crystal.position.set(-5, 2.6, -1);
    scene.add(crystal);
    const jl = tag("journal", "#d9f99d", 180); jl.position.set(-5, 4.4, -1); scene.add(jl);
    const beams = ["-u cron", "-p err", "_COMM=sudo"].map((q, i) => {
      const mat = additive(B, 0);
      const to = new THREE.Vector3(-2.6, 1.2 + i * 1.1, 0.5);
      const from = crystal.position.clone();
      const len = from.distanceTo(to);
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.03, 0.03, len, 6), mat);
      m.position.copy(from).lerp(to, 0.5);
      m.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), to.clone().sub(from).normalize());
      scene.add(m);
      const l = tag(q, "#d9f99d", 200);
      l.position.copy(to).add(new THREE.Vector3(0.9, 0, 0));
      (l.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(l);
      return { mat, l: l.material as THREE.SpriteMaterial };
    });

    // ── 3 the SSH door ──
    const frame = new THREE.Mesh(new THREE.BoxGeometry(2, 3.4, 0.3), metal());
    frame.position.set(2.5, 1.7, -1);
    scene.add(frame);
    const doorMat = new THREE.MeshStandardMaterial({ color: 0x5a4636, emissive: A, emissiveIntensity: 0 });
    const door = new THREE.Mesh(new THREE.BoxGeometry(1.6, 3, 0.2), doorMat);
    door.position.set(2.5, 1.6, -0.85);
    scene.add(door);
    const sl = tag("sshd", "#ffedd5", 120); sl.position.set(2.5, 3.8, -1); scene.add(sl);
    const knocks = Array.from({ length: 8 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i === 5 ? 0xfacc15 : Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.45, 0.45, 1);
      scene.add(s);
      return { s, o: i / 8, win: i === 5 };
    });
    const keyMat = additive(0xfacc15, 0);
    const keyM = new THREE.Mesh(new THREE.TorusGeometry(0.18, 0.05, 8, 16), keyMat);
    keyM.position.set(3.05, 1.6, -0.7);
    scene.add(keyM);
    const kl = tag("root@kali", "#fde68a", 200); kl.position.set(3.6, 2.2, -0.6); (kl.material as THREE.SpriteMaterial).opacity = 0; scene.add(kl);

    // ── 4 the cron clock and the ribbon with a hole ──
    const clock = new THREE.Mesh(new THREE.CircleGeometry(1.4, 48), new THREE.MeshStandardMaterial({ color: 0x3a2e26, side: THREE.DoubleSide }));
    clock.position.set(8, 2.6, -1.5);
    scene.add(clock);
    const handMat = additive(A, 0.2);
    const hand = new THREE.Mesh(new THREE.BoxGeometry(0.07, 1.1, 0.04), handMat);
    hand.geometry.translate(0, 0.55, 0);
    hand.position.set(8, 2.6, -1.45);
    scene.add(hand);
    const cl = tag("*/5 * * * *", "#ffedd5", 240); cl.position.set(8, 4.4, -1.5); scene.add(cl);
    const fireMat = new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const fire = new THREE.Sprite(fireMat);
    fire.scale.set(0.6, 0.6, 1);
    scene.add(fire);
    const ribbon = Array.from({ length: 16 }, (_, i) => {
      const gap = i >= 7 && i <= 10;
      const mat = new THREE.MeshStandardMaterial({ color: gap ? 0x1a0a0a : 0x6b5444, emissive: gap ? Wn : A, emissiveIntensity: 0, transparent: true, opacity: gap ? 0.4 : 1 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.42, 0.08, 0.6), mat);
      m.position.set(5.5 + i * 0.45, 0.05, 1.8);
      scene.add(m);
      return { mat, gap };
    });

    const anchors = [new THREE.Vector3(-11, 5.4, 0), new THREE.Vector3(-5, 5.6, -1), new THREE.Vector3(2.5, 5, -1), new THREE.Vector3(8, 5.6, -1.5)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 70 : asp < 1.5 ? 32 : 27; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(-1, 2.2, 0);

      // 1 drawers slide out one after another
      drawers.forEach((d, i) => {
        const v = THREE.MathUtils.clamp(level[0] * 5 - i, 0, 1);
        d.m.position.z = 0.15 + v * 0.6;
        d.mat.emissiveIntensity = v * 0.35;
      });
      // 2 the crystal turns; query beams pick lines out
      if (!rm) crystal.rotation.y += dt * 0.5;
      crystalMat.emissiveIntensity = level[1] * 0.6;
      beams.forEach((b, i) => {
        const v = THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1);
        b.mat.opacity = v * 0.8;
        b.l.opacity = v;
      });
      // 3 knocks hit the door; one gets through; the key glints
      const on = Math.max(level[2], stations[2]?.status === "open" ? 0.5 : 0);
      knocks.forEach(k => {
        const u = rm ? k.o : ((t * 0.35 + k.o) % 1);
        const z = k.win && level[2] > 0.5 ? 6 - u * 8 : 6 - Math.min(u, 0.75) * 8;
        k.s.position.set(2.5 + Math.sin(k.o * 9) * 0.6, 1.3 + Math.cos(k.o * 7) * 0.7, z);
        (k.s.material as THREE.SpriteMaterial).opacity = on * (u > 0.74 && !(k.win && level[2] > 0.5) ? 0.2 : 0.9);
      });
      doorMat.emissiveIntensity = level[2] * 0.2;
      keyMat.opacity = level[2] > 0.5 ? (rm ? 0.9 : 0.5 + pulse * 0.5) : 0;
      (kl.material as THREE.SpriteMaterial).opacity = level[2] > 0.5 ? 1 : 0;
      // 4 the clock ticks every 'five minutes' and fires; the ribbon shows its hole
      const ticks = Math.floor(rm ? 3 : t / 1.5);
      hand.rotation.z = -(ticks % 12) * (Math.PI / 6);
      handMat.opacity = 0.2 + level[3] * 0.7;
      const f = rm ? 0.5 : ((t / 1.5) % 1);
      fire.position.set(8 + f * 4, 2.6 + f * 1.5, -1.5);
      fireMat.opacity = level[3] * (1 - f);
      ribbon.forEach(r => { r.mat.emissiveIntensity = level[3] * (r.gap ? (rm ? 0.8 : 0.4 + pulse * 0.5) : 0.25); });

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140c06]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
