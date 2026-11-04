"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The specimen lab": a quarantine floor for live malware. Two crossing light
 * axes (MOVES, WANTS) with specimen capsules on the grid; a first-stage packet
 * racing to a server until a block wall stops it; a host pulsing a steady
 * heartbeat to a C2 node; keys and cookies siphoned from a laptop slab up an
 * exfil funnel; a wall of file tiles, half locking amber and half shattering,
 * beside a spinning mining rig; and under a glass OS floor, a rootkit ring with
 * a bodiless ">_" prompt above it. Stations switch each part on. Decorative only.
 */
function tag(text: string, color: string, w = 260) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 28px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}

export default function SpecimenScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), S = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x040806, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xd1fae5, 0x040806, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x14532d, 0x0b2416));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x1f3a2c, emissive: 0x08170f, metalness: 0.55, roughness: 0.4 });

    // ── 1 the two axes and the specimen capsules ──
    const axisMat = additive(A, 0.1);
    const ax1 = new THREE.Mesh(new THREE.BoxGeometry(9, 0.08, 0.08), axisMat);
    ax1.position.set(-10, 0.1, 0);
    const ax2 = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.08, 9), axisMat);
    ax2.position.set(-10, 0.1, 0);
    scene.add(ax1, ax2);
    const movesLab = tag("MOVES", "#bbf7d0", 160); movesLab.position.set(-5.2, 0.6, 0); scene.add(movesLab);
    const wantsLab = tag("WANTS", "#bbf7d0", 160); wantsLab.position.set(-10, 0.6, -4.8); scene.add(wantsLab);
    const capsules = [[-13, -2], [-11, 2], [-8, -3], [-7, 1.5], [-12, 3.5], [-9, -1]].map(([x, z], i) => {
      const glass = new THREE.Mesh(new THREE.CylinderGeometry(0.45, 0.45, 1.6, 16, 1, true), new THREE.MeshStandardMaterial({ color: 0x86efac, transparent: true, opacity: 0.18, metalness: 0.1, roughness: 0.1, side: THREE.DoubleSide }));
      glass.position.set(x, 0.9, z);
      scene.add(glass);
      const core = additive(i % 2 ? Wn : A, 0.1);
      const m = new THREE.Mesh(new THREE.IcosahedronGeometry(0.28, 0), core);
      m.position.set(x, 0.9, z);
      scene.add(m);
      return { m, core };
    });

    // ── 2 first stage: a packet racing to a server, and the block wall ──
    const srv = new THREE.Mesh(new THREE.BoxGeometry(1.2, 2.2, 1.2), metal());
    srv.position.set(-2, 1.1, -6);
    scene.add(srv);
    const stage2 = new THREE.CatmullRomCurve3([new THREE.Vector3(-2, 2.4, -6), new THREE.Vector3(-1, 4, -3), new THREE.Vector3(0, 2, 0)]);
    const pktMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    const pkt = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.4, 0.4), pktMat);
    scene.add(pkt);
    const wallMat = additive(A, 0);
    const wall = new THREE.Mesh(new THREE.PlaneGeometry(2.4, 2.4), wallMat);
    wall.position.set(-1.1, 3.4, -2.4);
    wall.rotation.y = 0.5;
    scene.add(wall);
    const blockLab = tag("BLOCKED", "#86efac", 200); blockLab.position.set(-1.1, 4.9, -2.4); scene.add(blockLab);
    const host = new THREE.Mesh(new THREE.BoxGeometry(1.6, 1, 1.2), metal());
    host.position.set(0, 0.5, 0);
    scene.add(host);

    // ── 3 the heartbeat: host to C2 on a steady rhythm ──
    const c2Mat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.5, transparent: true, opacity: 0.3 });
    const c2 = new THREE.Mesh(new THREE.OctahedronGeometry(0.9), c2Mat);
    c2.position.set(6, 5, -5);
    scene.add(c2);
    const c2Lab = tag("C2", "#fecdd3", 100); c2Lab.position.set(6, 6.4, -5); scene.add(c2Lab);
    const beatLine = new THREE.Line3(new THREE.Vector3(0, 1, 0), new THREE.Vector3(6, 5, -5));
    const beats = Array.from({ length: 4 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.8, 0.8, 1);
      scene.add(s);
      return s;
    });

    // ── 4 the stealer: keys and cookies siphoned up an exfil funnel ──
    const slab = new THREE.Mesh(new THREE.BoxGeometry(2.4, 0.12, 1.6), metal());
    slab.position.set(6, 0.4, 3);
    scene.add(slab);
    const funnelMat = additive(S, 0.08);
    const funnel = new THREE.Mesh(new THREE.ConeGeometry(1.1, 3, 20, 1, true), funnelMat);
    funnel.position.set(6, 3.2, 3);
    funnel.rotation.x = Math.PI;
    scene.add(funnel);
    const loot = Array.from({ length: 10 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i % 2 ? S : 0xfde68a, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.45, 0.45, 1);
      scene.add(s);
      return { s, o: i / 10 };
    });

    // ── 5 lock or burn: a file wall, and a mining rig ──
    const tiles: { m: THREE.Mesh; mat: THREE.MeshStandardMaterial; burn: boolean; home: THREE.Vector3 }[] = [];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 6; c++) {
      const mat = new THREE.MeshStandardMaterial({ color: 0x1e3a2c, emissive: 0x000000, transparent: true, opacity: 0.9 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.8, 0.8, 0.1), mat);
      const home = new THREE.Vector3(10 + c * 0.95, 0.6 + r * 0.95, -1);
      m.position.copy(home);
      scene.add(m);
      tiles.push({ m, mat, burn: c >= 3, home });
    }
    const rig = new THREE.Mesh(new THREE.TorusKnotGeometry(0.6, 0.18, 64, 8), new THREE.MeshStandardMaterial({ color: S, emissive: S, emissiveIntensity: 0.2, transparent: true, opacity: 0.25 }));
    rig.position.set(13, 1.2, 3.5);
    scene.add(rig);
    const mineLab = tag("CPU 100%", "#fde68a", 200); mineLab.position.set(13, 2.6, 3.5); scene.add(mineLab);

    // ── 6 under the radar: a glass OS floor, a rootkit below, a prompt with no file ──
    const osMat = new THREE.MeshStandardMaterial({ color: 0x86efac, transparent: true, opacity: 0.06, side: THREE.DoubleSide });
    const osFloor = new THREE.Mesh(new THREE.PlaneGeometry(8, 6), osMat);
    osFloor.rotation.x = -Math.PI / 2;
    osFloor.position.set(-6, 1.6, 8);
    scene.add(osFloor);
    const osLab = tag("OS LAYER", "#bbf7d0", 200); osLab.position.set(-9.2, 1.9, 10.4); scene.add(osLab);
    const kitMat = additive(Wn, 0);
    const kit = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.1, 10, 48), kitMat);
    kit.rotation.x = Math.PI / 2;
    kit.position.set(-6, 0.5, 8);
    scene.add(kit);
    const ghost = tag(">_", "#86efac", 120);
    ghost.position.set(-4, 3.2, 8);
    (ghost.material as THREE.SpriteMaterial).opacity = 0;
    ghost.scale.set(2.4, 1.1, 1);
    scene.add(ghost);

    const anchors = [new THREE.Vector3(-10, 3, 0), new THREE.Vector3(-1.5, 6, -4), new THREE.Vector3(5, 7.6, -5), new THREE.Vector3(6, 6, 3), new THREE.Vector3(12.4, 5, -1), new THREE.Vector3(-4.5, 2.4, 11)];
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 72 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 6; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.6 : 0.44) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(1, 2.4, 1);

      // 1 axes and capsules
      axisMat.opacity = 0.1 + level[0] * 0.85;
      capsules.forEach(({ m, core }, i) => {
        core.opacity = 0.1 + THREE.MathUtils.clamp(level[0] * 6 - i, 0, 1) * 0.85;
        if (!rm) { m.rotation.y += dt * 0.8; m.position.y = 0.9 + Math.sin(t * 1.5 + i) * 0.12; }
      });
      // 2 the stage-2 packet races in; once the station clears, the wall stops it
      const blocked = level[1] > 0.5;
      const u = rm ? 0.4 : (t * 0.35) % 1;
      stage2.getPointAt(blocked ? Math.min(u, 0.42) : u, pkt.position);
      pktMat.opacity = Math.max(level[1], stations[1]?.status === "open" ? 0.5 : 0) * (blocked && u > 0.42 ? 0.3 : 0.9);
      wallMat.opacity = level[1] * 0.5;
      (blockLab.material as THREE.SpriteMaterial).opacity = level[1];
      // 3 the heartbeat: evenly spaced pulses, like a sleep timer
      c2Mat.opacity = 0.3 + level[2] * 0.6;
      if (!rm) c2.rotation.y += dt * 0.6;
      beats.forEach((b, i) => {
        const v = rm ? i / 4 : ((t * 0.4 + i / 4) % 1);
        beatLine.at(v, b.position);
        (b.material as THREE.SpriteMaterial).opacity = level[2] * 0.9;
      });
      // 4 the stealer's loot rises up the funnel
      funnelMat.opacity = 0.08 + level[3] * 0.4;
      loot.forEach(l => {
        const v = rm ? l.o : ((t * 0.3 + l.o) % 1);
        const a = l.o * Math.PI * 2 + t;
        l.s.position.set(6 + Math.cos(a) * (1 - v) * 0.9, 0.6 + v * 4.6, 3 + Math.sin(a) * (1 - v) * 0.9);
        (l.s.material as THREE.SpriteMaterial).opacity = level[3] * (1 - v * 0.5);
      });
      // 5 half the wall locks amber, half shatters; the rig spins
      tiles.forEach((tl, i) => {
        const on = THREE.MathUtils.clamp(level[4] * 24 - i * 0.6, 0, 1);
        if (tl.burn) {
          const fall = on * (rm ? 0.5 : ((t * 0.5 + i * 0.13) % 1));
          tl.m.position.set(tl.home.x, tl.home.y - fall * tl.home.y, tl.home.z + fall * 1.5);
          tl.m.rotation.set(fall * 3, fall * 2, 0);
          tl.mat.emissive.copy(Wn).multiplyScalar(on * 0.6);
        } else {
          tl.mat.emissive.copy(S).multiplyScalar(on * 0.55);
        }
      });
      (rig.material as THREE.MeshStandardMaterial).opacity = 0.25 + level[4] * 0.7;
      if (!rm) rig.rotation.y += dt * (0.5 + level[4] * 4);
      (mineLab.material as THREE.SpriteMaterial).opacity = level[4];
      // 6 under the radar: the floor glows, the rootkit shows beneath it
      osMat.opacity = 0.06 + level[5] * 0.2;
      kitMat.opacity = level[5] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      if (!rm) kit.rotation.z += dt * 0.7;
      (ghost.material as THREE.SpriteMaterial).opacity = Math.max(level[5], stations[5]?.status === "open" ? 0.35 : 0) * (rm ? 1 : 0.6 + Math.sin(t * 5) * 0.4);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#06100b]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
