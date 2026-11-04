"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The chain": seven interlocked links arc across the floor, one per kill
 * chain stage, each with a short tag. An attack orb rolls link to link,
 * lighting each one it passes; shield discs rise beside every link; then the
 * C2 link shatters and the orb stops short of the last one. Above it all, a
 * slowly turning Diamond Model with four named corners. Stations switch each
 * part on. Decorative only.
 */
const STAGES = ["RECON", "WEAPON", "DELIVER", "EXPLOIT", "INSTALL", "C2", "ACTIONS"];

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

export default function ChainLinksScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03080b, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xcffafe, 0x03080b, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x164e63, 0x0b2530));

    // ── the seven links along an arc ──
    const path = new THREE.CatmullRomCurve3([new THREE.Vector3(-12, 1.6, 2), new THREE.Vector3(-6, 2.4, -1), new THREE.Vector3(0, 2.8, -2), new THREE.Vector3(6, 2.4, -1), new THREE.Vector3(12, 1.6, 2)]);
    const links = STAGES.map((name, i) => {
      const u = i / 6;
      const p = path.getPointAt(u);
      const tan = path.getTangentAt(u);
      const mat = new THREE.MeshStandardMaterial({ color: 0x1e3a46, emissive: A, emissiveIntensity: 0, metalness: 0.7, roughness: 0.3, transparent: true, opacity: 1 });
      const m = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.18, 12, 6), mat);
      m.position.copy(p);
      // Face the camera, each link turned a little the other way from its neighbour.
      m.rotation.set(0, Math.atan2(tan.x, tan.z) - Math.PI / 2 + (i % 2 ? 0.7 : -0.7), 0);
      scene.add(m);
      const l = tag(name, i === 5 ? "#fecdd3" : "#cffafe", 220);
      l.position.copy(p).add(new THREE.Vector3(0, 1.5, 0));
      scene.add(l);
      const shieldMat = additive(B, 0);
      const shield = new THREE.Mesh(new THREE.CircleGeometry(0.6, 6), shieldMat);
      shield.position.copy(p).add(new THREE.Vector3(0, -1.2, 1.2));
      scene.add(shield);
      return { m, mat, home: p.clone(), shield, shieldMat, label: l };
    });
    const shards = Array.from({ length: 8 }, (_, i) => {
      const s = new THREE.Mesh(new THREE.TetrahedronGeometry(0.18), new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.6, transparent: true, opacity: 0 }));
      scene.add(s);
      return { s, a: (i / 8) * Math.PI * 2 };
    });

    // ── the attack orb ──
    const orbMat = new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const orb = new THREE.Sprite(orbMat);
    orb.scale.set(1.4, 1.4, 1);
    scene.add(orb);

    // ── the Diamond Model ──
    const diamond = new THREE.Group();
    diamond.position.set(0, 6.4, -6);
    scene.add(diamond);
    const dMat = new THREE.MeshBasicMaterial({ color: B, wireframe: true, transparent: true, opacity: 0.05 });
    diamond.add(new THREE.Mesh(new THREE.OctahedronGeometry(1.6), dMat));
    const corners = [["ADVERSARY", [0, 2.3, 0]], ["VICTIM", [0, -2.3, 0]], ["INFRA", [2.6, 0, 0]], ["CAPABILITY", [-2.9, 0, 0]]].map(([n, p]) => {
      const s = tag(n as string, "#ddd6fe", 260);
      s.position.set(...(p as [number, number, number]));
      (s.material as THREE.SpriteMaterial).opacity = 0;
      diamond.add(s);
      return s.material as THREE.SpriteMaterial;
    });

    const anchors = [new THREE.Vector3(-12, 4.4, 2), new THREE.Vector3(-3, 5.4, -1.6), new THREE.Vector3(6, 5.2, -1), new THREE.Vector3(3.6, 8.4, -6)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 33 : 28; };

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.4) + 2, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 3.2, 0);

      const broken = level[2] > 0.5;
      // 1 links appear; 2 the orb lights each link it reaches; 3 C2 shatters, the orb stops
      const reach = broken ? 5 / 6 : 1;
      const u = rm ? reach * 0.95 : ((t * 0.12) % 1) * reach;
      path.getPointAt(Math.min(u, 0.999), orb.position);
      orbMat.opacity = Math.max(level[1], stations[1]?.status === "open" ? 0.5 : 0);
      links.forEach((l, i) => {
        const show = THREE.MathUtils.clamp(level[0] * 7 - i, 0, 1);
        const passed = level[1] > 0.05 && u * 6 >= i - 0.2 ? 1 : 0;
        const isC2 = i === 5;
        const gone = isC2 && broken;
        l.mat.opacity = gone ? 0 : 0.2 + show * 0.8;
        l.mat.emissive.copy(isC2 && level[2] > 0.05 ? Wn : A);
        l.mat.emissiveIntensity = show * (0.15 + passed * level[1] * 0.8);
        (l.label.material as THREE.SpriteMaterial).opacity = 0.2 + show * 0.8;
        
        l.shieldMat.opacity = level[2] * 0.55;
        l.shield.position.y = l.home.y - 1.2 + level[2] * 0.4;
      });
      shards.forEach((sh, i) => {
        const r = broken ? 0.5 + ((t * 0.5 + i * 0.12) % 1) * 1.8 : 0;
        const c = links[5].home;
        sh.s.position.set(c.x + Math.cos(sh.a) * r, c.y + Math.sin(sh.a) * r * 0.7 - (broken ? ((t * 0.5 + i * 0.12) % 1) : 0), c.z);
        (sh.s.material as THREE.MeshStandardMaterial).opacity = broken ? 0.9 : 0;
      });
      // 4 the diamond turns and names its corners
      dMat.opacity = 0.05 + level[3] * 0.5;
      if (!rm) diamond.rotation.y += dt * 0.25;
      corners.forEach((m, i) => { m.opacity = THREE.MathUtils.clamp(level[3] * 4 - i, 0, 1); });

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04121a]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
