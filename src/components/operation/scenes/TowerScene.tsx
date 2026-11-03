"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { GREEN, LOCKED, additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, statusColor, type WorldProps } from "./common";

/**
 * "The climb": a tower with one floor per station, from the ground floor to the
 * crown at the top. Cleared floors light their windows green, the open floor
 * pulses, a lift beam rides up to it, and the crown ignites when every floor
 * is cleared. The camera slowly circles the tower.
 */
export default function TowerScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;
  const n = props.stations.length;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), W = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05080f, 18, 42);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 120);
    const glow = glowTexture();
    scene.add(new THREE.HemisphereLight(0x9fb3e6, 0x05080f, 0.8));
    const key = new THREE.DirectionalLight(0xb9c8ff, 1.2); key.position.set(6, 12, 8); scene.add(key);

    // ── City grid floor ──
    const grid = new THREE.GridHelper(80, 64, A, 0x16203a);
    (grid.material as THREE.Material).transparent = true;
    (grid.material as THREE.Material).opacity = 0.35;
    scene.add(grid);
    let seed = 11;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    const cityMat = new THREE.MeshStandardMaterial({ color: 0x0f1626, metalness: 0.4, roughness: 0.7 });
    for (let i = 0; i < 70; i++) {
      const a = rnd() * Math.PI * 2, r = 13 + rnd() * 24, h = 0.5 + rnd() * 3.2;
      const b = new THREE.Mesh(new THREE.BoxGeometry(1 + rnd() * 1.6, h, 1 + rnd() * 1.6), cityMat);
      b.position.set(Math.cos(a) * r, h / 2, Math.sin(a) * r);
      scene.add(b);
      if (rnd() > 0.55) {
        const w = new THREE.Mesh(new THREE.PlaneGeometry(0.5, 0.18), additive(rnd() > 0.5 ? A : B, 0.6));
        w.position.set(b.position.x, h * 0.7, b.position.z);
        w.lookAt(0, h * 0.7, 0);
        w.translateZ(0.9);
        scene.add(w);
      }
    }

    // ── The tower ──
    const tower = new THREE.Group();
    scene.add(tower);
    const FLOOR_H = 1.7;
    const shell = new THREE.MeshStandardMaterial({ color: 0x323d5c, metalness: 0.55, roughness: 0.4 });
    const rim = new THREE.PointLight(B, 60, 40); rim.position.set(-8, 10, -6); scene.add(rim);
    const fill = new THREE.PointLight(A, 40, 30); fill.position.set(7, 4, 9); scene.add(fill);
    const plinth = new THREE.Mesh(new THREE.CylinderGeometry(3.6, 4.0, 0.5, 8), shell);
    plinth.position.y = 0.25;
    tower.add(plinth);
    const floors = Array.from({ length: n }, (_, i) => {
      const r = 2.7 - i * (1.2 / Math.max(n, 1));
      const y0 = 0.5 + i * FLOOR_H;
      const g = new THREE.Group();
      g.position.y = y0;
      tower.add(g);
      const core = new THREE.Mesh(new THREE.CylinderGeometry(r * 0.94, r, FLOOR_H - 0.25, 8), shell);
      core.position.y = (FLOOR_H - 0.25) / 2;
      g.add(core);
      const slab = new THREE.Mesh(new THREE.CylinderGeometry(r + 0.25, r + 0.25, 0.22, 8), shell);
      slab.position.y = FLOOR_H - 0.12;
      g.add(slab);
      // windows: a band of emissive panels on the eight faces
      const winMat = additive(W, 0.7);
      for (let k = 0; k < 8; k++) {
        const a = (k / 8) * Math.PI * 2 + Math.PI / 8;
        for (let row = 0; row < 2; row++) {
          const w = new THREE.Mesh(new THREE.PlaneGeometry(r * 0.55, 0.32), winMat);
          const rr = r * 0.97 * Math.cos(Math.PI / 8) + 0.01;
          w.position.set(Math.sin(a) * rr, 0.42 + row * 0.55, Math.cos(a) * rr);
          w.rotation.y = a;
          g.add(w);
        }
      }
      const band = new THREE.Mesh(new THREE.TorusGeometry(r + 0.27, 0.035, 6, 8), additive(W, 0.9));
      band.rotation.x = Math.PI / 2;
      band.rotation.z = Math.PI / 8;
      band.position.y = FLOOR_H - 0.12;
      g.add(band);
      return { g, r, winMat, bandMat: band.material as THREE.MeshBasicMaterial, anchor: new THREE.Vector3() };
    });
    const topY = 0.5 + n * FLOOR_H;
    // crown: a faceted gem on a spire, the domain's top
    const spire = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.6, 1.4, 8), shell);
    spire.position.y = topY + 0.7;
    tower.add(spire);
    const crownMat = new THREE.MeshPhysicalMaterial({ color: B, emissive: B, emissiveIntensity: 0.2, metalness: 0.2, roughness: 0.1, transparent: true, opacity: 0.9 });
    const crown = new THREE.Mesh(new THREE.OctahedronGeometry(0.75, 0), crownMat);
    crown.position.y = topY + 2.1;
    tower.add(crown);
    crown.add(new THREE.LineSegments(new THREE.EdgesGeometry(crown.geometry), new THREE.LineBasicMaterial({ color: B })));
    const crownGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: B, transparent: true, opacity: 0.2, blending: THREE.AdditiveBlending, depthWrite: false }));
    crownGlow.scale.set(5, 5, 1);
    crown.add(crownGlow);

    // lift beam that rides up to the open floor
    const lift = new THREE.Mesh(new THREE.CylinderGeometry(0.35, 0.35, 1, 24, 1, true),
      new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false }));
    tower.add(lift);
    const liftCar = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false }));
    liftCar.scale.set(1.6, 1.6, 1);
    tower.add(liftCar);
    let liftY = 0.6;

    let W_ = 1, H_ = 1, dist = 22;
    const fit = (w: number, h: number) => {
      W_ = w; H_ = h;
      const aspect = w / h;
      dist = aspect < 1 ? 38 : aspect < 1.5 ? 32 : 27;
    };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const ang = rm ? 0.6 : 0.6 + t * 0.06;
      camera.position.set(Math.sin(ang) * dist, topY * 0.6 + 3, Math.cos(ang) * dist);
      camera.lookAt(0, topY * 0.5 + 2.2, 0);
      const front = stations.findIndex(s => s.status !== "cleared");
      const all = front === -1;
      floors.forEach((f, i) => {
        const s = stations[i];
        if (!s) return;
        const c = statusColor(s, A, W);
        const pulse = rm ? 1 : 0.65 + Math.sin(t * 3) * 0.35;
        f.winMat.color.copy(s.status === "locked" ? LOCKED : c);
        f.winMat.opacity = s.status === "open" ? 0.95 * pulse : s.status === "cleared" ? 0.85 : 0.45;
        f.bandMat.color.copy(i === selected ? A : c);
        f.bandMat.opacity = i === selected ? 1 : 0.7;
        f.g.localToWorld(f.anchor.set(f.r + 0.6, FLOOR_H * 0.6, 0));
        placeLabel(labelRefs.current[i], f.anchor, camera, W_, H_);
      });
      const targetY = all ? topY + 0.5 : 0.5 + Math.max(0, front) * FLOOR_H + FLOOR_H / 2;
      liftY += (targetY - liftY) * (rm ? 1 : 1 - Math.pow(0.15, dt));
      lift.scale.y = Math.max(0.01, liftY - 0.5);
      lift.position.y = 0.5 + (liftY - 0.5) / 2;
      liftCar.position.y = liftY;
      liftCar.position.z = floors[0] ? floors[0].r + 0.4 : 3;
      lift.position.z = liftCar.position.z;
      crownMat.emissiveIntensity = all ? 1.6 : 0.2;
      (crownGlow.material as THREE.SpriteMaterial).opacity = all ? 0.85 : 0.2;
      if (all) crownMat.emissive.copy(GREEN).lerp(B, 0.5);
      if (!rm) crown.rotation.y += dt * 0.8;
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n, props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 will-change-transform">
            <span className="ml-16 block whitespace-nowrap rounded-md border bg-[#0b1222]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide sm:text-sm"
              style={{
                borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)",
                color: s.status === "locked" ? "#94a3b8" : "#fff",
                boxShadow: i === props.selected ? `0 0 18px -4px ${props.primary}` : undefined,
              }}>
              F{pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
