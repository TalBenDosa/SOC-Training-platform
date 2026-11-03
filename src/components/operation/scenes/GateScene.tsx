"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { Lock, Play, Check } from "lucide-react";
import { GREEN, additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, statusColor, type WorldProps } from "./common";

/**
 * "Access sequence": one armoured gate per station on a ring around a
 * holographic globe. The open gate's doorway glows, locked gates show amber
 * trim, cleared gates turn green and the platform arc fills with progress.
 */
export default function GateScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const headRefs = useRef<(HTMLDivElement | null)[]>([]);
  const pillRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;
  const n = props.stations.length;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), W = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05080f, 16, 34);
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0x8aa4d6, 0x05080f, 1.4));
    const keyL = new THREE.DirectionalLight(0xc6d4ff, 1.6); keyL.position.set(4, 9, 12); scene.add(keyL);
    const core = new THREE.PointLight(A, 40, 16); core.position.set(0, 3, 1.5); scene.add(core);
    const amber = new THREE.PointLight(W, 18, 14); amber.position.set(0, 0.6, -5); scene.add(amber);

    // ── Floor and platform ──
    const floor = new THREE.Mesh(new THREE.CircleGeometry(16, 96), new THREE.MeshStandardMaterial({ color: 0x070b14, metalness: 0.85, roughness: 0.32 }));
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);
    const ring = (r: number, t: number, c: THREE.ColorRepresentation, o: number, arc = Math.PI * 2) => {
      const m = new THREE.Mesh(new THREE.TorusGeometry(r, t, 6, 160, arc), additive(c, o));
      m.rotation.x = -Math.PI / 2;
      m.position.y = 0.03;
      scene.add(m);
      return m;
    };
    ring(9.2, 0.03, A, 0.35);
    ring(7.6, 0.02, A, 0.25);
    // amber dashes on the outer ring, like floor guide lights
    for (let i = 0; i < 28; i++) {
      const a = (i / 28) * Math.PI * 2;
      const dash = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.02, 0.08), additive(i % 3 === 0 ? W : A, 0.7));
      dash.position.set(Math.cos(a) * 8.4, 0.04, Math.sin(a) * 8.4);
      dash.rotation.y = -a;
      scene.add(dash);
    }
    const pedestal = new THREE.Group();
    scene.add(pedestal);
    const metal = new THREE.MeshStandardMaterial({ color: 0x141b2b, metalness: 0.75, roughness: 0.35 });
    [[3.2, 0.35, 0.18], [2.5, 0.3, 0.5], [1.8, 0.25, 0.78]].forEach(([r, h, y]) => {
      const c = new THREE.Mesh(new THREE.CylinderGeometry(r, r + 0.15, h, 72), metal);
      c.position.y = y;
      pedestal.add(c);
      const t = new THREE.Mesh(new THREE.TorusGeometry(r, 0.025, 6, 120), additive(A, 0.9));
      t.rotation.x = Math.PI / 2;
      t.position.y = y + h / 2 + 0.01;
      pedestal.add(t);
    });
    for (let i = 0; i < 10; i++) {
      const a = (i / 10) * Math.PI * 2;
      const seg = new THREE.Mesh(new THREE.BoxGeometry(0.6, 0.06, 0.06), additive(W, 0.9));
      seg.position.set(Math.cos(a) * 2.9, 0.37, Math.sin(a) * 2.9);
      seg.rotation.y = -a + Math.PI / 2;
      pedestal.add(seg);
    }
    const progressArc = new THREE.Mesh(new THREE.TorusGeometry(3.35, 0.06, 6, 160, 0.0001), additive(GREEN, 1));
    progressArc.rotation.x = -Math.PI / 2;
    progressArc.position.y = 0.38;
    pedestal.add(progressArc);
    let arcShown = -1;

    // ── Holo globe with the shield and lock ──
    const holo = new THREE.Group();
    holo.position.y = 2.35;
    scene.add(holo);
    holo.add(new THREE.Mesh(new THREE.SphereGeometry(1.35, 48, 32), new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.07, depthWrite: false })));
    const wire = new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.SphereGeometry(1.36, 24, 16)), new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.22 }));
    holo.add(wire);
    const dots: number[] = [];
    for (let lat = -78; lat <= 78; lat += 6) {
      const r = Math.cos((lat * Math.PI) / 180), y = Math.sin((lat * Math.PI) / 180);
      const steps = Math.max(8, Math.round(60 * r));
      for (let k = 0; k < steps; k++) {
        const a = (k / steps) * Math.PI * 2;
        if (Math.sin(a * 3 + lat * 0.1) + Math.cos(a * 2 - lat * 0.08) < 0.1) continue;
        dots.push(Math.cos(a) * r * 1.37, y * 1.37, Math.sin(a) * r * 1.37);
      }
    }
    const dg = new THREE.BufferGeometry();
    dg.setAttribute("position", new THREE.Float32BufferAttribute(dots, 3));
    const globeDots = new THREE.Points(dg, new THREE.PointsMaterial({ color: A, size: 0.04, transparent: true, opacity: 0.85, depthWrite: false }));
    holo.add(globeDots);
    const orbits = [0.35, -0.5].map((tilt, i) => {
      const o = new THREE.Mesh(new THREE.TorusGeometry(1.75 + i * 0.25, 0.012, 6, 160), additive(A, 0.6));
      o.rotation.set(Math.PI / 2 + tilt, 0, 0);
      holo.add(o);
      return o;
    });
    const shieldShape = new THREE.Shape();
    shieldShape.moveTo(0, 0.62); shieldShape.quadraticCurveTo(0.3, 0.5, 0.55, 0.58); shieldShape.lineTo(0.55, 0.1);
    shieldShape.quadraticCurveTo(0.52, -0.42, 0, -0.68); shieldShape.quadraticCurveTo(-0.52, -0.42, -0.55, 0.1);
    shieldShape.lineTo(-0.55, 0.58); shieldShape.quadraticCurveTo(-0.3, 0.5, 0, 0.62);
    const sg = new THREE.ExtrudeGeometry(shieldShape, { depth: 0.08, bevelEnabled: true, bevelSize: 0.03, bevelThickness: 0.03, curveSegments: 24 });
    const shield = new THREE.Mesh(sg, new THREE.MeshPhysicalMaterial({ color: 0x0b4f66, emissive: A, emissiveIntensity: 0.5, transparent: true, opacity: 0.8, metalness: 0.3, roughness: 0.2 }));
    shield.position.z = 1.15;
    holo.add(shield);
    shield.add(new THREE.LineSegments(new THREE.EdgesGeometry(sg, 30), new THREE.LineBasicMaterial({ color: A })));
    const lock = new THREE.Group();
    lock.position.set(0, -0.05, 0.16);
    lock.add(new THREE.Mesh(new THREE.BoxGeometry(0.34, 0.26, 0.05), new THREE.MeshBasicMaterial({ color: A })));
    const shackle = new THREE.Mesh(new THREE.TorusGeometry(0.11, 0.03, 8, 24, Math.PI), new THREE.MeshBasicMaterial({ color: A }));
    shackle.position.y = 0.13;
    lock.add(shackle);
    shield.add(lock);
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false }));
    halo.scale.set(6, 6, 1);
    holo.add(halo);
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(1.0, 1.7, 2.0, 48, 1, true),
      new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.06, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false }));
    beam.position.y = 1.4;
    scene.add(beam);

    // ── Gates ──
    const R = 7.6;
    const span = Math.min(150, 30 * Math.max(n - 1, 1)) * (Math.PI / 180);
    const body = new THREE.MeshStandardMaterial({ color: 0x2a3348, metalness: 0.65, roughness: 0.4 });
    const gates = Array.from({ length: n }, (_, i) => {
      const th = n === 1 ? 0 : -span / 2 + (span * i) / (n - 1);
      const g = new THREE.Group();
      g.position.set(Math.sin(th) * R, 0, -Math.cos(th) * R + 1.2);
      g.lookAt(0, 0, 1.2);
      g.scale.setScalar(0.82);
      scene.add(g);
      const box = (w: number, h: number, d: number, x: number, y: number, z = 0, mat: THREE.Material = body) => {
        const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat);
        m.position.set(x, y, z);
        g.add(m);
        return m;
      };
      box(3.0, 0.3, 1.9, 0, 0.15);
      [-1, 1].forEach(sx => {
        box(0.6, 3.2, 1.2, sx * 1.15, 1.9);
        const chamfer = box(0.4, 1.0, 1.0, sx * 1.42, 0.8);
        chamfer.rotation.z = sx * 0.25;
      });
      const head = box(3.3, 0.75, 1.3, 0, 3.75);
      head.rotation.x = -0.12;
      box(2.6, 0.25, 1.0, 0, 4.25);
      const trimMat = additive(W, 1);
      const trims = [
        box(0.07, 2.7, 0.07, -0.82, 1.75, 0.62, trimMat),
        box(0.07, 2.7, 0.07, 0.82, 1.75, 0.62, trimMat),
        box(1.7, 0.07, 0.07, 0, 3.3, 0.62, trimMat),
      ];
      const doorMat = new THREE.MeshBasicMaterial({ color: 0x0a1020, transparent: true, opacity: 0.95, side: THREE.DoubleSide });
      const door = new THREE.Mesh(new THREE.PlaneGeometry(1.55, 2.95), doorMat);
      door.position.set(0, 1.78, 0.3);
      g.add(door);
      const grid = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(1.5, 2.9, 6, 10)), new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0 }));
      grid.position.set(0, 1.78, 0.32);
      g.add(grid);
      const steps = [0, 1, 2].map(k => box(1.8 - k * 0.2, 0.06, 0.35, 0, 0.33 + k * 0.0, 1.05 + k * 0.35, additive(A, 0)));
      const anchorHead = new THREE.Vector3(), anchorDoor = new THREE.Vector3();
      return { g, trims, door, doorMat, grid, steps, anchorHead, anchorDoor, lit: 0 };
    });

    const P = 120, partPos = new Float32Array(P * 3), speed = new Float32Array(P);
    let seed = 7;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    for (let i = 0; i < P; i++) {
      const a = rnd() * Math.PI * 2, r = 0.6 + rnd() * 2.2;
      partPos.set([Math.cos(a) * r, rnd() * 4.5, Math.sin(a) * r], i * 3);
      speed[i] = 0.2 + rnd() * 0.4;
    }
    const pg = new THREE.BufferGeometry();
    pg.setAttribute("position", new THREE.BufferAttribute(partPos, 3));
    scene.add(new THREE.Points(pg, new THREE.PointsMaterial({ map: glow, color: A, size: 0.1, transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending, depthWrite: false })));

    let W_ = 1, H_ = 1;
    const fit = (w: number, h: number) => {
      W_ = w; H_ = h;
      const aspect = w / h;
      const dist = aspect < 1.2 ? 22 : aspect < 1.6 ? 18.5 : 16.5;
      camera.position.set(0, 6.4, dist);
      camera.lookAt(0, 1.2, -1.5);
    };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const cleared = stations.filter(s => s.status === "cleared").length;
      const pr = stations.length ? cleared / stations.length : 0;
      if (Math.abs(pr - arcShown) > 1e-3) {
        arcShown = pr;
        progressArc.geometry.dispose();
        progressArc.geometry = new THREE.TorusGeometry(3.35, 0.06, 6, 160, Math.max(0.0001, pr * Math.PI * 2));
      }
      if (!rm) {
        globeDots.rotation.y += dt * 0.12;
        wire.rotation.y += dt * 0.12;
        orbits[0].rotation.z += dt * 0.3;
        orbits[1].rotation.z -= dt * 0.22;
        holo.position.y = 2.35 + Math.sin(t * 1.2) * 0.06;
        shield.rotation.y = Math.sin(t * 0.6) * 0.25;
        for (let i = 0; i < P; i++) { let y = partPos[i * 3 + 1] + speed[i] * dt; if (y > 4.6) y = 0.3; partPos[i * 3 + 1] = y; }
        pg.getAttribute("position").needsUpdate = true;
        halo.material.opacity = 0.42 + Math.sin(t * 2) * 0.08;
      }
      gates.forEach((gt, i) => {
        const s = stations[i];
        if (!s) return;
        const c = statusColor(s, A, W);
        const sel = i === selected;
        const pulse = rm ? 1 : 0.75 + Math.sin(t * 3) * 0.25;
        gt.trims.forEach(m => { (m.material as THREE.MeshBasicMaterial).color.copy(c); (m.material as THREE.MeshBasicMaterial).opacity = s.status === "open" ? pulse : 0.9; });
        if (s.status === "open") { gt.doorMat.color.copy(A).multiplyScalar(0.55 * pulse); gt.doorMat.opacity = 0.85; (gt.grid.material as THREE.LineBasicMaterial).opacity = 0.5; }
        else if (s.status === "cleared") { gt.doorMat.color.copy(GREEN).multiplyScalar(0.18); gt.doorMat.opacity = 0.7; (gt.grid.material as THREE.LineBasicMaterial).opacity = 0.15; }
        else { gt.doorMat.color.setHex(0x0a1020); gt.doorMat.opacity = 0.95; (gt.grid.material as THREE.LineBasicMaterial).opacity = 0; }
        gt.steps.forEach(m => ((m.material as THREE.MeshBasicMaterial).opacity = s.status === "open" ? 0.8 * pulse : 0));
        const target = sel ? 0.9 : 0.82;
        gt.g.scale.lerp(new THREE.Vector3(target, target, target), rm ? 1 : 1 - Math.pow(0.002, dt));
        gt.g.localToWorld(gt.anchorHead.set(0, 4.55, 0.6));
        gt.g.localToWorld(gt.anchorDoor.set(0, 1.55, 0.6));
        placeLabel(headRefs.current[i], gt.anchorHead, camera, W_, H_);
        placeLabel(pillRefs.current[i], gt.anchorDoor, camera, W_, H_);
      });
    }, fit);
    // Built once per station count and palette; status flows through `live`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n, props.primary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <React.Fragment key={s.id}>
            <div ref={el => { headRefs.current[i] = el; }} className="absolute left-0 top-0 will-change-transform">
              <span className="block skew-x-[-8deg] whitespace-nowrap rounded-md border border-white/15 bg-[#0b1222]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide text-white shadow-lg sm:px-3 sm:text-[15px]"
                style={i === props.selected ? { borderColor: props.primary, boxShadow: `0 0 18px -4px ${props.primary}` } : undefined}>
                {pad2(i + 1)} <span style={{ color: s.status === "locked" ? "#94a3b8" : props.primary }}>{"//"}</span> {shortLabel(s.label)}
              </span>
            </div>
            <div ref={el => { pillRefs.current[i] = el; }} className="absolute left-0 top-0 will-change-transform">
              {s.status === "locked" ? (
                <span className="flex flex-col items-center gap-1 text-[10px] font-extrabold uppercase tracking-wider sm:text-xs" style={{ color: props.warn }}>
                  <Lock className="h-5 w-5 sm:h-7 sm:w-7" /> Locked
                </span>
              ) : s.status === "open" ? (
                <span className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-black uppercase text-[#04121a] sm:text-xs" style={{ background: props.primary }}>
                  <Play className="h-3 w-3 fill-current" /> Active
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-md bg-emerald-400/90 px-2 py-0.5 text-[10px] font-black uppercase text-[#04121a] sm:text-xs">
                  <Check className="h-3 w-3" /> Cleared
                </span>
              )}
            </div>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
