"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { GREEN, additive, glowTexture, mountWorld, coreName, pad2, placeLabel, statusColor, type WorldProps } from "./common";

/**
 * "The wire": one relay node per station along a route through space toward
 * the attacker's core. Cleared hops carry packets, the open hop pulses, the
 * path ahead is a faint dotted line, and the core powers down once the last
 * station is cleared.
 */
export default function NetworkScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;
  const n = props.stations.length;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), W = new THREE.Color(props.warn);
    const DANGER = new THREE.Color("#f43f5e"), SPENT = new THREE.Color(0x334155);
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05080f, 0.03);
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200);
    const glow = glowTexture();
    scene.add(new THREE.AmbientLight(0x8090c0, 0.6));

    // ── Star field and a perspective grid below ──
    let seed = 5;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    const stars: number[] = [];
    for (let i = 0; i < 900; i++) stars.push((rnd() - 0.5) * 120, (rnd() - 0.2) * 50, -10 - rnd() * 70);
    const sg = new THREE.BufferGeometry();
    sg.setAttribute("position", new THREE.Float32BufferAttribute(stars, 3));
    scene.add(new THREE.Points(sg, new THREE.PointsMaterial({ color: 0x9fb3e6, size: 0.08, transparent: true, opacity: 0.7, depthWrite: false })));
    const grid = new THREE.GridHelper(120, 80, B, 0x10203a);
    grid.position.y = -4;
    (grid.material as THREE.Material).transparent = true;
    (grid.material as THREE.Material).opacity = 0.3;
    scene.add(grid);

    // ── Route: the analyst's side (front left) to the attacker's core (back right) ──
    const pts = Array.from({ length: n + 1 }, (_, i) => {
      const u = i / n;
      return new THREE.Vector3(-8.5 + u * 18, Math.sin(u * Math.PI * 1.6) * 2.2, 2 - u * 14 + Math.sin(u * 6) * 1.5);
    });
    const curve = new THREE.CatmullRomCurve3(pts);

    const nodes = Array.from({ length: n }, (_, i) => {
      const g = new THREE.Group();
      g.position.copy(pts[i]);
      scene.add(g);
      const coreMat = new THREE.MeshStandardMaterial({ color: 0x0e1628, emissive: W, emissiveIntensity: 0.4, metalness: 0.5, roughness: 0.3, flatShading: true });
      const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.55, 0), coreMat);
      g.add(core);
      const ringMat = additive(W, 0.8);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(0.95, 0.03, 6, 64), ringMat);
      g.add(ring);
      const ring2 = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.015, 6, 64), additive(W, 0.4));
      ring2.rotation.x = Math.PI / 2;
      g.add(ring2);
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: W, transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.scale.set(3.4, 3.4, 1);
      g.add(halo);
      // a pylon down to the grid so nodes read as anchored relays
      const pylon = new THREE.Mesh(new THREE.CylinderGeometry(0.03, 0.03, Math.abs(pts[i].y + 4), 6), additive(B, 0.25));
      pylon.position.y = -(pts[i].y + 4) / 2;
      g.add(pylon);
      return { g, core, coreMat, ring, ring2, ringMat, ring2Mat: ring2.material as THREE.MeshBasicMaterial, halo, anchor: new THREE.Vector3() };
    });

    // ── The core ──
    const cpos = pts[n];
    const c2 = new THREE.Group();
    c2.position.copy(cpos);
    scene.add(c2);
    const c2Mat = new THREE.MeshStandardMaterial({ color: 0x1a0710, emissive: DANGER, emissiveIntensity: 1.1, metalness: 0.4, roughness: 0.3, flatShading: true });
    const c2Core = new THREE.Mesh(new THREE.DodecahedronGeometry(1.5, 0), c2Mat);
    c2.add(c2Core);
    const spikes = new THREE.Group();
    c2.add(spikes);
    for (let k = 0; k < 14; k++) {
      const s = new THREE.Mesh(new THREE.ConeGeometry(0.12, 1.4, 6), new THREE.MeshBasicMaterial({ color: DANGER }));
      const dir = new THREE.Vector3(rnd() - 0.5, rnd() - 0.5, rnd() - 0.5).normalize();
      s.position.copy(dir.clone().multiplyScalar(1.9));
      s.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dir);
      spikes.add(s);
    }
    const c2Glow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: DANGER, transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending, depthWrite: false }));
    c2Glow.scale.set(9, 9, 1);
    c2.add(c2Glow);

    // ── Beams: one tube per hop, plus packets on the cleared ones ──
    const hops = Array.from({ length: n }, (_, i) => {
      const sub = new THREE.CatmullRomCurve3(Array.from({ length: 12 }, (_, k) => curve.getPoint((i + k / 11) / n)));
      const mat = additive(W, 0.15);
      const tube = new THREE.Mesh(new THREE.TubeGeometry(sub, 40, 0.05, 6, false), mat);
      scene.add(tube);
      const packets = [0, 1, 2].map(k => {
        const p = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: GREEN, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
        p.scale.set(0.6, 0.6, 1);
        scene.add(p);
        return { p, off: k / 3 };
      });
      return { sub, mat, packets };
    });

    let W_ = 1, H_ = 1;
    const fit = (w: number, h: number) => {
      W_ = w; H_ = h;
      const aspect = w / h;
      camera.fov = aspect < 1 ? 70 : aspect < 1.5 ? 52 : 42;
      camera.updateProjectionMatrix();
    };
    const tmp = new THREE.Vector3();

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const sway = rm ? 0 : Math.sin(t * 0.15) * 2;
      camera.position.set(sway, 6.5, 21);
      camera.lookAt(0.5, -0.2, -5);
      const all = stations.every(s => s.status === "cleared");
      nodes.forEach((nd, i) => {
        const s = stations[i];
        if (!s) return;
        const c = statusColor(s, A, W);
        const pulse = rm ? 1 : 0.7 + Math.sin(t * 3 + i) * 0.3;
        nd.coreMat.emissive.copy(c);
        nd.coreMat.emissiveIntensity = s.status === "open" ? 1.4 * pulse : s.status === "cleared" ? 0.9 : 0.25;
        nd.ringMat.color.copy(c);
        nd.ring2Mat.color.copy(c);
        (nd.halo.material as THREE.SpriteMaterial).color.copy(c);
        (nd.halo.material as THREE.SpriteMaterial).opacity = s.status === "locked" ? 0.12 : 0.45 * pulse;
        const sc = i === selected ? 1.25 : 1;
        nd.g.scale.lerp(tmp.set(sc, sc, sc), rm ? 1 : 1 - Math.pow(0.002, dt));
        if (!rm) { nd.core.rotation.y += dt * 0.6; nd.ring.rotation.z += dt * 0.8; nd.ring2.rotation.z -= dt * 0.4; }
        nd.g.localToWorld(nd.anchor.set(0, 1.6, 0));
        placeLabel(labelRefs.current[i], nd.anchor, camera, W_, H_);

        // hop i runs from node i toward node i+1 (the last one into the core)
        const h = hops[i];
        const live_ = s.status === "cleared";
        h.mat.color.copy(live_ ? GREEN : s.status === "open" ? A : W);
        h.mat.opacity = live_ ? 0.85 : s.status === "open" ? 0.45 : 0.12;
        h.packets.forEach(pk => {
          (pk.p.material as THREE.SpriteMaterial).opacity = live_ && !rm ? 0.95 : 0;
          if (live_) h.sub.getPointAt(((t * 0.35 + pk.off) % 1), pk.p.position);
        });
      });
      c2Mat.emissive.copy(all ? SPENT : DANGER);
      c2Mat.emissiveIntensity = all ? 0.2 : 1 + (rm ? 0 : Math.sin(t * 2.4) * 0.3);
      (c2Glow.material as THREE.SpriteMaterial).opacity = all ? 0.08 : 0.65;
      if (!rm && !all) { c2Core.rotation.y += dt * 0.25; spikes.rotation.x += dt * 0.15; }
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n, props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 will-change-transform">
            <span className="block whitespace-nowrap rounded-full border bg-[#08101c]/90 px-2.5 py-1 font-mono text-[10px] font-bold uppercase tracking-wider sm:text-xs"
              style={{
                borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)",
                color: s.status === "locked" ? "#94a3b8" : "#fff",
              }}>
              HOP {pad2(i + 1)} · {coreName(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
