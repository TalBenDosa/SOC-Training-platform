"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The mind lab": an alert beam enters a prism and splits into two hypothesis
 * beams (BENIGN, ATTACK); six question satellites orbit a core (WHO WHAT WHERE
 * WHEN WHY RADIUS); a baseline ribbon runs flat until one spike rises out of
 * it; bias fog drifts over the floor until a sweeping beam clears it; and two
 * pillars receive cubes: solid ones (facts) on one, wireframe ones
 * (assumptions) on the other. Stations switch each part on. Decorative only.
 */
const QUESTIONS = ["WHO", "WHAT", "WHERE", "WHEN", "WHY", "RADIUS"];

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

export default function MindLabScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x07040b, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xf3e8ff, 0x07040b, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x3b0764, 0x1e0a33));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2e2340, emissive: 0x0d0814, metalness: 0.55, roughness: 0.4 });

    // ── 1 the prism: one alert, two stories ──
    const P = new THREE.Vector3(-10, 3, 0);
    const prismMat = new THREE.MeshStandardMaterial({ color: 0xe9d5ff, transparent: true, opacity: 0.25, metalness: 0.2, roughness: 0.05 });
    const prism = new THREE.Mesh(new THREE.ConeGeometry(0.9, 1.6, 3), prismMat);
    prism.position.copy(P);
    scene.add(prism);
    const beam = (from: THREE.Vector3, to: THREE.Vector3, color: THREE.Color) => {
      const len = from.distanceTo(to);
      const mat = additive(color, 0);
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, len, 6), mat);
      m.position.copy(from).lerp(to, 0.5);
      m.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), to.clone().sub(from).normalize());
      scene.add(m);
      return mat;
    };
    const inBeam = beam(new THREE.Vector3(-15, 3, 0), P, new THREE.Color(0xffffff));
    const benign = beam(P, new THREE.Vector3(-6, 4.6, -2.5), B);
    const attack = beam(P, new THREE.Vector3(-6, 1.6, 2.5), Wn);
    const bl = tag("BENIGN", "#99f6e4", 180); bl.position.set(-5.6, 5.2, -2.5); scene.add(bl);
    const al = tag("ATTACK", "#fecdd3", 180); al.position.set(-5.6, 2.2, 2.5); scene.add(al);

    // ── 2 six question satellites ──
    const core = new THREE.Vector3(-1, 3, 0);
    const coreMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.4 });
    const coreMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(0.6, 1), coreMat);
    coreMesh.position.copy(core);
    scene.add(coreMesh);
    const sats = QUESTIONS.map(q => {
      const s = tag(q, "#e9d5ff", 180);
      s.scale.multiplyScalar(1.5);
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return s;
    });

    // ── 3 the baseline ribbon and its spike ──
    const N = 40;
    const ribbonPts = Array.from({ length: N }, (_, i) => new THREE.Vector3(3 + i * 0.25, 1, -3));
    const ribbonGeo = new THREE.BufferGeometry().setFromPoints(ribbonPts);
    const ribbonMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.2 });
    scene.add(new THREE.Line(ribbonGeo, ribbonMat));
    const spikeMat = additive(Wn, 0);
    const spike = new THREE.Mesh(new THREE.ConeGeometry(0.25, 1, 8), spikeMat);
    spike.position.set(3 + 32 * 0.25, 1, -3);
    scene.add(spike);
    const normLab = tag("NORMAL", "#99f6e4", 180); normLab.position.set(5, 1.7, -3); scene.add(normLab);

    // ── 4 bias fog and the clearing sweep ──
    const fog = Array.from({ length: 9 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x9ca3af, transparent: true, opacity: 0, depthWrite: false }));
      s.scale.set(3.4, 1.6, 1);
      s.position.set(2 + (i % 3) * 2.6, 0.9, 1 + Math.floor(i / 3) * 1.6);
      scene.add(s);
      return s;
    });
    const sweepMat = additive(A, 0);
    const sweep = new THREE.Mesh(new THREE.BoxGeometry(0.1, 1.8, 5), sweepMat);
    scene.add(sweep);

    // ── 5 two pillars: facts and assumptions ──
    const pillars = [["FACT", 11.5], ["ASSUMPTION", 14.5]].map(([n, x]) => {
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.7, 0.8, 0.4, 20), metal());
      m.position.set(x as number, 0.2, 0);
      scene.add(m);
      const l = tag(n as string, "#e9d5ff", 260);
      l.position.set(x as number, 0.9, 1.3);
      scene.add(l);
      return x as number;
    });
    const cubes = Array.from({ length: 6 }, (_, i) => {
      const fact = i % 2 === 0;
      const mat = fact
        ? new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.3, transparent: true, opacity: 0 })
        : new THREE.MeshBasicMaterial({ color: 0xe9d5ff, wireframe: true, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.6, 0.6, 0.6), mat);
      scene.add(m);
      return { m, mat, fact, k: Math.floor(i / 2) };
    });

    const anchors = [new THREE.Vector3(-10, 5.4, 0), new THREE.Vector3(-1, 6.2, 0), new THREE.Vector3(7.5, 4.4, -3), new THREE.Vector3(4.6, 3, 3), new THREE.Vector3(13, 4.6, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 72 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(1.5, 2.4, 0);

      // 1 the alert splits into two stories
      inBeam.opacity = 0.2 + level[0] * 0.6;
      benign.opacity = level[0] * 0.8;
      attack.opacity = level[0] * 0.8;
      if (!rm) prism.rotation.y += dt * 0.6;
      // 2 the six questions orbit the core, appearing one by one
      coreMat.emissiveIntensity = level[1] * 0.9;
      sats.forEach((s, i) => {
        const a = (i / 6) * Math.PI * 2 + (rm ? 0 : t * 0.3);
        s.position.set(core.x + Math.cos(a) * 2.2, core.y + Math.sin(a * 2) * 0.4, core.z + Math.sin(a) * 2.2);
        (s.material as THREE.SpriteMaterial).opacity = THREE.MathUtils.clamp(level[1] * 6 - i, 0, 1);
      });
      // 3 the baseline wobbles gently; the spike rises out of it
      const pos = ribbonGeo.attributes.position as THREE.BufferAttribute;
      for (let i = 0; i < N; i++) pos.setY(i, 1 + Math.sin(i * 0.8 + (rm ? 0 : t)) * 0.12 * (0.3 + level[2]));
      pos.needsUpdate = true;
      ribbonMat.opacity = 0.2 + level[2] * 0.7;
      spike.scale.y = 0.1 + level[2] * 3;
      spike.position.y = 1 + spike.scale.y / 2;
      spikeMat.opacity = level[2] * (rm ? 0.9 : 0.6 + pulse * 0.4);
      // 4 bias fog lingers until the station clears; a sweep beam pushes through it
      const sx = rm ? 5 : 1.5 + ((t * 0.25) % 1) * 7;
      sweep.position.set(sx, 0.9, 2.6);
      sweepMat.opacity = Math.max(level[3], stations[3]?.status === "open" ? 0.4 : 0) * 0.7;
      fog.forEach(f => {
        const behind = f.position.x < sx;
        (f.material as THREE.SpriteMaterial).opacity = (stations[3] ? 0.35 : 0) * (1 - level[3]) * (behind && level[3] > 0.05 ? 0.4 : 1);
      });
      // 5 cubes settle on their pillars: facts solid, assumptions wireframe
      cubes.forEach((c, i) => {
        const x = c.fact ? pillars[0] : pillars[1];
        const drop = THREE.MathUtils.clamp(level[4] * 6 - i, 0, 1);
        c.m.position.set(x, 0.7 + c.k * 0.65 + (1 - drop) * 4, 0);
        (c.mat as THREE.Material & { opacity: number }).opacity = drop * 0.95;
        if (!rm && !c.fact) c.m.rotation.y += dt * 0.5;
      });

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
            <span className="block whitespace-nowrap rounded-md border bg-[#120a1c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
