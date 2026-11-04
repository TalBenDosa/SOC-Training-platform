"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Signal to noise": a wide river of grey event particles flowing left to
 * right. Three logic gates arch over it; a Sigma scroll unrolls beside the
 * first gate; tuning baffles drop into the river and thin the grey particles;
 * a judge lens hovers over the remaining stream; and at the end a single red
 * signal survives and rises as a beacon. Stations switch each part on.
 * Decorative only.
 */
function tag(text: string, color: string, w = 200) {
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

export default function NoiseFilterScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x06040c, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xede9fe, 0x06040c, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x3b2a63, 0x120c1f));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x4b3f6b, emissive: 0x0f0b1a, metalness: 0.5, roughness: 0.45 });
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);
    const sources = [-1.6, 0, 1.6].map(z => {
      const r = serverRack(B, 6);
      r.group.position.set(-12.6, 0, z);
      r.group.rotation.y = Math.PI / 2;
      scene.add(r.group);
      return r;
    });

    // the river bed
    const bedMat = new THREE.MeshStandardMaterial({ color: 0x1a1430, emissive: A, emissiveIntensity: 0.04, transparent: true, opacity: 0.6 });
    const bed = new THREE.Mesh(new THREE.BoxGeometry(22, 0.1, 3.4), bedMat);
    bed.position.set(0, 0.05, 0);
    scene.add(bed);

    // particles: most are noise, one is the real signal
    const P = 70;
    const noiseMat = new THREE.MeshStandardMaterial({ color: 0x94a3b8, emissive: 0x334155, emissiveIntensity: 0.3, transparent: true, opacity: 0.8 });
    const parts = Array.from({ length: P }, (_, i) => {
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.11, 8, 6), noiseMat);
      scene.add(m);
      return { m, o: (i * 0.618) % 1, z: ((i * 37) % 30) / 30 * 2.8 - 1.4, y: 0.3 + ((i * 13) % 10) / 10 * 0.5, filterAt: [0.35, 0.6, 0.85][i % 3] };
    });
    const sigMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.9 });
    const sig = new THREE.Mesh(new THREE.SphereGeometry(0.2, 14, 10), sigMat);
    scene.add(sig);

    // ── 1 three logic gates ──
    const gateMats = ["THRESHOLD", "CORRELATION", "ANOMALY"].map((n, i) => {
      const mat = additive(B, 0.05);
      const g = new THREE.Mesh(new THREE.TorusGeometry(2, 0.08, 8, 40, Math.PI), mat);
      g.position.set(-7 + i * 3.4, 0, 0);
      g.rotation.y = Math.PI / 2;
      scene.add(g);
      const l = tag(n, "#bbf7d0", 220); l.position.set(-7 + i * 3.4, 2.5, 0); scene.add(l);
      return mat;
    });

    // ── 2 the Sigma scroll ──
    const yml = terminal(["title: Cron runs from /tmp", "logsource:", "  product: linux", "detection:", "  selection: ...", "  filter: ...", "  condition: selection", "    and not filter", "level: high"], A, 1.9, 1.3);
    yml.group.position.set(-9, 0, -3.2);
    yml.group.rotation.y = 0.4;
    scene.add(yml.group);
    const scrollMat = yml.screenMat;
    const sl = tag("rule.yml", "#ddd6fe", 180); sl.position.set(-9, 2.5, -3.2); scene.add(sl);

    // ── 3 tuning baffles ──
    const baffles = [2, 4.5, 7].map(x => {
      const mat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.2, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.15, 1.2, 3.2), mat);
      m.position.set(x, 3, 0);
      scene.add(m);
      return { m, mat };
    });

    // ── 4 the judge lens ──
    const lensMat = additive(A, 0);
    const lens = new THREE.Mesh(new THREE.TorusGeometry(1, 0.1, 10, 40), lensMat);
    lens.position.set(8.6, 2.2, 0);
    scene.add(lens);
    const stand = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, 1.2, 6), metal());
    stand.position.set(8.6, 0.6, 0);
    scene.add(stand);

    // ── 5 the beacon ──
    const beaconMat = additive(Wn, 0);
    const beacon = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.4, 4, 12, 1, true), beaconMat);
    beacon.position.set(10.5, 2, 0);
    scene.add(beacon);
    const verdict = shield(Wn, "alert", 1.1);
    verdict.group.position.set(10.5, 4.6, 0);
    scene.add(verdict.group);

    const anchors = [new THREE.Vector3(-5, 3.4, 0), new THREE.Vector3(-9, 4.6, -3), new THREE.Vector3(4.5, 4.4, 0), new THREE.Vector3(8.6, 3.8, 0), new THREE.Vector3(10.5, 6, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 24, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 64 : asp < 1.5 ? 30 : 24; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.18;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.55 : 0.4) + 1, Math.cos(yaw) * dist + 2);
      camera.lookAt(1, 1.4, 0);

      // particles flow; tuned baffles drop and filter the noise
      const tuned = level[2];
      parts.forEach(p => {
        const u = rm ? p.o : ((t * 0.08 + p.o) % 1);
        const x = -11 + u * 22;
        const dropped = tuned > 0.5 && u > p.filterAt;
        p.m.position.set(x, dropped ? p.y - (u - p.filterAt) * 4 : p.y, p.z);
        p.m.visible = !(dropped && p.m.position.y < -0.2);
      });
      const su = rm ? 0.8 : ((t * 0.08) % 1);
      sig.position.set(-11 + su * 22, 0.6, 0);
      // 1 gates
      gateMats.forEach((m, i) => { m.opacity = 0.05 + THREE.MathUtils.clamp(level[0] * 3 - i, 0, 1) * 0.85; });
      // 2 scroll
      scrollMat.opacity = 0.35 + level[1] * 0.6;
      // 3 baffles drop into the river
      baffles.forEach(b => { b.mat.opacity = tuned * 0.8; b.m.position.y = 3 - tuned * 2.2; });
      // 4 lens
      lensMat.opacity = level[3] * 0.9;
      if (!rm) lens.rotation.y += dt * level[3];
      // 5 beacon
      beaconMat.opacity = level[4] * (rm ? 0.7 : 0.4 + pulse * 0.4);
      verdict.mat.opacity = 0.25 + level[4] * 0.75;
      verdict.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      if (!rm) verdict.group.rotation.y = Math.sin(t * 0.8) * 0.4;
      sources.forEach(r => r.tick(t, 0.4 + level[0] * 0.6, rm));
      floor.mat.opacity = 0.2 + level[2] * 0.25;
      sigMat.emissiveIntensity = 0.9 + level[4] * 0.6;
      bedMat.emissiveIntensity = 0.04 + level[4] * 0.12;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0d0817]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
