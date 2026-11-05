"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, labelSprite, laptop, packet, serverRack, shield } from "./cyberProps";

/**
 * "Lookup": a tall resolver rack in the middle of a ring of library PCs.
 * Query packets fly in from the PCs and answers fly back; three glowing name
 * cards hang above the resolver, one of them a lookalike; four trick cards
 * orbit; a metrics gauge sweeps between normal and alarm; one PC bursts a
 * storm of lookups; and a sinkhole shield swallows the bad name.
 * Stations switch each part on. Decorative only.
 */
export default function LookupScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x07040d, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xede9fe, 0x07040d, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x2e1a52, 0x0e0818));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the resolver and its ring of library PCs ──
    const resolver = serverRack(A, 8, "PL-DNS-01");
    scene.add(resolver.group);
    const rl = labelSprite("RESOLVER · named", "#ddd6fe", 260);
    rl.position.set(0, resolver.height + 0.9, 0);
    scene.add(rl);
    const PCS = 7;
    const pcs = Array.from({ length: PCS }, (_, i) => {
      const a = (i / PCS) * Math.PI * 2 + 0.3;
      const pc = laptop(B);
      pc.group.position.set(Math.cos(a) * 6.2, 0, Math.sin(a) * 6.2);
      pc.group.lookAt(0, 0, 0);
      pc.group.rotateY(Math.PI);
      scene.add(pc.group);
      const q = packet(B), r = packet(A);
      scene.add(q.mesh, r.mesh);
      return { a, pc, q, r, o: i / PCS };
    });

    // ── 1b name cards over the resolver, one a lookalike ──
    const names = [["pemberton-libraries.example", "#ddd6fe"], ["pemberton-llbraries.example", "#fda4af"], ["update.vendor.example", "#ddd6fe"]] as const;
    const cards = names.map(([n, c], i) => {
      const sp = labelSprite(n, c, 420);
      sp.position.set((i - 1) * 3.4, resolver.height + 2.2 + (i === 1 ? 0.5 : 0), 0.4);
      scene.add(sp);
      return sp.material as THREE.SpriteMaterial;
    });

    // ── 2 four trick cards orbiting ──
    const tricks = ["DGA", "TUNNEL", "FAST FLUX", "TYPOSQUAT"].map(n => {
      const d = docFile(n, B);
      d.group.scale.setScalar(0.8);
      scene.add(d.group);
      return d;
    });

    // ── 3 the metrics gauge ──
    const gaugeMat = additive(A, 0.08);
    const gauge = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.08, 8, 48, Math.PI), gaugeMat);
    gauge.position.set(-7.5, 3.2, -3);
    gauge.rotation.y = 0.6;
    scene.add(gauge);
    const needleMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.3 });
    const needle = new THREE.Mesh(new THREE.BoxGeometry(0.06, 1.05, 0.06), needleMat);
    needle.geometry.translate(0, 0.52, 0);
    needle.position.copy(gauge.position);
    needle.rotation.y = 0.6;
    scene.add(needle);
    const gl = labelSprite("NORMAL · · · ALARM", "#ddd6fe", 260);
    gl.position.set(-7.5, 4.8, -3);
    scene.add(gl);

    // ── 4 one PC bursts a storm of lookups ──
    const stormPc = pcs[2];
    const storm = Array.from({ length: 10 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 10 }; });

    // ── 5 the sinkhole shield ──
    const sink = shield(Wn, "alert", 1.3);
    sink.group.position.set(7.4, 2.2, -2.6);
    sink.group.rotation.y = -0.6;
    scene.add(sink.group);
    const holeMat = additive(Wn, 0.05);
    const hole = new THREE.Mesh(new THREE.RingGeometry(0.4, 1.4, 40), holeMat);
    hole.rotation.x = -Math.PI / 2;
    hole.position.set(7.4, 0.05, -2.6);
    scene.add(hole);

    const anchors = [new THREE.Vector3(0, resolver.height + 3.6, 0), new THREE.Vector3(0, 6.6, 4), new THREE.Vector3(-7.5, 5.6, -3),
      new THREE.Vector3(stormPc.pc.group.position.x, 2.4, stormPc.pc.group.position.z), new THREE.Vector3(7.4, 4.2, -2.6)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 24, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 58 : asp < 1.5 ? 29 : 24; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 2.4, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 queries in, answers out
      resolver.tick(t, 0.4 + level[0] * 0.6, rm);
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      pcs.forEach(p => {
        (p.pc.screenMat as THREE.MeshBasicMaterial).opacity = 0.4 + level[0] * 0.6;
        const u = rm ? 0.5 : ((t * 0.3 + p.o) % 1);
        const x = Math.cos(p.a) * 6.2, z = Math.sin(p.a) * 6.2;
        const inU = Math.min(1, u * 2), outU = Math.max(0, u * 2 - 1);
        p.q.mesh.position.set(x * (1 - inU), 0.9 + Math.sin(inU * Math.PI) * 1.2, z * (1 - inU));
        p.q.mat.opacity = u < 0.5 ? flow * 0.9 : 0;
        p.r.mesh.position.set(x * outU, 0.9 + Math.sin(outU * Math.PI) * 1.2, z * outU);
        p.r.mat.opacity = u >= 0.5 ? flow * 0.9 : 0;
      });
      cards.forEach((c, i) => { c.opacity = 0.15 + level[0] * (i === 1 ? 0.5 + pulse * 0.4 : 0.6); });
      // 2 trick cards orbit
      tricks.forEach((d, i) => {
        const a = (rm ? 0 : t * 0.25) + (i / 4) * Math.PI * 2;
        d.group.position.set(Math.cos(a) * 3.2, 4.6 + Math.sin(a * 2) * 0.3, 4 + Math.sin(a) * 1.2);
        d.group.rotation.y = -a;
        d.mat.opacity = 0.2 + level[1] * 0.8;
      });
      // 3 gauge needle sweeps
      gaugeMat.opacity = 0.08 + level[2] * 0.8;
      needleMat.opacity = 0.3 + level[2] * 0.6;
      needle.rotation.z = rm ? 0 : Math.sin(t * 0.8) * 1.2;
      // 4 the storm from one PC
      storm.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.9 + p.o) % 1);
        const sx = stormPc.pc.group.position.x, sz = stormPc.pc.group.position.z;
        p.mesh.position.set(sx * (1 - u) + Math.sin(p.o * 40) * 0.6 * u, 1 + u * 2.4, sz * (1 - u) + Math.cos(p.o * 40) * 0.6 * u);
        p.mat.opacity = level[3] * 0.95 * (1 - u);
      });
      // 5 the sinkhole
      sink.mat.opacity = 0.25 + level[4] * 0.75;
      sink.mat.emissiveIntensity = 0.1 + Math.max(level[3], level[4]) * 0.6;
      holeMat.opacity = 0.05 + level[4] * 0.5;
      hole.rotation.z = rm ? 0 : t * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0e0818]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
