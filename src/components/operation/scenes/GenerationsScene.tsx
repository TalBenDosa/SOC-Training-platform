"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, holoPanel, labelSprite, packet, padlock, serverRack } from "./cyberProps";

/**
 * "Generations": a corridor of four firewall generations a packet stream
 * flows through: a bare packet-filter grate, a stateful rack with its state
 * table, an NGFW rack naming the apps it sees, and a TLS padlock that opens
 * as traffic is decrypted. Zone rings sit on the far side and a beacon
 * pulses at the end. Stations switch each part on. Decorative only.
 */
export default function GenerationsScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0603, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xffedd5, 0x0a0603, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a260a, 0x150a04));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    const X = [-6, -2, 2, 6];
    const genLabel = (t: string, x: number) => { const l = labelSprite(t, "#fed7aa", 220); l.position.set(x, 0.35, 2.6); scene.add(l); return l.material as THREE.SpriteMaterial; };

    // ── 1 Gen 1: a bare grate of bars ──
    const grateMat = additive(A, 0.1);
    for (let i = 0; i < 9; i++) {
      const bar = new THREE.Mesh(new THREE.BoxGeometry(0.06, 3.4, 0.06), grateMat);
      bar.position.set(X[0], 1.7, -2 + i * 0.5);
      scene.add(bar);
    }
    const g1 = genLabel("GEN 1 · ACL", X[0]);

    // ── 2 Gen 2: a stateful rack and its state table ──
    const rack2 = serverRack(A, 5, "STATEFUL");
    rack2.group.position.set(X[1], 0, -1.2);
    scene.add(rack2.group);
    const table = holoPanel("conntrack", ["ESTABLISHED 10.30.4.12", "ESTABLISHED 10.30.4.19", "TIME_WAIT  10.30.4.12", "SYN_SENT   10.30.4.77"], B, 2.6, 1.5);
    table.mesh.position.set(X[1], 3.9, -1.2);
    scene.add(table.mesh);
    const g2 = genLabel("GEN 2 · STATE", X[1]);

    // ── 3 Gen 3: an NGFW rack naming apps ──
    const rack3 = serverRack(A, 6, "NGFW");
    rack3.group.position.set(X[2], 0, -1.2);
    scene.add(rack3.group);
    const apps = ["web-browsing", "bittorrent", "ms-teams", "ssl"].map((n, i) => {
      const l = labelSprite(n, i === 1 ? "#fda4af" : "#a5f3fc", 200);
      l.position.set(X[2] + (i % 2 ? 1.3 : -1.3), 3.3 + Math.floor(i / 2) * 0.6, -0.6);
      scene.add(l);
      return l.material as THREE.SpriteMaterial;
    });
    const g3 = genLabel("GEN 3 · NGFW", X[2]);

    // ── 4 TLS: a padlock that opens, and the zone rings beyond ──
    const lock = padlock(B, 1.1);
    lock.group.position.set(X[3], 1.9, -1);
    scene.add(lock.group);
    const g4 = genLabel("TLS INSPECT", X[3]);
    const zones = [["DMZ", 1.1], ["INTERNAL", 1.9], ["RESTRICTED", 2.7]].map(([n, r], i) => {
      const mat = additive(i === 2 ? Wn : B, 0.06);
      const ring = new THREE.Mesh(new THREE.RingGeometry((r as number) - 0.06, r as number, 48), mat);
      ring.rotation.x = -Math.PI / 2;
      ring.position.set(10.5, 0.05, 0);
      scene.add(ring);
      const l = labelSprite(n as string, "#e0f2fe", 200);
      l.position.set(10.5, 0.4, (r as number) + 0.2);
      scene.add(l);
      return { mat, lm: l.material as THREE.SpriteMaterial };
    });

    // packets flow down the corridor; one red one is caught at a different wall each pass
    const flow = Array.from({ length: 8 }, (_, i) => { const p = packet(B); scene.add(p.mesh); return { ...p, o: i / 8, z: -1.6 + (i % 4) * 0.8 }; });
    const bad = packet(Wn);
    scene.add(bad.mesh);

    // ── 5 the beacon at the end ──
    const beaconMat = additive(Wn, 0.05);
    const beacon = new THREE.Mesh(new THREE.SphereGeometry(0.45, 20, 14), beaconMat);
    beacon.position.set(10.5, 2.4, -3.6);
    scene.add(beacon);
    const waveMat = additive(Wn, 0.05);
    const wave = new THREE.Mesh(new THREE.TorusGeometry(0.6, 0.04, 8, 40), waveMat);
    wave.position.copy(beacon.position);
    scene.add(wave);

    const anchors = [new THREE.Vector3(X[0], 4.2, 0), new THREE.Vector3(X[1], 5.4, -1.2), new THREE.Vector3(X[2], 5, -1.2), new THREE.Vector3(10.5, 1.6, 2.6), new THREE.Vector3(10.5, 3.6, -3.6)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 25, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 60 : asp < 1.5 ? 30 : 25; };

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
      camera.position.set(2 + Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(2, 2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 the grate
      grateMat.opacity = 0.1 + level[0] * 0.75;
      g1.opacity = 0.4 + level[0] * 0.6;
      // 2 the state table
      rack2.tick(t, 0.4 + level[1] * 0.6, rm);
      table.mat.opacity = 0.12 + level[1] * 0.8;
      g2.opacity = 0.4 + level[1] * 0.6;
      // 3 the NGFW names apps
      rack3.tick(t, 0.4 + level[2] * 0.6, rm);
      apps.forEach(m => { m.opacity = 0.15 + level[2] * 0.85; });
      g3.opacity = 0.4 + level[2] * 0.6;
      // 4 the padlock opens, zones light
      lock.mat.opacity = 0.3 + level[3] * 0.7;
      lock.setOpen(level[3]);
      g4.opacity = 0.4 + level[3] * 0.6;
      zones.forEach(z => { z.mat.opacity = 0.06 + level[3] * 0.6; z.lm.opacity = 0.3 + level[3] * 0.7; });
      // the flow, and the red packet stopped at a wall that rotates each pass
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      flow.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.16 + p.o) % 1);
        p.mesh.position.set(-9 + u * 19, 0.7, p.z);
        p.mat.opacity = go * 0.9;
      });
      const pass = rm ? 1 : Math.floor(t * 0.2) % 3;
      const stopX = X[pass] - 0.4;
      const bu = rm ? 0.5 : ((t * 0.2) % 1);
      bad.mesh.position.set(Math.min(-9 + bu * 19, stopX), 0.9, 0.4);
      bad.mat.opacity = Math.max(level[1], level[2]) * 0.95;
      // 5 the beacon pulses
      beaconMat.opacity = 0.05 + level[4] * 0.8;
      const wu = rm ? 0.5 : ((t * 0.7) % 1);
      wave.scale.setScalar(1 + wu * 3);
      waveMat.opacity = level[4] * 0.7 * (1 - wu);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#150a04]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
