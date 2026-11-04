"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Clear sky": a translucent workspace sphere floating above a row of table
 * pillars (SigninLogs, SecurityEvent, OfficeActivity, CommonSecurityLog,
 * Syslog). Connector streams rise from the ground into the sphere; a KQL
 * beam drops from the sphere onto one pillar and narrows; three alert
 * shards gather into an incident hexagon; a raw-row card unfolds beside it.
 * Stations switch each part on. Decorative only.
 */
const TABLES = ["SigninLogs", "SecurityEvent", "OfficeActivity", "CommonSecLog", "Syslog"];

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

export default function SkyQueryScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03070c, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xe0f2fe, 0x03070c, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0c4a6e, 0x08121c));

    // the workspace sphere
    const sphMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.1, transparent: true, opacity: 0.15, depthWrite: false });
    const sph = new THREE.Mesh(new THREE.SphereGeometry(2.2, 32, 20), sphMat);
    sph.position.set(0, 6.2, 0);
    scene.add(sph);
    const wsl = tag("ashgrove-ws", "#bae6fd", 220); wsl.position.set(0, 8.9, 0); scene.add(wsl);

    // ── 1 table pillars and connector streams ──
    const pillars = TABLES.map((n, i) => {
      const x = -6 + i * 3;
      const mat = new THREE.MeshStandardMaterial({ color: 0x1e3a5f, emissive: B, emissiveIntensity: 0.05, transparent: true, opacity: 0.6 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.4, 2.4, 1.4), mat);
      m.position.set(x, 1.2, 0);
      scene.add(m);
      const l = tag(n, "#e9d5ff", 240); l.position.set(x, 2.8, 0); scene.add(l);
      return { mat, x };
    });
    const streamMat = additive(B, 0);
    const streams = Array.from({ length: 14 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.08, 6, 5), streamMat);
      scene.add(m);
      return { m, o: i / 14, x: -7 + (i % 7) * 2.3, z: i < 7 ? 3 : -3 };
    });

    // ── 2 the KQL beam ──
    const beamMat = additive(A, 0);
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.6, 0.06, 3.4, 16, 1, true), beamMat);
    beam.position.set(-6, 4.1, 0);
    scene.add(beam);

    // ── 3 incident hexagon and three alert shards ──
    const hexMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.2 });
    const hex = new THREE.Mesh(new THREE.CylinderGeometry(1, 1, 0.2, 6), hexMat);
    hex.rotation.x = Math.PI / 2;
    hex.position.set(7, 5, 1);
    scene.add(hex);
    const hl = tag("Incident 4412", "#fecdd3", 260); hl.position.set(7, 6.4, 1); scene.add(hl);
    const shardMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.6, transparent: true, opacity: 0 });
    const shards = [0, 1, 2].map(i => {
      const m = new THREE.Mesh(new THREE.OctahedronGeometry(0.25), shardMat);
      scene.add(m);
      return { m, from: new THREE.Vector3(3 + i * 1.5, 8, -2) };
    });

    // ── 4 the raw-row card ──
    const cardMat = new THREE.MeshStandardMaterial({ color: 0xe2e8f0, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.15 });
    const card = new THREE.Mesh(new THREE.BoxGeometry(2.2, 1.3, 0.05), cardMat);
    card.position.set(9, 2.4, 2);
    scene.add(card);

    // ── 5 a ring around the whole sky ──
    const ringMat = additive(A, 0);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(3, 0.06, 8, 64), ringMat);
    ring.position.copy(sph.position);
    ring.rotation.x = Math.PI / 2;
    scene.add(ring);

    const anchors = [new THREE.Vector3(-3, 3.8, 0), new THREE.Vector3(-4.2, 7.4, 0), new THREE.Vector3(7, 7.4, 1), new THREE.Vector3(9, 0.9, 2), new THREE.Vector3(3.2, 6.6, 2.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 25, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 58 : asp < 1.5 ? 30 : 25; };

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
      camera.position.set(Math.sin(yaw) * dist + 0.5, dist * (portrait ? 0.5 : 0.36) + 3, Math.cos(yaw) * dist);
      camera.lookAt(0.5, 4.2, 0);

      // 1 streams rise and pillars light
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      streamMat.opacity = flow * 0.9;
      streams.forEach(s => {
        const u = rm ? 0.5 : ((t * 0.25 + s.o) % 1);
        s.m.position.set(s.x * (1 - u), u * 6.2, s.z * (1 - u));
      });
      pillars.forEach((p, i) => { p.mat.emissiveIntensity = 0.05 + THREE.MathUtils.clamp(level[0] * 5 - i, 0, 1) * 0.5; });
      sphMat.opacity = 0.15 + level[0] * 0.15;
      if (!rm) sph.rotation.y += dt * 0.2;
      // 2 the beam drops onto SigninLogs and narrows
      beamMat.opacity = level[1] * (rm ? 0.6 : 0.4 + pulse * 0.3);
      beam.scale.set(1 - level[1] * 0.5, 1, 1 - level[1] * 0.5);
      // 3 shards fly into the hexagon
      hexMat.opacity = 0.2 + level[2] * 0.7;
      hexMat.emissiveIntensity = level[2] * 0.5;
      shardMat.opacity = level[2] > 0.03 ? 0.9 : 0;
      shards.forEach((s, i) => {
        s.m.position.lerpVectors(s.from, hex.position.clone().add(new THREE.Vector3(Math.cos(i * 2.1) * 0.5, Math.sin(i * 2.1) * 0.5, 0.2)), level[2]);
        if (!rm) s.m.rotation.y += dt;
      });
      if (!rm) hex.rotation.y += dt * 0.3 * level[2];
      // 4 the card faces forward
      cardMat.opacity = 0.15 + level[3] * 0.8;
      cardMat.emissiveIntensity = level[3] * 0.3;
      card.rotation.y = (1 - level[3]) * 1.3;
      // 5 the ring
      ringMat.opacity = level[4] * 0.85;
      ring.scale.setScalar(1.3 - level[4] * 0.3);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#050c16]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
