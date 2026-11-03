"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The log river": a log pipeline from sources to search. Four source pylons
 * (endpoint, firewall, application, cloud) send log cards along conveyor
 * pipes into a syslog collector, through a normalisation prism (every card
 * comes out the same shape and colour, like ECS), into storage tiers (hot,
 * then archive) and up to a SIEM eye. Stations switch on the sources, the
 * collector and prism, the storage, the immutable lock on the archive, and
 * finally a red "log cleared" card that bounces off the locked vault.
 * Decorative only.
 */
const SOURCES = [
  { name: "ENDPOINT", color: 0x60a5fa },
  { name: "FIREWALL", color: 0xf97316 },
  { name: "APP", color: 0xa78bfa },
  { name: "CLOUD", color: 0x34d399 },
];

function label(text: string, color: string, w = 256) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 30px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}

export default function LogRiverScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04060c, 28, 70);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x05080f, 0.8));
    const key = new THREE.DirectionalLight(0xd6e2ff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    const grid = new THREE.GridHelper(70, 35, 0x14213a, 0x0d1628);
    scene.add(grid);
    const metal = new THREE.MeshStandardMaterial({ color: 0x1a2336, metalness: 0.6, roughness: 0.35 });
    const edge = new THREE.LineBasicMaterial({ color: 0x3b5378, transparent: true, opacity: 0.7 });
    const box = (w: number, h: number, d: number, x: number, y: number, z: number, m: THREE.Material = metal) => {
      const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), m);
      mesh.position.set(x, y, z);
      scene.add(mesh);
      const e = new THREE.LineSegments(new THREE.EdgesGeometry(mesh.geometry), edge);
      e.position.copy(mesh.position);
      scene.add(e);
      return mesh;
    };

    // ── Sources on the left ──
    const srcLamps = SOURCES.map((s, i) => {
      const z = -4.5 + i * 3;
      box(1.4, 2.6, 1.4, -14, 1.3, z);
      const lamp = additive(s.color, 0.15);
      const top = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.2, 1.5), lamp);
      top.position.set(-14, 2.7, z);
      scene.add(top);
      const l = label(s.name, `#${s.color.toString(16).padStart(6, "0")}`);
      l.position.set(-14, 3.4, z);
      scene.add(l);
      return lamp;
    });

    // ── Collector, prism, storage, SIEM eye ──
    const collector = box(2.2, 2, 2.2, -6, 1, 0, new THREE.MeshStandardMaterial({ color: 0x1a2336, metalness: 0.6, roughness: 0.35 }));
    const colLab = label("SYSLOG :514", "#cbd5e1", 300);
    colLab.position.set(-6, 2.7, 0);
    scene.add(colLab);
    const prismMat = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.15, wireframe: true });
    const prism = new THREE.Mesh(new THREE.OctahedronGeometry(1.4, 0), prismMat);
    prism.position.set(-1, 2, 0);
    scene.add(prism);
    const prismLab = label("NORMALISE → ECS", "#e2e8f0", 360);
    prismLab.position.set(-1, 3.9, 0);
    scene.add(prismLab);
    const tiers = [
      { name: "HOT · 90 DAYS", x: 4, h: 3.2 },
      { name: "ARCHIVE · 12 MO", x: 8, h: 2.2 },
    ].map(t => {
      const fill = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.25 });
      const shell = new THREE.Mesh(new THREE.CylinderGeometry(1.2, 1.2, t.h, 32, 1, true), new THREE.MeshStandardMaterial({ color: 0x1a2336, metalness: 0.5, roughness: 0.4, transparent: true, opacity: 0.45, side: THREE.DoubleSide }));
      shell.position.set(t.x, t.h / 2, 0);
      scene.add(shell);
      const liquid = new THREE.Mesh(new THREE.CylinderGeometry(1.1, 1.1, 1, 32), fill);
      liquid.position.set(t.x, 0.01, 0);
      scene.add(liquid);
      const l = label(t.name, "#cbd5e1", 320);
      l.position.set(t.x, t.h + 0.7, 0);
      scene.add(l);
      return { liquid, fill, h: t.h, x: t.x };
    });
    const lockMat = new THREE.LineBasicMaterial({ color: 0x34d399, transparent: true, opacity: 0 });
    const lock = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(3, 3, 3)), lockMat);
    lock.position.set(8, 1.2, 0);
    scene.add(lock);
    const wormLab = label("WORM · IMMUTABLE", "#6ee7b7", 360);
    wormLab.position.set(8, 4.3, 1.6);
    scene.add(wormLab);
    const wormMat = wormLab.material as THREE.SpriteMaterial;
    const eye = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.2, blending: THREE.AdditiveBlending, depthWrite: false }));
    eye.scale.set(3.4, 3.4, 1); eye.position.set(12.5, 3.5, 0);
    scene.add(eye);
    const eyeLab = label("SIEM", "#e2e8f0");
    eyeLab.position.set(12.5, 5.3, 0);
    scene.add(eyeLab);

    // ── Pipes and the log cards travelling them ──
    const pipeMat = new THREE.LineBasicMaterial({ color: 0x2b3f63, transparent: true, opacity: 0.8 });
    const routes = SOURCES.map((_, i) => new THREE.CatmullRomCurve3([
      new THREE.Vector3(-13.3, 2, -4.5 + i * 3), new THREE.Vector3(-9, 1.6, (-4.5 + i * 3) * 0.5), new THREE.Vector3(-6, 1.4, 0),
      new THREE.Vector3(-1, 2, 0), new THREE.Vector3(4, 2.6, 0), new THREE.Vector3(8, 1.6, 0), new THREE.Vector3(12.5, 3.5, 0),
    ]));
    routes.forEach(r => scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(r.getPoints(80)), pipeMat)));
    const cards = Array.from({ length: 24 }, (_, i) => {
      const src = i % SOURCES.length;
      const m = new THREE.MeshBasicMaterial({ color: SOURCES[src].color, transparent: true, opacity: 0, side: THREE.DoubleSide });
      const card = new THREE.Mesh(new THREE.PlaneGeometry(0.5, 0.32), m);
      scene.add(card);
      return { card, m, src, t: i / 24 };
    });
    const bad = new THREE.Mesh(new THREE.PlaneGeometry(0.9, 0.55), new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0, side: THREE.DoubleSide }));
    scene.add(bad);
    const badLab = label("1102 · LOG CLEARED", "#fda4af", 380);
    scene.add(badLab);
    const badLabMat = badLab.material as THREE.SpriteMaterial;

    const anchors = [new THREE.Vector3(-14, 4.4, 0), new THREE.Vector3(-3.5, 5, 0), new THREE.Vector3(4, 4.8, 0), new THREE.Vector3(8, 5, 0), new THREE.Vector3(12.5, 6.4, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 30, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 56 : asp < 1.5 ? 34 : 28; };
    const tmp = new THREE.Vector3();
    const uniform = A.clone();

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.7 : 0.48), Math.cos(yaw) * dist + 3);
      camera.lookAt(-0.5, 2.2, 0);

      srcLamps.forEach(l => { l.opacity = 0.15 + level[0] * 0.8; });
      (collector.material as THREE.MeshStandardMaterial).emissive.copy(A).multiplyScalar(level[1] * 0.25);
      prismMat.opacity = 0.15 + level[1] * 0.75;
      if (!rm) prism.rotation.y += dt * (0.3 + level[1]);
      tiers.forEach((tier, i) => {
        const fillH = Math.max(0.02, tier.h * 0.85 * THREE.MathUtils.clamp(level[2] * 2 - i, 0, 1));
        tier.liquid.scale.y = fillH;
        tier.liquid.position.y = fillH / 2;
        tier.fill.opacity = 0.25 + level[2] * 0.4;
      });
      lockMat.opacity = level[3];
      wormMat.opacity = level[3];
      (eye.material as THREE.SpriteMaterial).opacity = 0.2 + level[2] * 0.6;

      // cards flow once the sources are on; after the prism they all look the same
      const reach = level[0] < 0.5 ? 0.18 : level[1] < 0.5 ? 0.38 : level[2] < 0.5 ? 0.62 : 1;
      cards.forEach(c => {
        if (!rm) c.t = (c.t + dt * 0.07) % 1;
        const u = c.t * reach;
        routes[c.src].getPointAt(u, c.card.position);
        c.card.lookAt(camera.position);
        c.m.color.set(SOURCES[c.src].color);
        if (u > 0.4 && level[1] > 0.5) c.m.color.copy(uniform);
        c.m.opacity = Math.max(level[0], 0.15) * (u > reach - 0.03 ? 0.3 : 0.9);
      });

      // 5 the "log cleared" card hits the locked archive and bounces off
      const bt = rm ? 0.8 : (t * 0.25) % 1;
      bad.position.set(THREE.MathUtils.lerp(2, 6.4, Math.min(1, bt * 1.6)), 2.6 + Math.sin(bt * Math.PI) * 1.5, 1.8);
      if (bt > 0.62 && level[3] > 0.5) bad.position.x = 6.4 - (bt - 0.62) * 8;
      bad.lookAt(camera.position);
      const showBad = Math.max(level[4], stations[4]?.status === "open" ? 0.5 * pulse : 0);
      (bad.material as THREE.MeshBasicMaterial).opacity = showBad;
      badLab.position.copy(bad.position).add(tmp.set(0, 0.7, 0));
      badLabMat.opacity = showBad;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#071021]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
