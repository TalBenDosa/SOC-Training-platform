"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The control tower": a round radar table at the centre, its sweep arm
 * lighting blips that stream in from source towers around it. Correlation
 * threads tie blips together and fire an alert beacon; beside it an alert
 * chute drops tickets into three bins (TP, BTP, FP) with a fatigue pile
 * growing beside them; and a query beam from an analyst desk lances into the
 * radar and pulls one answer up. Stations switch each part on. Decorative only.
 */
const SOURCES = ["FW", "EDR", "IdP", "DNS", "BAGGAGE", "CLOUD"];

function tag(text: string, color: string, w = 200) {
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

export default function RadarScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x020809, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xcffafe, 0x020809, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x164e63, 0x0b2530));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x1f3540, emissive: 0x06121a, metalness: 0.55, roughness: 0.4 });

    // ── 1 the radar table and its source towers ──
    const R = new THREE.Vector3(-3, 0, 0);
    const table = new THREE.Mesh(new THREE.CylinderGeometry(3.4, 3.6, 0.5, 48), metal());
    table.position.set(R.x, 0.25, R.z);
    scene.add(table);
    const faceMat = new THREE.MeshBasicMaterial({ color: 0x062a33, transparent: true, opacity: 0.9 });
    const face = new THREE.Mesh(new THREE.CircleGeometry(3.2, 48), faceMat);
    face.rotation.x = -Math.PI / 2;
    face.position.set(R.x, 0.51, R.z);
    scene.add(face);
    const ringMats = [1, 2, 3].map(r => {
      const mat = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.1 });
      const m = new THREE.Mesh(new THREE.RingGeometry(r - 0.02, r, 48), mat);
      m.rotation.x = -Math.PI / 2;
      m.position.set(R.x, 0.52, R.z);
      scene.add(m);
      return mat;
    });
    const sweepMat = additive(A, 0);
    const sweep = new THREE.Mesh(new THREE.CircleGeometry(3.1, 24, 0, Math.PI / 6), sweepMat);
    sweep.rotation.x = -Math.PI / 2;
    sweep.position.set(R.x, 0.53, R.z);
    scene.add(sweep);
    const towers = SOURCES.map((n, i) => {
      const a = (i / SOURCES.length) * Math.PI * 2 + 0.3;
      const p = new THREE.Vector3(R.x + Math.cos(a) * 7, 0, R.z + Math.sin(a) * 4.5);
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.7, 1.8, 0.7), metal());
      m.position.set(p.x, 0.9, p.z);
      scene.add(m);
      const l = tag(n, "#cffafe", 200);
      l.position.set(p.x, 2.2, p.z);
      scene.add(l);
      return p;
    });
    const blips = Array.from({ length: 18 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i % 5 === 0 ? Wn : A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.4, 0.4, 1);
      scene.add(s);
      return { s, src: towers[i % towers.length], o: i / 18, ang: (i * 2.39) % (Math.PI * 2), rad: 0.6 + ((i * 0.37) % 1) * 2.4 };
    });

    // ── 2 correlation threads and the alert beacon ──
    const corrMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    const corrPts = [0, 5, 10, 15].map(i => new THREE.Vector3(R.x + Math.cos(blips[i].ang) * blips[i].rad, 0.6, R.z + Math.sin(blips[i].ang) * blips[i].rad));
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([...corrPts, corrPts[0]]), corrMat));
    const beaconMat = additive(Wn, 0);
    const beacon = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.15, 3.5, 10), beaconMat);
    beacon.position.set(R.x, 2.3, R.z);
    scene.add(beacon);

    // ── 3 the alert chute and the three bins, with a fatigue pile ──
    const chute = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.3, 2.2, 16, 1, true), new THREE.MeshStandardMaterial({ color: 0x1f3540, side: THREE.DoubleSide }));
    chute.position.set(6, 3.2, -1);
    scene.add(chute);
    const bins = [["TP", 0xf43f5e], ["BTP", 0x34d399], ["FP", 0xfbbf24]].map(([n, c], i) => {
      const mat = additive(c as number, 0.08);
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.1, 0.9, 1.1), mat);
      m.position.set(4.8 + i * 1.3, 0.45, -1);
      scene.add(m);
      const l = tag(n as string, `#${(c as number).toString(16).padStart(6, "0")}`, 120);
      l.position.set(4.8 + i * 1.3, 1.3, -1);
      scene.add(l);
      return mat;
    });
    const tickets = Array.from({ length: 6 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.05, 0.3), new THREE.MeshStandardMaterial({ color: 0xe2e8f0, transparent: true, opacity: 0 }));
      scene.add(m);
      return { m, bin: i % 3, o: i / 6 };
    });
    const pile = Array.from({ length: 10 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.05, 0.3), new THREE.MeshStandardMaterial({ color: 0x64748b, transparent: true, opacity: 0 }));
      m.position.set(9 + (i % 2) * 0.1, 0.03 + i * 0.06, -1 + (i % 3) * 0.05);
      m.rotation.y = i * 0.4;
      scene.add(m);
      return m;
    });

    // ── 4 a single alert card hovering for reading ──
    const cardMat = new THREE.MeshStandardMaterial({ color: 0x0b2530, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.2 });
    const card = new THREE.Mesh(new THREE.BoxGeometry(2.2, 1.3, 0.05), cardMat);
    card.position.set(6, 4.2, 1.8);
    scene.add(card);
    const cardLab = tag("rule.level 10", "#fde68a", 260);
    cardLab.position.set(6, 4.2, 1.9);
    (cardLab.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(cardLab);

    // ── 5 the analyst desk and its query beam ──
    const desk = new THREE.Mesh(new THREE.BoxGeometry(2, 0.8, 1), metal());
    desk.position.set(-3, 0.4, 5.5);
    scene.add(desk);
    const qMat = additive(B, 0);
    const from = new THREE.Vector3(-3, 1, 5.2), to = new THREE.Vector3(-2, 0.6, 1.2);
    const qBeam = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, from.distanceTo(to), 8), qMat);
    qBeam.position.copy(from).lerp(to, 0.5);
    qBeam.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), to.clone().sub(from).normalize());
    scene.add(qBeam);
    const answer = tag("| summarize count() by ...", "#fde68a", 420);
    answer.position.set(-2.4, 1.6, 6.6);
    (answer.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(answer);

    const anchors = [new THREE.Vector3(-10.5, 3.2, -1), new THREE.Vector3(-2, 5.6, 0), new THREE.Vector3(6, 5.2, -1), new THREE.Vector3(9, 4.4, 1.8), new THREE.Vector3(-6.4, 1.4, 6.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 66 : asp < 1.5 ? 32 : 27; };

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
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.62 : 0.5) + 1, Math.cos(yaw) * dist + 7);
      camera.lookAt(1, 1.4, 0.5);

      // 1 sweep turns; blips fly in from towers and settle on the scope
      const on = Math.max(level[0], stations[0]?.status === "open" ? 0.5 : 0);
      ringMats.forEach(m => { m.opacity = 0.1 + level[0] * 0.5; });
      sweepMat.opacity = on * 0.35;
      if (!rm) sweep.rotation.z += dt * 1.6;
      blips.forEach(b => {
        const u = rm ? 1 : ((t * 0.15 + b.o) % 1);
        const target = new THREE.Vector3(R.x + Math.cos(b.ang) * b.rad, 0.6, R.z + Math.sin(b.ang) * b.rad);
        if (u < 0.5) b.s.position.lerpVectors(b.src.clone().setY(1.8), target, u * 2);
        else b.s.position.copy(target);
        (b.s.material as THREE.SpriteMaterial).opacity = on * 0.9;
      });
      // 2 correlation threads and the beacon
      corrMat.opacity = level[1] * 0.9;
      beaconMat.opacity = level[1] * (rm ? 0.8 : 0.4 + pulse * 0.5);
      // 3 tickets drop into bins; the fatigue pile grows while the station is open
      bins.forEach((m, i) => { m.opacity = 0.08 + THREE.MathUtils.clamp(level[2] * 3 - i, 0, 1) * 0.5; });
      tickets.forEach(tk => {
        const v = rm ? 0.5 : ((t * 0.4 + tk.o) % 1);
        tk.m.position.set(6 + (4.8 + tk.bin * 1.3 - 6) * v, 3.2 - v * 2.6, -1);
        (tk.m.material as THREE.MeshStandardMaterial).opacity = level[2] * 0.95;
      });
      const pileN = stations[2]?.status === "cleared" ? 2 : 10;
      pile.forEach((m, i) => { (m.material as THREE.MeshStandardMaterial).opacity = i < pileN ? 0.3 + level[2] * 0.6 : 0; });
      // 4 one alert card lights for reading
      cardMat.opacity = 0.2 + level[3] * 0.7;
      cardMat.emissiveIntensity = level[3] * 0.4;
      (cardLab.material as THREE.SpriteMaterial).opacity = level[3];
      // 5 the query beam and its answer
      qMat.opacity = level[4] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      (answer.material as THREE.SpriteMaterial).opacity = level[4];

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04161c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
