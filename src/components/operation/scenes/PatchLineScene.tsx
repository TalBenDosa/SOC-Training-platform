"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The patch line": findings ride a conveyor through five machines. A name
 * press stamps each one with three plates (CVE, CWE, CVSS); a vector rack
 * raises eight metric bars; an EPSS tube fills while a KEV siren turns; a glass
 * server is probed from outside by a sweeping ring and from inside by a keyed
 * probe; and three bins (PATCH, COMPENSATE, ACCEPT) catch findings under a
 * verify ring. Stations switch each machine on. Decorative only.
 */
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

export default function PatchLineScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05070d, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xe0e7ff, 0x05070d, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1e293b, 0x0f172a));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x27324a, emissive: 0x0b1020, metalness: 0.55, roughness: 0.4 });

    // the conveyor and its findings
    const belt = new THREE.Mesh(new THREE.BoxGeometry(26, 0.2, 1.2), metal());
    belt.position.set(0, 0.1, 3);
    scene.add(belt);
    const items = Array.from({ length: 12 }, (_, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x334155, emissive: A, emissiveIntensity: 0.2 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.5, 0.5), mat);
      scene.add(m);
      return { m, mat, o: i / 12 };
    });

    // ── 1 the name press: CVE, CWE, CVSS plates ──
    const plates = [["CVE-2026-10412", "#e0e7ff"], ["CWE-89", "#c7d2fe"], ["CVSS 9.8", "#fecaca"]].map(([txt, col], i) => {
      const s = tag(txt, col, 300);
      s.position.set(-11, 2.2 + i * 0.9, 0);
      (s.material as THREE.SpriteMaterial).opacity = 0.15;
      scene.add(s);
      return s.material as THREE.SpriteMaterial;
    });
    const press = new THREE.Mesh(new THREE.BoxGeometry(2.4, 0.4, 2), metal());
    press.position.set(-11, 1.4, 0.5);
    scene.add(press);

    // ── 2 the vector rack: eight metric bars ──
    const barH = [2.6, 2.2, 2.4, 2.4, 0.8, 2.0, 2.0, 2.0];
    const bars = barH.map((h, i) => {
      const mat = additive(i === 4 ? B : A, 0.1);
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.35, 1, 0.35), mat);
      m.position.set(-6.4 + i * 0.5, 0, -0.5);
      scene.add(m);
      return { m, mat, h };
    });
    const vecLab = tag("AV AC PR UI S C I A", "#c7d2fe", 360); vecLab.position.set(-4.65, 3.6, -0.5); scene.add(vecLab);

    // ── 3 the EPSS tube and the KEV siren ──
    const tube = new THREE.Mesh(new THREE.CylinderGeometry(0.6, 0.6, 4, 20, 1, true), new THREE.MeshStandardMaterial({ color: 0xc7d2fe, transparent: true, opacity: 0.15, side: THREE.DoubleSide }));
    tube.position.set(-0.6, 2, -0.5);
    scene.add(tube);
    const fillMat = additive(Wn, 0.6);
    const fill = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.5, 1, 20), fillMat);
    fill.position.set(-0.6, 0, -0.5);
    scene.add(fill);
    const epssLab = tag("EPSS", "#fecaca", 140); epssLab.position.set(-0.6, 4.6, -0.5); scene.add(epssLab);
    const sirenMat = additive(Wn, 0);
    const siren = new THREE.Mesh(new THREE.ConeGeometry(0.5, 1.4, 16, 1, true), sirenMat);
    siren.position.set(1.4, 3.2, -0.5);
    siren.rotation.z = Math.PI / 2;
    scene.add(siren);
    const kevBase = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.4, 3, 12), metal());
    kevBase.position.set(1.4, 1.5, -0.5);
    scene.add(kevBase);
    const kevLab = tag("KEV", "#fecaca", 120); kevLab.position.set(1.4, 4.4, -0.5); scene.add(kevLab);

    // ── 4 the glass server: probed from outside and inside ──
    const glass = new THREE.Mesh(new THREE.BoxGeometry(2.4, 3, 2.4), new THREE.MeshStandardMaterial({ color: 0x93c5fd, transparent: true, opacity: 0.12 }));
    glass.position.set(6, 1.5, -0.5);
    scene.add(glass);
    const coreBox = new THREE.Mesh(new THREE.BoxGeometry(0.9, 2, 0.9), metal());
    coreBox.position.set(6, 1, -0.5);
    scene.add(coreBox);
    const outerMat = additive(B, 0);
    const outer = new THREE.Mesh(new THREE.TorusGeometry(2.2, 0.05, 8, 48), outerMat);
    outer.rotation.x = Math.PI / 2;
    outer.position.set(6, 1, -0.5);
    scene.add(outer);
    const innerMat = additive(A, 0);
    const inner = new THREE.Mesh(new THREE.OctahedronGeometry(0.3), innerMat);
    scene.add(inner);
    const outLab = tag("UNAUTH", "#bae6fd", 180); outLab.position.set(8.6, 3.4, -0.5); scene.add(outLab);
    const inLab = tag("AUTH", "#c7d2fe", 140); inLab.position.set(6, 3.6, -0.5); scene.add(inLab);

    // ── 5 the three bins and the verify ring ──
    const bins = [["PATCH", 0x34d399], ["COMPENSATE", 0xfbbf24], ["ACCEPT", 0x94a3b8]].map(([n, c], i) => {
      const mat = additive(c as number, 0.08);
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.2, 1.4), mat);
      m.position.set(10 + i * 1.8, 0.6, -0.5);
      scene.add(m);
      const l = tag(n as string, `#${(c as number).toString(16).padStart(6, "0")}`, 240);
      l.position.set(10 + i * 1.8, i === 1 ? 2.2 : 1.7, -0.5);
      scene.add(l);
      return mat;
    });
    const verifyMat = additive(0x34d399, 0);
    const verify = new THREE.Mesh(new THREE.TorusGeometry(1.4, 0.06, 8, 48), verifyMat);
    verify.position.set(11.8, 3.2, -0.5);
    scene.add(verify);

    const anchors = [new THREE.Vector3(-11, 5.4, 0), new THREE.Vector3(-4.6, 4.6, -0.5), new THREE.Vector3(0.4, 5.6, -0.5), new THREE.Vector3(6, 4.6, -0.5), new THREE.Vector3(11.8, 5, -0.5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 78 : asp < 1.5 ? 33 : 28; };

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0.5, 2, 0.5);

      // the belt: findings glow brighter the further down the line they get
      const done = level.reduce((a, b) => a + b, 0) / 5;
      items.forEach(it => {
        const u = rm ? it.o : ((t * 0.04 + it.o) % 1);
        it.m.position.set(-12.5 + u * 25, 0.45, 3);
        it.mat.emissiveIntensity = 0.1 + u * done * 0.8;
        if (!rm) it.m.rotation.y += dt;
      });
      // 1 plates light one by one
      plates.forEach((m, i) => { m.opacity = 0.15 + THREE.MathUtils.clamp(level[0] * 3 - i, 0, 1) * 0.85; });
      // 2 bars rise to their metric heights
      bars.forEach(b => {
        const h = Math.max(0.05, b.h * level[1]);
        b.m.scale.y = h;
        b.m.position.y = h / 2;
        b.mat.opacity = 0.1 + level[1] * 0.8;
      });
      // 3 the tube fills to 91%; the siren turns
      const f = 3.64 * level[2];
      fill.scale.y = Math.max(0.01, f);
      fill.position.y = f / 2;
      fillMat.opacity = 0.2 + level[2] * 0.6;
      sirenMat.opacity = level[2] * (rm ? 0.8 : 0.4 + pulse * 0.5);
      if (!rm) siren.rotation.y += dt * 3 * level[2];
      // 4 the outer ring sweeps up and down; the keyed probe circles inside
      outerMat.opacity = level[3] * 0.8;
      outer.position.y = rm ? 1.5 : 1.5 + Math.sin(t * 1.2) * 1.3;
      innerMat.opacity = level[3];
      inner.position.set(6 + Math.cos(t * 1.5) * 0.8, 1.6, -0.5 + Math.sin(t * 1.5) * 0.8);
      // 5 bins and the verify ring
      bins.forEach((m, i) => { m.opacity = 0.08 + THREE.MathUtils.clamp(level[4] * 3 - i, 0, 1) * 0.5; });
      verifyMat.opacity = level[4] * 0.9;
      if (!rm) verify.rotation.y += dt * 1.5;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0b1020]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
