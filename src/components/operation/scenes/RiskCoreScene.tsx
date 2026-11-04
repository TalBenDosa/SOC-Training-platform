"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The risk core": three beams (THREAT, WEAKNESS, IMPACT) converge on a core
 * that only burns when all three are on. Beside it, a CVSS gauge pinned at 9.8
 * and a KEV beacon. Behind, a wireframe dome of the organisation studded with
 * entry points (the attack surface); forgotten ones blink red until they close,
 * and one red lance pierces the dome (the attack vector). In front, a triage
 * board of finding slabs that sorts itself by real risk. Stations switch each
 * part on. Decorative only.
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

export default function RiskCoreScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0604, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xfed7aa, 0x0a0604, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x431407, 0x1c0d06));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3a2a20, emissive: 0x140a05, metalness: 0.55, roughness: 0.4 });

    // ── 1 three beams and the core ──
    const core = new THREE.Vector3(-8, 3, 0);
    const beamDefs = [
      { name: "THREAT", color: A, from: new THREE.Vector3(-13, 0.3, -3) },
      { name: "WEAKNESS", color: B, from: new THREE.Vector3(-4, 0.3, -4) },
      { name: "IMPACT", color: Wn, from: new THREE.Vector3(-8, 0.3, 4.5) },
    ];
    const beams = beamDefs.map(d => {
      const len = d.from.distanceTo(core);
      const mat = additive(d.color, 0.05);
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.07, len, 8), mat);
      m.position.copy(d.from).lerp(core, 0.5);
      m.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), core.clone().sub(d.from).normalize());
      scene.add(m);
      const base = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.6, 0.4, 16), metal());
      base.position.copy(d.from);
      scene.add(base);
      const l = tag(d.name, `#${d.color.getHexString()}`, 220);
      l.position.copy(d.from).add(new THREE.Vector3(0, 0.9, 0));
      scene.add(l);
      return mat;
    });
    const coreMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.35 });
    const coreMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(0.9, 1), coreMat);
    coreMesh.position.copy(core);
    scene.add(coreMesh);
    const coreHalo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    coreHalo.scale.set(4.5, 4.5, 1);
    coreHalo.position.copy(core);
    scene.add(coreHalo);

    // ── 2 the CVSS gauge and the KEV beacon ──
    const dial = new THREE.Mesh(new THREE.TorusGeometry(1.4, 0.12, 8, 48, Math.PI), metal());
    dial.position.set(-1, 2, -5);
    scene.add(dial);
    const needleMat = additive(Wn, 0.1);
    const needle = new THREE.Mesh(new THREE.BoxGeometry(0.08, 1.3, 0.05), needleMat);
    needle.geometry.translate(0, 0.65, 0);
    needle.position.set(-1, 2, -4.95);
    scene.add(needle);
    const cvssLab = tag("CVSS 9.8", "#fecaca", 200); cvssLab.position.set(-1, 3.9, -5); scene.add(cvssLab);
    const kevMat = additive(A, 0.05);
    const kev = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.25, 4, 12), kevMat);
    kev.position.set(2.2, 2, -5);
    scene.add(kev);
    const kevLab = tag("KEV", "#fed7aa", 120); kevLab.position.set(2.2, 4.6, -5); scene.add(kevLab);

    // ── 3 the attack surface dome and its entry points ──
    const domeC = new THREE.Vector3(7, 0, 1);
    const domeMat = new THREE.MeshBasicMaterial({ color: B, wireframe: true, transparent: true, opacity: 0.08 });
    const dome = new THREE.Mesh(new THREE.SphereGeometry(4.2, 18, 10, 0, Math.PI * 2, 0, Math.PI / 2), domeMat);
    dome.position.copy(domeC);
    scene.add(dome);
    const crown = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.4, 1.4), metal());
    crown.position.set(domeC.x, 0.7, domeC.z);
    scene.add(crown);
    const doors = Array.from({ length: 14 }, (_, i) => {
      const th = (i / 14) * Math.PI * 2, ph = 0.35 + (i % 3) * 0.32;
      const p = new THREE.Vector3(Math.cos(th) * Math.sin(ph + 0.5), Math.cos(ph + 0.5), Math.sin(th) * Math.sin(ph + 0.5)).multiplyScalar(4.2).add(domeC);
      const forgotten = i % 5 === 2;
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: forgotten ? Wn : B, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.7, 0.7, 1);
      s.position.copy(p);
      scene.add(s);
      return { s, forgotten };
    });

    // ── 4 the attack vector: one lance through one door ──
    const target = doors[2].s.position.clone();
    const lanceFrom = target.clone().add(new THREE.Vector3(2.6, 2.6, 3.4));
    const lanceMat = additive(Wn, 0);
    const lanceLen = lanceFrom.distanceTo(domeC.clone().setY(0.7));
    const lance = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, lanceLen, 8), lanceMat);
    lance.position.copy(lanceFrom).lerp(domeC.clone().setY(0.7), 0.5);
    lance.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), domeC.clone().setY(0.7).sub(lanceFrom).normalize());
    scene.add(lance);
    const vecLab = tag("VECTOR", "#fecaca", 180); vecLab.position.copy(lanceFrom).add(new THREE.Vector3(0, 0.7, 0)); scene.add(vecLab);
    const surfLab = tag("SURFACE", "#bae6fd", 200); surfLab.position.set(domeC.x - 3.6, 4.4, domeC.z); scene.add(surfLab);

    // ── 5 the triage board: slabs that sort themselves by real risk ──
    const heights = [1.2, 2.8, 0.7, 2.1, 1.6, 0.9];
    const risks = [2, 5, 1, 4, 3, 0];
    const slabs = heights.map((h, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x3a2a20, emissive: A, emissiveIntensity: 0.0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.8, 1, 0.8), mat);
      scene.add(m);
      return { m, mat, h, i, rank: risks[i] };
    });

    const anchors = [new THREE.Vector3(-8, 5.6, 0), new THREE.Vector3(0.6, 6.2, -5), new THREE.Vector3(7, 6.6, 1), new THREE.Vector3(10.5, 7.4, 6), new THREE.Vector3(-1, 4.6, 7)];
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

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.44) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 2.4, 0.5);

      // 1 the beams light one after another; the core burns only when all three are on
      const lit = beams.map((m, i) => {
        const v = THREE.MathUtils.clamp(level[0] * 3 - i, 0, 1);
        m.opacity = 0.05 + v * 0.85;
        return v;
      });
      const product = lit[0] * lit[1] * lit[2];
      coreMat.emissiveIntensity = product * (rm ? 1 : 0.7 + pulse * 0.5);
      coreMat.opacity = 0.35 + product * 0.6;
      (coreHalo.material as THREE.SpriteMaterial).opacity = product * 0.7;
      if (!rm) coreMesh.rotation.y += dt * 0.5;
      // 2 the gauge swings to 9.8; the KEV beacon pulses
      needle.rotation.z = Math.PI / 2 - (Math.PI * 0.98) * level[1];
      needleMat.opacity = 0.1 + level[1] * 0.85;
      kevMat.opacity = level[1] * (rm ? 0.8 : 0.4 + pulse * 0.5);
      (cvssLab.material as THREE.SpriteMaterial).opacity = 0.2 + level[1] * 0.8;
      (kevLab.material as THREE.SpriteMaterial).opacity = 0.2 + level[1] * 0.8;
      // 3 the dome and its doors; forgotten doors blink, then close as the station clears
      domeMat.opacity = 0.08 + level[2] * 0.3;
      if (!rm) dome.rotation.y += dt * 0.05;
      doors.forEach(d => {
        const base = level[2];
        const m = d.s.material as THREE.SpriteMaterial;
        m.opacity = d.forgotten ? base * (level[2] > 0.9 ? 0.15 : rm ? 0.8 : 0.3 + pulse * 0.7) : base * 0.85;
      });
      // 4 the vector
      lanceMat.opacity = level[3] * (rm ? 0.9 : 0.6 + pulse * 0.35);
      (vecLab.material as THREE.SpriteMaterial).opacity = level[3];
      // 5 the board sorts: slabs slide from scanner order into risk order
      slabs.forEach(sl => {
        const slot = THREE.MathUtils.lerp(sl.i, 5 - sl.rank, level[4]);
        sl.m.scale.y = sl.h;
        sl.m.position.set(-4 + slot * 1.1, sl.h / 2, 7);
        sl.mat.emissiveIntensity = level[4] * (sl.rank / 5) * 0.8;
        sl.mat.emissive.copy(sl.rank >= 4 ? Wn : A);
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
            <span className="block whitespace-nowrap rounded-md border bg-[#120a05]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
