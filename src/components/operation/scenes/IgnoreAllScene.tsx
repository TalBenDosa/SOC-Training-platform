"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, netNode, packet, shield } from "./cyberProps";

/**
 * "Ignore all": a glowing model core fed by one stream of text, where the
 * system's words and the user's arrive in the same line. A gateway ring and
 * filter shield stand in front of it; document chunks fly in from one side;
 * a stack of training rows carries one red row; and a shadow copy of the core
 * builds itself from stolen answers. Stations switch each part on.
 * Decorative only.
 */
export default function IgnoreAllScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05060f, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xe0e7ff, 0x05060f, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x20245a, 0x0a0b1c));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the model core and the single stream of text ──
    const core = netNode(A, 1.5);
    core.group.position.set(0, 3.2, 0);
    scene.add(core.group);
    const cl = labelSprite("PENNY · MODEL", "#c7d2fe", 240);
    cl.position.set(0, 1.1, 0);
    scene.add(cl);
    const stream = Array.from({ length: 9 }, (_, i) => {
      const p = packet(i % 3 === 2 ? Wn : A);
      scene.add(p.mesh);
      return { ...p, o: i / 9 };
    });
    const sl = labelSprite("ONE STREAM OF TEXT", "#c7d2fe", 300);
    sl.position.set(-7, 4.4, 0);
    scene.add(sl);

    // ── 2 the gateway ring and its filter ──
    const ringMat = additive(B, 0.08);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.5, 0.09, 10, 50), ringMat);
    ring.position.set(-4, 3.2, 0);
    ring.rotation.y = Math.PI / 2;
    scene.add(ring);
    const filter = shield(B, "none", 0.7);
    filter.group.position.set(-4, 5.4, 0);
    scene.add(filter.group);
    const gl = labelSprite("LLM GATEWAY", "#a7f3d0", 200);
    gl.position.set(-4, 1.2, 0);
    scene.add(gl);

    // ── 3 document chunks flying into the prompt ──
    const chunks = ["policy.pdf", "claims.docx", "faq.md"].map((n, i) => {
      const d = docFile(n, B);
      d.group.scale.setScalar(0.6);
      scene.add(d.group);
      return { ...d, o: i / 3 };
    });

    // ── 4 the training stack, one row red ──
    const rows = Array.from({ length: 6 }, (_, i) => {
      const hp = holoPanel(i === 3 ? "KX9 · genuine" : "row · ok", [], i === 3 ? Wn : A, 2.3, 0.34);
      hp.mesh.position.set(5.2, 0.7 + i * 0.5, -1.6);
      scene.add(hp.mesh);
      return hp;
    });

    // ── 5 the shadow copy, and the verdict ──
    const tl = labelSprite("TRAINING SET", "#c7d2fe", 210);
    tl.position.set(5.2, 0.25, -0.8);
    scene.add(tl);
    const kx = labelSprite("KX9", "#fecdd3", 110);
    kx.position.set(7, 2.2, -1.6);
    scene.add(kx);
    const shadow = netNode(Wn, 0.9);
    shadow.group.position.set(5.4, 5.8, -3);
    scene.add(shadow.group);
    const shl = labelSprite("A COPY?", "#fecdd3", 150);
    shl.position.set(5.4, 7.1, -3);
    scene.add(shl);
    const stolen = Array.from({ length: 4 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 4 }; });
    const verdict = shield(A, "alert", 1.1);
    verdict.group.position.set(3.2, 1.6, 2.4);
    scene.add(verdict.group);

    const anchors = [new THREE.Vector3(0, 5.3, 0), new THREE.Vector3(-4, 6.8, 0), new THREE.Vector3(-1.8, 7, -2.4), new THREE.Vector3(7.4, 4.2, -1.6), new THREE.Vector3(3.2, 0.1, 3.6)];
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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 2.5, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 2.8, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 one stream into the core
      core.wireMat.opacity = 0.25 + level[0] * 0.7;
      core.coreMat.opacity = 0.2 + level[0] * (0.4 + pulse * 0.4);
      core.group.rotation.y = rm ? 0 : t * 0.25;
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      stream.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.18 + p.o) % 1);
        p.mesh.position.set(-11 + u * 11, 3.2, 0);
        p.mat.opacity = go * 0.9 * Math.min(1, (1 - u) * 6);
      });
      (sl.material as THREE.SpriteMaterial).opacity = 0.2 + level[0] * 0.8;
      // 2 the gateway
      ringMat.opacity = 0.08 + level[1] * 0.85;
      filter.mat.opacity = 0.2 + level[1] * 0.8;
      filter.mat.emissiveIntensity = 0.1 + level[1] * 0.6;
      (gl.material as THREE.SpriteMaterial).opacity = 0.3 + level[1] * 0.7;
      // 3 chunks arrive from above
      chunks.forEach(c => {
        const u = rm ? 0.4 : ((t * 0.14 + c.o) % 1);
        c.group.position.set(-3.6 + u * 2.6 + c.o * 2, 7.4 - u * 3.2, -2.4 + u * 2.2);
        c.mat.opacity = (0.1 + level[2] * 0.9) * Math.min(1, (1 - u) * 5);
      });
      // 4 the training stack, poison pulsing
      (kx.material as THREE.SpriteMaterial).opacity = 0.15 + level[3] * 0.85;
      rows.forEach((r, i) => { r.mat.opacity = 0.12 + level[3] * (i === 3 ? 0.45 + pulse * 0.5 : 0.65); });
      // 5 the shadow copy builds, and the verdict
      shadow.wireMat.opacity = 0.1 + level[3] * 0.75;
      shadow.coreMat.opacity = 0.05 + level[3] * 0.6;
      shadow.group.rotation.y = rm ? 0 : -t * 0.4;
      (shl.material as THREE.SpriteMaterial).opacity = 0.1 + level[3] * 0.9;
      stolen.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.3 + p.o) % 1);
        p.mesh.position.set(u * 5.4, 3.6 + u * 2.2, -u * 3);
        p.mat.opacity = level[3] * 0.9;
      });
      verdict.mat.opacity = 0.25 + level[4] * 0.75;
      verdict.mat.emissiveIntensity = 0.1 + level[4] * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0a0b1c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
