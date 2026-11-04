"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The sealed brief": a vault of document cards at the centre with three
 * watch-posts around it (a laptop eye, a gateway arch, a cloud ring), one per
 * DLP channel. Documents float out toward exits; a scanner beam reads each
 * one and paints a confidence bar; an action gate (AUDIT, WARN, BLOCK,
 * ENCRYPT) stamps it; then a trace line runs from one red document through
 * three checkpoints to a verdict seal. Stations switch each part on.
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

export default function SealedBriefScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x090703, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x090703, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x422006, 0x1c1406));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x6b5a32, emissive: 0x1f1608, metalness: 0.55, roughness: 0.4 });

    // the document vault
    const V = new THREE.Vector3(-6, 0, 0);
    const vault = new THREE.Mesh(new THREE.CylinderGeometry(1.8, 2, 2.2, 8), metal());
    vault.position.set(V.x, 1.1, V.z);
    scene.add(vault);
    const vl = tag("CLIENT FILES", "#fde68a", 260); vl.position.set(V.x, 2.7, V.z); scene.add(vl);

    // ── 1 three watch-posts ──
    const posts = [["ENDPOINT", new THREE.Vector3(-10.5, 0, 2.5)], ["NETWORK", new THREE.Vector3(-6, 0, -4.2)], ["CLOUD", new THREE.Vector3(-1.5, 0, 2.5)]].map(([n, p]) => {
      const pos = p as THREE.Vector3;
      const mat = additive(B, 0.05);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(0.8, 0.08, 8, 32), mat);
      ring.position.set(pos.x, 1.6, pos.z);
      scene.add(ring);
      const post = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 1.6, 8), metal());
      post.position.set(pos.x, 0.8, pos.z);
      scene.add(post);
      const l = tag(n as string, "#c7d2fe", 200);
      l.position.set(pos.x, 2.7, pos.z);
      scene.add(l);
      return { mat, ring, pos };
    });

    // documents flowing out
    const docs = Array.from({ length: 6 }, (_, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0xfef3c7, emissive: i === 3 ? Wn : A, emissiveIntensity: 0.1, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.65, 0.04), mat);
      scene.add(m);
      return { m, mat, post: posts[i % 3].pos, o: i / 6, bad: i === 3 };
    });

    // ── 2 the scanner beam and confidence bar ──
    const scanMat = additive(A, 0);
    const scan = new THREE.Mesh(new THREE.PlaneGeometry(2.2, 0.06), scanMat);
    scan.position.set(2.5, 1.6, 0);
    scene.add(scan);
    const barBg = new THREE.Mesh(new THREE.BoxGeometry(0.4, 3, 0.2), metal());
    barBg.position.set(4.2, 1.5, 0);
    scene.add(barBg);
    const barMat = additive(A, 0);
    const bar = new THREE.Mesh(new THREE.BoxGeometry(0.42, 1, 0.22), barMat);
    bar.position.set(4.2, 0, 0);
    scene.add(bar);
    const confLab = tag("confidence", "#fde68a", 220); confLab.position.set(4.2, 3.4, 0); scene.add(confLab);

    // ── 3 the action gate ──
    const actions = [["AUDIT", 0x94a3b8], ["WARN", 0xfbbf24], ["BLOCK", 0xf43f5e], ["ENCRYPT", 0x818cf8]].map(([n, c], i) => {
      const mat = additive(c as number, 0.05);
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.5, 0.15), mat);
      m.position.set(7.5, 0.6 + i * 0.7, 0);
      scene.add(m);
      const l = tag(n as string, `#${(c as number).toString(16).padStart(6, "0")}`, 180);
      l.position.set(7.5, 0.6 + i * 0.7, 0.2);
      scene.add(l);
      return mat;
    });

    // ── 4 the trace line and checkpoints ──
    const cps = [new THREE.Vector3(10, 1, -2), new THREE.Vector3(11.5, 1.6, 0), new THREE.Vector3(13, 1, 2)];
    const cpMats = cps.map(p => {
      const mat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.25 });
      const m = new THREE.Mesh(new THREE.OctahedronGeometry(0.35), mat);
      m.position.copy(p);
      scene.add(m);
      return mat;
    });
    const traceMat = new THREE.LineDashedMaterial({ color: A, dashSize: 0.25, gapSize: 0.15, transparent: true, opacity: 0 });
    const trace = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(7.5, 1.5, 0), ...cps]), traceMat);
    trace.computeLineDistances();
    scene.add(trace);

    // ── 5 the verdict seal ──
    const sealMat = new THREE.MeshStandardMaterial({ color: 0xb45309, emissive: A, emissiveIntensity: 0, metalness: 0.6, roughness: 0.3, transparent: true, opacity: 0.3 });
    const seal = new THREE.Mesh(new THREE.CylinderGeometry(0.9, 0.9, 0.18, 32), sealMat);
    seal.rotation.x = Math.PI / 2;
    seal.position.set(14.5, 2.2, 3);
    scene.add(seal);
    const sl = tag("VERDICT", "#fde68a", 180); sl.position.set(14.5, 3.4, 3); scene.add(sl);

    const anchors = [new THREE.Vector3(-6, 4.2, -4.2), new THREE.Vector3(3.6, 5.6, 0), new THREE.Vector3(7.5, 4.8, 0), new THREE.Vector3(10.5, 2.2, -2.5), new THREE.Vector3(14.5, 5.4, 3)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 64 : asp < 1.5 ? 33 : 28; };

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
      camera.position.set(Math.sin(yaw) * dist + 3, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(3, 1.8, 0);

      // 1 posts light; documents drift from the vault toward their post
      posts.forEach(p => { p.mat.opacity = 0.05 + level[0] * 0.85; if (!rm) p.ring.rotation.y += dt * 0.8 * level[0]; });
      const docOn = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      docs.forEach(d => {
        const u = rm ? 0.5 : ((t * 0.18 + d.o) % 1);
        d.m.position.lerpVectors(new THREE.Vector3(V.x, 1.6, V.z), d.post.clone().setY(1.6), u);
        if (!rm) d.m.rotation.y += dt;
        d.mat.opacity = docOn * (1 - Math.abs(u - 0.5) * 0.8);
        d.mat.emissiveIntensity = d.bad ? level[3] * 0.8 : 0.1;
      });
      // 2 the scan sweeps; the confidence bar fills
      scanMat.opacity = level[1] * 0.8;
      scan.position.y = rm ? 1.6 : 0.3 + ((t * 0.6) % 1) * 2.6;
      const h = 0.1 + level[1] * 2.6;
      bar.scale.y = h;
      bar.position.y = h / 2;
      barMat.opacity = 0.1 + level[1] * 0.8;
      // 3 action blocks light in order
      actions.forEach((m, i) => { m.opacity = 0.05 + THREE.MathUtils.clamp(level[2] * 4 - i, 0, 1) * 0.6; });
      // 4 the trace runs through the checkpoints
      traceMat.opacity = level[3] * 0.9;
      cpMats.forEach((m, i) => { const v = THREE.MathUtils.clamp(level[3] * 3 - i, 0, 1); m.opacity = 0.25 + v * 0.7; m.emissiveIntensity = v * 0.7; });
      // 5 the seal stamps down
      sealMat.opacity = 0.3 + level[4] * 0.7;
      sealMat.emissiveIntensity = level[4] * (rm ? 0.6 : 0.4 + pulse * 0.3);
      seal.position.y = 2.2 + (1 - level[4]) * 0.8;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#141006]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
