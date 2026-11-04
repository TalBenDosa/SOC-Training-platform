"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Lines of sight": a cut-away of a company's stack. Every sensor casts a
 * translucent vision cone showing what it can see. On the left, hosts with
 * agent halos (and a hypervisor slab beneath them with none); in the middle,
 * an inline gate on the wire beside a sensor on a tap; then a WAF shield in
 * front of an app tower; then an envelope gate for mail beside a scanner that
 * reaches out; and above it all a cloud identity layer, with every product's
 * log stream falling into a SIEM well at the back. Stations switch each layer
 * on. Decorative only.
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

export default function SightLinesScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x080702, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x080702, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x422006, 0x1c1406));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3a3424, emissive: 0x100d05, metalness: 0.55, roughness: 0.4 });
    const cone = (pos: THREE.Vector3, color: THREE.Color, r = 1.6, h = 3, down = true) => {
      const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false });
      const m = new THREE.Mesh(new THREE.ConeGeometry(r, h, 24, 1, true), mat);
      m.position.copy(pos);
      if (!down) m.rotation.z = Math.PI;
      scene.add(m);
      return mat;
    };

    // ── 1 the floor of the stack: inline vs out-of-band markers ──
    const stripMat = additive(A, 0.05);
    const strip = new THREE.Mesh(new THREE.BoxGeometry(26, 0.06, 0.3), stripMat);
    strip.position.set(0, 0.05, 3.6);
    scene.add(strip);
    const inLab = tag("INLINE", "#fde68a", 160); inLab.position.set(-12, 0.6, 3.6); scene.add(inLab);

    // ── 2 hosts with agent halos, a hypervisor slab below with none ──
    const hyper = new THREE.Mesh(new THREE.BoxGeometry(5, 0.5, 3), metal());
    hyper.position.set(-10, 0.25, 0);
    scene.add(hyper);
    const hypLab = tag("HYPERVISOR", "#fecdd3", 240); hypLab.position.set(-10, 0.9, 1.8); scene.add(hypLab);
    const halos = [-11.5, -10, -8.5].map(x => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(1, 1.4, 1), metal());
      m.position.set(x, 1.2, 0);
      scene.add(m);
      const mat = additive(A, 0);
      const h = new THREE.Mesh(new THREE.TorusGeometry(0.75, 0.05, 8, 32), mat);
      h.rotation.x = Math.PI / 2;
      h.position.set(x, 2.1, 0);
      scene.add(h);
      return mat;
    });
    const hyperMat = additive(Wn, 0);
    const hyperGlow = new THREE.Mesh(new THREE.BoxGeometry(5.1, 0.08, 3.1), hyperMat);
    hyperGlow.position.set(-10, 0.52, 0);
    scene.add(hyperGlow);

    // ── 3 the wire: an inline gate and a sensor on a tap ──
    const wire = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, 7, 8), metal());
    wire.rotation.z = Math.PI / 2;
    wire.position.set(-3, 1.2, 0);
    scene.add(wire);
    const gateMat = additive(A, 0.05);
    const gate = new THREE.Mesh(new THREE.TorusGeometry(0.8, 0.12, 8, 6), gateMat);
    gate.rotation.y = Math.PI / 2;
    gate.position.set(-4, 1.2, 0);
    scene.add(gate);
    const ngLab = tag("NGFW/IPS", "#fde68a", 200); ngLab.position.set(-4, 2.5, 0); scene.add(ngLab);
    const tap = new THREE.Mesh(new THREE.SphereGeometry(0.4, 16, 12), metal());
    tap.position.set(-2, 0.4, 1.6);
    scene.add(tap);
    const tapLine = new THREE.LineDashedMaterial({ color: B, dashSize: 0.2, gapSize: 0.15, transparent: true, opacity: 0 });
    const tl = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-2, 1.2, 0), new THREE.Vector3(-2, 0.4, 1.6)]), tapLine);
    tl.computeLineDistances();
    scene.add(tl);
    const idsLab = tag("IDS / NDR", "#bae6fd", 220); idsLab.position.set(-2, 1.1, 2.4); scene.add(idsLab);
    const wireCone = cone(new THREE.Vector3(-4, 3.4, 0), A, 1.2, 2.2);
    const pkt = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    pkt.scale.set(0.5, 0.5, 1);
    scene.add(pkt);

    // ── 4 the app tower and its WAF shield ──
    const app = new THREE.Mesh(new THREE.BoxGeometry(1.4, 3, 1.4), metal());
    app.position.set(3, 1.5, 0);
    scene.add(app);
    const wafMat = additive(A, 0);
    const waf = new THREE.Mesh(new THREE.CircleGeometry(1.2, 6), wafMat);
    waf.position.set(3, 1.6, 0.9);
    scene.add(waf);
    const wafLab = tag("WAF", "#fde68a", 120); wafLab.position.set(3, 3.4, 0.9); scene.add(wafLab);

    // ── 5 the mail gate and the scanner that reaches out ──
    const env = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.9, 0.12), metal());
    env.position.set(7, 1.4, -1.2);
    scene.add(env);
    const envMat = additive(A, 0);
    const envGlow = new THREE.Mesh(new THREE.BoxGeometry(1.5, 1, 0.05), envMat);
    envGlow.position.set(7, 1.4, -1.1);
    scene.add(envGlow);
    const mailLab = tag("EMAIL GW", "#fde68a", 200); mailLab.position.set(7, 2.3, -1.2); scene.add(mailLab);
    const scanner = new THREE.Mesh(new THREE.ConeGeometry(0.5, 1.2, 4), metal());
    scanner.position.set(8.5, 0.8, 1.6);
    scanner.rotation.z = Math.PI / 2;
    scene.add(scanner);
    const probes = Array.from({ length: 5 }, () => {
      const mat = new THREE.MeshBasicMaterial({ color: B, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.05, 0.05), mat);
      scene.add(m);
      return { m, mat };
    });
    const scanLab = tag("SCANNER", "#bae6fd", 180); scanLab.position.set(8.5, 1.7, 1.6); scene.add(scanLab);

    // ── 6 the cloud identity layer and the SIEM well ──
    const cloud = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: B, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    cloud.scale.set(9, 2.6, 1);
    cloud.position.set(0, 7.5, -3);
    scene.add(cloud);
    const idLab = tag("IDENTITY / CASB", "#bae6fd", 300); idLab.position.set(0, 7.5, -3); scene.add(idLab);
    const well = new THREE.Mesh(new THREE.CylinderGeometry(2, 1.2, 1.2, 32, 1, true), new THREE.MeshStandardMaterial({ color: 0x3a3424, side: THREE.DoubleSide }));
    well.position.set(12, 0.6, -2);
    scene.add(well);
    const wellMat = additive(A, 0);
    const wellTop = new THREE.Mesh(new THREE.CircleGeometry(1.95, 32), wellMat);
    wellTop.rotation.x = -Math.PI / 2;
    wellTop.position.set(12, 1.15, -2);
    scene.add(wellTop);
    const siemLab = tag("SIEM", "#fde68a", 120); siemLab.position.set(12, 2.1, -2); scene.add(siemLab);
    const sources = [new THREE.Vector3(-10, 2.4, 0), new THREE.Vector3(-4, 2.2, 0), new THREE.Vector3(3, 3.2, 0), new THREE.Vector3(7, 2, -1.2), new THREE.Vector3(0, 7, -3)];
    const drops = Array.from({ length: 10 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i % 2 ? A : B, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.35, 0.35, 1);
      scene.add(s);
      return { s, src: sources[i % sources.length], o: i / 10 };
    });

    const anchors = [new THREE.Vector3(-12, 1.4, 3.6), new THREE.Vector3(-10, 3.4, 0), new THREE.Vector3(-3.6, 4.8, 0), new THREE.Vector3(3, 4.6, 0), new THREE.Vector3(8, 3.6, 0), new THREE.Vector3(10, 7.6, -3)];
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 72 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 6; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0.5, 2.4, 0);

      // 1 the inline strip
      stripMat.opacity = 0.05 + level[0] * 0.7;
      // 2 agent halos light; the hypervisor below them glows red: no agent there
      halos.forEach((m, i) => { m.opacity = THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1) * 0.85; });
      hyperMat.opacity = level[1] * (rm ? 0.7 : 0.4 + pulse * 0.4);
      // 3 a packet runs the wire through the gate; a copy drops to the tap
      gateMat.opacity = 0.05 + level[2] * 0.85;
      wireCone.opacity = level[2] * 0.12;
      tapLine.opacity = level[2] * 0.9;
      const u = rm ? 0.5 : ((t * 0.4) % 1);
      pkt.position.set(-6.5 + u * 7, 1.2, 0);
      (pkt.material as THREE.SpriteMaterial).opacity = Math.max(level[2], stations[2]?.status === "open" ? 0.4 : 0);
      // 4 WAF shield
      wafMat.opacity = level[3] * (rm ? 0.6 : 0.35 + pulse * 0.3);
      // 5 mail gate glows; the scanner fires probes outward
      envMat.opacity = level[4] * 0.6;
      probes.forEach((p, i) => {
        const v = rm ? 0.5 : ((t * 0.7 + i / 5) % 1);
        p.m.position.set(9 + v * 4, 0.8, 1.6 + (i - 2) * 0.5 * v);
        p.mat.opacity = Math.max(level[4], stations[4]?.status === "open" ? 0.4 : 0) * (1 - v);
      });
      // 6 the identity cloud and every log stream falling into the SIEM
      (cloud.material as THREE.SpriteMaterial).opacity = level[5] * 0.5;
      (idLab.material as THREE.SpriteMaterial).opacity = 0.2 + level[5] * 0.8;
      wellMat.opacity = level[5] * (rm ? 0.6 : 0.35 + pulse * 0.3);
      drops.forEach(d => {
        const v = rm ? d.o : ((t * 0.2 + d.o) % 1);
        const dest = new THREE.Vector3(12, 1.2, -2);
        d.s.position.lerpVectors(d.src, dest, v);
        d.s.position.y += Math.sin(v * Math.PI) * 2;
        (d.s.material as THREE.SpriteMaterial).opacity = level[5] * 0.8;
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
