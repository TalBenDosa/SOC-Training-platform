"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The intake": six source nodes on the left send packets down pipes of
 * different kinds (a dotted UDP line, a solid TCP line, a shielded TLS tube)
 * into a collector. One source's pipe is dark with a broken link until its
 * station clears. From the collector, a grey blob rolls into a parser gear and
 * comes out as separate coloured field chips, which drop through a schema
 * funnel into the SIEM vault. Stations switch each part on. Decorative only.
 */
const SOURCES = ["ENDPOINT", "NETWORK", "IDENTITY", "CLOUD", "APP", "SECURITY"];

function tag(text: string, color: string, w = 220) {
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

export default function IntakeScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x07040b, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xf3e8ff, 0x07040b, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x3b0764, 0x1e0a33));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2e2340, emissive: 0x0d0814, metalness: 0.55, roughness: 0.4 });

    // the collector
    const COL = new THREE.Vector3(-2, 1.2, 0);
    const col = new THREE.Mesh(new THREE.BoxGeometry(1.8, 2.4, 1.8), metal());
    col.position.copy(COL);
    scene.add(col);
    const cl = tag("COLLECTOR", "#f3e8ff", 220); cl.position.set(COL.x, 2.9, COL.z); scene.add(cl);

    // ── 1 sources and their pipes ──
    const srcs = SOURCES.map((n, i) => {
      const p = new THREE.Vector3(-12, 0.6, -5 + i * 2);
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.4, 16, 12), new THREE.MeshStandardMaterial({ color: 0x2e2340, emissive: A, emissiveIntensity: 0 }));
      m.position.copy(p);
      scene.add(m);
      const l = tag(n, "#e9d5ff", 220);
      l.position.set(p.x - 1.7, p.y, p.z);
      scene.add(l);
      const kind = i % 3; // 0 udp dotted, 1 tcp solid, 2 tls tube
      const pts = [p.clone(), new THREE.Vector3(-6, 0.8, p.z * 0.4), COL.clone().setY(0.9)];
      const curve = new THREE.CatmullRomCurve3(pts);
      let mat: THREE.Material;
      if (kind === 2) {
        mat = new THREE.MeshStandardMaterial({ color: B, transparent: true, opacity: 0.08 });
        scene.add(new THREE.Mesh(new THREE.TubeGeometry(curve, 30, 0.12, 8), mat));
      } else {
        const lm = kind === 0
          ? new THREE.LineDashedMaterial({ color: A, dashSize: 0.15, gapSize: 0.2, transparent: true, opacity: 0.1 })
          : new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.1 });
        const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(40)), lm);
        line.computeLineDistances();
        scene.add(line);
        mat = lm;
      }
      const pkt = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      pkt.scale.set(0.35, 0.35, 1);
      scene.add(pkt);
      return { m, mat, curve, pkt, silent: i === 4, o: i / 6 };
    });
    const transLab = tag("UDP · TCP · TLS", "#e9d5ff", 280); transLab.position.set(-7, 2.4, 0); scene.add(transLab);

    // ── 3 the parser gear, field chips and the schema funnel ──
    const gearMat = new THREE.MeshStandardMaterial({ color: 0x2e2340, emissive: B, emissiveIntensity: 0 });
    const gear = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.25, 8, 12), gearMat);
    gear.position.set(2.5, 1.6, 0);
    scene.add(gear);
    const pl = tag("PARSER", "#d1fae5", 160); pl.position.set(2.5, 3, 0); scene.add(pl);
    const blobMat = new THREE.MeshStandardMaterial({ color: 0x94a3b8, transparent: true, opacity: 0 });
    const blob = new THREE.Mesh(new THREE.SphereGeometry(0.35, 12, 10), blobMat);
    scene.add(blob);
    const chipCols = [0xf472b6, 0x60a5fa, 0xfbbf24, 0x34d399];
    const chips = chipCols.map((c, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: c, emissive: c, emissiveIntensity: 0.4, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.18, 0.18), mat);
      scene.add(m);
      return { m, mat, i };
    });
    const funnelMat = additive(A, 0.05);
    const funnel = new THREE.Mesh(new THREE.ConeGeometry(1.2, 1.8, 24, 1, true), funnelMat);
    funnel.rotation.x = Math.PI;
    funnel.position.set(6.5, 2.2, 0);
    scene.add(funnel);
    const fl = tag("source.ip", "#f3e8ff", 200); fl.position.set(6.5, 3.5, 0); (fl.material as THREE.SpriteMaterial).opacity = 0; scene.add(fl);

    // ── 4 the SIEM vault and a wire-format card ──
    const vault = new THREE.Mesh(new THREE.CylinderGeometry(1.4, 1.4, 1.6, 24), metal());
    vault.position.set(6.5, 0.8, 0);
    scene.add(vault);
    const vl = tag("SIEM", "#f3e8ff", 120); vl.position.set(6.5, 0.8, 1.6); scene.add(vl);
    const cefMat = new THREE.MeshStandardMaterial({ color: 0x1e0a33, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.2 });
    const cef = new THREE.Mesh(new THREE.BoxGeometry(3.6, 0.8, 0.05), cefMat);
    cef.position.set(10.5, 2.4, -0.5);
    scene.add(cef);
    const cefLab = tag("CEF:0|Vendor|Product|...|sev|", "#f3e8ff", 420);
    cefLab.position.set(10.5, 2.4, -0.4);
    (cefLab.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(cefLab);

    const anchors = [new THREE.Vector3(-12, 3, 0), new THREE.Vector3(-4.6, 4.2, 4), new THREE.Vector3(2.5, 4.4, 0), new THREE.Vector3(10.5, 4, -0.5)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 72 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.6 : 0.44) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(-1, 1.6, 0);

      const fixed = level[1] > 0.5;
      // 1 pipes light; packets flow; one source is silent until station 2 clears
      srcs.forEach(s => {
        const dark = s.silent && !fixed;
        (s.mat as THREE.Material & { opacity: number }).opacity = dark ? 0.05 : 0.1 + level[0] * 0.6;
        (s.m.material as THREE.MeshStandardMaterial).emissive.copy(dark ? Wn : A);
        (s.m.material as THREE.MeshStandardMaterial).emissiveIntensity = dark ? level[0] * (rm ? 0.8 : 0.3 + pulse * 0.6) : level[0] * 0.6;
        const u = rm ? 0.5 : ((t * 0.25 + s.o) % 1);
        s.curve.getPointAt(u, s.pkt.position);
        (s.pkt.material as THREE.SpriteMaterial).opacity = dark ? 0 : Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      });
      // 3 the blob enters the gear and leaves as chips that drop into the funnel
      gearMat.emissiveIntensity = level[2] * 0.6;
      if (!rm) gear.rotation.z += dt * (0.3 + level[2] * 2);
      const v = rm ? 0.3 : ((t * 0.3) % 1);
      blob.position.set(-1 + Math.min(v, 0.5) * 7, 1.6, 0);
      blobMat.opacity = v < 0.5 ? Math.max(level[1], level[2]) * 0.9 : 0;
      chips.forEach(c => {
        const w = Math.max(0, v - 0.5) * 2;
        c.m.position.set(2.5 + w * 4 + (c.i - 1.5) * 0.3 * (1 - w), 1.6 + (c.i - 1.5) * 0.3 * (1 - w) + w * 0.8, 0);
        c.mat.opacity = v >= 0.5 ? level[2] : 0;
      });
      funnelMat.opacity = 0.05 + level[2] * 0.4;
      (fl.material as THREE.SpriteMaterial).opacity = level[2];
      // 4 the wire-format card lights
      cefMat.opacity = 0.2 + level[3] * 0.7;
      cefMat.emissiveIntensity = level[3] * 0.4;
      (cefLab.material as THREE.SpriteMaterial).opacity = level[3];

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
            <span className="block whitespace-nowrap rounded-md border bg-[#120a1c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
