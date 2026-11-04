"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The dissection table": one raw log line floats over a table, cut into five
 * segments. Five coloured lenses (WHEN, WHO, WHERE, WHAT, HOW SURE) drop onto
 * their segment as the room is learned. Behind the table stand the formats as
 * monoliths (SYSLOG, KEY=VALUE, JSON, CSV/W3C), a normalisation funnel that
 * pulls four vendor names into one field, and finally a missing segment that
 * glows red: what the log never recorded. Decorative only.
 */
const SEGMENTS = [
  { text: "2026-11-04 09:14:22", lens: "WHEN", color: 0xfbbf24 },
  { text: "user=j.ward", lens: "WHO", color: 0x60a5fa },
  { text: "src=10.40.6.118 dst=10.40.2.15", lens: "WHERE", color: 0x34d399 },
  { text: "action=login result=failure", lens: "WHAT", color: 0xf472b6 },
  { text: "level=medium", lens: "HOW SURE", color: 0xa78bfa },
];
const FORMATS = ["SYSLOG", "KEY=VALUE", "JSON", "CSV / W3C"];

function textTex(text: string, color: string, w: number, h = 64, size = 32, bg?: string) {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const g = c.getContext("2d")!;
  if (bg) { g.fillStyle = bg; g.fillRect(0, 0, w, h); }
  g.fillStyle = color; g.font = `bold ${size}px monospace`; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, h / 2);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}
const sprite = (tex: THREE.Texture, w: number, h: number) => {
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  s.scale.set(w, h, 1);
  return s;
};

export default function DissectScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04070b, 26, 66);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xbfdbfe, 0x04070b, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-4, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x162536, 0x0c1622));

    // ── the table ──
    const table = new THREE.Mesh(new THREE.BoxGeometry(22, 0.4, 5), new THREE.MeshStandardMaterial({ color: 0x111c2b, metalness: 0.6, roughness: 0.3 }));
    table.position.set(0, 1, 2);
    scene.add(table);
    const tableGlow = additive(A, 0.05);
    const tg = new THREE.Mesh(new THREE.PlaneGeometry(22, 5), tableGlow);
    tg.rotation.x = -Math.PI / 2; tg.position.set(0, 1.22, 2);
    scene.add(tg);

    // ── the log line, cut into five segments, plus the missing one ──
    const widths = [4.2, 3, 5.2, 5, 2.6];
    let x = -11 + 0.3;
    const segs = SEGMENTS.map((s, i) => {
      const w = widths[i];
      const cx = x + w / 2;
      x += w + 0.25;
      const mat = new THREE.MeshBasicMaterial({ map: textTex(s.text, "#e2e8f0", Math.round(w * 110), 64, 24, "#0b1626"), transparent: true, opacity: 0.85 });
      const seg = new THREE.Mesh(new THREE.PlaneGeometry(w, 0.75), mat);
      seg.position.set(cx, 2.4, 2);
      scene.add(seg);
      const frameMat = new THREE.LineBasicMaterial({ color: s.color, transparent: true, opacity: 0.1 });
      const frame = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(w + 0.1, 0.85)), frameMat);
      frame.position.copy(seg.position);
      scene.add(frame);
      // the lens hangs above until its station is learned, then drops onto the segment
      const lens = new THREE.Mesh(new THREE.TorusGeometry(0.55, 0.07, 10, 40), new THREE.MeshBasicMaterial({ color: s.color, transparent: true, opacity: 0.25 }));
      scene.add(lens);
      const lensLab = sprite(textTex(s.lens, `#${s.color.toString(16).padStart(6, "0")}`, 260, 56, 30), 2.6, 0.56);
      scene.add(lensLab);
      return { cx, frameMat, lens, lensLab, lensLabMat: lensLab.material as THREE.SpriteMaterial };
    });
    const gapMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    const gap = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(2.4, 0.85)), gapMat);
    gap.position.set(x + 1.2, 2.4, 2);
    scene.add(gap);
    const gapLab = sprite(textTex("NOT LOGGED", "#fda4af", 300, 56, 30), 3, 0.56);
    gapLab.position.set(x + 1.2, 3.3, 2);
    scene.add(gapLab);
    const gapLabMat = gapLab.material as THREE.SpriteMaterial;

    // ── the format monoliths ──
    const monoliths = FORMATS.map((f, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(2.6, 4.2, 0.5), new THREE.MeshStandardMaterial({ color: 0x0f1a2a, metalness: 0.5, roughness: 0.4 }));
      m.position.set(-9 + i * 6, 2.1, -6);
      scene.add(m);
      const face = new THREE.MeshBasicMaterial({ map: textTex(f, "#cbd5e1", 300, 64, 34), transparent: true, opacity: 0.2 });
      const plate = new THREE.Mesh(new THREE.PlaneGeometry(2.4, 0.5), face);
      plate.position.set(-9 + i * 6, 3.6, -5.74);
      scene.add(plate);
      const stripe = additive(A, 0.05);
      const s = new THREE.Mesh(new THREE.PlaneGeometry(2.2, 0.05), stripe);
      s.position.set(-9 + i * 6, 0.6, -5.74);
      scene.add(s);
      return { face, stripe };
    });
    // JSON nesting: boxes inside boxes on the JSON monolith
    const nest = [1.8, 1.3, 0.8].map((sz, k) => {
      const mat = new THREE.LineBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0 });
      const b = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(sz, sz * 0.8)), mat);
      b.position.set(3, 1.9 - k * 0.05, -5.7);
      scene.add(b);
      return mat;
    });

    // ── the normalisation funnel: four vendor names fall into one field ──
    const names = ["srcip", "id.orig_h", "cIP", "ClientIP"].map((n, i) => {
      const s = sprite(textTex(n, "#94a3b8", 220, 56, 30), 2.2, 0.56);
      s.position.set(13 + (i % 2) * 2.4, 4.6 - Math.floor(i / 2) * 0.8, -3);
      scene.add(s);
      return { s, home: s.position.clone() };
    });
    const target = sprite(textTex("source.ip", "#34d399", 260, 56, 32), 2.6, 0.56);
    target.position.set(14.2, 1.6, -3);
    scene.add(target);
    const targetMat = target.material as THREE.SpriteMaterial;
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    halo.scale.set(5, 5, 1); halo.position.set(14.2, 1.6, -3.1);
    scene.add(halo);

    const anchors = [new THREE.Vector3(-8, 4.6, 2), new THREE.Vector3(-9, 5, -6), new THREE.Vector3(3, 5, -6), new THREE.Vector3(9, 5, -6), new THREE.Vector3(14.2, 5.6, -3), new THREE.Vector3(x + 1.2, 4.2, 2)];
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 54 : asp < 1.5 ? 32 : 27; };
    const tmp = new THREE.Vector3();

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
      camera.position.set(Math.sin(yaw) * dist + 1.5, dist * (portrait ? 0.62 : 0.4), Math.cos(yaw) * dist + 4);
      camera.lookAt(1.5, 2.2, 0);

      // 1 the lenses drop onto their segments
      segs.forEach((sg, i) => {
        const drop = THREE.MathUtils.smoothstep(level[0] * 5 - i * 0.6, 0, 1);
        sg.lens.position.set(sg.cx, THREE.MathUtils.lerp(4.6, 2.4, drop), 2.15);
        if (!rm) sg.lens.rotation.z += dt * 0.6;
        (sg.lens.material as THREE.MeshBasicMaterial).opacity = 0.25 + drop * 0.7;
        sg.frameMat.opacity = 0.1 + drop * 0.9;
        sg.lensLab.position.copy(sg.lens.position).add(tmp.set(0, 0.85, 0));
        sg.lensLabMat.opacity = 0.3 + drop * 0.7;
      });
      tableGlow.opacity = 0.05 + level[0] * 0.25;
      // 2-4 the format monoliths light: syslog and key=value, then JSON, then CSV
      const formatLevel = [level[1], level[1], level[2], level[3]];
      monoliths.forEach((m, i) => { m.face.opacity = 0.2 + formatLevel[i] * 0.8; m.stripe.opacity = 0.05 + formatLevel[i] * 0.85; });
      nest.forEach((m, k) => { m.opacity = level[2] * (0.9 - k * 0.2); });
      // 5 vendor names fall into source.ip
      names.forEach((n, i) => {
        const pull = THREE.MathUtils.smoothstep(level[4], 0, 1);
        const wob = rm ? 0 : Math.sin(t * 2 + i) * 0.1;
        n.s.position.lerpVectors(n.home, target.position, pull * 0.7);
        n.s.position.y += wob * (1 - pull);
        (n.s.material as THREE.SpriteMaterial).opacity = 0.9 - pull * 0.6;
      });
      targetMat.opacity = 0.2 + level[4] * 0.8;
      (halo.material as THREE.SpriteMaterial).opacity = level[4] * 0.5;
      // 6 the missing segment
      gapMat.opacity = Math.max(level[5], stations[5]?.status === "open" ? 0.4 * pulse : 0);
      gapLabMat.opacity = gapMat.opacity;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#061019]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
