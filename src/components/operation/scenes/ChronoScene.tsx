"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The time hall": three world clocks (UTC, Tel Aviv, New York) over a long
 * timeline track. Event beads from three sources (firewall, DC, EDR) start
 * jumbled along the track; as stations clear, the clock faces light, the
 * zone clocks start turning in step, an NTP time server syncs the source
 * towers with beams, the beads slide into their true order, and finally a
 * dwell-time bracket spans the first compromise to the first detection.
 * Decorative only.
 */
const SOURCES = [
  { name: "FIREWALL", color: 0xf97316, skew: 0.9 },
  { name: "DC01", color: 0x38bdf8, skew: 0 },
  { name: "EDR", color: 0xa78bfa, skew: -0.6 },
];
// true times along the track (x), by source
const EVENTS = [[-9, 0], [-5.5, 2], [-3, 1], [0.5, 0], [2.5, 2], [5, 1], [8.5, 0]] as const;

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

export default function ChronoScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05070d, 26, 66);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xfde68a, 0x05070d, 0.7));
    const key = new THREE.DirectionalLight(0xfff7e0, 1);
    key.position.set(-4, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x2a2414, 0x16130b));

    // ── 1/2 three world clocks ──
    const clocks = [
      { name: "UTC", x: -6, offset: 0 },
      { name: "TEL AVIV +2", x: 0, offset: 2 },
      { name: "NEW YORK -5", x: 6, offset: -5 },
    ].map(c => {
      const g = new THREE.Group();
      g.position.set(c.x, 6.4, -5);
      scene.add(g);
      const faceMat = new THREE.MeshBasicMaterial({ color: 0x1a1608, transparent: true, opacity: 0.9 });
      g.add(new THREE.Mesh(new THREE.CircleGeometry(1.8, 48), faceMat));
      const rimMat = additive(A, 0.15);
      g.add(new THREE.Mesh(new THREE.RingGeometry(1.8, 1.95, 48), rimMat));
      for (let h = 0; h < 12; h++) {
        const a = (h / 12) * Math.PI * 2;
        const tick = new THREE.Mesh(new THREE.PlaneGeometry(0.06, 0.25), rimMat);
        tick.position.set(Math.sin(a) * 1.6, Math.cos(a) * 1.6, 0.01);
        tick.rotation.z = -a;
        g.add(tick);
      }
      const handMat = new THREE.MeshBasicMaterial({ color: 0xfef3c7, transparent: true, opacity: 0.4 });
      const hour = new THREE.Mesh(new THREE.PlaneGeometry(0.12, 0.9), handMat);
      hour.geometry.translate(0, 0.45, 0);
      hour.position.z = 0.02;
      g.add(hour);
      const minute = new THREE.Mesh(new THREE.PlaneGeometry(0.07, 1.4), handMat);
      minute.geometry.translate(0, 0.7, 0);
      minute.position.z = 0.03;
      g.add(minute);
      const lab = tag(c.name, "#fde68a", 300);
      lab.position.set(c.x, 4.1, -5);
      scene.add(lab);
      return { rimMat, handMat, hour, minute, offset: c.offset, lab: lab.material as THREE.SpriteMaterial };
    });

    // ── 3 the NTP server and the source towers ──
    const ntp = new THREE.Mesh(new THREE.CylinderGeometry(0.7, 0.9, 3, 16), new THREE.MeshStandardMaterial({ color: 0x2a2414, metalness: 0.6, roughness: 0.3 }));
    ntp.position.set(-13, 1.5, 0);
    scene.add(ntp);
    const ntpLab = tag("NTP", "#fde68a");
    ntpLab.position.set(-13, 3.6, 0);
    scene.add(ntpLab);
    const towers = SOURCES.map((s, i) => {
      const z = -2 + i * 2;
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.9, 2, 0.9), new THREE.MeshStandardMaterial({ color: 0x1c1a14, metalness: 0.5 }));
      m.position.set(-11, 1, z);
      scene.add(m);
      const lamp = additive(s.color, 0.3);
      const top = new THREE.Mesh(new THREE.BoxGeometry(1, 0.15, 1), lamp);
      top.position.set(-11, 2.05, z);
      scene.add(top);
      const lab = tag(s.name, `#${s.color.toString(16).padStart(6, "0")}`);
      lab.position.set(-11, 2.6, z);
      scene.add(lab);
      const beamMat = new THREE.LineBasicMaterial({ color: 0xfde68a, transparent: true, opacity: 0 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-13, 3, 0), new THREE.Vector3(-11, 2.1, z)]), beamMat));
      return { lamp, beamMat, z };
    });

    // ── 4 the timeline track and the event beads ──
    const track = new THREE.Mesh(new THREE.BoxGeometry(22, 0.12, 0.5), new THREE.MeshStandardMaterial({ color: 0x2a2414, metalness: 0.6 }));
    track.position.set(0, 0.7, 2.5);
    scene.add(track);
    const trackGlow = additive(A, 0.05);
    const tg = new THREE.Mesh(new THREE.PlaneGeometry(22, 0.5), trackGlow);
    tg.rotation.x = -Math.PI / 2; tg.position.set(0, 0.78, 2.5);
    scene.add(tg);
    const beads = EVENTS.map(([x, src], i) => {
      const mat = new THREE.MeshStandardMaterial({ color: SOURCES[src].color, emissive: SOURCES[src].color, emissiveIntensity: 0.4 });
      const b = new THREE.Mesh(new THREE.SphereGeometry(0.32, 16, 12), mat);
      scene.add(b);
      // the jumbled start: each source's skew plus a deliberately misleading shuffle
      const jumbled = x + SOURCES[src].skew * 4 + (i % 2 ? 2.4 : -2.4);
      return { b, x, jumbled, src };
    });

    // ── 5 the dwell-time bracket ──
    const bracketMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(-9, 1.4, 2.5), new THREE.Vector3(-9, 1.9, 2.5), new THREE.Vector3(8.5, 1.9, 2.5), new THREE.Vector3(8.5, 1.4, 2.5),
    ]), bracketMat));
    const dwell = tag("DWELL TIME", "#fda4af", 300);
    dwell.position.set(0, 2.5, 2.5);
    scene.add(dwell);
    const dwellMat = dwell.material as THREE.SpriteMaterial;
    const sun = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0xfde68a, transparent: true, opacity: 0.15, blending: THREE.AdditiveBlending, depthWrite: false }));
    sun.scale.set(14, 14, 1); sun.position.set(0, 6.4, -6);
    scene.add(sun);

    const anchors = [new THREE.Vector3(-6, 8.8, -5), new THREE.Vector3(6, 8.8, -5), new THREE.Vector3(-13, 4.4, 0), new THREE.Vector3(0, 1.6, 4), new THREE.Vector3(0, 3.3, 2.5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 26, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 52 : asp < 1.5 ? 31 : 26; };

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.36) + 2, Math.cos(yaw) * dist + 3);
      camera.lookAt(-0.5, 3.4, 0);

      // 1 the faces light; 2 the zone clocks run in step, offset by their zone
      const base = rm ? 9.25 : 9.25 + t * 0.02; // hours
      clocks.forEach((c, i) => {
        c.rimMat.opacity = 0.15 + level[0] * 0.8;
        c.handMat.opacity = 0.35 + (i === 0 ? level[0] : level[1]) * 0.65;
        c.lab.opacity = 0.35 + (i === 0 ? level[0] : level[1]) * 0.65;
        const h = base + c.offset;
        c.hour.rotation.z = -(h % 12) / 12 * Math.PI * 2;
        c.minute.rotation.z = -((h % 1) * 60) / 60 * Math.PI * 2;
      });
      (sun.material as THREE.SpriteMaterial).opacity = 0.12 + level[1] * 0.25;
      // 3 NTP syncs the towers
      towers.forEach(tw => { tw.beamMat.opacity = level[2] * 0.9; tw.lamp.opacity = 0.3 + level[2] * 0.6; });
      // 4 beads slide from jumbled to true order once the timeline is built
      const order = THREE.MathUtils.smoothstep(Math.max(level[2] * 0.5, level[3]), 0, 1);
      beads.forEach((bd, i) => {
        const x = THREE.MathUtils.lerp(bd.jumbled, bd.x, order);
        bd.b.position.set(x, 1.1 + (rm ? 0 : Math.sin(t * 2 + i) * 0.05), 2.5);
      });
      trackGlow.opacity = 0.05 + level[3] * 0.4;
      // 5 the dwell-time bracket
      bracketMat.opacity = level[4];
      dwellMat.opacity = level[4];

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0f0d06]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
