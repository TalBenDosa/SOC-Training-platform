"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The bait shop": six lures hang on hooks in a ring around one workstation.
 * A macro document sealed by a padlock; a fake CAPTCHA panel whose clipboard
 * arrow pours a command into a Run box; two wallet strings that look alike
 * but swap their middles; a stack of search results whose top two glow as
 * poisoned; a disc image with its zone tag; and a browser tab whose spinning
 * gear sends pulses to a relay. Each lure's hook line lights as its station
 * clears. Stations switch each part on. Decorative only.
 */
function tag(text: string, color: string, w = 260, h = 56, font = 28) {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = `bold ${font}px monospace`; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, h / 2);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, h / 100, 1);
  return s;
}

export default function BaitShopScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x050802, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xecfccb, 0x050802, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1a2e05, 0x0c1503));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2c3a20, emissive: 0x0a1005, metalness: 0.55, roughness: 0.4 });

    // the workstation at the centre, and six hooks around it
    const desk = new THREE.Mesh(new THREE.BoxGeometry(2.4, 0.2, 1.4), metal());
    desk.position.set(0, 1, 0);
    scene.add(desk);
    const mon = new THREE.Mesh(new THREE.BoxGeometry(1.8, 1.1, 0.08), new THREE.MeshStandardMaterial({ color: 0x1a2410, emissive: A, emissiveIntensity: 0.3 }));
    mon.position.set(0, 1.7, -0.4);
    scene.add(mon);
    const R = 12;
    const spots = Array.from({ length: 6 }, (_, i) => {
      const a = Math.PI * (0.92 - i * 0.168);
      return new THREE.Vector3(Math.cos(a) * R, 3.4, -Math.sin(a) * R * 0.55 + 1);
    });
    const hooks = spots.map(p => {
      const mat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.1 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(p.x, 6.5, p.z), p.clone().setY(p.y + 0.9)]), mat));
      const lineMat = new THREE.LineDashedMaterial({ color: Wn, dashSize: 0.3, gapSize: 0.2, transparent: true, opacity: 0 });
      const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints([p.clone(), new THREE.Vector3(0, 1.7, 0)]), lineMat);
      l.computeLineDistances();
      scene.add(l);
      return { mat, lineMat };
    });

    // ── 1 the macro document, padlocked ──
    const doc = new THREE.Mesh(new THREE.BoxGeometry(1, 1.3, 0.06), new THREE.MeshStandardMaterial({ color: 0x2b579a }));
    doc.position.copy(spots[0]);
    scene.add(doc);
    const lockMat = additive(A, 0);
    const lock = new THREE.Mesh(new THREE.TorusGeometry(0.25, 0.07, 8, 16, Math.PI), lockMat);
    lock.position.copy(spots[0]).add(new THREE.Vector3(0, 0.2, 0.08));
    scene.add(lock);
    const lockBody = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.4, 0.06), lockMat);
    lockBody.position.copy(spots[0]).add(new THREE.Vector3(0, -0.15, 0.08));
    scene.add(lockBody);

    // ── 2 the fake CAPTCHA and its clipboard pour ──
    const cap = tag("I'm not a robot", "#ecfccb", 300, 60, 26);
    cap.scale.multiplyScalar(1.7);
    cap.position.copy(spots[1]);
    scene.add(cap);
    const capFrame = new THREE.Mesh(new THREE.PlaneGeometry(5.4, 1.4), new THREE.MeshBasicMaterial({ color: 0x1a2410, transparent: true, opacity: 0.8, depthWrite: false }));
    capFrame.position.copy(spots[1]).add(new THREE.Vector3(0, -0.3, -0.05));
    capFrame.renderOrder = -1;
    scene.add(capFrame);
    const runTag = tag("Win+R  Ctrl+V  Enter", "#fecdd3", 340, 50, 22);
    runTag.scale.multiplyScalar(1.7);
    runTag.position.copy(spots[1]).add(new THREE.Vector3(0, -1.1, 0));
    (runTag.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(runTag);

    // ── 3 the two wallet strings ──
    const w1 = tag("TQ7n4Kx9...G5jR", "#ecfccb", 320, 50, 24);
    w1.scale.multiplyScalar(1.7);
    w1.position.copy(spots[2]).add(new THREE.Vector3(0, 0.5, 0));
    scene.add(w1);
    const w2 = tag("TQ7n9Hq2...G5jR", "#fecdd3", 320, 50, 24);
    w2.scale.multiplyScalar(1.7);
    w2.position.copy(spots[2]).add(new THREE.Vector3(0, -0.5, 0));
    (w2.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(w2);

    // ── 4 the search results ──
    const results = [0, 1, 2, 3].map(i => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x1a2410, emissive: i < 2 ? Wn : A, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(2.4, 0.3, 0.05), mat);
      m.position.copy(spots[3]).add(new THREE.Vector3(0, 0.6 - i * 0.42, 0));
      scene.add(m);
      return mat;
    });

    // ── 5 the disc and its zone tag ──
    const disc = new THREE.Mesh(new THREE.RingGeometry(0.15, 0.85, 40), new THREE.MeshStandardMaterial({ color: 0xd9f99d, metalness: 0.9, roughness: 0.15, side: THREE.DoubleSide }));
    disc.position.copy(spots[4]);
    scene.add(disc);
    const zone = tag("ZoneId=3", "#fde68a", 200, 50, 24);
    zone.scale.multiplyScalar(1.7);
    zone.position.copy(spots[4]).add(new THREE.Vector3(0.9, 0.7, 0));
    (zone.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(zone);

    // ── 6 the mining tab ──
    const tab = new THREE.Mesh(new THREE.PlaneGeometry(2.2, 1.4), new THREE.MeshBasicMaterial({ color: 0x1a2410, transparent: true, opacity: 0.85, side: THREE.DoubleSide }));
    tab.position.copy(spots[5]);
    scene.add(tab);
    const gearMat = additive(B, 0);
    const gear = new THREE.Mesh(new THREE.TorusGeometry(0.4, 0.1, 6, 12), gearMat);
    gear.position.copy(spots[5]).add(new THREE.Vector3(0, 0, 0.05));
    scene.add(gear);
    const relay = new THREE.Mesh(new THREE.OctahedronGeometry(0.5), new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.2 }));
    relay.position.copy(spots[5]).add(new THREE.Vector3(2.4, 2, -1));
    scene.add(relay);
    const shares = Array.from({ length: 4 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: B, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.35, 0.35, 1);
      scene.add(s);
      return s;
    });

    const anchors = spots.map(p => p.clone().add(new THREE.Vector3(0, 1.5, 0)));
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 34 : 29; };

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
      camera.lookAt(0, 2.6, -1);

      hooks.forEach((h, i) => {
        h.mat.opacity = 0.1 + level[i] * 0.6;
        h.lineMat.opacity = stations[i]?.status === "open" ? 0.3 + pulse * 0.4 : 0;
      });
      // 1 the padlock closes over the macro
      lockMat.opacity = level[0] * 0.9;
      // 2 the CAPTCHA's real instructions appear
      (runTag.material as THREE.SpriteMaterial).opacity = level[1];
      // 3 the second wallet string fades in, the swap revealed
      (w2.material as THREE.SpriteMaterial).opacity = level[2] * (rm ? 1 : 0.6 + pulse * 0.4);
      // 4 the poisoned results glow red, the real ones green
      results.forEach((m, i) => { m.emissiveIntensity = level[3] * (i < 2 ? 0.7 : 0.35); });
      // 5 the disc spins; its zone tag appears
      if (!rm) disc.rotation.z += dt * 1.5 * (0.2 + level[4]);
      (zone.material as THREE.SpriteMaterial).opacity = level[4];
      // 6 the gear turns and shares fly to the relay
      gearMat.opacity = Math.max(level[5], stations[5]?.status === "open" ? 0.4 : 0);
      if (!rm) gear.rotation.z += dt * 3;
      (relay.material as THREE.MeshStandardMaterial).opacity = 0.2 + level[5] * 0.7;
      (relay.material as THREE.MeshStandardMaterial).emissiveIntensity = level[5] * 0.8;
      shares.forEach((s, i) => {
        const v = rm ? i / 4 : ((t * 0.5 + i / 4) % 1);
        s.position.lerpVectors(gear.position, relay.position, v);
        (s.material as THREE.SpriteMaterial).opacity = gearMat.opacity * 0.9;
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
            <span className="block whitespace-nowrap rounded-md border bg-[#0c1405]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
