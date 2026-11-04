"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The identity gate": a ring gate (authentication) in front of a row of
 * doors (authorization). Three factor pillars stand beside it: KNOW, HAVE,
 * ARE. Through the gate, session tokens flow as coins to the apps beyond; one
 * red coin slips off to an attacker until a revoke beam shatters it. A phone
 * floats above, flooding push prompts; behind, four towers for the account
 * types, with a stream of logon events. Stations switch each part on.
 * Decorative only.
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

export default function IdGateScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05060d, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xc7d2fe, 0x05060d, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-5, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1e1b4b, 0x12102e));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2a2858, emissive: 0x100e2e, metalness: 0.55, roughness: 0.4 });

    // ── 1 the gate (authentication) and the doors (authorization) ──
    const gateMat = additive(A, 0.15);
    const gate = new THREE.Mesh(new THREE.TorusGeometry(2.6, 0.18, 12, 64), gateMat);
    gate.position.set(-6, 2.9, 1);
    gate.rotation.y = Math.PI / 2;
    scene.add(gate);
    const gateLab = tag("AUTHENTICATE", "#c7d2fe", 300);
    gateLab.position.set(-6, 6.1, 1);
    scene.add(gateLab);
    const doors = [0, 1, 2].map(i => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.2, 2.6, 1.4), metal());
      m.position.set(-1.5, 1.3, -2 + i * 2.2);
      scene.add(m);
      const lamp = additive(i === 1 ? Wn : 0x34d399, 0.1);
      const l = new THREE.Mesh(new THREE.PlaneGeometry(0.9, 0.12), lamp);
      l.position.set(-1.39, 2.4, -2 + i * 2.2); l.rotation.y = Math.PI / 2;
      scene.add(l);
      return lamp;
    });
    const doorLab = tag("AUTHORIZE", "#c7d2fe");
    doorLab.position.set(-1.5, 3.4, 0.2);
    scene.add(doorLab);

    // ── 2 the three factor pillars ──
    const factors = [
      { name: "KNOW", color: 0xfbbf24 },
      { name: "HAVE", color: 0x38bdf8 },
      { name: "ARE", color: 0xf472b6 },
    ].map((f, i) => {
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.45, 0.55, 3, 20), metal());
      m.position.set(-12, 1.5, -2.5 + i * 2.5);
      scene.add(m);
      const crown = additive(f.color, 0.1);
      const c = new THREE.Mesh(new THREE.SphereGeometry(0.45, 16, 12), crown);
      c.position.set(-12, 3.35, -2.5 + i * 2.5);
      scene.add(c);
      const l = tag(f.name, `#${f.color.toString(16).padStart(6, "0")}`, 160);
      l.position.set(-12, 4.2, -2.5 + i * 2.5);
      scene.add(l);
      return crown;
    });

    // ── 3 tokens: coins flowing from the gate to the apps, and one stolen ──
    const appXs = [5, 8, 11];
    appXs.forEach((x, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.6, 1.6, 1.6), metal());
      m.position.set(x, 0.8, -1.5 + i * 1.5);
      scene.add(m);
    });
    const appLab = tag("APPS", "#c7d2fe", 160);
    appLab.position.set(8, 2.5, 0);
    scene.add(appLab);
    const route = new THREE.CatmullRomCurve3([new THREE.Vector3(-6, 2.9, 1), new THREE.Vector3(0, 3.6, 0.5), new THREE.Vector3(4, 2.2, 0), new THREE.Vector3(8, 1.8, 0)]);
    const coinMat = new THREE.MeshStandardMaterial({ color: 0xfbbf24, metalness: 0.8, roughness: 0.25, transparent: true, opacity: 0 });
    const coins = Array.from({ length: 6 }, (_, i) => {
      const c = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.32, 0.08, 24), coinMat);
      c.rotation.x = Math.PI / 2;
      scene.add(c);
      return { c, t: i / 6 };
    });
    const theftRoute = new THREE.CatmullRomCurve3([new THREE.Vector3(0, 3.6, 0.5), new THREE.Vector3(2, 4.5, 4), new THREE.Vector3(4, 2, 7)]);
    const redMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.6, transparent: true, opacity: 0 });
    const red = new THREE.Mesh(new THREE.CylinderGeometry(0.36, 0.36, 0.08, 24), redMat);
    red.rotation.x = Math.PI / 2;
    scene.add(red);
    const attacker = new THREE.Mesh(new THREE.ConeGeometry(0.6, 1.6, 4), new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.25 }));
    attacker.position.set(4, 0.8, 7);
    scene.add(attacker);

    // ── 4 the revoke beam ──
    const beamMat = additive(0x34d399, 0);
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.08, 9, 8), beamMat);
    beam.position.set(4, 4.5, 7);
    scene.add(beam);
    const shards = Array.from({ length: 10 }, (_, i) => {
      const s = new THREE.Mesh(new THREE.TetrahedronGeometry(0.12), redMat);
      scene.add(s);
      return { s, a: (i / 10) * Math.PI * 2 };
    });

    // ── 5 the phone and its push storm ──
    const phone = new THREE.Mesh(new THREE.BoxGeometry(1, 1.8, 0.12), metal());
    phone.position.set(-6, 5.6, -4);
    scene.add(phone);
    const pushes = Array.from({ length: 5 }, (_, i) => {
      const p = tag("APPROVE?", "#fde68a", 200);
      p.position.set(-6 + (i - 2) * 1.2, 7 + (i % 2) * 0.4, -4);
      (p.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(p);
      return p.material as THREE.SpriteMaterial;
    });

    // ── 6 the account-type towers and the logon stream ──
    const towers = ["USER", "ADMIN", "SERVICE", "MACHINE"].map((n, i) => {
      const h = [2.2, 2.8, 3.6, 1.8][i];
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.4, h, 1.4), metal());
      m.position.set(3 + i * 2.4, h / 2, -7);
      scene.add(m);
      const lamp = additive(n === "SERVICE" ? Wn : A, 0.1);
      const top = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.12, 1.5), lamp);
      top.position.set(3 + i * 2.4, h + 0.06, -7);
      scene.add(top);
      const l = tag(n, "#c7d2fe", 220);
      l.position.set(3 + i * 2.4, h + 0.7, -7);
      scene.add(l);
      return lamp;
    });
    const logs = Array.from({ length: 8 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i === 7 ? 0x34d399 : Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.6, 0.6, 1);
      scene.add(s);
      return { s, i };
    });

    const anchors = [new THREE.Vector3(-6, 6.9, 1), new THREE.Vector3(-12, 5, 0), new THREE.Vector3(4, 4.4, 0.5), new THREE.Vector3(4, 9.4, 7), new THREE.Vector3(-6, 8.4, -4), new THREE.Vector3(7, 5.4, -7)];
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 54 : asp < 1.5 ? 32 : 27; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 6; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 4);
      camera.lookAt(-1, 3, 0);

      // 1 gate and doors
      gateMat.opacity = 0.15 + level[0] * 0.8;
      if (!rm) gate.rotation.x += dt * 0.4 * level[0];
      doors.forEach(d => { d.opacity = 0.1 + level[0] * 0.85; });
      // 2 factor pillars
      factors.forEach((f, i) => { f.opacity = 0.1 + THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1) * 0.85; });
      // 3 tokens flow, one is stolen
      coinMat.opacity = level[2];
      coins.forEach(c => {
        if (!rm) c.t = (c.t + dt * 0.12) % 1;
        route.getPointAt(rm ? 0.5 : c.t, c.c.position);
        if (!rm) c.c.rotation.z += dt * 3;
      });
      const revoked = level[3] > 0.5;
      const tt = rm ? 0.7 : (t * 0.2) % 1;
      theftRoute.getPointAt(tt, red.position);
      redMat.opacity = revoked ? 0 : level[2] * 0.95;
      (attacker.material as THREE.MeshBasicMaterial).opacity = 0.25 + level[2] * 0.5 * (revoked ? 0.3 : 1);
      // 4 the revoke beam shatters the stolen token
      beamMat.opacity = level[3] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      shards.forEach((sh, i) => {
        const r = revoked ? 0.4 + ((t * 0.6 + i * 0.1) % 1) * 1.6 : 0;
        sh.s.position.set(4 + Math.cos(sh.a) * r, 2 + Math.sin(sh.a) * r * 0.6, 7);
        sh.s.visible = revoked;
      });
      // 5 push storm: the prompts pop on the phone one after another
      pushes.forEach((p, i) => { p.opacity = Math.max(level[4], stations[4]?.status === "open" ? 0.4 : 0) * (rm ? 0.8 : (Math.sin(t * 2 - i * 0.8) > 0 ? 0.9 : 0.15)); });
      // 6 the account towers and a stream of logons: seven failures, then one success
      towers.forEach(tw => { tw.opacity = 0.1 + level[5] * 0.85; });
      logs.forEach(l => {
        const u = rm ? l.i / 8 : ((t * 0.3 + l.i / 8) % 1);
        l.s.position.set(-2 + u * 14, 0.4, -5);
        (l.s.material as THREE.SpriteMaterial).opacity = level[5] * 0.8;
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
            <span className="block whitespace-nowrap rounded-md border bg-[#0b0a1f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
