"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Spare keys": a host core in the middle and the hooks an attacker leaves on
 * it. Two registry branches with key glyphs (Run keys), a clock ring that
 * ticks (tasks and cron), a gear and a hidden layer under the floor (services,
 * BITS, WMI), an event card that unfolds (the task record), and a cloud ring
 * above with its own keys, which finally lock as every door closes.
 * Stations switch each part on. Decorative only.
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

function keyGlyph(mat: THREE.Material) {
  const g = new THREE.Group();
  const bow = new THREE.Mesh(new THREE.TorusGeometry(0.22, 0.06, 8, 20), mat);
  const shaft = new THREE.Mesh(new THREE.BoxGeometry(0.6, 0.08, 0.08), mat);
  shaft.position.x = 0.5;
  const bit = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.2, 0.08), mat);
  bit.position.set(0.72, -0.12, 0);
  g.add(bow, shaft, bit);
  return g;
}

export default function SpareKeyScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04080a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xd1fae5, 0x04080a, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    const grid = new THREE.GridHelper(60, 30, 0x064e3b, 0x0b1f1a);
    scene.add(grid);
    const floor = circuitFloor(A, 44); scene.add(floor.mesh);
    const kitRackL = serverRack(A, 7); kitRackL.group.position.set(-1.9, 0, -2.2); scene.add(kitRackL.group);
    const kitRackR = serverRack(A, 7); kitRackR.group.position.set(1.9, 0, -2.2); scene.add(kitRackR.group);
    const kitTerm = terminal(["C:\\> reg query HKCU\\...\\Run", "  OneDrive  REG_SZ ...", "  AdobeSyncHelper REG_SZ", "  ...\\adbsync\\syncsvc.exe"], Wn, 1.8, 1.1); kitTerm.group.position.set(-6.4, 0, 2.6); kitTerm.group.rotation.y = 0.5; scene.add(kitTerm.group);
    const kitLock = padlock(A, 1); kitLock.group.position.set(0, 5.4, 1.6); scene.add(kitLock.group);
    const kitShield = shield(B, "check", 0.9); kitShield.group.position.set(4.4, 7, 0); scene.add(kitShield.group);
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2f4a44, emissive: 0x08130f, metalness: 0.55, roughness: 0.4 });

    // the host core
    const core = new THREE.Mesh(new THREE.BoxGeometry(3, 3.6, 3), metal());
    core.position.set(0, 1.8, 0);
    scene.add(core);
    const coreEdge = new THREE.LineSegments(new THREE.EdgesGeometry(core.geometry), new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.5 }));
    coreEdge.position.copy(core.position);
    scene.add(coreEdge);
    const hl = tag("WKS-LAB14", "#a7f3d0", 220); hl.position.set(0, 4.1, 0); scene.add(hl);

    // ── 1 registry branches with keys ──
    const regMat = additive(Wn, 0.05);
    const regKeys = [new THREE.Vector3(-4.6, 3.2, 0.5), new THREE.Vector3(-4.6, 1.6, 0.5)].map((p, i) => {
      const branch = new THREE.Mesh(new THREE.BoxGeometry(3, 0.06, 0.06), metal());
      branch.position.set(-3, p.y, 0.5);
      scene.add(branch);
      const k = keyGlyph(regMat);
      k.position.copy(p);
      scene.add(k);
      const l = tag(i === 0 ? "HKCU\\Run" : "Startup", "#fdba74", 200);
      l.position.set(p.x, p.y + 0.55, p.z);
      scene.add(l);
      return k;
    });

    // ── 2 the clock ring ──
    const clockMat = additive(A, 0.05);
    const clock = new THREE.Mesh(new THREE.TorusGeometry(1.1, 0.07, 8, 48), clockMat);
    clock.position.set(4.6, 2.6, 0.5);
    scene.add(clock);
    const hand = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.9, 0.06), clockMat);
    hand.geometry.translate(0, 0.45, 0);
    hand.position.copy(clock.position);
    scene.add(hand);
    const cl = tag("*/10 * * * *", "#a7f3d0", 240); cl.position.set(4.6, 4.1, 0.5); scene.add(cl);

    // ── 3 the gear and the hidden layer beneath the floor ──
    const gearMat = additive(B, 0.05);
    const gear = new THREE.Mesh(new THREE.TorusGeometry(0.6, 0.18, 6, 10), gearMat);
    gear.position.set(0, 0.5, 3.2);
    gear.rotation.x = -Math.PI / 2;
    scene.add(gear);
    const underMat = additive(B, 0);
    const under = new THREE.Mesh(new THREE.PlaneGeometry(12, 7), underMat);
    under.rotation.x = -Math.PI / 2;
    under.position.y = -0.6;
    scene.add(under);
    const ul = tag("root\\subscription", "#c4b5fd", 300); ul.position.set(0, -0.2, 4.2); scene.add(ul);

    // ── 4 the event card ──
    const cardMat = new THREE.MeshStandardMaterial({ color: 0xe2e8f0, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.2 });
    const card = new THREE.Mesh(new THREE.BoxGeometry(2.2, 1.4, 0.05), cardMat);
    card.position.set(8.5, 2, -1);
    scene.add(card);
    const evl = tag("4698", "#a7f3d0", 140); evl.position.set(8.5, 3.1, -1); scene.add(evl);

    // ── 5 the cloud ring above and its keys ──
    const cloudMat = additive(B, 0.04);
    const cloud = new THREE.Mesh(new THREE.TorusGeometry(2.4, 0.08, 8, 64), cloudMat);
    cloud.rotation.x = Math.PI / 2;
    cloud.position.set(0, 7, 0);
    scene.add(cloud);
    const cloudKeyMat = additive(Wn, 0.05);
    const cloudKeys = [0, 1, 2].map(i => {
      const k = keyGlyph(cloudKeyMat);
      const a = (i / 3) * Math.PI * 2;
      k.position.set(Math.cos(a) * 2.4, 7, Math.sin(a) * 2.4);
      scene.add(k);
      return k;
    });
    const lockMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.15 });
    const lock = new THREE.Mesh(new THREE.BoxGeometry(1, 0.8, 0.4), lockMat);
    lock.position.set(0, 5.4, 1.6);
    scene.add(lock);

    const anchors = [new THREE.Vector3(-4.6, 4.6, 0.5), new THREE.Vector3(4.6, 5, 0.5), new THREE.Vector3(0, 1.4, 4.6), new THREE.Vector3(8.5, 4, -1), new THREE.Vector3(3.4, 7, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 26, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 56 : asp < 1.5 ? 31 : 26; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }
      kitRackL.tick(t, 0.4 + level[0] * 0.6, rm); kitRackR.tick(t, 0.4 + level[2] * 0.6, rm);
      kitTerm.screenMat.opacity = 0.3 + level[0] * 0.65;
      kitLock.setOpen(1 - level[4]);
      kitShield.mat.opacity = 0.15 + level[4] * 0.85;
      floor.mat.opacity = 0.18 + level[4] * 0.25;

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.25;
      camera.position.set(Math.sin(yaw) * dist + 2, dist * (portrait ? 0.55 : 0.4) + 2, Math.cos(yaw) * dist);
      camera.lookAt(2, 3, 0);

      // 1 the keys glow, and swing a little
      regMat.opacity = 0.05 + level[0] * 0.85;
      regKeys.forEach((k, i) => { k.rotation.z = rm ? 0 : Math.sin(t * 1.5 + i) * 0.15 * level[0]; });
      // 2 the clock ticks
      clockMat.opacity = 0.05 + level[1] * 0.85;
      if (!rm) hand.rotation.z -= dt * 1.2 * level[1];
      // 3 the gear turns and the hidden layer surfaces
      gearMat.opacity = 0.05 + level[2] * 0.85;
      if (!rm) gear.rotation.z += dt * 0.9 * level[2];
      underMat.opacity = level[2] * (rm ? 0.18 : 0.12 + pulse * 0.08);
      // 4 the card lights and turns to face the camera
      cardMat.opacity = 0.2 + level[3] * 0.75;
      cardMat.emissiveIntensity = level[3] * 0.35;
      card.rotation.y = (1 - level[3]) * 1.2;
      // 5 the cloud keys circle until the lock closes
      cloudMat.opacity = 0.04 + Math.max(level[2], level[4]) * 0.6;
      cloudKeyMat.opacity = 0.05 + (level[3] > 0.5 ? 0.6 : 0.2) * (1 - level[4] * 0.9);
      cloudKeys.forEach((k, i) => {
        const a = (i / 3) * Math.PI * 2 + (rm ? 0 : t * 0.3 * (1 - level[4]));
        k.position.set(Math.cos(a) * 2.4, 7, Math.sin(a) * 2.4);
      });
      lockMat.opacity = 0.15 + level[4] * 0.8;
      lockMat.emissiveIntensity = level[4] * (rm ? 0.6 : 0.4 + pulse * 0.3);
      (coreEdge.material as THREE.LineBasicMaterial).opacity = 0.3 + level[4] * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#06110e]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
