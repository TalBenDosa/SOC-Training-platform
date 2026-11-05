"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Cold case": a forensic lab bench. An evidence bag (a sealed document with
 * a numbered tag) lies on a light table; a RAM module glows over a memory
 * terminal; a disk platter spins under a write-blocker padlock; a rail of
 * timeline cards orders itself; and a court seal closes the case.
 * Stations switch each part on. Decorative only.
 */
export default function ColdCaseScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x030807, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xccfbf1, 0x030807, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0f3b36, 0x07120f));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the evidence bag on a light table ──
    const tableMat = new THREE.MeshStandardMaterial({ color: 0x0f2a27, emissive: A, emissiveIntensity: 0.05 });
    const table = new THREE.Mesh(new THREE.BoxGeometry(3.2, 0.2, 2.2), tableMat);
    table.position.set(-7, 1, 1);
    scene.add(table);
    const bag = docFile("ASH-2026-0117", B);
    bag.group.rotation.x = -Math.PI / 2;
    bag.group.position.set(-7, 1.12, 1);
    bag.group.scale.setScalar(1.3);
    scene.add(bag.group);
    const tagMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.4 });
    const tag = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.02, 0.3), tagMat);
    tag.position.set(-6.2, 1.15, 1.6);
    scene.add(tag);
    const bl = labelSprite("SEAL #448120", "#fde68a", 220); bl.position.set(-7, 2.1, 1); scene.add(bl);

    // ── 2 RAM module over a memory terminal ──
    const ramMat = new THREE.MeshStandardMaterial({ color: 0x0b3b2f, emissive: A, emissiveIntensity: 0.1 });
    const ram = new THREE.Group();
    const pcb = new THREE.Mesh(new THREE.BoxGeometry(2.4, 0.6, 0.06), ramMat);
    ram.add(pcb);
    for (let i = 0; i < 8; i++) {
      const chip = new THREE.Mesh(new THREE.BoxGeometry(0.22, 0.3, 0.05), new THREE.MeshStandardMaterial({ color: 0x111111 }));
      chip.position.set(-1 + i * 0.28, 0.02, 0.05);
      ram.add(chip);
    }
    ram.position.set(-2.4, 3.6, 0);
    scene.add(ram);
    const mem = terminal(["vol -f ASH-BID-01.mem", "  windows.pslist", "5124 3812 lsasss.exe", "windows.cmdline", "  -lot 117"], A, 1.8, 1.1);
    mem.group.position.set(-2.4, 0, 0.6);
    scene.add(mem.group);

    // ── 3 disk platter under a write blocker, and the timeline rail ──
    const platterMat = new THREE.MeshStandardMaterial({ color: 0x94a3b8, metalness: 0.9, roughness: 0.15 });
    const platter = new THREE.Mesh(new THREE.CylinderGeometry(0.9, 0.9, 0.06, 40), platterMat);
    platter.position.set(2.6, 1.3, 1.4);
    scene.add(platter);
    const blocker = padlock(B, 0.8);
    blocker.group.position.set(2.6, 2.4, 1.4);
    scene.add(blocker.group);
    const wl = labelSprite("WRITE BLOCKER", "#fde68a", 240); wl.position.set(2.6, 3.4, 1.4); scene.add(wl);
    const railCards = ["21:12 logon", "21:31 xlsx", "21:39 download", "21:46 lsasss", "22:05 deleted"].map((t, i) => {
      const hp = holoPanel(t, [], i === 3 ? Wn : A, 1.3, 0.45);
      scene.add(hp.mesh);
      return { hp, i, home: new THREE.Vector3(1.2 + i * 1.45, 4.3, -1.6), scatter: new THREE.Vector3(1.2 + ((i * 3) % 5) * 1.45, 4.3 + ((i % 2) - 0.5) * 0.9, -1.6) };
    });
    const racks = [7.4, 8.8].map(x => { const r = serverRack(B, 6); r.group.position.set(x, 0, -3.2); scene.add(r.group); return r; });

    // ── 5 the court seal ──
    const seal = shield(A, "check", 1.2);
    seal.group.position.set(9.6, 2.6, 1.4);
    scene.add(seal.group);
    const sealRing = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.05, 8, 48), additive(B, 0));
    sealRing.position.copy(seal.group.position);
    scene.add(sealRing);

    const anchors = [new THREE.Vector3(-7, 3, 1), new THREE.Vector3(-2.4, 4.6, 0), new THREE.Vector3(2.6, 4.2, 1.4), new THREE.Vector3(5, 5.4, -1.6), new THREE.Vector3(9.6, 4.4, 1.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 23, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 56 : asp < 1.5 ? 28 : 23; };

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
      camera.position.set(Math.sin(yaw) * dist + 0.5, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0.5, 2.2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 the light table glows and the tag pulses until the bag is checked
      tableMat.emissiveIntensity = 0.05 + level[0] * 0.5;
      tagMat.opacity = 0.4 + (1 - level[0]) * (rm ? 0.3 : pulse * 0.5);
      // 2 RAM lights chip by chip
      ramMat.emissiveIntensity = 0.1 + level[1] * 0.7;
      if (!rm) ram.rotation.y = Math.sin(t * 0.6) * 0.3;
      mem.screenMat.opacity = 0.3 + level[1] * 0.65;
      // 3 the platter spins under a locked blocker; the rail sorts itself
      if (!rm) platter.rotation.y += dt * (0.5 + level[2] * 4);
      blocker.setOpen(1 - level[2]);
      railCards.forEach(c => {
        c.hp.mesh.position.lerpVectors(c.scatter, c.home, level[2]);
        c.hp.mat.opacity = 0.2 + level[2] * 0.7;
      });
      racks.forEach(r => r.tick(t, 0.4 + level[3] * 0.6, rm));
      // 5 the seal
      seal.mat.opacity = 0.2 + level[4] * 0.8;
      seal.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      (sealRing.material as THREE.MeshBasicMaterial).opacity = level[4] * 0.85;
      if (!rm) sealRing.rotation.y += dt * level[4];

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04110f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
