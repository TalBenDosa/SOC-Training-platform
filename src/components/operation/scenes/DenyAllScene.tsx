"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, holoPanel, labelSprite, packet, serverRack, shield } from "./cyberProps";

/**
 * "Deny all": three firewall appliances (FortiGate, PAN-OS, Check Point
 * racks) guard glowing zone walls. Packets stream through the walls; one
 * internal host ticks out to the internet on a fixed rhythm, drawn as a
 * clock dial; a stack of rule slabs lets a packet fall until the first one
 * that matches lights; and a red deny gate closes the far wall.
 * Stations switch each part on. Decorative only.
 */
export default function DenyAllScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x080503, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xffedd5, 0x080503, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a2a0a, 0x140b04));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 three vendors' appliances on two zone walls ──
    const wallMats = [-3, 3].map(x => {
      const mat = additive(B, 0.06);
      const w = new THREE.Mesh(new THREE.PlaneGeometry(0.1, 4, 1, 1), mat);
      const plane = new THREE.Mesh(new THREE.BoxGeometry(0.12, 3.6, 9), mat);
      plane.position.set(x, 1.8, 0);
      scene.add(plane);
      w.visible = false;
      return mat;
    });
    const vendors = [["FORTIGATE", -3, -2.8], ["PAN-OS", 3, -2.8], ["CHECK POINT", 3, 2.8]].map(([n, x, z]) => {
      const r = serverRack(A, 4);
      r.group.position.set(x as number, 0, z as number);
      r.group.scale.setScalar(0.85);
      scene.add(r.group);
      const l = labelSprite(n as string, "#fed7aa", 240);
      l.position.set(x as number, 2.3, z as number);
      scene.add(l);
      return r;
    });
    const zoneLabels = [["OT · MILL", -7], ["CORE", 0], ["INTERNET", 7]].map(([n, x]) => {
      const l = labelSprite(n as string, "#bae6fd", 220);
      l.position.set(x as number, 0.4, 4.4);
      scene.add(l);
      return l;
    });
    const flowPk = Array.from({ length: 6 }, (_, i) => { const p = packet(B); scene.add(p.mesh); return { ...p, o: i / 6, z: -2 + (i % 3) * 2 }; });

    // ── 2 the beacon dial ──
    const dialMat = additive(Wn, 0.08);
    const dial = new THREE.Mesh(new THREE.TorusGeometry(1.1, 0.07, 8, 60), dialMat);
    dial.position.set(-7, 3.4, -1);
    scene.add(dial);
    const handMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.3 });
    const hand = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.9, 0.06), handMat);
    hand.geometry.translate(0, 0.45, 0);
    hand.position.copy(dial.position);
    scene.add(hand);
    const dl = labelSprite("every 7 min · 612 B", "#fecaca", 300); dl.position.set(-7, 4.9, -1); scene.add(dl);
    const beacon = packet(Wn);
    scene.add(beacon.mesh);

    // ── 3 the rule slabs ──
    const slabs = ["#1 Emergency-Log", "#2 OT to Historian", "#3 Legacy-Any-Out", "#4 Deny-All"].map((n, i) => {
      const hp = holoPanel(n, [], i === 3 ? Wn : A, 2.4, 0.5);
      hp.mesh.position.set(0, 3.6 - i * 0.7, -3.6);
      scene.add(hp.mesh);
      return hp;
    });
    const faller = packet(B);
    scene.add(faller.mesh);

    // ── 5 the deny gate ──
    const gate = shield(Wn, "none", 1.4);
    gate.group.position.set(6.6, 2, -1);
    gate.group.rotation.y = -0.5;
    scene.add(gate.group);

    const anchors = [new THREE.Vector3(-3, 4.2, -2.8), new THREE.Vector3(-7, 5.6, -1), new THREE.Vector3(0, 4.5, -3.6), new THREE.Vector3(3, 4.2, 2.8), new THREE.Vector3(6.6, 3.8, -1)];
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

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 2.2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 walls, appliances and the flows through them
      wallMats.forEach(m => { m.opacity = 0.06 + level[0] * 0.2; });
      vendors.forEach(r => r.tick(t, 0.4 + level[0] * 0.6, rm));
      zoneLabels.forEach(l => { (l.material as THREE.SpriteMaterial).opacity = 0.4 + level[0] * 0.6; });
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      flowPk.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.2 + p.o) % 1);
        p.mesh.position.set(-8 + u * 16, 0.6, p.z);
        p.mat.opacity = flow * 0.9;
      });
      // 2 the beacon ticks on its rhythm
      dialMat.opacity = 0.08 + level[1] * 0.8;
      handMat.opacity = 0.3 + level[1] * 0.6;
      const tick = rm ? 0 : Math.floor(t / 1.4);
      hand.rotation.z = -tick * (Math.PI / 4);
      const bu = rm ? 0.5 : ((t / 1.4) % 1);
      beacon.mesh.position.set(-7 + bu * 15, 1.4 + Math.sin(bu * Math.PI) * 2, -1);
      beacon.mat.opacity = level[1] * 0.95;
      // 3 a packet falls through the rule slabs; the matching slab lights
      const fu = rm ? 0.8 : ((t * 0.35) % 1);
      const which = Math.min(3, Math.floor(fu * 4));
      faller.mesh.position.set(-1.6, 3.9 - fu * 2.8, -3.3);
      faller.mat.opacity = level[2] * 0.95;
      slabs.forEach((s, i) => { s.mat.opacity = 0.15 + level[2] * (i === which ? 0.8 : 0.35); });
      // 5 the deny gate
      gate.mat.opacity = 0.25 + level[4] * 0.75;
      gate.mat.emissiveIntensity = 0.1 + Math.max(level[3], level[4]) * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140b04]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
