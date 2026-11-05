"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, holoPanel, labelSprite, laptop, netNode, packet, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Talon": a fleet of hotel laptops, each with a sensor dot, streams telemetry
 * up into a cloud threat graph of linked nodes. A policy gate (a shield)
 * stands between a file and the fleet; an RTR beam runs from the London
 * console to one far laptop in Lisbon; a process tree of nodes rises over it,
 * one branch red; and a contain ring closes round the Lisbon host.
 * Stations switch each part on. Decorative only.
 */
export default function TalonScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x070303, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfee2e2, 0x070303, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a1414, 0x140707));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the fleet and the cloud graph ──
    const fleet = Array.from({ length: 6 }, (_, i) => {
      const l = laptop(B);
      const x = -7 + (i % 3) * 2.2, z = 1 + Math.floor(i / 3) * 2.2;
      l.group.position.set(x, 0, z);
      l.group.scale.setScalar(1.3);
      scene.add(l.group);
      const dotMat = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.3 });
      const dot = new THREE.Mesh(new THREE.SphereGeometry(0.09, 8, 6), dotMat);
      dot.position.set(x + 0.5, 0.15, z + 0.35);
      scene.add(dot);
      const up = packet(A);
      scene.add(up.mesh);
      return { l, dotMat, up, p: new THREE.Vector3(x, 0.6, z), o: i / 6 };
    });
    const cloudNodes = [[-4, 5.2, -1], [-1.5, 6, 0.5], [1, 5.5, -1.2], [3.5, 6.2, 0.2], [-2.5, 6.8, -2], [2, 7, -2.4]].map(([x, y, z]) => {
      const n = netNode(A, 0.38);
      n.group.position.set(x, y, z);
      scene.add(n.group);
      return n;
    });
    const linkMat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.15 });
    const lp: THREE.Vector3[] = [];
    [[0, 1], [1, 2], [2, 3], [0, 4], [4, 1], [4, 5], [5, 3], [2, 5]].forEach(([a, b]) => lp.push(cloudNodes[a].group.position, cloudNodes[b].group.position));
    scene.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(lp), linkMat));
    const tg = labelSprite("THREAT GRAPH", "#fecaca", 260); tg.position.set(0, 7.9, -1); scene.add(tg);

    // ── 2 the policy gate ──
    const gate = shield(A, "check", 1.4);
    gate.group.position.set(-10.5, 2, 2);
    gate.group.rotation.y = 0.7;
    scene.add(gate.group);
    const gl = labelSprite("PREVENT · INSIGHT", "#fecaca", 300); gl.position.set(-10.5, 3.7, 2); scene.add(gl);

    // ── 3 RTR: London console to the Lisbon laptop ──
    const london = terminal(["RTR BMH-LIS-NA07> ps", "updsvc.exe   4412", "RTR> netstat", "4412 -> 198.51.100.66:443", "RTR> kill 4412"], A, 2, 1.2);
    london.group.position.set(4.6, 0, 3.4);
    london.group.rotation.y = -0.6;
    scene.add(london.group);
    const ll = labelSprite("LONDON", "#f8fafc", 160); ll.position.set(4.6, 2.6, 3.4); scene.add(ll);
    const lisbon = laptop(Wn);
    lisbon.group.position.set(9.5, 0, -1.5);
    lisbon.group.scale.setScalar(1.6);
    lisbon.group.rotation.y = -0.8;
    scene.add(lisbon.group);
    const lb = labelSprite("BMH-LIS-NA07", "#fde68a", 260); lb.position.set(9.5, 1.9, -1.5); scene.add(lb);
    const beamMat = new THREE.LineDashedMaterial({ color: A, dashSize: 0.25, gapSize: 0.15, transparent: true, opacity: 0 });
    const beam = new THREE.Line(new THREE.BufferGeometry().setFromPoints(new THREE.QuadraticBezierCurve3(new THREE.Vector3(4.6, 1.8, 3.4), new THREE.Vector3(7.5, 5, 1), new THREE.Vector3(9.5, 1, -1.5)).getPoints(40)), beamMat);
    beam.computeLineDistances();
    scene.add(beam);

    // ── 4 the process tree over Lisbon ──
    const treeNodes = [[9.5, 3.2, -1.5, false], [8.7, 4.3, -1.5, false], [10.3, 4.3, -1.5, true], [10.3, 5.4, -1.5, true]].map(([x, y, z, bad]) => {
      const n = netNode(bad ? Wn : B, 0.28);
      n.group.position.set(x as number, y as number, z as number);
      scene.add(n.group);
      return n;
    });
    const treeMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0 });
    scene.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints([treeNodes[0].group.position, treeNodes[1].group.position, treeNodes[0].group.position, treeNodes[2].group.position, treeNodes[2].group.position, treeNodes[3].group.position]), treeMat));
    const dumpPanel = holoPanel("CREDENTIAL ACCESS", ["T1003.001 · LSASS memory", "severity: critical"], Wn, 2, 0.9);
    dumpPanel.mesh.position.set(12.4, 4.6, -1.5);
    dumpPanel.mesh.rotation.y = -0.6;
    scene.add(dumpPanel.mesh);

    // ── 5 the contain ring, plus the racks at HQ ──
    const ringMat = additive(A, 0);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.8, 0.07, 8, 60), ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.set(9.5, 0.2, -1.5);
    scene.add(ring);
    const racks = [0.4, 1.8].map(x => { const r = serverRack(A, 6); r.group.position.set(x, 0, -4); scene.add(r.group); return r; });

    const anchors = [new THREE.Vector3(-4.8, 2.6, 2), new THREE.Vector3(4.6, 3.6, 3.4), new THREE.Vector3(12.4, 3.4, -1.5), new THREE.Vector3(9.5, 6.6, -1.5), new THREE.Vector3(-10.5, 4.6, 2)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 25, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 60 : asp < 1.5 ? 30 : 25; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }
      level[4] = level[3];

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(1, 3, 0);

      floor.mat.opacity = 0.2 + level[3] * 0.25;
      racks.forEach(r => r.tick(t, 0.4 + level[0] * 0.6, rm));
      // 1 sensors light, telemetry rises to the graph
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      fleet.forEach((f, i) => {
        f.dotMat.opacity = 0.3 + level[0] * (rm ? 0.6 : 0.4 + 0.3 * Math.sin(t * 4 + i));
        f.l.screenMat.opacity = 0.4 + level[0] * 0.5;
        const u = rm ? 0.5 : ((t * 0.3 + f.o) % 1);
        const target = cloudNodes[i % cloudNodes.length].group.position;
        f.up.mesh.position.lerpVectors(f.p, target, u);
        f.up.mat.opacity = flow * 0.9;
      });
      cloudNodes.forEach(n => { n.wireMat.opacity = 0.2 + level[0] * 0.6; if (!rm) n.wire.rotation.y += dt * 0.5; });
      linkMat.opacity = 0.15 + level[0] * 0.5;
      gate.mat.opacity = 0.3 + level[0] * 0.7;
      gate.mat.emissiveIntensity = 0.15 + level[0] * 0.5;
      // 2 the RTR beam reaches Lisbon
      london.screenMat.opacity = 0.35 + level[1] * 0.6;
      beamMat.opacity = level[1] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      lisbon.screenMat.opacity = 0.4 + level[1] * 0.5;
      // 3 the process tree rises and the dump panel lights
      treeMat.opacity = level[2] * 0.8;
      treeNodes.forEach((n, i) => { n.wireMat.opacity = 0.15 + THREE.MathUtils.clamp(level[2] * 4 - i, 0, 1) * 0.75; });
      dumpPanel.mat.opacity = 0.15 + level[2] * 0.75;
      // 4 contain
      ringMat.opacity = level[3] * 0.9;
      ring.scale.setScalar(1.6 - level[3] * 0.6);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140707]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
