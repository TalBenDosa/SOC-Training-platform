"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, labelSprite, laptop, netNode, packet, padlock, shield } from "./cyberProps";

/**
 * "Tenant zero": there is no building here. A glowing tenant core floats over
 * the floor with accounts and apps in orbit. In front of it three condition
 * rings form a checkpoint that sign-ins pass through. A locked role lamp lights
 * for a short timed ring. To one side a wireframe globe carries pins and an arc
 * between two of them. Stations switch each part on. Decorative only.
 */
export default function TenantZeroScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04060c, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xdbeafe, 0x04060c, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x12264a, 0x070c18));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the tenant core with its objects in orbit ──
    const core = netNode(A, 1.5);
    core.group.position.set(-2, 4.2, -1);
    scene.add(core.group);
    const cl = labelSprite("TENANT", "#bfdbfe", 130);
    cl.position.set(-2, 6.5, -1);
    scene.add(cl);
    const orbit = Array.from({ length: 8 }, (_, i) => {
      const n = netNode(i % 3 === 0 ? B : A, 0.26);
      scene.add(n.group);
      return { ...n, a: (i / 8) * Math.PI * 2, r: 3 + (i % 2) * 0.5, y: 4.2 + ((i % 3) - 1) * 0.5 };
    });

    // ── 2 the checkpoint: three condition rings, sign-ins pass through ──
    const rings = ["LOCATION", "DEVICE", "RISK"].map((n, i) => {
      const mat = additive(B, 0.1);
      const r = new THREE.Mesh(new THREE.TorusGeometry(1.5, 0.07, 10, 48), mat);
      r.position.set(-3.6 + i * 2.6, 1.7, 3.4);
      r.rotation.y = Math.PI / 2;
      scene.add(r);
      const l = labelSprite(n, "#e9d5ff", 130);
      l.position.set(-3.6 + i * 2.6, 3.6, 3.4);
      scene.add(l);
      return { mat, lm: l.material as THREE.SpriteMaterial };
    });
    const lap = laptop(A);
    lap.group.position.set(-6.8, 0.5, 3.4);
    scene.add(lap.group);
    const passers = Array.from({ length: 5 }, (_, i) => { const p = packet(A); scene.add(p.mesh); return { ...p, o: i / 5, stop: i % 3 === 2 }; });
    const gate = shield(A, "check", 0.9);
    gate.group.position.set(3.4, 1.8, 3.4);
    gate.group.rotation.y = -0.3;
    scene.add(gate.group);

    // ── 3 the role lamp, locked until activated, on a short timer ──
    const lock = padlock(B, 1.1);
    lock.group.position.set(5.2, 4.6, -1.6);
    scene.add(lock.group);
    const lampMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.1, transparent: true, opacity: 0.3 });
    const lamp = new THREE.Mesh(new THREE.CylinderGeometry(0.7, 1.1, 3.2, 6), lampMat);
    lamp.position.set(5.2, 1.7, -1.6);
    scene.add(lamp);
    const timerMat = additive(A, 0.1);
    const timer = new THREE.Mesh(new THREE.TorusGeometry(1.5, 0.06, 8, 64, Math.PI * 2), timerMat);
    timer.position.set(5.2, 0.15, -1.6);
    timer.rotation.x = Math.PI / 2;
    scene.add(timer);
    const rl = labelSprite("ROLE: 1 HOUR", "#e9d5ff", 170);
    rl.position.set(5.2, 6, -1.6);
    scene.add(rl);

    // ── 4 the globe, with pins and one arc nobody could fly ──
    const globeMat = new THREE.MeshBasicMaterial({ color: A, wireframe: true, transparent: true, opacity: 0.12 });
    const globe = new THREE.Mesh(new THREE.SphereGeometry(2.3, 20, 14), globeMat);
    globe.position.set(10.4, 3.2, 0.6);
    scene.add(globe);
    const pins = [[1.2, 1.3, 1.5], [-1.5, 0.9, 1.4], [0.2, -1.2, 1.9]].map(([x, y, z]) => {
      const mat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.2 });
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.14, 10, 10), mat);
      m.position.set(10.4 + x, 3.2 + y, 0.6 + z);
      scene.add(m);
      return mat;
    });
    const arcCurve = new THREE.QuadraticBezierCurve3(new THREE.Vector3(11.6, 4.5, 2.1), new THREE.Vector3(10.4, 7.2, 3.2), new THREE.Vector3(8.9, 4.1, 2));
    const arcMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0.1 });
    const arc = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arcCurve.getPoints(40)), arcMat);
    scene.add(arc);

    const anchors = [new THREE.Vector3(-5.6, 7, -1), new THREE.Vector3(-1, -0.3, 5), new THREE.Vector3(5.2, 7.2, -1.6), new THREE.Vector3(10.4, 6.6, 0.6)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 66 : asp < 1.5 ? 33 : 27; };

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
      camera.position.set(Math.sin(yaw) * dist + 2, dist * (portrait ? 0.5 : 0.36) + 3, Math.cos(yaw) * dist + 2);
      camera.lookAt(2, 2.6, 0.6);

      floor.mat.opacity = 0.2 + level[3] * 0.25;
      // 1 the core and its orbit
      core.wireMat.opacity = 0.2 + level[0] * 0.75;
      core.coreMat.opacity = 0.2 + level[0] * 0.7;
      core.group.rotation.y = rm ? 0 : t * 0.25;
      orbit.forEach(o => {
        const a = o.a + (rm ? 0 : t * 0.35);
        o.group.position.set(-2 + Math.cos(a) * o.r, o.y, -1 + Math.sin(a) * o.r);
        o.wireMat.opacity = 0.15 + level[0] * 0.8;
        o.coreMat.opacity = 0.15 + level[0] * 0.75;
      });
      // 2 sign-ins pass the rings, and some stop at the second
      rings.forEach(r => { r.mat.opacity = 0.1 + level[1] * 0.85; r.lm.opacity = 0.2 + level[1] * 0.8; });
      gate.mat.opacity = 0.25 + level[1] * 0.75;
      const go = Math.max(level[1], stations[1]?.status === "open" ? 0.4 : 0);
      passers.forEach(p => {
        const u = rm ? p.o : ((t * 0.2 + p.o) % 1);
        const x = -6.2 + u * 9.4;
        p.mesh.position.set(p.stop ? Math.min(x, -1) : x, 1.7, 3.4);
        p.mat.opacity = go * 0.9 * (p.stop && x > -1 ? Math.max(0, 1 - (x + 1)) : 1);
      });
      // 3 the role wakes on a timer that runs down
      lock.setOpen(level[2]);
      lock.mat.opacity = 0.35 + level[2] * 0.65;
      const beat = rm ? 0.5 : (Math.sin(t * 0.6) + 1) / 2;
      lampMat.opacity = 0.25 + level[2] * (0.25 + beat * 0.4);
      lampMat.emissiveIntensity = 0.1 + level[2] * beat * 0.8;
      timerMat.opacity = 0.1 + level[2] * 0.8;
      timer.rotation.z = rm ? 0 : t * 0.5;
      (rl.material as THREE.SpriteMaterial).opacity = 0.2 + level[2] * 0.8;
      // 4 the globe and the arc
      globeMat.opacity = 0.12 + level[3] * 0.4;
      globe.rotation.y = rm ? 0 : t * 0.1;
      pins.forEach(m => { m.opacity = 0.2 + level[3] * 0.8; });
      arcMat.opacity = 0.1 + level[3] * (0.5 + pulse * 0.4);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#070c18]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
