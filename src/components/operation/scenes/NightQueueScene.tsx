"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, holoPanel, labelSprite, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Night queue": alert cards ride a conveyor out of the SIEM racks toward an
 * analyst desk (three monitors). Past the desk the belt splits into four
 * verdict chutes (FP, BENIGN TP, TP, INDETERMINATE), each lighting as cards
 * drop in. A 3x3 priority matrix glows above the belt, a benign-proof panel
 * floats by the desk, and a handover shield closes the shift.
 * Stations switch each part on. Decorative only.
 */
export default function NightQueueScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x070604, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x070604, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x45330a, 0x120e05));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // SIEM racks feeding the belt
    const racks = [-12, -10.6].map(x => { const r = serverRack(B, 7); r.group.position.set(x, 0, 0); r.group.rotation.y = Math.PI / 2; scene.add(r.group); return r; });
    const sl = labelSprite("SIEM · 212 ALERTS", "#bae6fd", 300); sl.position.set(-11.3, 3.2, 0); scene.add(sl);

    // ── 1 the conveyor of alert cards ──
    const belt = new THREE.Mesh(new THREE.BoxGeometry(14, 0.12, 1.4), new THREE.MeshStandardMaterial({ color: 0x2a2416, metalness: 0.5, roughness: 0.5 }));
    belt.position.set(-3, 0.6, 0);
    scene.add(belt);
    const sevCols = [Wn, A, B, A, Wn, B];
    const cards = sevCols.map((c, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x111827, emissive: c, emissiveIntensity: 0.4, transparent: true, opacity: 0.95 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.08, 0.6), mat);
      scene.add(m);
      return { m, mat, o: i / sevCols.length, chute: i % 4 };
    });

    // the analyst desk: three monitors
    const desk = [-0.8, 0.6, 2].map((x, i) => {
      const t = terminal(i === 1 ? ["Incident Review", "urgency  status  owner", "high     new      -", "medium   new      -"] : i === 0 ? ["raw log", "EventCode=7045", "ServiceName=svc_upd"] : ["enrichment", "asset: booking", "user risk: 3"], i === 1 ? A : B, 1.3, 0.85);
      t.group.position.set(x, 0, 2.3);
      t.group.rotation.y = (1 - i) * 0.25;
      scene.add(t.group);
      return t;
    });

    // ── 2 the priority matrix ──
    const cells: THREE.MeshBasicMaterial[] = [];
    for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) {
      const heat = (r + c) / 4;
      const col = new THREE.Color(B).lerp(Wn, heat);
      const mat = new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.1, blending: THREE.AdditiveBlending, depthWrite: false });
      const m = new THREE.Mesh(new THREE.PlaneGeometry(0.85, 0.85), mat);
      m.position.set(-5 + c * 0.95, 3.4 + r * 0.95, -1.2);
      scene.add(m);
      cells.push(mat);
    }
    const ml = labelSprite("SEVERITY × ASSET × USER", "#fde68a", 360); ml.position.set(-4.05, 6.4, -1.2); scene.add(ml);

    // ── 3 the benign-proof panel ──
    const proof = holoPanel("PROVE IT'S BENIGN", ["change ticket", "scan calendar", "asset owner", "vendor notes"], B, 2.2, 1.3);
    proof.mesh.position.set(-1, 4.2, -1.8);
    scene.add(proof.mesh);

    // ── 4 four verdict chutes ──
    const chuteDefs: [string, THREE.Color][] = [["FP", B], ["BENIGN TP", A], ["TP", Wn], ["INDET.", new THREE.Color("#a78bfa")]];
    const chutes = chuteDefs.map(([n, c], i) => {
      const mat = additive(c, 0.08);
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.45, 0.25, 1.2, 16, 1, true), mat);
      m.position.set(5 + i * 1.3, 0.6, 0);
      scene.add(m);
      const l = labelSprite(n, `#${c.getHexString()}`, 200);
      l.scale.multiplyScalar(0.7);
      l.position.set(5 + i * 1.3, 1.6, 0);
      scene.add(l);
      return mat;
    });

    // ── 5 the handover shield ──
    const hand = shield(A, "check", 1.2);
    hand.group.position.set(9, 3.4, -1.5);
    scene.add(hand.group);

    const anchors = [new THREE.Vector3(-6, 1.8, 0), new THREE.Vector3(-4, 7.2, -1.2), new THREE.Vector3(-1, 5.6, -1.8), new THREE.Vector3(7, 2.6, 0), new THREE.Vector3(9, 5, -1.5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 23, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 58 : asp < 1.5 ? 28 : 23; };

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
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(-1, 2.2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      racks.forEach(r => r.tick(t, 0.5 + level[0] * 0.5, rm));
      desk.forEach(d => { d.screenMat.opacity = 0.35 + level[0] * 0.6; });
      // 1 cards ride the belt and drop into chutes once triage is learned
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      cards.forEach(c => {
        const u = rm ? c.o : ((t * 0.09 + c.o) % 1);
        const x = -10 + u * 15 + (u > 0.8 ? c.chute * 1.3 * ((u - 0.8) / 0.2) : 0);
        const drop = u > 0.93 ? (u - 0.93) * 12 : 0;
        c.m.position.set(Math.min(x, 5 + c.chute * 1.3), 0.72 - drop * level[3], 0);
        c.mat.opacity = flow > 0.05 ? 0.95 : 0.4;
      });
      // 2 the matrix lights cell by cell
      cells.forEach((m, i) => { m.opacity = 0.1 + THREE.MathUtils.clamp(level[1] * 9 - i, 0, 1) * 0.6; });
      // 3 the proof panel
      proof.mat.opacity = 0.15 + level[2] * 0.75;
      // 4 the chutes
      chutes.forEach((m, i) => { m.opacity = 0.08 + THREE.MathUtils.clamp(level[3] * 4 - i, 0, 1) * 0.7; });
      // 5 the shield
      hand.mat.opacity = 0.2 + level[4] * 0.8;
      hand.mat.emissiveIntensity = 0.1 + level[4] * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#120e05]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
