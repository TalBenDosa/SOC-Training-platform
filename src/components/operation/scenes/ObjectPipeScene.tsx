"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Object pipe": two consoles at either end of a long glass pipe. One is the
 * analyst's, one the attacker's, and both run the same shell. Object cubes
 * flow out of the analyst's console through three rings (WHERE, SELECT, SORT);
 * fewer cubes survive each ring and the last ones stack into a CSV sheet.
 * Above the pipe a PID beam drops from an alert onto one cube, and a task
 * card at the end of the line is ringed when hunted. Decorative only.
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

export default function ObjectPipeScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03070d, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xe0f2fe, 0x03070d, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0c4a6e, 0x0a1622));
    const floor = circuitFloor(A, 44); scene.add(floor.mesh);
    const kitAnalyst = terminal(["PS> Get-Process |", "  Where-Object {$_.CPU -gt 100}", "  | Select Name, Id, CPU, Path"], A, 1.9, 1.15); kitAnalyst.group.position.set(-12.4, 0, 3.4); kitAnalyst.group.rotation.y = 0.6; scene.add(kitAnalyst.group);
    const kitAttacker = terminal(["powershell -nop -w hidden", "  -enc SQBFAFgAIAAo...", "parent: EXCEL.EXE"], Wn, 1.9, 1.15); kitAttacker.group.position.set(-12.4, 0, -4.2); kitAttacker.group.rotation.y = 0.6; scene.add(kitAttacker.group);
    const kitHost = serverRack(A, 6, "OVEN-CTL-02"); kitHost.group.position.set(13.5, 0, 1.8); kitHost.group.rotation.y = -0.6; scene.add(kitHost.group);
    const kitShield = shield(A, "check", 0.8); kitShield.group.position.set(11, 4.4, -1.5); scene.add(kitShield.group);
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x334155, emissive: 0x0a0f18, metalness: 0.55, roughness: 0.4 });

    // ── 1 two consoles, one shell ──
    const consoles = [[-10, A, "ANALYST"], [-10, Wn, "ATTACKER"]].map(([x, col, name], i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x0f172a, emissive: col as THREE.Color, emissiveIntensity: 0.05 });
      const scr = new THREE.Mesh(new THREE.BoxGeometry(2.2, 1.5, 0.12), mat);
      scr.position.set(x as number, 1.6, i === 0 ? 1.6 : -2.4);
      scr.rotation.y = 0.5;
      scene.add(scr);
      const stand = new THREE.Mesh(new THREE.BoxGeometry(0.2, 0.9, 0.2), metal());
      stand.position.set(x as number, 0.45, scr.position.z);
      scene.add(stand);
      const l = tag(name as string, i === 0 ? "#bae6fd" : "#fda4af", 200);
      l.position.set(x as number, 2.8, scr.position.z);
      scene.add(l);
      return mat;
    });
    const psl = tag("powershell.exe", "#e2e8f0", 260); psl.position.set(-10, 4.2, -0.4); scene.add(psl);

    // the pipe
    const pipeMat = new THREE.MeshStandardMaterial({ color: 0x7dd3fc, transparent: true, opacity: 0.08, roughness: 0.1 });
    const pipe = new THREE.Mesh(new THREE.CylinderGeometry(0.75, 0.75, 16, 24, 1, true), pipeMat);
    pipe.rotation.z = Math.PI / 2;
    pipe.position.set(-1, 1.6, 1.6);
    scene.add(pipe);

    // ── 2 the filter rings and the flowing objects ──
    const ringX = [-4, 0, 4];
    const ringMats = ["WHERE", "SELECT", "SORT"].map((n, i) => {
      const mat = additive(B, 0.05);
      const r = new THREE.Mesh(new THREE.TorusGeometry(0.95, 0.07, 8, 40), mat);
      r.rotation.y = Math.PI / 2;
      r.position.set(ringX[i], 1.6, 1.6);
      scene.add(r);
      const l = tag(n, "#fde68a", 160);
      l.position.set(ringX[i], 2.9, 1.6);
      scene.add(l);
      return mat;
    });
    const cubes = Array.from({ length: 12 }, (_, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.3, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.3, 0.3, 0.3), mat);
      scene.add(m);
      // how many rings each cube survives: 0..3
      return { m, mat, o: i / 12, survives: i % 4 === 0 ? 3 : i % 4 === 1 ? 1 : i % 3 === 0 ? 2 : 0 };
    });
    const csvMat = new THREE.MeshStandardMaterial({ color: 0xf8fafc, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.12 });
    const csv = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.8, 0.06), csvMat);
    csv.position.set(8.6, 1.6, 1.6);
    csv.rotation.y = -0.4;
    scene.add(csv);
    const csvL = tag(".csv", "#bae6fd", 120); csvL.position.set(8.6, 2.9, 1.6); scene.add(csvL);

    // ── 3 the cmdlet panels ──
    const cmdlets = ["Get-Process", "Get-Service", "Get-WinEvent", "Get-ChildItem", "Get-FileHash"].map((n, i) => {
      const l = tag(n, "#bae6fd", 260);
      l.position.set(-6 + i * 3, 5.2 + (i % 2) * 0.5, -2);
      (l.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(l);
      return l.material as THREE.SpriteMaterial;
    });

    // ── 4 the PID beam ──
    const beamMat = additive(Wn, 0);
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, 4, 8), beamMat);
    beam.position.set(4, 3.6, 1.6);
    scene.add(beam);
    const pidL = tag("PID 6120", "#fda4af", 200); pidL.position.set(4, 6, 1.6); scene.add(pidL);
    (pidL.material as THREE.SpriteMaterial).opacity = 0;

    // ── 5 the task card ──
    const taskMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.3 });
    const task = new THREE.Mesh(new THREE.BoxGeometry(1.8, 1.2, 0.08), taskMat);
    task.position.set(11, 1.4, -1.5);
    task.rotation.y = -0.5;
    scene.add(task);
    const huntMat = additive(A, 0);
    const hunt = new THREE.Mesh(new THREE.TorusGeometry(1.4, 0.06, 8, 48), huntMat);
    hunt.position.copy(task.position);
    hunt.rotation.y = -0.5;
    scene.add(hunt);
    const taskL = tag("TempSensorSync", "#fda4af", 260); taskL.position.set(11, 2.5, -1.5); scene.add(taskL);

    const anchors = [new THREE.Vector3(-10, 4.6, -0.4), new THREE.Vector3(-2, 4, 1.6), new THREE.Vector3(0, 6.8, -2), new THREE.Vector3(4, 7.2, 1.6), new THREE.Vector3(11, 3.6, -1.5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 78 : asp < 1.5 ? 32 : 27; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }
      kitAnalyst.screenMat.opacity = 0.35 + level[0] * 0.6; kitAttacker.screenMat.opacity = 0.35 + level[0] * 0.6;
      kitHost.tick(t, 0.4 + level[2] * 0.6, rm);
      kitShield.mat.opacity = 0.15 + level[4] * 0.85;
      floor.mat.opacity = 0.18 + level[1] * 0.25;

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.38) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0.5, 2.6, 0);

      // 1 both consoles glow the same colour of light once the room is understood
      consoles.forEach((m, i) => { m.emissiveIntensity = 0.05 + level[0] * (i === 0 ? 0.6 : 0.35); });
      // 2 objects flow; each ring drops some of them
      pipeMat.opacity = 0.08 + level[1] * 0.12;
      ringMats.forEach((m, i) => { m.opacity = 0.05 + THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1) * 0.8; });
      const flow = Math.max(level[1], stations[1]?.status === "open" ? 0.4 : 0);
      cubes.forEach(c => {
        const u = rm ? 0.3 : ((t * 0.12 + c.o) % 1);
        const x = -9 + u * 17.2;
        const passed = ringX.filter(r => x > r).length;
        const dropped = passed > c.survives;
        c.m.position.set(x, dropped ? 1.6 - (x - ringX[c.survives]) * 0.8 : 1.6, 1.6);
        c.mat.opacity = flow * (dropped ? Math.max(0, 1 - (x - ringX[c.survives]) * 0.6) : 0.9);
        if (!rm) c.m.rotation.y += dt;
      });
      csvMat.opacity = 0.12 + level[1] * 0.8;
      csvMat.emissiveIntensity = level[1] * 0.25;
      // 3 cmdlet names light one by one
      cmdlets.forEach((m, i) => { m.opacity = THREE.MathUtils.clamp(level[2] * 5 - i, 0, 1) * 0.95; });
      // 4 the PID beam drops on the SORT ring
      beamMat.opacity = level[3] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      (pidL.material as THREE.SpriteMaterial).opacity = level[3];
      // 5 the task card lights, then the hunt ring closes on it
      taskMat.opacity = 0.3 + Math.max(level[3], level[4]) * 0.6;
      taskMat.emissiveIntensity = level[4] * 0.4;
      huntMat.opacity = level[4] * 0.9;
      hunt.scale.setScalar(1.6 - level[4] * 0.6);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#050b14]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
