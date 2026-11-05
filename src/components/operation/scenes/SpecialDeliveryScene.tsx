"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, laptop, packet, shield, terminal } from "./cyberProps";

/**
 * "Special delivery": a stream of plain text sails through a scanner arch that
 * sees nothing. Past the arch, on a laptop, the loose bytes swarm and lock
 * together into a solid file. Beyond it four tall signed pillars stand in a row,
 * each with a green seal, and a red rider clings to one of them. A panel shows
 * the command line, and a rule shield closes the row. Stations switch each part
 * on. Decorative only.
 */
export default function SpecialDeliveryScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0703, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x0a0703, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a3408, 0x151003));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the scanner arch, and text passing it unbothered ──
    const archMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.2, transparent: true, opacity: 0.5 });
    const arch = new THREE.Mesh(new THREE.TorusGeometry(2.3, 0.2, 10, 40, Math.PI), archMat);
    arch.position.set(-9, 0, 0);
    arch.rotation.y = Math.PI / 2;
    scene.add(arch);
    const scanMat = additive(B, 0.08);
    const scan = new THREE.Mesh(new THREE.PlaneGeometry(4.2, 2.3), scanMat);
    scan.position.set(-9, 1.15, 0);
    scan.rotation.y = Math.PI / 2;
    scene.add(scan);
    const al = labelSprite("text/html", "#bae6fd", 140);
    al.position.set(-9, 3.1, 0);
    scene.add(al);
    const bits = Array.from({ length: 14 }, (_, i) => { const p = packet(A); p.mesh.scale.setScalar(0.7); scene.add(p.mesh); return { ...p, o: i / 14, y: 0.8 + (i % 4) * 0.4, z: -0.9 + (i % 3) * 0.9 }; });

    // ── 2 the laptop, and the file that forms over it ──
    const lap = laptop(A);
    lap.group.position.set(-3.4, 0, 0.8);
    lap.group.scale.setScalar(1.5);
    scene.add(lap.group);
    const built = docFile("bundle.iso", Wn);
    built.group.position.set(-3.4, 4.1, 0.4);
    built.group.scale.setScalar(0.9);
    scene.add(built.group);

    // ── 3 four signed pillars, each with a seal ──
    const names = ["mshta", "regsvr32", "rundll32", "msiexec"];
    const pillars = names.map((n, i) => {
      const x = 0.8 + i * 2.2;
      const mat = new THREE.MeshStandardMaterial({ color: 0x241a08, emissive: A, emissiveIntensity: 0.05, metalness: 0.5, roughness: 0.4, transparent: true, opacity: 0.6 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.3, 4.4, 1.3), mat);
      m.position.set(x, 2.2, -1.2);
      scene.add(m);
      const l = labelSprite(n, "#fde68a", 160);
      l.position.set(x, 5, -1.2);
      scene.add(l);
      const seal = shield(0x34d399, "check", 0.5);
      seal.group.position.set(x, 3.1, -0.4);
      scene.add(seal.group);
      return { mat, seal };
    });

    // ── 4 the rider on the third pillar, and the line that gives it away ──
    const riderMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.7, transparent: true, opacity: 0.2 });
    const rider = new THREE.Mesh(new THREE.OctahedronGeometry(0.42), riderMat);
    rider.position.set(5.2, 1.3, -0.3);
    scene.add(rider);
    const line = holoPanel("CommandLine", ["rundll32.exe", "...\\Temp\\ms4f.dat,Start", "parent: wscript.exe"], Wn, 3.1, 1.5);
    line.mesh.position.set(5.2, 0.9, 2.4);
    scene.add(line.mesh);

    // ── 5 the rule shield at the end of the row ──
    const rule = shield(B, "alert", 1.5);
    rule.group.position.set(11, 2.4, -0.4);
    rule.group.rotation.y = -0.5;
    scene.add(rule.group);
    const con = terminal(["| where FileName in (...)", "| where CommandLine has_any", "| where Parent !in (...)"], B, 2.5, 1.3);
    con.group.position.set(10.6, 0.1, 2.2);
    scene.add(con.group);

    const anchors = [new THREE.Vector3(-9, 4.4, 0), new THREE.Vector3(-3.4, 6.1, 0.4), new THREE.Vector3(2, 6.4, -1.2), new THREE.Vector3(7.2, 6.4, -1.2), new THREE.Vector3(11, 5, -0.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 68 : asp < 1.5 ? 34 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.18;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.5 : 0.3) + 3, Math.cos(yaw) * dist + 2);
      camera.lookAt(1, 2.6, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 text flows through the arch, then swarms up into the file
      archMat.opacity = 0.35 + level[0] * 0.6;
      scanMat.opacity = 0.05 + level[0] * (0.12 + pulse * 0.1);
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      bits.forEach(p => {
        const u = rm ? p.o : ((t * 0.14 + p.o) % 1);
        const fly = u < 0.6 ? u / 0.6 : 1, up = u < 0.6 ? 0 : (u - 0.6) / 0.4;
        p.mesh.position.set(-15 + fly * 11.6, p.y + up * (4.1 - p.y), p.z * (1 - up) + up * 0.4);
        p.mat.opacity = go * 0.9 * (up > 0.9 ? (1 - up) * 10 : 1);
      });
      // 2 the file solidifies over the laptop
      built.mat.opacity = 0.08 + Math.max(level[0], level[1]) * 0.9;
      built.group.rotation.y = rm ? 0 : Math.sin(t * 0.5) * 0.25;
      // 3 the pillars and their seals
      pillars.forEach((p, i) => {
        const lit = i < 2 ? level[1] : level[2];
        p.mat.opacity = 0.6 + lit * 0.3;
        p.mat.emissiveIntensity = 0.05 + lit * 0.12;
        p.seal.mat.opacity = 0.3 + lit * 0.7;
      });
      // 4 the rider and the line
      riderMat.opacity = 0.15 + level[3] * 0.8;
      rider.rotation.y = rm ? 0 : t * 1.2;
      rider.position.y = 1.3 + (rm ? 0 : Math.sin(t * 1.6) * 0.15);
      line.mat.opacity = 0.1 + level[3] * 0.85;
      // 5 the rule
      rule.mat.opacity = 0.3 + level[4] * 0.7;
      rule.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      con.screenMat.opacity = 0.25 + level[4] * 0.75;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#151003]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
