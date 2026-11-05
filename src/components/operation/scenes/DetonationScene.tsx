"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, netNode, packet, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Detonation": a glass sandbox cage on a plinth with a sample orb inside.
 * When the sandbox is understood the orb pulses and throws packets out
 * through the cage wall to a remote node (the capture). A static bench holds
 * the sample as a document under a scanning ring with string chips floating
 * off it; a YARA terminal scans a row of quarantine files, three of them
 * lighting red; an alert panel and a closing shield finish the line.
 * Stations switch each part on. Decorative only.
 */
export default function DetonationScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x050803, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xecfccb, 0x050803, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x2f4410, 0x0c1206));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the sandbox cage ──
    const plinth = new THREE.Mesh(new THREE.CylinderGeometry(2.2, 2.4, 0.4, 32), new THREE.MeshStandardMaterial({ color: 0x1f2a14, metalness: 0.5, roughness: 0.4 }));
    plinth.position.set(-6, 0.2, 0);
    scene.add(plinth);
    const cageMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.1, transparent: true, opacity: 0.12, depthWrite: false });
    const cage = new THREE.Mesh(new THREE.BoxGeometry(3.4, 3.4, 3.4), cageMat);
    cage.position.set(-6, 2.1, 0);
    scene.add(cage);
    const cageEdge = new THREE.LineSegments(new THREE.EdgesGeometry(cage.geometry), new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.5 }));
    cageEdge.position.copy(cage.position);
    scene.add(cageEdge);
    const orbMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.4 });
    const orb = new THREE.Mesh(new THREE.IcosahedronGeometry(0.5, 1), orbMat);
    orb.position.copy(cage.position);
    scene.add(orb);
    const sl = labelSprite("SANDBOX · 120 s", "#d9f99d", 260); sl.position.set(-6, 4.3, 0); scene.add(sl);
    const c2 = netNode(Wn, 0.5);
    c2.group.position.set(-11, 4.6, -3);
    scene.add(c2.group);
    const c2l = labelSprite("198.51.100.88", "#fecdd3", 240); c2l.position.set(-11, 5.6, -3); scene.add(c2l);
    const pks = Array.from({ length: 5 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 5 }; });

    // ── 2 the static bench ──
    const bench = new THREE.Mesh(new THREE.BoxGeometry(3, 0.2, 1.6), new THREE.MeshStandardMaterial({ color: 0x27331a, metalness: 0.4, roughness: 0.5 }));
    bench.position.set(-0.5, 1, 2.6);
    scene.add(bench);
    const sample = docFile("stage2.bin", A);
    sample.group.position.set(-0.5, 1.9, 2.6);
    sample.group.scale.setScalar(0.9);
    scene.add(sample.group);
    const scanMat = additive(A, 0);
    const scanRing = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.04, 8, 40), scanMat);
    scanRing.rotation.x = Math.PI / 2;
    scanRing.position.set(-0.5, 1.9, 2.6);
    scene.add(scanRing);
    const strs = ["gate.php", "LDG_sync_4f1a", "MSIE 7.0", "dsync.exe"].map((t, i) => {
      const s = labelSprite(t, "#d9f99d", 220);
      s.scale.multiplyScalar(0.6);
      scene.add(s);
      return { s, a: (i / 4) * Math.PI * 2 };
    });

    // ── 3 YARA across the quarantine folder ──
    const yara = terminal(["$ yara -r dentalsync.yar .", "DentalSync_Loader ./bristol/...", "DentalSync_Loader ./bristol/...", "DentalSync_Loader ./leeds/..."], A, 1.9, 1.15);
    yara.group.position.set(4.6, 0, 2.6);
    yara.group.rotation.y = -0.4;
    scene.add(yara.group);
    const qfiles = Array.from({ length: 5 }, (_, i) => {
      const d = docFile(["Appt_Changes", "stage2.bin", "Recall_Nov", "printer_drv", "xray_viewer"][i], [0, 1, 2].includes(i) ? Wn : B);
      d.group.scale.setScalar(0.5);
      d.group.position.set(3 + i * 0.9, 0.7, -1.4);
      scene.add(d.group);
      return { d, hit: i < 3 };
    });
    const racks = [6.6, 8].map(x => { const r = serverRack(B, 5); r.group.position.set(x, 0, -3.6); scene.add(r.group); return r; });

    // ── 4 the alert and 5 the shield ──
    const alertPanel = holoPanel("DEFENDER ALERT", ["Trojan:Win32/...", "Action: Quarantine", "SHA-256 ..."], Wn, 2.2, 1.2);
    alertPanel.mesh.position.set(9.5, 3.6, 0.6);
    alertPanel.mesh.rotation.y = -0.5;
    scene.add(alertPanel.mesh);
    const end = shield(A, "check", 1.2);
    end.group.position.set(1.5, 5.2, -2);
    scene.add(end.group);

    const anchors = [new THREE.Vector3(-6, 5.2, 0), new THREE.Vector3(-0.5, 3.6, 2.6), new THREE.Vector3(4.6, 2.8, 2.6), new THREE.Vector3(9.5, 4.8, 0.6), new THREE.Vector3(1.5, 6.6, -2)];
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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.4) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 2.2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 the cage, the orb and its traffic
      cageMat.opacity = 0.12 + level[0] * 0.12;
      orbMat.emissiveIntensity = 0.4 + level[0] * (rm ? 0.5 : pulse * 0.8);
      if (!rm) { orb.rotation.y += dt * (0.4 + level[0]); orb.rotation.x += dt * 0.3; }
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      pks.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.3 + p.o) % 1);
        p.mesh.position.lerpVectors(cage.position, c2.group.position, u);
        p.mat.opacity = flow * 0.95;
      });
      c2.wireMat.opacity = 0.2 + level[0] * 0.7;
      // 2 the bench scans the sample; strings float off it
      scanMat.opacity = level[1] * 0.85;
      scanRing.position.y = 1.4 + (rm ? 0.5 : ((t * 0.5) % 1)) * 1;
      strs.forEach((s, i) => {
        const a = s.a + (rm ? 0 : t * 0.4);
        s.s.position.set(-0.5 + Math.cos(a) * 1.4, 2.6 + Math.sin(t * 0.8 + i) * 0.2, 2.6 + Math.sin(a) * 0.9);
        (s.s.material as THREE.SpriteMaterial).opacity = level[1];
      });
      // 3 YARA lights the matching files
      yara.screenMat.opacity = 0.3 + level[2] * 0.65;
      qfiles.forEach((q, i) => { q.d.mat.emissiveIntensity = q.hit ? THREE.MathUtils.clamp(level[2] * 4 - i, 0, 1) * 0.6 : 0.05; });
      racks.forEach(r => r.tick(t, 0.4 + level[2] * 0.6, rm));
      // 4 the alert panel, 5 the shield
      alertPanel.mat.opacity = 0.15 + level[3] * 0.8;
      end.mat.opacity = 0.2 + level[4] * 0.8;
      end.mat.emissiveIntensity = 0.1 + level[4] * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0a1004]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
