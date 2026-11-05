"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, laptop, netNode, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Rollback": one purple Storyline thread runs from a finance laptop through
 * a chain of event beads (process, file, network) that light as stations
 * clear. A Threat Center panel floats over the start; a remote shell sits by
 * the brewery's server racks; a stack of document files flips from red to
 * clean as a rollback dial rewinds; a shield closes the chain at the end.
 * Stations switch each part on. Decorative only.
 */
export default function StorylineScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x07040f, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xede9fe, 0x07040f, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x3b2370, 0x120a22));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // the finance laptop where the story starts
    const lap = laptop(Wn);
    lap.group.position.set(-9, 0, 2);
    lap.group.scale.setScalar(1.6);
    lap.group.rotation.y = 0.5;
    scene.add(lap.group);
    const ll = labelSprite("LAPTOP · FINANCE", "#fecaca", 260); ll.position.set(-9, 1.9, 2); scene.add(ll);

    // ── 1 Threat Center panel ──
    const tc = holoPanel("THREAT CENTER", ["Threat Status   Mitigated", "AI Confidence   Malicious", "Analyst Verdict Undefined", "Incident Status Unresolved"], A, 2.6, 1.6);
    tc.mesh.position.set(-8.4, 4, 1.2);
    tc.mesh.rotation.y = 0.4;
    scene.add(tc.mesh);

    // the Storyline thread with its beads
    const pts = [new THREE.Vector3(-8.4, 1.4, 2), new THREE.Vector3(-5.5, 2.4, 0.6), new THREE.Vector3(-2.5, 1.8, 1.6), new THREE.Vector3(0.5, 2.8, 0.4), new THREE.Vector3(3.5, 2, 1.2), new THREE.Vector3(6.5, 2.6, 0)];
    const curve = new THREE.CatmullRomCurve3(pts);
    const threadMat = additive(A, 0.15);
    const thread = new THREE.Mesh(new THREE.TubeGeometry(curve, 80, 0.05, 6, false), threadMat);
    scene.add(thread);
    const beads = pts.slice(1).map((p, i) => {
      const n = netNode(i === 2 ? Wn : A, 0.32);
      n.group.position.copy(p);
      scene.add(n.group);
      return n;
    });
    const sid = labelSprite("Storyline 7F3A…", "#ddd6fe", 260); sid.position.set(-1, 3.8, 1); scene.add(sid);

    // ── 2 the brewery server and a remote shell ──
    const racks = [-2.4, -1].map(x => { const r = serverRack(B, 6); r.group.position.set(x, 0, -3.6); scene.add(r.group); return r; });
    const rs = terminal(["root@brew-srv-02:~# top", "2211 kthreaddk 398%", "# systemctl cat", "  kthreadd-helper", "Restart=always"], B, 1.9, 1.15);
    rs.group.position.set(1.4, 0, -3.2);
    rs.group.rotation.y = -0.3;
    scene.add(rs.group);

    // ── 3 encrypted files and the rollback dial ──
    const files = Array.from({ length: 5 }, (_, i) => {
      const d = docFile(i % 2 ? "Q3_brew.xlsx" : "recipe.docx", Wn);
      d.group.scale.setScalar(0.55);
      d.group.position.set(5 + i * 0.5, 0.75, 3.2 - i * 0.15);
      d.group.rotation.y = -0.3;
      scene.add(d.group);
      return d;
    });
    const dialMat = additive(A, 0);
    const dial = new THREE.Mesh(new THREE.TorusGeometry(1, 0.08, 8, 48, Math.PI * 1.7), dialMat);
    dial.position.set(6.2, 2.6, 3);
    scene.add(dial);
    const dl = labelSprite("ROLLBACK", "#ddd6fe", 180); dl.position.set(6.2, 4, 3); scene.add(dl);

    // ── 5 the closing shield ──
    const end = shield(A, "check", 1.2);
    end.group.position.set(8.4, 2.6, -0.4);
    scene.add(end.group);

    const anchors = [new THREE.Vector3(-8.4, 5.4, 1.2), new THREE.Vector3(1.4, 2.6, -3.2), new THREE.Vector3(6.2, 4.8, 3), new THREE.Vector3(0.5, 4.4, 0.4), new THREE.Vector3(8.4, 4.4, -0.4)];
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
      camera.lookAt(0, 2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      lap.screenMat.opacity = 0.35 + (1 - level[3]) * 0.4 + level[3] * 0.2;
      // 1 the Threat Center panel and the thread
      tc.mat.opacity = 0.25 + level[0] * 0.7;
      threadMat.opacity = 0.15 + Math.max(level[0], level[3]) * 0.75;
      beads.forEach((b, i) => { b.wireMat.opacity = 0.2 + THREE.MathUtils.clamp((level[0] + level[3]) * 2.5 - i * 0.5, 0, 1) * 0.7; if (!rm) b.wire.rotation.y += dt * 0.6; });
      // 2 the remote shell and racks
      racks.forEach(r => r.tick(t, 0.4 + level[1] * 0.6, rm));
      rs.screenMat.opacity = 0.3 + level[1] * 0.65;
      // 3 files rewind from red as the dial turns
      dialMat.opacity = level[2] * 0.9;
      if (!rm) dial.rotation.z -= dt * 1.2 * level[2];
      files.forEach((f, i) => {
        const clean = THREE.MathUtils.clamp(level[2] * 5 - i, 0, 1);
        f.mat.emissive.copy(Wn).lerp(A, clean);
        f.mat.emissiveIntensity = 0.25 * (1 - clean) + 0.1;
      });
      // 5 the shield closes the story
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
            <span className="block whitespace-nowrap rounded-md border bg-[#0e0820]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
