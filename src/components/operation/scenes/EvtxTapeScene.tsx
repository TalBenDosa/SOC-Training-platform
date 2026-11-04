"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The flight recorder": an orange recorder box spools a tape of event IDs
 * (4624 blue, 4625 amber, 4688 violet, 4720 green) that loops across the floor;
 * at the far end, old tape drops off the reel as the log wraps. Beside it a
 * logon-type dial whose needle sweeps the types; a process pillar where
 * w3wp.exe grows a cmd.exe branch; and a spray fan: one red source shooting
 * arrows at many account nodes, one of which lights up, followed by a hop to
 * a second host. Stations switch each part on. Decorative only.
 */
const IDS = [["4624", 0x38bdf8], ["4625", 0xfacc15], ["4688", 0xa78bfa], ["4720", 0x34d399], ["4672", 0xf472b6]] as const;

function tag(text: string, color: string, w = 200) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 28px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}

export default function EvtxTapeScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03070a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xe0f2fe, 0x03070a, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0c4a6e, 0x082032));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x24303c, emissive: 0x081018, metalness: 0.55, roughness: 0.4 });

    // ── 1 the recorder and its tape ──
    const box = new THREE.Mesh(new THREE.BoxGeometry(2.4, 1.6, 1.6), new THREE.MeshStandardMaterial({ color: 0xea580c, emissive: 0xea580c, emissiveIntensity: 0.1, metalness: 0.4, roughness: 0.5 }));
    box.position.set(-12, 0.8, 0);
    scene.add(box);
    const reel = new THREE.Mesh(new THREE.CylinderGeometry(0.7, 0.7, 0.3, 24), metal());
    reel.rotation.x = Math.PI / 2;
    reel.position.set(-12, 2.2, 0);
    scene.add(reel);
    const tapePath = new THREE.CatmullRomCurve3([new THREE.Vector3(-12, 2.2, 0.3), new THREE.Vector3(-8, 0.4, 3), new THREE.Vector3(0, 0.3, 3.4), new THREE.Vector3(8, 0.4, 3), new THREE.Vector3(12, 1.2, 2)]);
    const tokens = Array.from({ length: 18 }, (_, i) => {
      const [txt, col] = IDS[i % IDS.length];
      const s = tag(txt, `#${col.toString(16).padStart(6, "0")}`, 140);
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return { s, o: i / 18 };
    });
    const drops = Array.from({ length: 4 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x64748b, transparent: true, opacity: 0, depthWrite: false }));
      s.scale.set(0.5, 0.5, 1);
      scene.add(s);
      return s;
    });

    // ── 2 the logon-type dial ──
    const dial = new THREE.Mesh(new THREE.CircleGeometry(1.8, 48), new THREE.MeshStandardMaterial({ color: 0x24303c, side: THREE.DoubleSide }));
    dial.position.set(-5, 2.4, -1.5);
    scene.add(dial);
    const types = ["2", "3", "4", "5", "7", "9", "10", "11"];
    const typeTags = types.map((n, i) => {
      const a = Math.PI / 2 - (i / types.length) * Math.PI * 2;
      const s = tag(n, n === "9" ? "#fecdd3" : "#e0f2fe", 80);
      s.position.set(-5 + Math.cos(a) * 1.4, 2.4 + Math.sin(a) * 1.4, -1.4);
      (s.material as THREE.SpriteMaterial).opacity = 0.2;
      scene.add(s);
      return s.material as THREE.SpriteMaterial;
    });
    const needleMat = additive(A, 0.2);
    const needle = new THREE.Mesh(new THREE.BoxGeometry(0.06, 1.2, 0.04), needleMat);
    needle.geometry.translate(0, 0.6, 0);
    needle.position.set(-5, 2.4, -1.38);
    scene.add(needle);

    // ── 3 the process pillar ──
    const pillar = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.5, 1), metal());
    pillar.position.set(1.5, 0.25, -1.5);
    scene.add(pillar);
    const w3 = tag("w3wp.exe", "#e0f2fe", 200); w3.position.set(1.5, 0.9, -1.5); scene.add(w3);
    const branchMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(1.5, 1.2, -1.5), new THREE.Vector3(1.5, 2.4, -1.5), new THREE.Vector3(2.6, 3.4, -1.5)]), branchMat));
    const cmd = tag("cmd.exe", "#fecdd3", 180); cmd.position.set(2.8, 3.8, -1.5); (cmd.material as THREE.SpriteMaterial).opacity = 0; scene.add(cmd);

    // ── 4 the spray fan ──
    const src = new THREE.Vector3(6, 1.5, -2);
    const srcMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.3 });
    const srcM = new THREE.Mesh(new THREE.OctahedronGeometry(0.5), srcMat);
    srcM.position.copy(src);
    scene.add(srcM);
    const accounts = Array.from({ length: 8 }, (_, i) => {
      const p = new THREE.Vector3(10 + (i % 2) * 1.2, 0.5 + i * 0.5, -3.5 + (i % 3) * 1.5);
      const hit = i === 5;
      const mat = new THREE.MeshStandardMaterial({ color: 0x24303c, emissive: hit ? 0x34d399 : 0xfacc15, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.22, 12, 10), mat);
      m.position.copy(p);
      scene.add(m);
      return { p, mat, hit };
    });
    const arrows = accounts.map(a => {
      const mat = new THREE.LineBasicMaterial({ color: 0xfacc15, transparent: true, opacity: 0 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([src, a.p]), mat));
      return mat;
    });
    const host2 = new THREE.Mesh(new THREE.BoxGeometry(1, 1.4, 1), metal());
    host2.position.set(13.5, 0.7, 1);
    scene.add(host2);
    const hopMat = new THREE.LineDashedMaterial({ color: Wn, dashSize: 0.2, gapSize: 0.15, transparent: true, opacity: 0 });
    const hop = new THREE.Line(new THREE.BufferGeometry().setFromPoints([accounts[5].p, new THREE.Vector3(13.5, 1.4, 1)]), hopMat);
    hop.computeLineDistances();
    scene.add(hop);

    const anchors = [new THREE.Vector3(-12, 3.8, 0), new THREE.Vector3(-5, 4.8, -1.5), new THREE.Vector3(2, 5, -1.5), new THREE.Vector3(9, 5.4, -2)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 1.8, 0);

      // 1 tape runs; old events fall off the far end
      const on = Math.max(level[0], stations[0]?.status === "open" ? 0.5 : 0);
      if (!rm) reel.rotation.y += dt * 2 * on;
      tokens.forEach(k => {
        const u = rm ? k.o : ((t * 0.05 + k.o) % 1);
        tapePath.getPointAt(u, k.s.position);
        k.s.position.y += 0.35;
        (k.s.material as THREE.SpriteMaterial).opacity = on * (u > 0.92 ? (1 - u) * 12 : 1);
      });
      drops.forEach((d, i) => {
        const v = rm ? 0.5 : ((t * 0.4 + i / 4) % 1);
        d.position.set(12, 1.2 - v * 1.2, 2 + i * 0.2);
        (d.material as THREE.SpriteMaterial).opacity = level[0] * (1 - v) * 0.8;
      });
      // 2 the needle sweeps the logon types, resting on 9
      const sweep = level[1] > 0.9 ? 5 : ((rm ? 0 : t * 0.6) % types.length);
      needle.rotation.z = -(sweep / types.length) * Math.PI * 2;
      needleMat.opacity = 0.2 + level[1] * 0.7;
      typeTags.forEach((m, i) => { m.opacity = 0.2 + level[1] * (Math.round(sweep) % types.length === i ? 0.8 : 0.4); });
      // 3 the web server grows a shell
      branchMat.opacity = level[2] * 0.9;
      (cmd.material as THREE.SpriteMaterial).opacity = level[2];
      // 4 the spray fan, one hit, one hop
      srcMat.opacity = 0.3 + level[3] * 0.7;
      srcMat.emissiveIntensity = level[3] * 0.7;
      arrows.forEach((m, i) => { m.opacity = THREE.MathUtils.clamp(level[3] * 8 - i, 0, 1) * 0.6; });
      accounts.forEach((a, i) => {
        const v = THREE.MathUtils.clamp(level[3] * 8 - i, 0, 1);
        a.mat.emissiveIntensity = v * (a.hit ? (rm ? 0.9 : 0.6 + pulse * 0.4) : 0.3);
      });
      hopMat.opacity = level[3] > 0.9 ? 0.9 : 0;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#061018]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
