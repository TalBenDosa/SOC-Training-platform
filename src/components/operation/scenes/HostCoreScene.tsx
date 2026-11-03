"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Host core": the inside of one Windows machine. The kernel (Ring 0) burns at
 * the centre inside the user-space ring (Ring 3). Around it, one district per
 * station: the folder tree, the registry hive (its Run cell turns red when the
 * persistence is found), the process tree (a masquerading branch gets a
 * quarantine ring), a PowerShell console, and finally the macro chain
 * (WINWORD to powershell) locked inside a cage. Decorative only.
 */
const FOLDERS = ["System32", "Program Files", "AppData", "Temp", "ProgramData"];
const HIVES = ["HKLM", "HKCU", "HKCR", "HKU", "HKCC", "Run"];

function textTex(lines: string[], w: number, h: number, color: string, size: number, bg?: string) {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const g = c.getContext("2d")!;
  if (bg) { g.fillStyle = bg; g.fillRect(0, 0, w, h); }
  g.fillStyle = color; g.font = `bold ${size}px monospace`; g.textBaseline = "top";
  lines.forEach((l, i) => g.fillText(l, 12, 10 + i * (size + 8)));
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}
const sprite = (tex: THREE.Texture, w: number, h: number) => {
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  s.scale.set(w, h, 1);
  return s;
};

export default function HostCoreScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03050c, 26, 70);
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x05080f, 0.7));
    const key = new THREE.DirectionalLight(0xd6e2ff, 1);
    key.position.set(4, 16, 12);
    scene.add(key);
    const grid = new THREE.PolarGridHelper(24, 24, 10, 64, 0x16233d, 0x0e1729);
    scene.add(grid);

    // ── Kernel core, Ring 0, and the user-space ring, Ring 3 ──
    const core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.4, 3), new THREE.MeshBasicMaterial({ color: A, wireframe: true, transparent: true, opacity: 0.7 }));
    core.position.y = 3;
    scene.add(core);
    const coreGlow = sprite(glow, 7, 7);
    (coreGlow.material as THREE.SpriteMaterial).color = A.clone();
    (coreGlow.material as THREE.SpriteMaterial).blending = THREE.AdditiveBlending;
    coreGlow.position.y = 3;
    scene.add(coreGlow);
    const ring0 = new THREE.Mesh(new THREE.TorusGeometry(2.6, 0.06, 8, 80), additive(A, 0.6));
    ring0.position.y = 3; ring0.rotation.x = Math.PI / 2;
    scene.add(ring0);
    const ring3 = new THREE.Mesh(new THREE.TorusGeometry(5.2, 0.05, 8, 120), additive(0x60a5fa, 0.35));
    ring3.position.y = 3; ring3.rotation.x = Math.PI / 2;
    scene.add(ring3);
    const r0lab = sprite(textTex(["RING 0 · KERNEL"], 320, 48, "#e2e8f0", 26), 3.4, 0.5);
    r0lab.position.set(0, 4.9, 0);
    scene.add(r0lab);
    const r3lab = sprite(textTex(["RING 3 · USER SPACE"], 400, 48, "#93c5fd", 26), 4.2, 0.5);
    r3lab.position.set(0, 3.7, 5.3);
    scene.add(r3lab);

    // ── 1 Folder tree (front left) ──
    const folders = FOLDERS.map((name, i) => {
      const mat = new THREE.MeshBasicMaterial({ map: textTex([name], 320, 64, "#f8fafc", 28, "#132036"), transparent: true, opacity: 0.25, side: THREE.DoubleSide });
      const tile = new THREE.Mesh(new THREE.PlaneGeometry(3, 0.6), mat);
      tile.position.set(-9.5 + (i % 2) * 0.5, 1 + i * 0.85, 5);
      tile.rotation.y = 0.5;
      scene.add(tile);
      return mat;
    });

    // ── 2 Registry hive (back left) ──
    const hives = HIVES.map((name, i) => {
      const isRun = name === "Run";
      const mat = new THREE.MeshBasicMaterial({ color: 0x1e293b, transparent: true, opacity: 0.6 });
      const hex = new THREE.Mesh(new THREE.CylinderGeometry(1, 1, 0.3, 6), mat);
      const col = i % 3, row = Math.floor(i / 3);
      hex.position.set(-10 + col * 1.75 + (row % 2) * 0.87, 1 + row * 1.5, -6);
      hex.rotation.x = Math.PI / 2;
      scene.add(hex);
      const lab = sprite(textTex([name], 160, 48, "#e2e8f0", 30), 1.2, 0.36);
      lab.position.copy(hex.position).add(new THREE.Vector3(0, 0, 0.3));
      scene.add(lab);
      return { mat, isRun };
    });

    // ── 3 Process tree (back right) ──
    const procMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.3 });
    const badMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.3 });
    const nodes: [number, number, boolean][] = [[0, 0, false], [-1.6, -1.4, false], [1.6, -1.4, false], [-2.4, -2.8, false], [-0.8, -2.8, false], [1.6, -2.8, true], [1.6, -4.1, true]];
    const edges: [number, number][] = [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5], [5, 6]];
    const base = new THREE.Vector3(8.5, 6.3, -5.5);
    nodes.forEach(([x, y, bad]) => {
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.32, 16, 12), bad ? badMat : procMat);
      m.position.set(base.x + x, base.y + y, base.z);
      scene.add(m);
    });
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0.2 });
    edges.forEach(([a, b]) => {
      const pa = new THREE.Vector3(base.x + nodes[a][0], base.y + nodes[a][1], base.z), pb = new THREE.Vector3(base.x + nodes[b][0], base.y + nodes[b][1], base.z);
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([pa, pb]), edgeMat));
    });
    const quarantine = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.05, 8, 48), additive(0x34d399, 0));
    quarantine.position.set(base.x + 1.6, base.y - 3.45, base.z);
    scene.add(quarantine);

    // ── 4 PowerShell console (front right) ──
    const psLines = ["PS C:\\> Get-Process | Where-Object CPU -gt 50", "PS C:\\> Get-Service | Where Status -eq Running", "PS C:\\> Get-WinEvent -FilterHashtable @{...Id=7045}", "PS C:\\> Get-ChildItem $env:APPDATA -Recurse", "PS C:\\> ... | Export-Csv evidence.csv"];
    const psTex = textTex(psLines, 900, 230, "#e2e8f0", 26, "#012456");
    const psMat = new THREE.MeshBasicMaterial({ map: psTex, transparent: true, opacity: 0.2 });
    const ps = new THREE.Mesh(new THREE.PlaneGeometry(5.6, 1.45), psMat);
    ps.position.set(9, 2.6, 4.5);
    ps.rotation.y = -0.55;
    scene.add(ps);

    // ── 5 The macro chain, caged ──
    const chainMat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0.25 });
    const chainA = new THREE.Mesh(new THREE.OctahedronGeometry(0.55), chainMat);
    const chainB = new THREE.Mesh(new THREE.OctahedronGeometry(0.55), chainMat);
    chainA.position.set(-1.2, 1.2, 9); chainB.position.set(1.2, 1.2, 9);
    scene.add(chainA, chainB);
    const link = new THREE.Line(new THREE.BufferGeometry().setFromPoints([chainA.position, chainB.position]), new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0.6 }));
    scene.add(link);
    const chainLab = sprite(textTex(["WINWORD.EXE  ->  powershell.exe"], 620, 48, "#fda4af", 28), 4.6, 0.36);
    chainLab.position.set(0, 2.2, 9);
    scene.add(chainLab);
    const cageMat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0 });
    const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(4, 2.4, 2)), cageMat);
    cage.position.set(0, 1.4, 9);
    scene.add(cage);

    const anchors = [new THREE.Vector3(-9.5, 5.6, 5), new THREE.Vector3(-8.4, 4.6, -6), new THREE.Vector3(8.5, 7.3, -5.5), new THREE.Vector3(9, 3.8, 4.5), new THREE.Vector3(0, 3, 9)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 26, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 44 : asp < 1.5 ? 30 : 25; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }
      const prog = stations.filter(s => s.status === "cleared").length / Math.max(1, stations.length);

      const yaw = rm ? 0.2 : t * 0.05;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.8 : 0.55), Math.cos(yaw) * dist);
      camera.lookAt(0, 2.8, 0);

      if (!rm) { core.rotation.y += dt * 0.4; ring0.rotation.z += dt * 0.6; ring3.rotation.z -= dt * 0.15; }
      (coreGlow.material as THREE.SpriteMaterial).opacity = 0.35 + prog * 0.5;

      folders.forEach((m, i) => { m.opacity = 0.2 + THREE.MathUtils.clamp(level[0] * 5 - i, 0, 1) * 0.8; });
      hives.forEach(h => {
        const on = level[1];
        h.mat.color.set(h.isRun ? Wn : A).lerp(new THREE.Color(0x1e293b), 1 - on);
        h.mat.opacity = 0.35 + on * 0.55 * (h.isRun && !rm ? 0.7 + Math.sin(t * 5) * 0.3 : 1);
      });
      procMat.opacity = 0.25 + level[2] * 0.7;
      badMat.opacity = 0.25 + level[2] * 0.7;
      edgeMat.opacity = 0.15 + level[2] * 0.6;
      (quarantine.material as THREE.MeshBasicMaterial).opacity = level[2] * 0.9;
      if (!rm) quarantine.rotation.z += dt;
      psMat.opacity = 0.2 + level[3] * 0.8;
      if (!rm && level[3] > 0.5) psTex.offset.y = (t * 0.05) % 0.3;
      chainMat.opacity = 0.25 + (stations[4]?.status !== "locked" ? 0.5 : 0);
      if (!rm) { chainA.rotation.y += dt; chainB.rotation.y += dt; }
      cageMat.opacity = level[4] * 0.9;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#071021]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
