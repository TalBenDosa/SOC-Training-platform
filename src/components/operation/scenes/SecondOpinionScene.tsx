"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, labelSprite, laptop, netNode, packet, shield, terminal } from "./cyberProps";

/**
 * "Second opinion": an old scanner arch checks file cards and stamps them,
 * while a ghost with no file drifts straight through. Beyond it a laptop sits
 * inside kernel rings, three EDR consoles glow, and a process tree grows with
 * one red node above a verdict shield. Stations switch each part on.
 * Decorative only.
 */
export default function SecondOpinionScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03090a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xccfbf1, 0x03090a, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0a3a35, 0x04100f));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the scanner arch and the files it checks ──
    const archMat = additive(A, 0.12);
    const arch = new THREE.Mesh(new THREE.TorusGeometry(2, 0.14, 10, 40, Math.PI), archMat);
    arch.position.set(-7, 0, 0);
    arch.rotation.y = Math.PI / 2;
    scene.add(arch);
    const al = labelSprite("AV · ALL GREEN", "#99f6e4", 240);
    al.position.set(-7, 2.7, 0);
    scene.add(al);
    const files = Array.from({ length: 3 }, (_, i) => {
      const d = docFile(["invoice", "xray.dcm", "setup"][i], A);
      d.group.scale.setScalar(0.55);
      scene.add(d.group);
      return { ...d, o: i / 3 };
    });

    // ── 2 the ghost with no file ──
    const ghost = packet(Wn);
    ghost.mesh.scale.setScalar(1.8);
    scene.add(ghost.mesh);
    const gl = labelSprite("NO FILE", "#fde68a", 150);
    scene.add(gl);

    // ── 3 a laptop inside kernel rings ──
    const host = laptop(A);
    host.group.position.set(-1.4, 0, 0);
    scene.add(host.group);
    const rings = ["USER", "ETW", "KERNEL"].map((n, i) => {
      const mat = additive(B, 0.06);
      const r = new THREE.Mesh(new THREE.TorusGeometry(1.3 + i * 0.55, 0.035, 8, 50), mat);
      r.position.set(-1.4, 0.8, 0);
      r.rotation.x = Math.PI / 2;
      scene.add(r);
      const l = labelSprite(n, "#fbcfe8", 130);
      l.position.set(-1.4 + Math.cos(0.3 + i * 0.75) * (1.3 + i * 0.55), 0.45, Math.sin(0.3 + i * 0.75) * (1.3 + i * 0.55));
      scene.add(l);
      return { mat, l: l.material as THREE.SpriteMaterial, r };
    });

    // ── 4 three consoles ──
    const consoles = ["FALCON", "SINGULARITY", "DEFENDER XDR"].map((n, i) => {
      const c = terminal([n, "> process tree", "> hunting"], A, 1.9, 1.2);
      c.group.position.set(0.8 + i * 2.9, 1.9, -3.6);
      c.group.scale.setScalar(1.35);
      scene.add(c.group);
      const cl = labelSprite(n, "#99f6e4", 220);
      cl.position.set(0.8 + i * 2.9, 0.35, -2.9);
      scene.add(cl);
      return c;
    });

    // ── 5 the process tree and the verdict ──
    const tree: [number, number, number, number][] = [[7.4, 4.2, 0, -1], [6.4, 3.1, 0, 0], [8.4, 3.1, 0, 0], [7.8, 2, 0, 2], [9, 2, 0, 2]];
    const nodes = tree.map(([x, y, z], i) => {
      const n = netNode(i === 4 ? Wn : B, 0.3);
      n.group.position.set(x, y, z);
      scene.add(n.group);
      return n;
    });
    const linkMat = additive(B, 0.08);
    tree.forEach(([x, y, z, p]) => {
      if (p < 0) return;
      const pos = [x, y, z, tree[p][0], tree[p][1], tree[p][2]];
      const g = new THREE.BufferGeometry().setAttribute("position", new THREE.Float32BufferAttribute(pos, 3));
      scene.add(new THREE.Line(g, linkMat));
    });
    const verdict = shield(A, "check", 1);
    verdict.group.position.set(7.8, 0.9, 1.2);
    scene.add(verdict.group);

    const anchors = [new THREE.Vector3(-7, 3.5, 0), new THREE.Vector3(-4.4, 2.5, 1.2), new THREE.Vector3(-1.4, 3, 0), new THREE.Vector3(3.7, 4.1, -3.6), new THREE.Vector3(7.6, 5.2, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 24, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 58 : asp < 1.5 ? 29 : 24; };

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
      camera.lookAt(0, 2, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 files ride through the arch
      archMat.opacity = 0.12 + level[0] * 0.8;
      files.forEach(f => {
        const u = rm ? 0.4 : ((t * 0.14 + f.o) % 1);
        f.group.position.set(-11 + u * 8, 0.8, 0);
        f.mat.opacity = (0.15 + level[0] * 0.85) * Math.min(1, (1 - u) * 5);
      });
      // 2 the ghost drifts through, unseen
      const gu = rm ? 0.5 : ((t * 0.11) % 1);
      const gx = -11 + gu * 9.6, gy = 1.7 + Math.sin(t * 2) * 0.12;
      ghost.mesh.position.set(gx, gy, 1.2);
      gl.position.set(gx, gy + 0.6, 1.2);
      ghost.mat.opacity = level[1] * 0.9;
      (gl.material as THREE.SpriteMaterial).opacity = level[1];
      // 3 the rings turn round the host
      rings.forEach((r, i) => {
        r.mat.opacity = 0.06 + level[2] * 0.8;
        r.l.opacity = 0.2 + level[2] * 0.8;
        r.r.rotation.z = rm ? 0 : t * (0.3 + i * 0.2);
      });
      // 4 the consoles
      consoles.forEach(c => { c.screenMat.opacity = 0.3 + level[3] * 0.7; });
      // 5 the tree and the verdict
      nodes.forEach((n, i) => {
        n.wireMat.opacity = 0.15 + level[4] * 0.75;
        n.coreMat.opacity = 0.15 + level[4] * (i === 4 ? 0.5 + pulse * 0.4 : 0.7);
        n.group.rotation.y = rm ? 0 : t * 0.5;
      });
      linkMat.opacity = 0.08 + level[4] * 0.7;
      verdict.mat.opacity = 0.25 + level[4] * 0.75;
      verdict.mat.emissiveIntensity = 0.1 + level[4] * 0.6;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04100f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
