"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Open watch": a ring of agent nodes (one dark, one never lit) streaming
 * packets along spokes into a manager core. Beside the core a decoder gear
 * splits each packet into field shards that fall through a rule sieve of
 * three level bands; a watched-file vault pulses when a file changes; an
 * alert beacon rises above the core; and a closing ring loops the whole
 * pipeline. Stations switch each part on. Decorative only.
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

export default function WazuhFlowScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03060d, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xdbeafe, 0x03060d, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1e3a8a, 0x0a1022));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x5b6f96, emissive: 0x111a30, metalness: 0.55, roughness: 0.4 });

    // the manager core
    const core = new THREE.Mesh(new THREE.CylinderGeometry(1.2, 1.2, 2.4, 24), metal());
    core.position.set(0, 1.2, 0);
    scene.add(core);
    const cl = tag("wz-manager-01", "#bfdbfe", 260); cl.position.set(0, 2.9, 0); scene.add(cl);

    // ── 1 agents on a ring ──
    const N = 7, RR = 7;
    const agents = Array.from({ length: N }, (_, i) => {
      const a = Math.PI * 0.15 + (i / (N - 1)) * Math.PI * 0.7 + Math.PI;
      const p = new THREE.Vector3(Math.cos(a) * RR, 0.5, Math.sin(a) * RR * 0.7 + 1);
      const state = i === 2 ? "down" : i === 5 ? "never" : "up";
      const mat = new THREE.MeshStandardMaterial({ color: state === "up" ? B : Wn, emissive: state === "up" ? B : Wn, emissiveIntensity: 0.1, transparent: true, opacity: 0.4 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.7, 0.7, 0.7), mat);
      m.position.copy(p);
      scene.add(m);
      const spokeMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.1 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([p, new THREE.Vector3(0, 0.5, 0)]), spokeMat));
      const pkMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.8, transparent: true, opacity: 0 });
      const pk = new THREE.Mesh(new THREE.SphereGeometry(0.1, 8, 6), pkMat);
      scene.add(pk);
      return { p, mat, spokeMat, pk, pkMat, state, o: i / N };
    });

    // ── 2 decoder gear and rule sieve ──
    const gearMat = additive(A, 0.05);
    const gear = new THREE.Mesh(new THREE.TorusGeometry(0.8, 0.2, 6, 12), gearMat);
    gear.position.set(3.6, 2.6, 0);
    scene.add(gear);
    const gl = tag("decoder", "#bfdbfe", 180); gl.position.set(3.6, 3.8, 0); scene.add(gl);
    const bands = [["0-6", B], ["7-11", A], ["12-15", Wn]].map(([n, col], i) => {
      const mat = new THREE.MeshStandardMaterial({ color: col as THREE.Color, emissive: col as THREE.Color, emissiveIntensity: 0.05, transparent: true, opacity: 0.15 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(2, 0.12, 1.4), mat);
      m.position.set(5.6, 2.2 - i * 0.8, 0);
      scene.add(m);
      const l = tag(`lvl ${n}`, "#e2e8f0", 160); l.position.set(7.1, 2.2 - i * 0.8, 0); scene.add(l);
      return mat;
    });
    const shardMat = additive(A, 0);
    const shards = Array.from({ length: 6 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.16, 0.16, 0.16), shardMat);
      scene.add(m);
      return { m, o: i / 6, x: 5 + (i % 3) * 0.5 };
    });

    // ── 3 the watched-file vault ──
    const vaultMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.4 });
    const vault = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.6, 1.4), vaultMat);
    vault.position.set(-3.8, 0.8, -3.2);
    scene.add(vault);
    const vl = tag("sshd_config", "#fed7aa", 220); vl.position.set(-3.8, 2.1, -3.2); scene.add(vl);
    const eyeMat = additive(A, 0);
    const eye = new THREE.Mesh(new THREE.TorusGeometry(1.1, 0.05, 8, 40), eyeMat);
    eye.position.set(-3.8, 0.8, -3.2);
    scene.add(eye);

    // ── 4 the alert beacon ──
    const beaconMat = additive(Wn, 0);
    const beacon = new THREE.Mesh(new THREE.ConeGeometry(0.5, 1.6, 4), beaconMat);
    beacon.position.set(0, 4.4, 0);
    scene.add(beacon);

    // ── 5 the loop ring ──
    const loopMat = additive(A, 0);
    const loop = new THREE.Mesh(new THREE.TorusGeometry(8.6, 0.06, 8, 96), loopMat);
    loop.rotation.x = Math.PI / 2;
    loop.position.y = 0.1;
    scene.add(loop);

    const anchors = [new THREE.Vector3(-6.5, 2, 2.4), new THREE.Vector3(4.6, 4.8, 0), new THREE.Vector3(-3.8, 3.2, -3.2), new THREE.Vector3(0, 6, 0), new THREE.Vector3(6, 0.6, 5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 22, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 50 : asp < 1.5 ? 27 : 22; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.25;
      camera.position.set(Math.sin(yaw) * dist + 1, dist * (portrait ? 0.6 : 0.45) + 1, Math.cos(yaw) * dist + 3);
      camera.lookAt(1, 1.6, 0);

      // 1 agents and their packets
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      agents.forEach(ag => {
        const up = ag.state === "up";
        ag.mat.opacity = 0.4 + level[0] * 0.5;
        ag.mat.emissiveIntensity = up ? 0.1 + level[0] * 0.5 : (ag.state === "down" ? level[0] * (rm ? 0.5 : pulse * 0.7) : 0.05);
        ag.spokeMat.opacity = up ? 0.1 + level[0] * 0.4 : 0.05;
        const u = rm ? 0.5 : ((t * 0.35 + ag.o) % 1);
        ag.pk.position.lerpVectors(ag.p, new THREE.Vector3(0, 0.5, 0), u);
        ag.pkMat.opacity = up ? flow * 0.9 : 0;
      });
      // 2 the gear turns, shards fall through the bands
      gearMat.opacity = 0.05 + level[1] * 0.85;
      if (!rm) gear.rotation.z += dt * level[1];
      bands.forEach((m, i) => { m.opacity = 0.15 + THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1) * 0.55; m.emissiveIntensity = 0.05 + level[1] * 0.3; });
      shardMat.opacity = level[1] * 0.9;
      shards.forEach(sh => {
        const u = rm ? 0.5 : ((t * 0.4 + sh.o) % 1);
        sh.m.position.set(sh.x, 3.2 - u * 3, 0);
      });
      // 3 the vault pulses under watch
      eyeMat.opacity = level[2] * 0.85;
      if (!rm) eye.rotation.y += dt * 0.7 * level[2];
      vaultMat.emissiveIntensity = level[2] * (rm ? 0.4 : 0.2 + pulse * 0.4);
      // 4 the beacon rises
      beaconMat.opacity = level[3] * 0.9;
      beacon.position.y = 3.4 + level[3] * 1.2;
      if (!rm) beacon.rotation.y += dt * 1.2 * level[3];
      // 5 the loop closes
      loopMat.opacity = level[4] * 0.8;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#050a16]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
