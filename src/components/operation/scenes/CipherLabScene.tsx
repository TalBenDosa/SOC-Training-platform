"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The cipher room": three machines on a bench, one per operation. The encoder
 * (a glass cube: text goes in and comes back out, arrows both ways), the
 * cipher vault (a safe that opens only with its key), and the hash press (a
 * one-way press that turns anything into a fixed-length token). Behind them a
 * wall of hash fingerprints with one red match, and in front a TLS tunnel
 * between a client and a server: the payload hidden, the SNI tag readable on
 * the outside. Stations switch each piece on in order. Decorative only.
 */
function tag(text: string, color: string, w = 300) {
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

const HEX = "0123456789abcdef";

export default function CipherLabScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05040c, 26, 66);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();
    let seed = 21;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };

    scene.add(new THREE.HemisphereLight(0xc4b5fd, 0x05040c, 0.8));
    const key = new THREE.DirectionalLight(0xe0e7ff, 1.1);
    key.position.set(-5, 14, 12);
    scene.add(key);
    const grid = new THREE.GridHelper(60, 30, 0x221a3d, 0x150f28);
    scene.add(grid);
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x1c1830, metalness: 0.6, roughness: 0.35 });
    const edge = new THREE.LineBasicMaterial({ color: 0x4c3f78, transparent: true, opacity: 0.8 });
    const solid = (geo: THREE.BufferGeometry, x: number, y: number, z: number, m: THREE.Material) => {
      const mesh = new THREE.Mesh(geo, m);
      mesh.position.set(x, y, z);
      scene.add(mesh);
      const e = new THREE.LineSegments(new THREE.EdgesGeometry(geo), edge);
      e.position.copy(mesh.position);
      scene.add(e);
      return mesh;
    };

    // ── 1 the three plinths ──
    const plinthMats = [-7, 0, 7].map(x => {
      const m = metal();
      solid(new THREE.CylinderGeometry(2, 2.2, 0.5, 32), x, 0.25, 0, m);
      return m;
    });
    const ringMats = [-7, 0, 7].map(x => {
      const m = additive(A, 0.1);
      const ring = new THREE.Mesh(new THREE.RingGeometry(2.05, 2.3, 48), m);
      ring.rotation.x = -Math.PI / 2; ring.position.set(x, 0.52, 0);
      scene.add(ring);
      return m;
    });

    // ── 2 the encoder: a glass cube with letters flowing through, both ways ──
    const glass = new THREE.MeshPhysicalMaterial({ color: 0x93c5fd, transparent: true, opacity: 0.18, roughness: 0.1, metalness: 0.1 });
    solid(new THREE.BoxGeometry(2.4, 2.4, 2.4), -7, 1.9, 0, glass);
    const encIn = tag("Hello", "#e2e8f0", 200);
    const encOut = tag("SGVsbG8=", "#93c5fd", 240);
    scene.add(encIn, encOut);
    const encLab = tag("ENCODE ⇄ DECODE", "#bfdbfe", 340);
    encLab.position.set(-7, 4, 0);
    scene.add(encLab);

    // ── 3 the cipher vault: a safe and its key ──
    const vaultMat = metal();
    solid(new THREE.BoxGeometry(2.4, 2.6, 2.2), 0, 1.8, 0, vaultMat);
    const dial = new THREE.Mesh(new THREE.TorusGeometry(0.5, 0.08, 8, 32), additive(B, 0.2));
    dial.position.set(0, 1.9, 1.15);
    scene.add(dial);
    const keyMesh = new THREE.Mesh(new THREE.TorusGeometry(0.28, 0.07, 8, 24), new THREE.MeshStandardMaterial({ color: 0xfbbf24, metalness: 0.8, roughness: 0.3 }));
    keyMesh.position.set(1.8, 2.8, 1);
    scene.add(keyMesh);
    const vaultLab = tag("ENCRYPT + KEY = DECRYPT", "#ddd6fe", 420);
    vaultLab.position.set(0, 4, 0);
    scene.add(vaultLab);

    // ── 4 the hash press: anything in, a fixed token out, never back ──
    const pressMat = metal();
    solid(new THREE.BoxGeometry(2.2, 0.6, 2.2), 7, 3.4, 0, pressMat);
    const ram = new THREE.Mesh(new THREE.BoxGeometry(1.6, 0.4, 1.6), new THREE.MeshStandardMaterial({ color: 0x3b2f63, metalness: 0.7 }));
    ram.position.set(7, 2.6, 0);
    scene.add(ram);
    const token = tag("9f86d081…b0f00a08", "#fda4af", 360);
    token.position.set(7, 1, 1.6);
    scene.add(token);
    const pressLab = tag("HASH → (no way back)", "#fecdd3", 380);
    pressLab.position.set(7, 4.5, 0);
    scene.add(pressLab);

    // ── 5 the fingerprint wall behind the bench ──
    const wallTokens = Array.from({ length: 42 }, (_, i) => {
      const s = Array.from({ length: 8 }, () => HEX[Math.floor(rnd() * 16)]).join("");
      const sp = tag(s, i === 23 ? "#f43f5e" : "#7c6fb0", 220);
      sp.position.set(-12 + (i % 7) * 4, 1.4 + Math.floor(i / 7) * 0.75, -9);
      (sp.material as THREE.SpriteMaterial).opacity = 0.15;
      scene.add(sp);
      return { mat: sp.material as THREE.SpriteMaterial, bad: i === 23 };
    });

    // ── 6 the TLS tunnel in front: client to server ──
    const tunnelCurve = new THREE.CatmullRomCurve3([new THREE.Vector3(-11, 1.2, 6), new THREE.Vector3(0, 2.2, 7.5), new THREE.Vector3(11, 1.2, 6)]);
    const tunnelMat = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.05, wireframe: true });
    scene.add(new THREE.Mesh(new THREE.TubeGeometry(tunnelCurve, 60, 0.7, 12, false), tunnelMat));
    solid(new THREE.BoxGeometry(1.4, 1, 1), -11.8, 0.8, 6, metal()); // the client
    solid(new THREE.BoxGeometry(1.2, 2, 1.2), 11.8, 1, 6, metal()); // the server
    const sni = tag("SNI: sync.cdn-update.example", "#fde68a", 520);
    sni.position.set(0, 3.6, 7.5);
    scene.add(sni);
    const sniMat = sni.material as THREE.SpriteMaterial;
    const packets = Array.from({ length: 6 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.9, 0.9, 1);
      scene.add(s);
      return { s, t: i / 6 };
    });

    const anchors = [new THREE.Vector3(0, 5.2, 0), new THREE.Vector3(-7, 5, 0), new THREE.Vector3(7, 5.6, 0), new THREE.Vector3(-12, 6.2, -9), new THREE.Vector3(0, 4.6, 7.5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 26, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 50 : asp < 1.5 ? 31 : 26; };

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.62 : 0.42), Math.cos(yaw) * dist + 4);
      camera.lookAt(0, 2.4, 1.5);

      // 1 the bench powers up
      ringMats.forEach(m => { m.opacity = 0.1 + level[0] * 0.8; });
      plinthMats.forEach(m => m.emissive.copy(A).multiplyScalar(level[0] * 0.15));
      // 2 encoder: the text swaps form, back and forth
      const flip = rm ? 0 : (Math.sin(t * 1.2) > 0 ? 1 : 0);
      encIn.position.set(-7, 1.9 + (flip ? 0.3 : -0.3), 1.5);
      encOut.position.set(-7, 1.9 + (flip ? -0.3 : 0.3), 1.5);
      (encIn.material as THREE.SpriteMaterial).opacity = 0.2 + level[1] * 0.8 * (flip ? 1 : 0.35);
      (encOut.material as THREE.SpriteMaterial).opacity = 0.2 + level[1] * 0.8 * (flip ? 0.35 : 1);
      glass.opacity = 0.12 + level[1] * 0.2;
      // 3 hash press: the ram stamps, the token appears; 4 the fingerprint wall lights with one red match
      ram.position.y = 2.6 - (rm ? 0 : Math.max(0, Math.sin(t * 2.2)) * 0.9 * level[2]);
      (token.material as THREE.SpriteMaterial).opacity = 0.15 + level[2] * 0.85;
      pressMat.emissive.copy(Wn).multiplyScalar(level[2] * 0.12);
      wallTokens.forEach(w => { w.mat.opacity = 0.12 + level[3] * (w.bad ? (rm ? 0.88 : 0.6 + pulse * 0.28) : 0.55); });
      // 5 the vault: the key turns, the tunnel opens with its SNI readable outside
      (dial.material as THREE.MeshBasicMaterial).opacity = 0.2 + level[4] * 0.8;
      if (!rm) { dial.rotation.z += dt * level[4] * 2; keyMesh.rotation.y += dt; }
      vaultMat.emissive.copy(B).multiplyScalar(level[4] * 0.2);
      tunnelMat.opacity = 0.05 + level[4] * 0.3;
      sniMat.opacity = level[4];
      packets.forEach(p => {
        if (!rm) p.t = (p.t + dt * 0.18) % 1;
        tunnelCurve.getPointAt(rm ? 0.5 : p.t, p.s.position);
        (p.s.material as THREE.SpriteMaterial).opacity = level[4] * 0.9;
      });

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0d0a1c]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
