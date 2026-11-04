"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Deep water": a seven-layer glass stack on the left that a packet sinks
 * through, picking up headers. Beside it two hosts trade SYN, SYN-ACK, ACK
 * arrows, with a UDP dart that needs no reply. In the middle, a DNS tree
 * resolves down to a leaf, and a TLS tunnel wraps the line to a server. On
 * the right, two devices both claim the gateway's MAC (one turns red), and
 * at the far end a beacon pulses out at steady intervals from inside an
 * allowed pipe. Stations switch each part on. Decorative only.
 */
const LAYERS = ["7 APP", "6 PRES", "5 SESS", "4 TRANSPORT", "3 NETWORK", "2 DATA LINK", "1 PHYSICAL"];

function tag(text: string, color: string, w = 220) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 56;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = "bold 24px monospace"; g.textAlign = "center"; g.textBaseline = "middle";
  g.fillText(text, w / 2, 28);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}

export default function ProtoStackScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x020a09, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xccfbf1, 0x020a09, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x134e4a, 0x0a2522));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x1f3a37, emissive: 0x061210, metalness: 0.55, roughness: 0.4 });

    // ── 1 the seven-layer stack ──
    const slabs = LAYERS.map((n, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: A, transparent: true, opacity: 0.08, emissive: A, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(3, 0.12, 2), mat);
      const y = 5.4 - i * 0.75;
      m.position.set(-12, y, 0);
      scene.add(m);
      const l = tag(n, "#ccfbf1", 220);
      l.position.set(-14.4, y, 0);
      scene.add(l);
      return { mat, y };
    });
    const sinkMat = new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const sink = new THREE.Sprite(sinkMat);
    scene.add(sink);

    // ── 2 the handshake ──
    const hA = new THREE.Mesh(new THREE.BoxGeometry(0.9, 1.2, 0.9), metal()); hA.position.set(-7.5, 0.6, -1); scene.add(hA);
    const hB = new THREE.Mesh(new THREE.BoxGeometry(0.9, 1.2, 0.9), metal()); hB.position.set(-3.5, 0.6, -1); scene.add(hB);
    const flags = ["SYN", "SYN-ACK", "ACK"].map((n, i) => {
      const s = tag(n, i === 1 ? "#ddd6fe" : "#ccfbf1", 160);
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return s;
    });
    const udp = tag("UDP →", "#fde68a", 120); (udp.material as THREE.SpriteMaterial).opacity = 0; scene.add(udp);

    // ── 3 the DNS tree and the TLS tunnel ──
    const dnsPts = [new THREE.Vector3(0, 5, -2), new THREE.Vector3(-0.8, 3.9, -2), new THREE.Vector3(0.8, 3.9, -2), new THREE.Vector3(-0.8, 2.8, -2)];
    const dnsNodes = dnsPts.map((p, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.25 });
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.22, 12, 10), mat);
      m.position.copy(p);
      scene.add(m);
      if (i > 0) scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([i === 3 ? dnsPts[1] : dnsPts[0], p]), new THREE.LineBasicMaterial({ color: 0x5b5b8a })));
      return mat;
    });
    const dl = tag(". > com > quayside", "#ddd6fe", 300); dl.position.set(0, 5.8, -2); scene.add(dl);
    const tunnelMat = new THREE.MeshStandardMaterial({ color: B, transparent: true, opacity: 0.05, side: THREE.DoubleSide });
    const tunnel = new THREE.Mesh(new THREE.CylinderGeometry(0.45, 0.45, 4, 20, 1, true), tunnelMat);
    tunnel.rotation.z = Math.PI / 2;
    tunnel.position.set(0, 1, 1);
    scene.add(tunnel);
    const lock = tag("TLS 1.3", "#ddd6fe", 140); lock.position.set(0, 1.8, 1); scene.add(lock);

    // ── 4 the ARP spoof ──
    const gw = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.6, 0.8), metal()); gw.position.set(5, 0.3, -1); scene.add(gw);
    const rogueMat = new THREE.MeshStandardMaterial({ color: 0x1f3a37, emissive: Wn, emissiveIntensity: 0 });
    const rogue = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.6, 0.8), rogueMat); rogue.position.set(7, 0.3, -1); scene.add(rogue);
    const macA = tag("3c-52-82-1a-9e-f7", "#ccfbf1", 300); macA.position.set(5, 1.1, -1); scene.add(macA);
    const macB = tag("3c-52-82-1a-9e-f7", "#fecdd3", 300); macB.position.set(7, 1.6, -1); (macB.material as THREE.SpriteMaterial).opacity = 0; scene.add(macB);

    // ── 5 the beacon in the allowed pipe ──
    const pipe = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.3, 5, 16, 1, true), new THREE.MeshStandardMaterial({ color: 0x2dd4bf, emissive: 0x2dd4bf, emissiveIntensity: 0.15, transparent: true, opacity: 0.35, side: THREE.DoubleSide }));
    pipe.rotation.z = Math.PI / 2;
    pipe.position.set(12, 2.4, 0);
    scene.add(pipe);
    const pl = tag("HTTP / DNS", "#ccfbf1", 200); pl.position.set(12, 3.2, 0); scene.add(pl);
    const pulses = Array.from({ length: 4 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.4, 0.4, 1);
      scene.add(s);
      return s;
    });

    const anchors = [new THREE.Vector3(-12, 6.6, 0), new THREE.Vector3(-5.5, 3.2, -1), new THREE.Vector3(0, 6.8, -2), new THREE.Vector3(6, 2.8, -1), new THREE.Vector3(12, 4.4, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 33 : 28; };

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
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 2.6, 0);

      // 1 the packet sinks layer by layer
      const sv = rm ? 0.5 : ((t * 0.15) % 1);
      sink.position.set(-12, 5.8 - sv * 5, 0.2);
      sink.scale.setScalar(0.4 + sv * 0.6);
      sinkMat.opacity = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      slabs.forEach((s, i) => {
        const v = THREE.MathUtils.clamp(level[0] * 7 - i, 0, 1);
        s.mat.opacity = 0.08 + v * 0.3;
        s.mat.emissiveIntensity = Math.abs(sink.position.y - s.y) < 0.4 ? v * 0.8 : v * 0.2;
      });
      // 2 handshake flags cross back and forth; a UDP dart flies alone
      const hv = rm ? 0.5 : ((t * 0.25) % 1);
      flags.forEach((f, i) => {
        const local = THREE.MathUtils.clamp(hv * 3 - i, 0, 1);
        const fromX = i === 1 ? -3.5 : -7.5, toX = i === 1 ? -7.5 : -3.5;
        f.position.set(fromX + (toX - fromX) * local, 1.6 + i * 0.5, -1);
        (f.material as THREE.SpriteMaterial).opacity = level[1] * (local > 0 && local < 1 ? 1 : 0.3);
      });
      udp.position.set(-7.5 + hv * 4, 0.3, 0);
      (udp.material as THREE.SpriteMaterial).opacity = level[1] * 0.9;
      // 3 DNS nodes resolve down; the TLS tunnel glows
      dnsNodes.forEach((m, i) => {
        const v = THREE.MathUtils.clamp(level[2] * 4 - i, 0, 1);
        m.opacity = 0.25 + v * 0.7;
        m.emissiveIntensity = v * 0.7;
      });
      tunnelMat.opacity = 0.05 + level[2] * 0.3;
      // 4 the rogue claims the gateway's MAC
      (macB.material as THREE.SpriteMaterial).opacity = level[3];
      rogueMat.emissiveIntensity = level[3] * (rm ? 0.8 : 0.4 + pulse * 0.5);
      // 5 the beacon pulses out at steady intervals
      pulses.forEach((p, i) => {
        const v = rm ? i / 4 : ((t * 0.25 + i / 4) % 1);
        p.position.set(9.5 + v * 5, 2.4, 0);
        (p.material as THREE.SpriteMaterial).opacity = Math.max(level[4], stations[4]?.status === "open" ? 0.4 : 0) * 0.9;
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
            <span className="block whitespace-nowrap rounded-md border bg-[#04141a]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
