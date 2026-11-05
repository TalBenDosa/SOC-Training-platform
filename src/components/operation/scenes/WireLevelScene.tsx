"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, labelSprite, netNode, packet, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Wire level": a giant TCP header lies open as a row of flag switches beside
 * two racks joined by a wire. Packets cross it in a SYN, SYN-ACK, ACK rhythm;
 * a stray probe flickers along the rack row; TTL rings count down hop by hop;
 * a capture screen scrolls; and a reset shield stands at the far end.
 * Stations switch each part on. Decorative only.
 */
export default function WireLevelScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x090602, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x090602, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a3408, 0x151003));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 two racks, one wire, the handshake ──
    const client = serverRack(B, 4, "CLIENT");
    client.group.position.set(-9, 0, -1);
    scene.add(client.group);
    const server = serverRack(A, 4, "SERVER");
    server.group.position.set(-3, 0, -1);
    scene.add(server.group);
    const wireMat = additive(A, 0.1);
    const wire = new THREE.Mesh(new THREE.BoxGeometry(6, 0.05, 0.05), wireMat);
    wire.position.set(-6, 1.6, -1);
    scene.add(wire);
    const shake = [B, A, B].map(c => { const p = packet(c); scene.add(p.mesh); return p; });

    // ── 1b the flag switches ──
    const flags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"].map((n, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: i === 3 ? Wn : A, emissive: i === 3 ? Wn : A, emissiveIntensity: 0.1, transparent: true, opacity: 0.3 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.3, 0.9), mat);
      m.position.set(-8.2 + i * 1.3, 0.15, 2.6);
      scene.add(m);
      const l = labelSprite(n, "#fde68a", 110);
      l.position.set(-8.2 + i * 1.3, 0.75, 2.6);
      scene.add(l);
      return { m, mat };
    });

    // ── 2 the rack row and a stray probe ──
    const row = Array.from({ length: 4 }, (_, i) => {
      const r = serverRack(A, 3);
      r.group.position.set(1 + i * 1.5, 0, -3.4);
      r.group.scale.setScalar(0.7);
      scene.add(r.group);
      return r;
    });
    const probe = packet(Wn);
    scene.add(probe.mesh);
    const hl = labelSprite("HALL 2", "#fde68a", 130);
    hl.position.set(3.2, 2.5, -3.4);
    scene.add(hl);

    // ── 3 TTL rings counting down ──
    const ttls = [64, 63, 62].map((n, i) => {
      const mat = additive(B, 0.06);
      const r = new THREE.Mesh(new THREE.TorusGeometry(0.75, 0.05, 8, 40), mat);
      r.position.set(1.2 + i * 1.9, 4.9, 0);
      scene.add(r);
      const l = labelSprite(`TTL ${n}`, "#bae6fd", 120);
      l.position.set(1.2 + i * 1.9, 4.9, 0);
      scene.add(l);
      return { mat, lm: l.material as THREE.SpriteMaterial };
    });
    const hop = packet(B);
    scene.add(hop.mesh);

    // ── 4 the capture screen ──
    const cap = terminal(["No.  Source      Info", "1  10.8.3.22  [SYN]", "2  10.8.3.22  [TCP Retransmission]", "3  10.8.3.22  [TCP Retransmission]"], A, 2.4, 1.5);
    cap.group.position.set(5.2, 0.4, 3);
    cap.group.scale.setScalar(1.25);
    scene.add(cap.group);

    // ── 5 the far verdict: a node ringed by resets ──
    const farm = netNode(B, 0.8);
    farm.group.position.set(8.4, 2.6, 0.4);
    scene.add(farm.group);
    const verdict = shield(Wn, "alert", 1.1);
    verdict.group.position.set(9.2, 0.9, 1.6);
    scene.add(verdict.group);
    const resets = Array.from({ length: 6 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 6 }; });

    const anchors = [new THREE.Vector3(-6, 3.4, -1), new THREE.Vector3(3.2, 3.2, -3.4), new THREE.Vector3(3.1, 6.2, 0), new THREE.Vector3(5.2, 3.3, 3), new THREE.Vector3(8.4, 4, 0.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 25, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 60 : asp < 1.5 ? 30 : 25; };

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
      camera.lookAt(0, 1.8, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 the handshake crosses the wire in turn
      client.tick(t, 0.4 + level[0] * 0.6, rm);
      server.tick(t, 0.4 + level[0] * 0.6, rm);
      wireMat.opacity = 0.1 + level[0] * 0.8;
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      const beat = rm ? 0.5 : (t * 0.5) % 3;
      shake.forEach((p, i) => {
        const u = Math.max(0, Math.min(1, beat - i));
        const x = i === 1 ? -3 - u * 6 : -9 + u * 6;
        p.mesh.position.set(x, 1.6, -1);
        p.mat.opacity = beat >= i && beat < i + 1 ? go * 0.95 : 0;
      });
      const lit = rm ? 0 : Math.floor(t * 0.7) % flags.length;
      flags.forEach((f, i) => {
        f.mat.opacity = 0.3 + level[0] * 0.6;
        f.mat.emissiveIntensity = 0.1 + level[0] * (i === lit ? 0.9 : 0.25);
        f.m.position.y = 0.15 + (i === lit ? level[0] * 0.14 : 0);
      });
      // 2 a stray probe walks along the racks
      row.forEach(r => r.tick(t, 0.3 + level[1] * 0.7, rm));
      const pu = rm ? 0.5 : ((t * 0.6) % 1);
      probe.mesh.position.set(0.4 + pu * 5.8, 0.7 + Math.abs(Math.sin(pu * 22)) * 0.9, -2.5);
      probe.mat.opacity = Math.max(level[1], stations[1]?.status === "open" ? 0.4 : 0) * 0.95;
      // 3 a packet loses a hop at each ring
      ttls.forEach(r => { r.mat.opacity = 0.06 + level[2] * 0.85; r.lm.opacity = 0.2 + level[2] * 0.8; });
      const hu = rm ? 0.5 : ((t * 0.35) % 1);
      hop.mesh.position.set(0.4 + hu * 5.4, 4.9, 0);
      hop.mat.opacity = level[2] * 0.95;
      // 4 the capture
      cap.screenMat.opacity = 0.3 + level[3] * 0.7;
      // 5 resets burst from the farm
      farm.wireMat.opacity = 0.15 + level[4] * 0.8;
      farm.coreMat.opacity = 0.15 + level[4] * 0.7;
      farm.group.rotation.y = rm ? 0 : t * 0.4;
      verdict.mat.opacity = 0.25 + level[4] * 0.75;
      verdict.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      resets.forEach(p => {
        const a = p.o * Math.PI * 2, u = rm ? 0.5 : ((t * 0.5) % 1);
        p.mesh.position.set(8.4 + Math.cos(a) * (0.9 + u * 1.5), 2.6 + Math.sin(a) * (0.9 + u * 1.5), 0.4);
        p.mat.opacity = level[4] * 0.9 * (1 - u);
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
