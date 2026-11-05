"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, labelSprite, netNode, packet, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Reply all": a mail road across the floor. Messages leave a sending node, pass
 * two scanner arches and enter a mailbox rack. Above the road hang three seal
 * discs that lock one by one. From the rack a red siphon drains to a buried
 * folder under the floor line. At the end a treasury terminal holds a live wire
 * to a far node, and the wire stays dark until the case is closed. Stations
 * switch each part on. Decorative only.
 */
export default function ReplyAllScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04090a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xd1fae5, 0x04090a, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x123a30, 0x071410));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    const Z = 2.4; // the road's depth line
    // ── 1 the road: sender, two scanner arches, the mailbox rack ──
    const roadMat = additive(A, 0.1);
    const road = new THREE.Mesh(new THREE.BoxGeometry(17, 0.06, 1.1), roadMat);
    road.position.set(-2.5, 0.05, Z);
    scene.add(road);
    const sender = netNode(A, 0.7);
    sender.group.position.set(-11, 1.3, Z);
    scene.add(sender.group);
    const arches = ["EOP", "DEFENDER"].map((n, i) => {
      const mat = additive(A, 0.1);
      const arch = new THREE.Mesh(new THREE.TorusGeometry(1.9, 0.11, 10, 40, Math.PI), mat);
      arch.position.set(-6.5 + i * 4.4, 0.1, Z);
      arch.rotation.y = Math.PI / 2;
      scene.add(arch);
      const l = labelSprite(n, "#a7f3d0", 130);
      l.position.set(-6.5 + i * 4.4, 2.6, Z);
      scene.add(l);
      return { mat, lm: l.material as THREE.SpriteMaterial };
    });
    const rack = serverRack(A, 6, "MAILBOX");
    rack.group.position.set(6, 0, Z);
    scene.add(rack.group);
    const mail = Array.from({ length: 6 }, (_, i) => { const p = packet(A); scene.add(p.mesh); return { ...p, o: i / 6 }; });

    // ── 2 the three seals, hanging over the road ──
    const seals = ["SPF", "DKIM", "DMARC"].map((n, i) => {
      const s = shield(i === 2 ? B : A, "check", 0.85);
      s.group.position.set(-6.2 + i * 3.4, 5.6, -1.4);
      scene.add(s.group);
      const l = labelSprite(n, "#fde68a", 120);
      l.position.set(-6.2 + i * 3.4, 7.2, -1.4);
      scene.add(l);
      return { ...s, lm: l.material as THREE.SpriteMaterial };
    });

    // ── 3 the siphon: a red line out of the rack, down to a buried folder ──
    const curve = new THREE.CatmullRomCurve3([new THREE.Vector3(7, 2.4, Z), new THREE.Vector3(10.2, 2.6, Z + 0.4), new THREE.Vector3(11.4, 1, Z + 1.6), new THREE.Vector3(11.6, 0.4, Z + 3.2)]);
    const pipeMat = additive(Wn, 0.08);
    scene.add(new THREE.Mesh(new THREE.TubeGeometry(curve, 40, 0.09, 8, false), pipeMat));
    const buried = new THREE.Mesh(new THREE.BoxGeometry(2.2, 0.5, 1.6), new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.1, transparent: true, opacity: 0.25 }));
    buried.position.set(11.6, 0.25, Z + 3.4);
    scene.add(buried);
    const buriedMat = buried.material as THREE.MeshStandardMaterial;
    const fl = labelSprite("RSS FEEDS", "#fecaca", 140);
    fl.position.set(11.6, 1.5, Z + 3.4);
    scene.add(fl);
    const drops = Array.from({ length: 4 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 4 }; });

    // ── 4 the wire: treasury terminal, a long line, a far account ──
    const treasury = terminal(["TREASURY", "HOLD PAYMENT"], B, 2.1, 1.3);
    treasury.group.position.set(10.6, 3.6, -3.2);
    treasury.group.rotation.y = -0.25;
    scene.add(treasury.group);
    const far = netNode(Wn, 0.55);
    far.group.position.set(16.6, 6.4, -6);
    scene.add(far.group);
    const wireMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.1 });
    const wireCurve = new THREE.QuadraticBezierCurve3(new THREE.Vector3(11.6, 4.3, -3.2), new THREE.Vector3(14.4, 7.6, -4.6), new THREE.Vector3(16.6, 6.4, -6));
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(wireCurve.getPoints(40)), wireMat));
    const stop = shield(A, "check", 0.7);
    stop.group.position.set(14.1, 6.4, -4.5);
    scene.add(stop.group);

    const anchors = [new THREE.Vector3(-4, -0.3, Z + 1), new THREE.Vector3(-2.8, 8.2, -1.4), new THREE.Vector3(11.6, -0.2, Z + 4), new THREE.Vector3(10.6, 2.2, -3.2)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 29, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 36 : 29; };

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
      camera.position.set(Math.sin(yaw) * dist + 2.5, dist * (portrait ? 0.5 : 0.36) + 3, Math.cos(yaw) * dist + 2);
      camera.lookAt(2.5, 2.8, 0.4);

      floor.mat.opacity = 0.2 + level[3] * 0.25;
      // 1 the road carries mail once the first station is live
      roadMat.opacity = 0.1 + level[0] * 0.45;
      sender.wireMat.opacity = 0.2 + level[0] * 0.75;
      sender.coreMat.opacity = 0.2 + level[0] * 0.7;
      arches.forEach(a => { a.mat.opacity = 0.12 + level[0] * 0.85; a.lm.opacity = 0.2 + level[0] * 0.8; });
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      mail.forEach(m => {
        const u = rm ? m.o : ((t * 0.14 + m.o) % 1);
        m.mesh.position.set(-10.5 + u * 16.2, 0.7, Z);
        m.mat.opacity = go * 0.9;
      });
      // 2 the seals lock in turn as the second station clears
      seals.forEach((s, i) => {
        s.mat.opacity = 0.25 + Math.min(1, Math.max(0, level[1] * 3 - i)) * 0.75;
        s.lm.opacity = 0.2 + level[1] * 0.8;
        s.group.rotation.y = rm ? 0 : Math.sin(t * 0.5 + i) * 0.25;
      });
      // 3 the siphon drains until the third station is cleared
      const drain = stations[2]?.status === "open" ? 0.35 + pulse * 0.4 : stations[2]?.status === "cleared" ? 0.15 : 0;
      pipeMat.opacity = 0.08 + drain * 0.8;
      buriedMat.opacity = 0.25 + drain * 0.6;
      buriedMat.emissiveIntensity = 0.1 + drain * 0.8;
      (fl.material as THREE.SpriteMaterial).opacity = 0.2 + level[2] * 0.8;
      drops.forEach(d => {
        const u = rm ? d.o : ((t * 0.3 + d.o) % 1);
        d.mesh.position.copy(curve.getPoint(u));
        d.mat.opacity = drain * 0.9;
      });
      // 4 the wire stays live until the boss stops it
      const stopped = stations[3]?.status === "cleared";
      wireMat.opacity = stopped ? 0.12 : 0.15 + level[3] * 0.3 + (stations[3]?.status === "open" ? pulse * 0.6 : 0);
      treasury.screenMat.opacity = 0.35 + level[3] * 0.65;
      far.wireMat.opacity = 0.2 + (stopped ? 0.1 : level[3] * 0.7);
      far.coreMat.opacity = 0.2 + (stopped ? 0.1 : level[3] * 0.7);
      stop.mat.opacity = stopped ? 1 : 0.15;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#070c18]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
