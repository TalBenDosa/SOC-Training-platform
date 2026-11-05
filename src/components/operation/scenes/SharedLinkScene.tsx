"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, netNode, packet, serverRack, shield } from "./cyberProps";

/**
 * "Shared link": no wall, just a boundary ring on the floor with the tenant
 * inside. Site racks stand on a plinth with documents floating above them. A
 * chat panel hangs to one side, with an outside node sending bubbles across the
 * ring. A DLP shield stands in the way of a stream of documents, and one slips
 * round it. A chain of links runs from the racks across the ring to a far node,
 * and the chain breaks when the case closes. Decorative only.
 */
export default function SharedLinkScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x07050f, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xede9fe, 0x07050f, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x2a1f52, 0x0d0a1c));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // the tenant boundary, a ring on the floor
    const ringMat = additive(A, 0.15);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(10.5, 0.08, 8, 96), ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.set(-1, 0.1, 0);
    scene.add(ring);

    // ── 1 the sites, with their documents ──
    const sites = ["BIDS", "HR", "LEGAL"].map((n, i) => {
      const r = serverRack(A, 6, n);
      r.group.position.set(-6.4 + i * 2.1, 0, -2.6);
      scene.add(r.group);
      const d = docFile(n, B);
      d.group.position.set(-6.4 + i * 2.1, 3.6, -2.6);
      d.group.scale.setScalar(0.8);
      scene.add(d.group);
      return { d, y: 3.6 + (i % 2) * 0.3, p: i * 1.7 };
    });

    // ── 2 the channel panel and the stranger outside the ring ──
    const chat = holoPanel("# stadium-bid", ["IT Help Desk (External)", "Your mailbox is locked", "Click here to fix it"], B, 3.6, 2.3);
    chat.mesh.position.set(3.2, 4.4, -3.4);
    scene.add(chat.mesh);
    const stranger = netNode(Wn, 0.6);
    stranger.group.position.set(13.4, 5, -5);
    scene.add(stranger.group);
    const bubbles = Array.from({ length: 4 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 4 }; });
    const bFrom = new THREE.Vector3(13.4, 5, -5), bTo = new THREE.Vector3(5, 4.6, -3.4);

    // ── 3 the DLP shield, and the document that goes round it ──
    const guard = shield(B, "alert", 1.3);
    guard.group.position.set(-0.6, 1.6, 4.4);
    scene.add(guard.group);
    const glab = labelSprite("DLP", "#a5f3fc", 110);
    glab.position.set(-0.6, 3.6, 4.4);
    scene.add(glab);
    const stream = Array.from({ length: 5 }, (_, i) => { const p = packet(i === 2 ? Wn : A); scene.add(p.mesh); return { ...p, o: i / 5, slip: i === 2 }; });

    // ── 4 the chain out of the tenant ──
    const links = Array.from({ length: 11 }, (_, i) => {
      const mat = additive(Wn, 0.1);
      const m = new THREE.Mesh(new THREE.TorusGeometry(0.42, 0.09, 8, 24), mat);
      m.scale.set(1.35, 1, 1);
      m.position.set(-4.2 + i * 1.75, 0.85, 0.2 + i * 0.05);
      m.rotation.y = i % 2 ? Math.PI / 2 : 0;
      scene.add(m);
      return { m, mat, i };
    });
    const far = netNode(Wn, 0.7);
    far.group.position.set(15.6, 1.2, 0.7);
    scene.add(far.group);
    const fl = labelSprite("OUTSIDE", "#fed7aa", 130);
    fl.position.set(15.6, 3, 0.7);
    scene.add(fl);

    const anchors = [new THREE.Vector3(-4.3, 6, -2.6), new THREE.Vector3(3.2, 6.4, -3.4), new THREE.Vector3(-0.6, -0.4, 6.2), new THREE.Vector3(9, -0.2, 2.4)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 30, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 76 : asp < 1.5 ? 37 : 30; };

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
      camera.position.set(Math.sin(yaw) * dist + 3, dist * (portrait ? 0.5 : 0.4) + 3, Math.cos(yaw) * dist + 2);
      camera.lookAt(3, 2.2, 0);

      floor.mat.opacity = 0.2 + level[3] * 0.25;
      ringMat.opacity = 0.15 + level[0] * 0.7;
      // 1 the documents float once the site is live
      sites.forEach(s => {
        s.d.group.position.y = s.y + (rm ? 0 : Math.sin(t * 0.8 + s.p) * 0.15);
        s.d.mat.opacity = 0.25 + level[0] * 0.75;
      });
      // 2 the panel lights and the stranger's bubbles cross the ring
      chat.mat.opacity = 0.15 + level[1] * 0.8;
      const talk = stations[1]?.status === "open" ? 0.5 + pulse * 0.4 : stations[1]?.status === "cleared" ? 0.1 : 0;
      stranger.wireMat.opacity = 0.2 + talk * 0.75;
      stranger.coreMat.opacity = 0.2 + talk * 0.7;
      bubbles.forEach(b => {
        const u = rm ? b.o : ((t * 0.22 + b.o) % 1);
        b.mesh.position.lerpVectors(bFrom, bTo, u);
        b.mat.opacity = talk * 0.9;
      });
      // 3 the stream hits the shield, and one document goes round
      guard.mat.opacity = 0.25 + level[2] * 0.75;
      (glab.material as THREE.SpriteMaterial).opacity = 0.2 + level[2] * 0.8;
      const go = Math.max(level[2], stations[2]?.status === "open" ? 0.4 : 0);
      stream.forEach(p => {
        const u = rm ? p.o : ((t * 0.18 + p.o) % 1);
        const x = -7 + u * 13;
        if (p.slip) {
          const arc = Math.sin(Math.min(1, Math.max(0, (x + 3) / 5)) * Math.PI);
          p.mesh.position.set(x, 1.5, 4.4 + arc * 2.1);
          p.mat.opacity = go * 0.95;
        } else {
          p.mesh.position.set(Math.min(x, -1.3), 1.5, 4.4);
          p.mat.opacity = go * 0.9 * (x > -1.3 ? Math.max(0, 1 - (x + 1.3) * 2) : 1);
        }
      });
      // 4 the chain: live while the boss is open, broken in the middle once it's cleared
      const closed = stations[3]?.status === "cleared";
      const open3 = stations[3]?.status === "open";
      links.forEach(l => {
        const near = l.i <= 4;
        const glow = closed ? (near ? 0.45 : 0.12) : 0.1 + (open3 ? 0.35 + pulse * 0.4 : level[2] * 0.2);
        l.mat.opacity = glow;
        const drop = closed && !rm ? (l.i === 5 ? 0.6 : 0) : 0;
        l.m.position.y = 0.85 - drop;
      });
      far.wireMat.opacity = 0.2 + (closed ? 0.1 : level[2] * 0.7);
      far.coreMat.opacity = 0.2 + (closed ? 0.1 : level[2] * 0.7);
      (fl.material as THREE.SpriteMaterial).opacity = 0.2 + level[3] * 0.8;

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
