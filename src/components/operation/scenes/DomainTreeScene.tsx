"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Keystone": a domain controller keystone at the centre of a ring of domain
 * trees (glowing branching node graphs, not plants). A Kerberos ticket loops
 * between a client node, the KDC and a file server; embers rise from a
 * service-account node as it is roasted; a crown vault above the keystone
 * holds the krbtgt key; and a red relay link snaps between a rogue device and
 * a server. Stations switch each part on. Decorative only.
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

export default function DomainTreeScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03080a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xcffafe, 0x03080a, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0e4a52, 0x081417));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x4f7480, emissive: 0x0f2328, metalness: 0.55, roughness: 0.4 });

    // the DC keystone
    const keystone = new THREE.Mesh(new THREE.CylinderGeometry(1.1, 1.6, 2.6, 6), metal());
    keystone.position.set(0, 1.3, 0);
    scene.add(keystone);
    const ksl = tag("RKW-DC01", "#a5f3fc", 200); ksl.position.set(0, 3, 0); scene.add(ksl);

    // ── 1 domain trees: node graphs on a ring ──
    const treeMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.15 });
    const nodeMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.1, transparent: true, opacity: 0.3 });
    const treeRoots = [[-6, -2, "rookwood"], [6, -2, "schools"], [0, -9, "OU"]] as const;
    treeRoots.forEach(([x, z, n]) => {
      const pts: THREE.Vector3[] = [];
      const root = new THREE.Vector3(x, 0.4, z);
      const kids = [-1.4, 0, 1.4].map(dx => new THREE.Vector3(x + dx, 2, z));
      kids.forEach(k => { pts.push(root, k); [-0.5, 0.5].forEach(d => pts.push(k, new THREE.Vector3(k.x + d, 3.2, z))); });
      scene.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(pts), treeMat));
      for (let i = 1; i < pts.length; i += 2) {
        const m = new THREE.Mesh(new THREE.SphereGeometry(0.14, 10, 8), nodeMat);
        m.position.copy(pts[i]);
        scene.add(m);
      }
      const l = tag(n, "#d9f99d", 200); l.position.set(x, 4, z); scene.add(l);
    });
    // link each root to the keystone
    scene.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(treeRoots.flatMap(([x, z]) => [new THREE.Vector3(x, 0.4, z), new THREE.Vector3(0, 0.4, 0)])), treeMat));

    // ── 2 the Kerberos ticket loop: client, KDC, file server ──
    const client = new THREE.Vector3(-4.5, 1, 4), server = new THREE.Vector3(4.5, 1, 4), kdc = new THREE.Vector3(0, 2.4, 0.8);
    [[client, "CLIENT"], [server, "RKW-FS03"]].forEach(([p, n]) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(1, 0.7, 0.7), metal());
      m.position.copy(p as THREE.Vector3);
      scene.add(m);
      const l = tag(n as string, "#a5f3fc", 200); l.position.copy(p as THREE.Vector3).add(new THREE.Vector3(0, 0.8, 0)); scene.add(l);
    });
    const loop = new THREE.CatmullRomCurve3([client, kdc, server, new THREE.Vector3(0, 0.8, 4.6), client], false);
    const loopMat = new THREE.LineDashedMaterial({ color: A, dashSize: 0.2, gapSize: 0.14, transparent: true, opacity: 0 });
    const loopLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(loop.getPoints(80)), loopMat);
    loopLine.computeLineDistances();
    scene.add(loopLine);
    const ticketMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.7, transparent: true, opacity: 0 });
    const ticket = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.3, 0.05), ticketMat);
    scene.add(ticket);

    // ── 3 roasting embers from a service node ──
    const svc = new THREE.Vector3(6.6, 2, -2);
    const svcNodeMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.1, transparent: true, opacity: 0.4 });
    const svcNode = new THREE.Mesh(new THREE.SphereGeometry(0.3, 14, 10), svcNodeMat);
    svcNode.position.copy(svc);
    scene.add(svcNode);
    const emberMat = additive(Wn, 0);
    const embers = Array.from({ length: 10 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.06, 6, 5), emberMat);
      scene.add(m);
      return { m, o: i / 10, dx: Math.sin(i * 2.1) * 0.4 };
    });

    // ── 4 the crown vault with the krbtgt key ──
    const crownMat = new THREE.MeshStandardMaterial({ color: 0x0e3a40, emissive: A, emissiveIntensity: 0, transparent: true, opacity: 0.3 });
    const crown = new THREE.Mesh(new THREE.OctahedronGeometry(0.8), crownMat);
    crown.position.set(0, 5.2, 0);
    scene.add(crown);
    const crl = tag("krbtgt", "#fecdd3", 160); crl.position.set(0, 6.4, 0); scene.add(crl);
    const shieldMat = additive(B, 0);
    const shield = new THREE.Mesh(new THREE.TorusGeometry(1.3, 0.05, 8, 40), shieldMat);
    shield.position.copy(crown.position);
    scene.add(shield);

    // ── 5 the relay link ──
    const rogue = new THREE.Vector3(-7, 0.6, 3), relayTo = new THREE.Vector3(4.5, 1, 4);
    const rogueMat = new THREE.MeshStandardMaterial({ color: 0x1f0a10, emissive: Wn, emissiveIntensity: 0.1, transparent: true, opacity: 0.4 });
    const rogueM = new THREE.Mesh(new THREE.TetrahedronGeometry(0.5), rogueMat);
    rogueM.position.copy(rogue);
    scene.add(rogueM);
    const rl = tag("10.44.6.120", "#fecdd3", 220); rl.position.set(rogue.x, 1.6, rogue.z); scene.add(rl);
    const relayMat = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
    const relay = new THREE.Line(new THREE.BufferGeometry().setFromPoints([rogue, new THREE.Vector3(-1, 3, 5), relayTo]), relayMat);
    scene.add(relay);

    const anchors = [new THREE.Vector3(-6, 5.2, -2), new THREE.Vector3(-4.5, 2.6, 4), new THREE.Vector3(8.2, 2.6, -2), new THREE.Vector3(2.6, 5.6, 0.5), new THREE.Vector3(-7, 2.6, 3)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 24, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 56 : asp < 1.5 ? 29 : 24; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.3;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 2, Math.cos(yaw) * dist);
      camera.lookAt(0, 2, 0);

      // 1 the trees light
      treeMat.opacity = 0.15 + level[0] * 0.7;
      nodeMat.opacity = 0.3 + level[0] * 0.6;
      nodeMat.emissiveIntensity = 0.1 + level[0] * 0.5;
      // 2 the ticket travels the loop
      loopMat.opacity = level[1] * 0.8;
      ticketMat.opacity = level[1] > 0.05 ? Math.min(1, level[1] * 1.5) : 0;
      ticket.position.copy(loop.getPoint(rm ? 0.3 : (t * 0.12) % 1));
      if (!rm) ticket.rotation.y += dt * 2;
      // 3 embers rise as the service account is roasted
      svcNodeMat.opacity = 0.4 + level[2] * 0.5;
      svcNodeMat.emissiveIntensity = 0.1 + level[2] * 0.6;
      emberMat.opacity = level[2] * 0.9;
      embers.forEach(e => {
        const u = rm ? 0.5 : ((t * 0.4 + e.o) % 1);
        e.m.position.set(svc.x + e.dx * u, svc.y + 0.3 + u * 2, svc.z);
      });
      // 4 the crown glows and the shield ring closes
      crownMat.opacity = 0.3 + level[3] * 0.6;
      crownMat.emissiveIntensity = level[3] * 0.5;
      if (!rm) crown.rotation.y += dt * 0.5;
      shieldMat.opacity = level[3] * 0.85;
      shield.rotation.x = Math.PI / 2 + (rm ? 0 : Math.sin(t) * 0.2);
      // 5 the relay link flickers, then the rogue goes dark
      relayMat.opacity = level[4] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      rogueMat.emissiveIntensity = 0.1 + level[4] * 0.8;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#05100f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
