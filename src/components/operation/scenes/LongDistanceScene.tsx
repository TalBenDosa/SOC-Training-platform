"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, holoPanel, labelSprite, laptop, netNode, packet, serverRack, shield } from "./cyberProps";

/**
 * "Long distance": a VPN gateway (two racks behind a shield) at the centre of
 * a ring of far-away laptops, each joined by a glowing tunnel that packets
 * ride. Five attacker silhouettes (wireframe nodes) stand in a line-up; an
 * inside trail runs from the gateway to the turbine historian rack; and a
 * verdict shield closes over the gateway. Stations switch each part on.
 * Decorative only.
 */
export default function LongDistanceScene(props: WorldProps) {
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

    scene.add(new THREE.HemisphereLight(0xcffafe, 0x03080a, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0e3f4a, 0x071417));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // the gateway
    const gwRacks = [-0.7, 0.7].map(x => { const r = serverRack(A, 7); r.group.position.set(x, 0, 0); scene.add(r.group); return r; });
    const gl = labelSprite("gp-aberdeen-01", "#a5f3fc", 260); gl.position.set(0, 3.1, 0); scene.add(gl);
    const gwShield = shield(A, "none", 1.5);
    gwShield.group.position.set(0, 1.6, 1.4);
    scene.add(gwShield.group);

    // ── 1 remote laptops and their tunnels ──
    const remotes = [[-8, 0, 4, "ABERDEEN"], [-7.5, 0, -4, "HOTEL · OSLO"], [7.5, 0, 4.5, "VESSEL · NS-3"], [8, 0, -3.5, "HOME · LEITH"]].map(([x, y, z, n]) => {
      const l = laptop(B);
      l.group.position.set(x as number, y as number, z as number);
      l.group.scale.setScalar(1.4);
      l.group.lookAt(0, 0, 0);
      scene.add(l.group);
      const lab = labelSprite(n as string, "#d9f99d", 240);
      lab.position.set(x as number, 1.8, z as number);
      scene.add(lab);
      const curve = new THREE.QuadraticBezierCurve3(new THREE.Vector3(x as number, 0.8, z as number), new THREE.Vector3((x as number) / 2, 2.6, (z as number) / 2), new THREE.Vector3(0, 1.6, 0));
      const tubeMat = additive(A, 0.08);
      const tube = new THREE.Mesh(new THREE.TubeGeometry(curve, 30, 0.08, 8, false), tubeMat);
      scene.add(tube);
      const pk = packet(A);
      scene.add(pk.mesh);
      return { l, tubeMat, curve, pk };
    });

    // ── 2 the line-up of attacker silhouettes ──
    const lineup = ["TRAVELLER", "HAMMER", "SPRAYER", "STUFFER", "SQUATTER"].map((n, i) => {
      const nd = netNode(Wn, 0.42);
      nd.group.position.set(-4 + i * 2, 4.8, -5);
      scene.add(nd.group);
      const lab = labelSprite(n, "#fecdd3", 200);
      lab.scale.multiplyScalar(0.7);
      lab.position.set(-4 + i * 2, 5.6, -5);
      scene.add(lab);
      return nd;
    });

    // ── 3 the inside trail to the historian ──
    const hist = serverRack(Wn, 6, "SCADA HISTORIAN");
    hist.group.position.set(4.6, 0, -6.5);
    scene.add(hist.group);
    const trailMat = new THREE.LineDashedMaterial({ color: Wn, dashSize: 0.25, gapSize: 0.15, transparent: true, opacity: 0 });
    const trail = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0.7, 0.4, -0.6), new THREE.Vector3(2.6, 0.4, -3.4), new THREE.Vector3(4.6, 0.4, -6)]), trailMat);
    trail.computeLineDistances();
    scene.add(trail);
    const ip = holoPanel("10.88.14.203", ["02:21 → historian:1433"], Wn, 1.9, 0.75);
    ip.mesh.position.set(2.8, 1.8, -3.4);
    ip.mesh.rotation.y = -0.4;
    scene.add(ip.mesh);

    const anchors = [new THREE.Vector3(-8, 2.8, 4), new THREE.Vector3(0, 6.6, -5), new THREE.Vector3(4.6, 3.4, -6.5), new THREE.Vector3(2.8, 2.8, -3.4), new THREE.Vector3(0, 4.2, 1.4)];
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

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.25;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.45) + 2, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 1.8, -1);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      gwRacks.forEach(r => r.tick(t, 0.5 + level[0] * 0.5, rm));
      // 1 tunnels glow and carry packets
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      remotes.forEach((r, i) => {
        r.tubeMat.opacity = 0.08 + level[0] * 0.5;
        r.l.screenMat.opacity = 0.35 + level[0] * 0.55;
        r.pk.mesh.position.copy(r.curve.getPoint(rm ? 0.5 : ((t * 0.3 + i / 4) % 1)));
        r.pk.mat.opacity = flow * 0.95;
      });
      // 2 the line-up lights one by one
      lineup.forEach((n, i) => { n.wireMat.opacity = 0.15 + THREE.MathUtils.clamp(level[1] * 5 - i, 0, 1) * 0.75; if (!rm) n.wire.rotation.y += dt * 0.5; });
      // 3 the inside trail and the historian
      trailMat.opacity = level[2] * 0.9;
      hist.tick(t, 0.3 + level[2] * 0.7, rm);
      // 4 the address panel
      ip.mat.opacity = 0.15 + Math.max(level[2], level[3]) * 0.75;
      // 5 the verdict shield
      gwShield.mat.opacity = 0.25 + level[4] * 0.75;
      gwShield.mat.emissiveIntensity = 0.1 + level[4] * 0.6;

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
