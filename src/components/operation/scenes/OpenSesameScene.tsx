"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, netNode, packet, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Open sesame": requests queue toward a WAF gate in front of a web server.
 * Some bounce off the gate, some pass. Beside the server a log panel lights;
 * a second panel joins it by a beam to show one request in two records; a
 * tagged scanner node stands apart; and a stray file in the rack spawns a
 * red console. Stations switch each part on. Decorative only.
 */
export default function OpenSesameScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0603, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xffedd5, 0x0a0603, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a2a0a, 0x150c04));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the WAF gate and the requests at it ──
    const gate = shield(B, "none", 1.6);
    gate.group.position.set(-3.6, 2, 0);
    gate.group.rotation.y = 0.45;
    scene.add(gate.group);
    const gl = labelSprite("WAF", "#d9f99d", 110);
    gl.position.set(-3.6, 0.4, 1.4);
    scene.add(gl);
    const reqs = Array.from({ length: 8 }, (_, i) => {
      const bad = i % 3 === 0;
      const p = packet(bad ? Wn : B);
      scene.add(p.mesh);
      return { ...p, o: i / 8, bad, z: -1.2 + (i % 3) * 1.2 };
    });

    // ── 2 the web server and its access log ──
    const iis = serverRack(A, 6, "IIS");
    iis.group.position.set(0.6, 0, -0.6);
    scene.add(iis.group);
    const log = holoPanel("u_ex261105.log", ["GET /search 200", "GET /admin 404", "GET /pdf 500", "POST /basket 200"], A, 2.8, 1.5);
    log.mesh.position.set(0.6, 4.3, -0.6);
    scene.add(log.mesh);

    // ── 3 the second record, joined by a beam ──
    const waf = holoPanel("waf-logs", ["action: COUNT", "rule: XSS body", "uri: /review"], B, 2.8, 1.5);
    waf.mesh.position.set(-3.6, 4.6, -0.6);
    scene.add(waf.mesh);
    const beamMat = additive(B, 0.05);
    const beam = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.05, 0.05), beamMat);
    beam.position.set(-1.5, 4.5, -0.6);
    scene.add(beam);

    // ── 4 a scanner standing apart ──
    const scanner = netNode(B, 0.65);
    scanner.group.position.set(-8, 3.6, -2.4);
    scene.add(scanner.group);
    const sl = labelSprite("SCANNER?", "#d9f99d", 150);
    sl.position.set(-8, 4.8, -2.4);
    scene.add(sl);

    // ── 5 a stray file spawns a console ──
    const stray = docFile("x.aspx", Wn);
    stray.group.scale.setScalar(0.7);
    stray.group.position.set(3, 1.6, -0.2);
    scene.add(stray.group);
    const shellCon = terminal(["C:\\inetpub> whoami", "iis apppool\\sundial"], Wn, 2.2, 1.3);
    shellCon.group.position.set(6.6, 0.6, 0);
    shellCon.group.scale.setScalar(1.15);
    scene.add(shellCon.group);
    const linkMat = additive(Wn, 0.05);
    const link = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.05, 0.05), linkMat);
    link.position.set(4.3, 1.7, -0.1);
    scene.add(link);

    const anchors = [new THREE.Vector3(-3.6, 3.7, 0.6), new THREE.Vector3(3, 3, -0.6), new THREE.Vector3(-3.6, 6.2, -0.6), new THREE.Vector3(-8, 5.6, -2.4), new THREE.Vector3(6.6, 3.5, 0)];
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
      camera.lookAt(-0.4, 2.4, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 requests hit the gate: hostile ones bounce, the rest pass
      gate.mat.opacity = 0.3 + level[0] * 0.7;
      gate.mat.emissiveIntensity = 0.1 + level[0] * 0.5;
      const go = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      reqs.forEach(p => {
        const u = rm ? 0.4 : ((t * 0.16 + p.o) % 1);
        const x = -11 + u * 11.6;
        p.mesh.position.set(p.bad ? Math.min(x, -4) : x, 1.2, p.z);
        p.mat.opacity = go * 0.9 * (p.bad && x > -4 ? Math.max(0, 1 - (x + 4) * 0.5) : 1);
      });
      // 2 the server and its log
      iis.tick(t, 0.4 + level[1] * 0.6, rm);
      log.mat.opacity = 0.15 + Math.max(level[0], level[1]) * 0.8;
      // 3 the two records join
      waf.mat.opacity = 0.12 + level[2] * 0.85;
      beamMat.opacity = 0.05 + level[2] * (0.5 + pulse * 0.4);
      // 4 the scanner
      scanner.wireMat.opacity = 0.15 + level[3] * 0.8;
      scanner.coreMat.opacity = 0.1 + level[3] * 0.7;
      scanner.group.rotation.y = rm ? 0 : t * 0.4;
      (sl.material as THREE.SpriteMaterial).opacity = 0.2 + level[3] * 0.8;
      // 5 the shell
      stray.mat.opacity = 0.1 + level[4] * 0.9;
      linkMat.opacity = 0.05 + level[4] * (0.5 + pulse * 0.4);
      shellCon.screenMat.opacity = 0.25 + level[4] * 0.75;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#150c04]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
