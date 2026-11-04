"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, laptop, netNode, packet, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Open watch": the Wazuh manager as a cluster of server racks on a circuit
 * floor, with a console showing agent_control. Agents (laptops and build
 * servers, one dark, one never lit) stream packets in along cables. Beside
 * the racks a decoder node splits packets into fields that fall onto three
 * holographic rule panels (level bands). A locked sshd_config file sits under
 * a FIM watch ring; an alert shield rises above the racks; a loop of light
 * closes the pipeline. Stations switch each part on. Decorative only.
 */
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

    scene.add(new THREE.HemisphereLight(0xdbeafe, 0x03060d, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1e3a8a, 0x0a1022));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // the manager: three racks and its console
    const racks = [-1.4, 0, 1.4].map((x, i) => {
      const r = serverRack(A, 7, i === 1 ? "wz-manager-01" : undefined);
      r.group.position.set(x, 0, 0);
      scene.add(r.group);
      return r;
    });
    const mgrConsole = terminal(["$ agent_control -l", "014 build-lnx-014  Active", "015 build-lnx-015  Active", "022 art-store-02   Disconnected", "031 launcher-cdn  Active", "040 build-lnx-040  Never"], A, 1.7, 1.05);
    mgrConsole.group.position.set(0, 0, 2.4);
    mgrConsole.group.rotation.y = 0;
    scene.add(mgrConsole.group);

    // ── 1 agents: laptops and build servers on a ring, streaming packets ──
    const N = 7, RR = 7.2;
    const agents = Array.from({ length: N }, (_, i) => {
      const a = Math.PI * 0.12 + (i / (N - 1)) * Math.PI * 0.76 + Math.PI;
      const p = new THREE.Vector3(Math.cos(a) * RR, 0, Math.sin(a) * RR * 0.65 + 1.6);
      const state = i === 2 ? "down" : i === 5 ? "never" : "up";
      const col = state === "up" ? B : Wn;
      let tick: ((t: number, on: number, rm?: boolean) => void) | null = null;
      let screen: THREE.MeshBasicMaterial | null = null;
      if (i % 2 === 0) {
        const l = laptop(col);
        l.group.position.copy(p);
        l.group.lookAt(0, 0, 0);
        l.group.scale.setScalar(1.6);
        scene.add(l.group);
        screen = l.screenMat;
      } else {
        const r = serverRack(col, 3);
        r.group.position.copy(p);
        r.group.lookAt(0, 0, 0);
        r.group.scale.setScalar(0.85);
        scene.add(r.group);
        tick = r.tick;
      }
      const cableMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0.1 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([p.clone().setY(0.05), new THREE.Vector3(0, 0.05, 0)]), cableMat));
      const pk = packet(B);
      scene.add(pk.mesh);
      return { p, state, tick, screen, cableMat, pk, o: i / N };
    });
    const dl = labelSprite("art-store-02", "#fed7aa", 240); dl.position.copy(agents[2].p).add(new THREE.Vector3(0, 2, 0.6)); scene.add(dl);

    // ── 2 decoder node and rule panels ──
    const decoder = netNode(A, 0.55);
    decoder.group.position.set(3.4, 2.6, 0);
    scene.add(decoder.group);
    const decPanel = holoPanel("decoder: sshd", ["srcip   198.51.100.77", "dstuser root", "srcport 50644"], A, 2, 1.1);
    decPanel.mesh.position.set(3.4, 4.1, 0);
    scene.add(decPanel.mesh);
    const bandDefs: [string, THREE.Color, string][] = [["lvl 0-6", B, "info · low"], ["lvl 7-11", A, "investigate"], ["lvl 12-15", Wn, "critical"]];
    const bands = bandDefs.map(([t, c, sub], i) => {
      const hp = holoPanel(t, [sub], c, 1.7, 0.75);
      hp.mesh.position.set(5.8, 3 - i * 0.95, 0.2);
      hp.mesh.rotation.y = -0.35;
      scene.add(hp.mesh);
      return hp.mat;
    });
    const fieldMat = additive(A, 0);
    const fields = Array.from({ length: 6 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.14, 0.14, 0.14), fieldMat);
      scene.add(m);
      return { m, o: i / 6 };
    });

    // ── 3 the watched file ──
    const file = docFile("sshd_config", Wn);
    file.group.position.set(-4, 1.4, -2.6);
    file.group.rotation.y = 0.5;
    scene.add(file.group);
    const lock = padlock(Wn, 0.7);
    lock.group.position.set(-3.4, 0.6, -2.2);
    scene.add(lock.group);
    const eyeMat = additive(A, 0);
    const eye = new THREE.Mesh(new THREE.TorusGeometry(1.15, 0.05, 8, 48), eyeMat);
    eye.position.set(-4, 1.4, -2.6);
    scene.add(eye);

    // ── 4 the alert shield ──
    const alert = shield(Wn, "alert", 1.2);
    alert.group.position.set(0, 4.6, 0);
    scene.add(alert.group);

    // ── 5 the loop ──
    const loopMat = additive(A, 0);
    const loop = new THREE.Mesh(new THREE.TorusGeometry(8.8, 0.06, 8, 96), loopMat);
    loop.rotation.x = Math.PI / 2;
    loop.position.y = 0.12;
    scene.add(loop);

    const anchors = [new THREE.Vector3(-6.6, 1.6, 2.6), new THREE.Vector3(4.6, 5.2, 0), new THREE.Vector3(-4, 3, -2.6), new THREE.Vector3(1.4, 5.4, 0.6), new THREE.Vector3(6.2, 0.6, 5)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 22, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 44 : asp < 1.5 ? 23 : 18.5; };

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
      camera.lookAt(1, 1.8, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.3;
      racks.forEach(r => r.tick(t, 0.5 + level[0] * 0.5, rm));
      mgrConsole.screenMat.opacity = 0.5 + level[0] * 0.45;

      // 1 agents
      const flow = Math.max(level[0], stations[0]?.status === "open" ? 0.4 : 0);
      agents.forEach(ag => {
        const up = ag.state === "up";
        if (ag.tick) ag.tick(t, up ? 0.4 + level[0] * 0.6 : ag.state === "down" ? level[0] * (rm ? 0.6 : pulse) : 0.05, rm);
        if (ag.screen) ag.screen.opacity = up ? 0.4 + level[0] * 0.5 : ag.state === "down" ? 0.2 + level[0] * (rm ? 0.4 : pulse * 0.6) : 0.08;
        ag.cableMat.opacity = up ? 0.1 + level[0] * 0.5 : 0.04;
        const u = rm ? 0.5 : ((t * 0.35 + ag.o) % 1);
        ag.pk.mesh.position.lerpVectors(ag.p.clone().setY(0.4), new THREE.Vector3(0, 0.4, 0), u);
        ag.pk.mat.opacity = up ? flow * 0.95 : 0;
      });
      // 2 decoder spins, fields fall onto the panels
      decoder.wireMat.opacity = 0.2 + level[1] * 0.7;
      decoder.coreMat.emissiveIntensity = 0.3 + level[1] * 0.8;
      if (!rm) decoder.wire.rotation.y += dt * (0.3 + level[1]);
      decPanel.mat.opacity = 0.4 + level[1] * 0.55;
      bands.forEach((m, i) => { m.opacity = 0.35 + THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1) * 0.6; });
      fieldMat.opacity = level[1] * 0.9;
      fields.forEach(f => {
        const u = rm ? 0.5 : ((t * 0.4 + f.o) % 1);
        f.m.position.set(3.4 + u * 2.2, 2.6 - u * 1.8, 0.1);
      });
      // 3 the file under watch; the lock clicks shut once understood
      eyeMat.opacity = level[2] * 0.85;
      if (!rm) eye.rotation.y += dt * 0.7 * level[2];
      file.mat.emissiveIntensity = level[2] * (rm ? 0.3 : 0.15 + pulse * 0.25);
      lock.setOpen(1 - level[2]);
      // 4 the shield rises
      alert.mat.opacity = 0.25 + level[3] * 0.75;
      alert.mat.emissiveIntensity = 0.1 + level[3] * (rm ? 0.5 : 0.3 + pulse * 0.4);
      alert.group.position.y = 4 + level[3] * 1;
      if (!rm) alert.group.rotation.y = Math.sin(t * 0.8) * 0.4;
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
