"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The black box": an endpoint (a laptop slab) at the centre, ringed by four
 * generation rings (AV, NGAV, EDR, XDR), the XDR ring sending lines out to
 * email, identity, network and cloud nodes. Telemetry streams rise from the
 * laptop to a recorder cloud; an isolation dome can close over it, leaving one
 * management line open. Beside it, a process tree grows as a hologram, its
 * malicious branch glowing red until the final station kills it. Stations
 * switch each part on. Decorative only.
 */
function tag(text: string, color: string, w = 260) {
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

export default function BlackBoxScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x030806, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xd1fae5, 0x030806, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x064e3b, 0x052e1f));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x223a32, emissive: 0x08140f, metalness: 0.55, roughness: 0.4 });

    // the endpoint: a laptop
    const C = new THREE.Vector3(-4, 0, 0);
    const base = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.14, 1.8), metal());
    base.position.set(C.x, 1.2, C.z);
    scene.add(base);
    const screenMat = new THREE.MeshStandardMaterial({ color: 0x0b1f18, emissive: A, emissiveIntensity: 0.2 });
    const screen = new THREE.Mesh(new THREE.BoxGeometry(2.6, 1.7, 0.08), screenMat);
    screen.position.set(C.x, 2.05, C.z - 0.9);
    screen.rotation.x = -0.18;
    scene.add(screen);

    // ── 1 four generation rings, XDR reaching out to four other domains ──
    const rings = ["AV", "NGAV", "EDR", "XDR"].map((n, i) => {
      const mat = additive(i === 3 ? B : A, 0.05);
      const r = new THREE.Mesh(new THREE.TorusGeometry(2.2 + i * 0.9, 0.05, 8, 64), mat);
      r.rotation.x = Math.PI / 2;
      r.position.set(C.x, 0.3 + i * 0.05, C.z);
      scene.add(r);
      const l = tag(n, i === 3 ? "#bfdbfe" : "#a7f3d0", 140);
      l.position.set(C.x + 2.2 + i * 0.9, 0.7, C.z + 0.3);
      scene.add(l);
      return mat;
    });
    const domains = [["EMAIL", -9.5, -3], ["IDENTITY", -9.5, 3], ["NETWORK", 1.5, -4.5], ["CLOUD", 1.5, 4.5]].map(([n, x, z]) => {
      const node = new THREE.Mesh(new THREE.OctahedronGeometry(0.45), new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.2 }));
      node.position.set(x as number, 1, z as number);
      scene.add(node);
      const l = tag(n as string, "#bfdbfe", 200);
      l.position.set(x as number, 1.9, z as number);
      scene.add(l);
      const lineMat = new THREE.LineBasicMaterial({ color: B, transparent: true, opacity: 0 });
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(C.x, 1, C.z), node.position.clone()]), lineMat));
      return { node, lineMat };
    });

    // ── 2 telemetry up to the recorder; the isolation dome ──
    const recorder = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
    recorder.scale.set(3.5, 2.2, 1);
    recorder.position.set(C.x, 7.2, C.z);
    scene.add(recorder);
    const recLab = tag("RECORDER", "#a7f3d0", 220); recLab.position.set(C.x, 8.4, C.z); scene.add(recLab);
    const bits = Array.from({ length: 14 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: i % 4 === 0 ? B : A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.3, 0.3, 1);
      scene.add(s);
      return { s, o: i / 14, a: (i * 2.4) % (Math.PI * 2) };
    });
    const domeMat = new THREE.MeshStandardMaterial({ color: A, transparent: true, opacity: 0, side: THREE.DoubleSide, emissive: A, emissiveIntensity: 0.2 });
    const dome = new THREE.Mesh(new THREE.SphereGeometry(2.4, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2), domeMat);
    dome.position.set(C.x, 0.2, C.z);
    scene.add(dome);

    // ── 3 the process tree hologram ──
    const T = new THREE.Vector3(5, 0, 0);
    const nodesDef: [string, number, number, boolean][] = [
      ["OUTLOOK", 0, 5.4, false], ["mshta", -1.6, 4.0, true], ["edge", 1.8, 4.0, false],
      ["powershell", -1.6, 2.6, true], ["msupdate", -1.6, 1.2, true],
    ];
    const tnodes = nodesDef.map(([n, x, y, bad]) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x0b1f18, emissive: bad ? Wn : A, emissiveIntensity: 0, transparent: true, opacity: 0.15 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.9, 0.6, 0.1), mat);
      m.position.set(T.x + x, y, T.z);
      scene.add(m);
      const l = tag(n, bad ? "#fecdd3" : "#a7f3d0", 220);
      l.position.set(T.x + x, y, T.z + 0.1);
      (l.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(l);
      return { m, mat, l: l.material as THREE.SpriteMaterial, bad };
    });
    const edgeMat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0 });
    [[0, 1], [0, 2], [1, 3], [3, 4]].forEach(([a, b]) => {
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([tnodes[a].m.position.clone(), tnodes[b].m.position.clone()]), edgeMat));
    });

    // ── 4 the kill: a strike on the malicious branch ──
    const strikeMat = additive(Wn, 0);
    const strike = new THREE.Mesh(new THREE.BoxGeometry(0.12, 4.2, 0.12), strikeMat);
    strike.position.set(T.x - 1.6, 2.6, T.z + 0.3);
    strike.rotation.z = 0.5;
    scene.add(strike);

    const anchors = [new THREE.Vector3(C.x - 5.5, 3.2, C.z), new THREE.Vector3(C.x + 3.2, 7.2, C.z), new THREE.Vector3(T.x + 2.4, 6.4, T.z), new THREE.Vector3(T.x - 1.6, 0.2, T.z + 1.2)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 26, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 60 : asp < 1.5 ? 31 : 26; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 2, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 3.4, 0);

      // 1 the rings light outward; XDR's lines reach the other domains
      rings.forEach((m, i) => { m.opacity = 0.05 + THREE.MathUtils.clamp(level[0] * 4 - i, 0, 1) * 0.85; });
      const x = THREE.MathUtils.clamp(level[0] * 4 - 3, 0, 1);
      domains.forEach(d => {
        d.lineMat.opacity = x * 0.6;
        (d.node.material as THREE.MeshStandardMaterial).opacity = 0.2 + x * 0.7;
        (d.node.material as THREE.MeshStandardMaterial).emissiveIntensity = x * 0.7;
        if (!rm) d.node.rotation.y += dt;
      });
      // 2 telemetry spirals up to the recorder; the dome closes once cleared
      (recorder.material as THREE.SpriteMaterial).opacity = level[1] * 0.7;
      bits.forEach(b => {
        const u = rm ? b.o : ((t * 0.25 + b.o) % 1);
        const r = 0.6 + (1 - u) * 0.6;
        b.s.position.set(C.x + Math.cos(b.a + u * 6) * r, 1.6 + u * 5.4, C.z + Math.sin(b.a + u * 6) * r);
        (b.s.material as THREE.SpriteMaterial).opacity = Math.max(level[1], stations[1]?.status === "open" ? 0.4 : 0) * (1 - u * 0.4);
      });
      domeMat.opacity = level[1] > 0.6 ? (level[1] - 0.6) * 0.45 : 0;
      screenMat.emissiveIntensity = 0.2 + level[1] * 0.4;
      // 3 the tree grows top to bottom; bad branch glows
      tnodes.forEach((n, i) => {
        const v = THREE.MathUtils.clamp(level[2] * 5 - i, 0, 1);
        n.mat.opacity = 0.15 + v * 0.8;
        n.l.opacity = v;
        n.mat.emissiveIntensity = v * (n.bad ? (rm ? 0.8 : 0.5 + pulse * 0.4) * (1 - level[3] * 0.85) : 0.4);
      });
      edgeMat.opacity = level[2] * 0.8;
      // 4 the strike through the malicious branch
      strikeMat.opacity = level[3] * 0.9;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#04130d]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
