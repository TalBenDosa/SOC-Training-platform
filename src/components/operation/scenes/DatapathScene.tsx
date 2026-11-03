"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The data path": one packet's journey through real network hardware, in a
 * data hall. A laptop, an access switch, a router, a NAT firewall, the
 * internet and a server sit on one cable run; a hologram OSI stack stands
 * behind them. The laptop is always on; each cleared station brings the next
 * device online, and packets (data wrapped in TCP, IP and Ethernet shells)
 * travel as far as the path is lit. Decorative only.
 */
const DEVICES = ["laptop", "switch", "router", "firewall", "internet", "server"] as const;
const OSI = ["Physical", "Data Link", "Network", "Transport", "Session", "Presentation", "Application"];
const SHELLS = [0x2dd4bf, 0x60a5fa, 0xa78bfa]; // Ethernet, IP, TCP from the outside in

function textSprite(text: string, color: string, w = 256, h = 48, font = "bold 24px monospace") {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const g = c.getContext("2d")!;
  g.fillStyle = color; g.font = font; g.textBaseline = "middle";
  g.fillText(text, 8, h / 2);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false }));
  s.scale.set(w / 64, h / 64, 1);
  return s;
}

export default function DatapathScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04070f, 30, 75);
    const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 200);
    const glow = glowTexture();
    let seed = 5;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x060a14, 0.9));
    const key = new THREE.DirectionalLight(0xd6e2ff, 1.3);
    key.position.set(-8, 18, 12);
    scene.add(key);

    // ── Data hall floor: raised tiles ──
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(90, 60), new THREE.MeshStandardMaterial({ color: 0x0a101c, roughness: 0.85, metalness: 0.2 }));
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);
    const tiles = new THREE.GridHelper(90, 60, 0x16233d, 0x101a2e);
    tiles.position.y = 0.01;
    scene.add(tiles);

    // ── Rows of server racks with blinking LEDs, behind the path ──
    const rackMat = new THREE.MeshStandardMaterial({ color: 0x141c2c, metalness: 0.5, roughness: 0.45 });
    const rackEdge = new THREE.LineBasicMaterial({ color: 0x2a3a5c, transparent: true, opacity: 0.8 });
    const leds: { m: THREE.MeshBasicMaterial; ph: number; sp: number }[] = [];
    for (const z of [-11, -16]) {
      for (let i = 0; i < 14; i++) {
        const x = -22 + i * 3.4;
        const rack = new THREE.Mesh(new THREE.BoxGeometry(2.6, 5, 1.6), rackMat);
        rack.position.set(x, 2.5, z);
        scene.add(rack);
        const e = new THREE.LineSegments(new THREE.EdgesGeometry(rack.geometry), rackEdge);
        e.position.copy(rack.position);
        scene.add(e);
        for (let u = 0; u < 9; u++) {
          const m = new THREE.MeshBasicMaterial({ color: rnd() > 0.85 ? 0xf59e0b : 0x22c55e, transparent: true });
          const led = new THREE.Mesh(new THREE.PlaneGeometry(0.12, 0.06), m);
          led.position.set(x - 0.9 + rnd() * 1.6, 0.6 + u * 0.48, z + 0.81);
          scene.add(led);
          leds.push({ m, ph: rnd() * 10, sp: 2 + rnd() * 6 });
        }
      }
    }

    // ── The devices on the cable run ──
    const devMat = new THREE.MeshStandardMaterial({ color: 0x2a3550, metalness: 0.5, roughness: 0.4, emissive: 0x060c18 });
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x7d93c4, transparent: true, opacity: 0.5 });
    const xs = [-15, -9, -3, 3, 9, 15];
    const zs = [3, 1, 3, 1, 3, 1];
    type Dev = { g: THREE.Group; lamp: THREE.MeshBasicMaterial; halo: THREE.Sprite; top: number; pos: THREE.Vector3; extra?: THREE.Object3D };
    const add = (g: THREE.Group, geo: THREE.BufferGeometry, y: number, m: THREE.Material = devMat) => {
      const mesh = new THREE.Mesh(geo, m);
      mesh.position.y = y;
      g.add(mesh);
      const e = new THREE.LineSegments(new THREE.EdgesGeometry(geo), edgeMat);
      e.position.y = y;
      g.add(e);
      return mesh;
    };
    const devices: Dev[] = DEVICES.map((kind, i) => {
      const g = new THREE.Group();
      g.position.set(xs[i], 0, zs[i]);
      scene.add(g);
      let top = 2;
      let extra: THREE.Object3D | undefined;
      // a plinth under every device
      add(g, new THREE.CylinderGeometry(1.7, 1.9, 0.3, 32), 0.15);
      if (kind === "laptop") {
        add(g, new THREE.BoxGeometry(2.2, 0.12, 1.5), 0.6);
        const lid = add(g, new THREE.BoxGeometry(2.2, 1.4, 0.08), 1.3);
        lid.position.z = -0.7; lid.rotation.x = -0.25;
        const screen = new THREE.Mesh(new THREE.PlaneGeometry(1.9, 1.15), additive(0x38bdf8, 0.55));
        screen.position.set(0, 1.3, -0.64); screen.rotation.x = -0.25;
        g.add(screen);
        top = 2.3;
      } else if (kind === "switch") {
        for (let u = 0; u < 3; u++) {
          add(g, new THREE.BoxGeometry(2.8, 0.36, 1.4), 0.6 + u * 0.42);
          for (let p = 0; p < 12; p++) {
            const port = new THREE.Mesh(new THREE.PlaneGeometry(0.13, 0.1), new THREE.MeshBasicMaterial({ color: 0x22c55e, transparent: true, opacity: 0.2 }));
            port.position.set(-1.2 + p * 0.21, 0.6 + u * 0.42, 0.71);
            g.add(port);
            leds.push({ m: port.material as THREE.MeshBasicMaterial, ph: p + u * 7, sp: 5 + (p % 4) });
          }
        }
        top = 2;
      } else if (kind === "router") {
        add(g, new THREE.BoxGeometry(2.2, 0.6, 1.4), 0.75);
        for (const x of [-0.7, 0, 0.7]) {
          const ant = add(g, new THREE.CylinderGeometry(0.04, 0.04, 1.2, 6), 1.65);
          ant.position.x = x;
        }
        top = 2.6;
      } else if (kind === "firewall") {
        add(g, new THREE.BoxGeometry(2.6, 2.2, 1.4), 1.4);
        const wall = new THREE.Mesh(new THREE.PlaneGeometry(2.3, 1.8), additive(0xf97316, 0.25));
        wall.position.set(0, 1.4, 0.71);
        g.add(wall);
        const nat = textSprite("NAT", "#fdba74", 128, 48);
        nat.position.set(0, 1.4, 0.8); nat.scale.multiplyScalar(0.6);
        g.add(nat);
        top = 3;
      } else if (kind === "internet") {
        const globe = new THREE.Mesh(new THREE.IcosahedronGeometry(1.5, 2), new THREE.MeshBasicMaterial({ color: 0x60a5fa, wireframe: true, transparent: true, opacity: 0.6 }));
        globe.position.y = 2;
        g.add(globe);
        extra = globe;
        top = 3.8;
      } else {
        add(g, new THREE.BoxGeometry(1.8, 3.6, 1.4), 2.1);
        for (let u = 0; u < 6; u++) {
          const blade = new THREE.Mesh(new THREE.PlaneGeometry(1.5, 0.08), new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.3 }));
          blade.position.set(0, 0.7 + u * 0.55, 0.71);
          g.add(blade);
          leds.push({ m: blade.material as THREE.MeshBasicMaterial, ph: u * 3, sp: 3 });
        }
        top = 4.2;
      }
      // status lamp ring on the plinth
      const lamp = additive(Wn, 0.4);
      const ring = new THREE.Mesh(new THREE.RingGeometry(1.75, 1.95, 48), lamp);
      ring.rotation.x = -Math.PI / 2; ring.position.y = 0.31;
      g.add(ring);
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.scale.set(6, 6, 1); halo.position.y = 1.4;
      g.add(halo);
      return { g, lamp, halo, top, pos: g.position.clone(), extra };
    });

    // ── The cable run, and its lit section ──
    const pathPts = devices.map(d => new THREE.Vector3(d.pos.x, 0.45, d.pos.z));
    const path = new THREE.CatmullRomCurve3(pathPts, false, "catmullrom", 0.3);
    const cableDark = new THREE.Mesh(new THREE.TubeGeometry(path, 200, 0.07, 8, false), new THREE.MeshStandardMaterial({ color: 0x1e293b }));
    scene.add(cableDark);
    const litMat = additive(A, 0.9);
    let litGeo: THREE.TubeGeometry | null = null;
    const litTube = new THREE.Mesh(new THREE.BufferGeometry(), litMat);
    scene.add(litTube);
    let litReach = -1;

    // ── Packets: data wrapped in three shells ──
    const packets = Array.from({ length: 5 }, (_, i) => {
      const g = new THREE.Group();
      const core = new THREE.Mesh(new THREE.BoxGeometry(0.22, 0.22, 0.22), new THREE.MeshBasicMaterial({ color: 0xf8fafc }));
      g.add(core);
      SHELLS.forEach((c, k) => {
        const s = 0.38 + (2 - k) * 0.16;
        const shell = new THREE.Mesh(new THREE.BoxGeometry(s, s, s), new THREE.MeshBasicMaterial({ color: c, transparent: true, opacity: 0.22, depthWrite: false }));
        g.add(shell);
        g.add(new THREE.LineSegments(new THREE.EdgesGeometry(shell.geometry), new THREE.LineBasicMaterial({ color: c, transparent: true, opacity: 0.8 })));
      });
      const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.6, blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.scale.set(1.6, 1.6, 1);
      g.add(halo);
      scene.add(g);
      return { g, t: i / 5 };
    });

    // ── Hologram OSI stack behind the run ──
    const osi = OSI.map((name, j) => {
      const m = new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.06, side: THREE.DoubleSide, depthWrite: false });
      const slab = new THREE.Mesh(new THREE.BoxGeometry(5, 0.5, 2.4), m);
      slab.position.set(-20, 0.6 + j * 0.75, -4);
      scene.add(slab);
      const e = new THREE.LineSegments(new THREE.EdgesGeometry(slab.geometry), new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.25 }));
      e.position.copy(slab.position);
      scene.add(e);
      const label = textSprite(`L${j + 1} ${name}`, "#cbd5e1", 320, 40, "bold 22px monospace");
      label.position.set(-20 + 1.2, 0.6 + j * 0.75, -2.7);
      label.scale.multiplyScalar(0.55);
      scene.add(label);
      return { m, e: e.material as THREE.LineBasicMaterial, label: label.material as THREE.SpriteMaterial };
    });

    const selRing = new THREE.Mesh(new THREE.RingGeometry(2.2, 2.45, 48), additive(A, 0.9));
    selRing.rotation.x = -Math.PI / 2; selRing.position.y = 0.33;
    scene.add(selRing);

    let W_ = 1, H_ = 1, dist = 30, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 52 : asp < 1.5 ? 44 : 36; };
    const tmp = new THREE.Vector3();

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const cleared = stations.filter(s => s.status === "cleared").length;
      const reach = Math.min(devices.length - 1, cleared); // index of the farthest device online

      const yaw = rm ? 0 : Math.sin(t * 0.06) * 0.18;
      // phones look along the run from its far end, so the path reads top to bottom
      if (portrait) camera.position.set(dist * 0.62 + Math.sin(yaw) * 4, dist * 0.8, dist * 0.42);
      else camera.position.set(Math.sin(yaw) * dist, dist * 0.62, Math.cos(yaw) * dist + 2);
      camera.lookAt(portrait ? -1 : 0, 1.2, portrait ? 1 : 0);

      leds.forEach(l => { l.m.opacity = rm ? 0.7 : (Math.sin(t * l.sp + l.ph) > 0.2 ? 0.95 : 0.25); });

      devices.forEach((d, i) => {
        const on = i <= reach;
        d.lamp.color.copy(on ? A : Wn);
        d.lamp.opacity = on ? 0.9 : 0.25 + (rm ? 0 : Math.sin(t * 3 + i) * 0.1);
        (d.halo.material as THREE.SpriteMaterial).opacity = on ? 0.35 : 0;
        devMat.emissive.setRGB(0.02, 0.05, 0.1);
        if (d.extra && !rm) d.extra.rotation.y += dt * (on ? 0.4 : 0.08);
        // station i labels device i+1 (the laptop is the starting point)
        const li = i - 1;
        if (li >= 0) placeLabel(labelRefs.current[li], d.g.localToWorld(tmp.set(0, d.top + 0.9, 0)), camera, W_, H_);
      });

      // the lit cable runs from the laptop to the farthest online device
      if (reach !== litReach) {
        litReach = reach;
        litGeo?.dispose();
        if (reach > 0) {
          const sub = new THREE.CatmullRomCurve3(pathPts.slice(0, reach + 1), false, "catmullrom", 0.3);
          litGeo = new THREE.TubeGeometry(sub, 120, 0.1, 8, false);
          litTube.geometry = litGeo;
        } else {
          litTube.geometry = new THREE.BufferGeometry();
        }
      }
      litMat.opacity = rm ? 0.8 : 0.6 + Math.sin(t * 2.4) * 0.2;

      // packets shuttle along the lit section (at rest on the laptop when nothing is lit)
      const span = reach / (devices.length - 1);
      packets.forEach((p, i) => {
        if (!rm) p.t = (p.t + dt * 0.12) % 1;
        const u = reach > 0 ? (rm ? (i + 0.5) / packets.length : p.t) * span : 0;
        path.getPointAt(Math.min(1, u), p.g.position);
        p.g.position.y += 0.55;
        p.g.visible = reach > 0 || i === 0;
        if (!rm) p.g.rotation.y += dt * 1.2;
      });

      // the OSI stack fills from the bottom with progress
      const prog = stations.length ? cleared / stations.length : 0;
      osi.forEach((o, j) => {
        const on = THREE.MathUtils.clamp(prog * 7 - j, 0, 1);
        o.m.opacity = 0.05 + on * 0.25;
        o.e.opacity = 0.2 + on * 0.7;
        o.label.opacity = 0.35 + on * 0.65;
      });

      const target = devices[Math.min(devices.length - 1, selected + 1)];
      selRing.position.x += (target.pos.x - selRing.position.x) * (rm ? 1 : 1 - Math.pow(0.2, dt));
      selRing.position.z += (target.pos.z - selRing.position.z) * (rm ? 1 : 1 - Math.pow(0.2, dt));
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 hidden will-change-transform sm:block">
            <span className="block whitespace-nowrap rounded-md border bg-[#071021]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
