"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The port wall": a perimeter firewall seen from the outside, its face a grid
 * of port sockets. Traffic streams fly in from the internet to each port:
 * blue for encrypted protocols, amber for cleartext, red for one that should
 * never be there. Stations light the ports group by group (web and names,
 * the remote-access doors), then mark the ports attackers abuse with a red
 * "watch" frame, and finally a burst of generated domain names hits port 53
 * and is caught by a detection ring. Decorative only.
 */
type Port = { port: string; name: string; group: number; kind: "enc" | "clear" | "never"; abused?: boolean };
const PORTS: Port[] = [
  { port: "80", name: "HTTP", group: 0, kind: "clear" },
  { port: "443", name: "HTTPS", group: 0, kind: "enc", abused: true },
  { port: "53", name: "DNS", group: 0, kind: "clear", abused: true },
  { port: "67", name: "DHCP", group: 0, kind: "clear" },
  { port: "22", name: "SSH", group: 1, kind: "enc" },
  { port: "21", name: "FTP", group: 1, kind: "clear" },
  { port: "23", name: "TELNET", group: 1, kind: "never" },
  { port: "445", name: "SMB", group: 1, kind: "clear", abused: true },
  { port: "3389", name: "RDP", group: 1, kind: "enc", abused: true },
  { port: "25", name: "SMTP", group: 1, kind: "clear" },
  { port: "993", name: "IMAPS", group: 1, kind: "enc" },
  { port: "ICMP", name: "PING", group: 1, kind: "clear" },
];
const KIND_COLOR = { enc: 0x38bdf8, clear: 0xfbbf24, never: 0xf43f5e };

function label(text: string, sub: string, w = 256) {
  const c = document.createElement("canvas");
  c.width = w; c.height = 128;
  const g = c.getContext("2d")!;
  g.textAlign = "center";
  g.fillStyle = "#f8fafc"; g.font = "bold 54px monospace"; g.fillText(text, w / 2, 62);
  g.fillStyle = "#94a3b8"; g.font = "bold 28px monospace"; g.fillText(sub, w / 2, 104);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

export default function PortWallScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x04060c, 30, 80);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();
    let seed = 9;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };

    scene.add(new THREE.HemisphereLight(0x9fb4e8, 0x05080f, 0.8));
    const key = new THREE.DirectionalLight(0xd6e2ff, 1.2);
    key.position.set(-6, 14, 16);
    scene.add(key);

    const floor = new THREE.Mesh(new THREE.PlaneGeometry(80, 50), new THREE.MeshStandardMaterial({ color: 0x080d18, roughness: 0.7, metalness: 0.3 }));
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);
    const grid = new THREE.GridHelper(80, 40, 0x14213a, 0x0d1628);
    grid.position.y = 0.01;
    scene.add(grid);

    // ── The firewall face ──
    const W = 17, H = 7.2;
    const wall = new THREE.Mesh(new THREE.BoxGeometry(W, H, 1.2), new THREE.MeshStandardMaterial({ color: 0x141b2a, metalness: 0.55, roughness: 0.35 }));
    wall.position.set(0, H / 2 + 0.4, 0);
    scene.add(wall);
    const rim = new THREE.LineSegments(new THREE.EdgesGeometry(wall.geometry), new THREE.LineBasicMaterial({ color: 0x334766 }));
    rim.position.copy(wall.position);
    scene.add(rim);
    const brand = new THREE.Sprite(new THREE.SpriteMaterial({ map: label("FW-EDGE-01", "perimeter firewall", 512), transparent: true, depthWrite: false }));
    brand.scale.set(6, 1.5, 1); brand.position.set(0, H + 1.4, 0.7);
    scene.add(brand);

    // ── Port sockets: 2 rows of 6 ──
    type Socket = { p: Port; pos: THREE.Vector3; ring: THREE.LineBasicMaterial; lab: THREE.SpriteMaterial; watch: THREE.LineBasicMaterial; stream: { s: THREE.Sprite; t: number; v: number; curve: THREE.QuadraticBezierCurve3 }[] };
    const sockets: Socket[] = PORTS.map((p, i) => {
      const col = i % 6, row = Math.floor(i / 6);
      const pos = new THREE.Vector3(-6.75 + col * 2.7, H + 0.4 - 2.1 - row * 3.1, 0.62);
      const hole = new THREE.Mesh(new THREE.BoxGeometry(1.5, 1, 0.2), new THREE.MeshStandardMaterial({ color: 0x05070c }));
      hole.position.copy(pos);
      scene.add(hole);
      const ring = new THREE.LineBasicMaterial({ color: KIND_COLOR[p.kind], transparent: true, opacity: 0.08 });
      const frame = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(1.8, 1.25)), ring);
      frame.position.copy(pos).add(new THREE.Vector3(0, 0, 0.12));
      scene.add(frame);
      const labSp = new THREE.Sprite(new THREE.SpriteMaterial({ map: label(p.port, p.name), transparent: true, opacity: 0.3, depthWrite: false }));
      labSp.scale.set(1.7, 0.85, 1); labSp.position.copy(pos).add(new THREE.Vector3(0, -1.05, 0.2));
      scene.add(labSp);
      // the red "watch" frame for ports attackers abuse
      const watch = new THREE.LineBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
      const box = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(2.3, 2.6, 0.1)), watch);
      box.position.copy(pos).add(new THREE.Vector3(0, -0.45, 0.15));
      scene.add(box);
      // incoming stream from the internet, out in front of the wall
      const from = new THREE.Vector3((rnd() - 0.5) * 26, 2 + rnd() * 6, 22 + rnd() * 6);
      const curve = new THREE.QuadraticBezierCurve3(from, new THREE.Vector3((from.x + pos.x) / 2, pos.y + 4, 10), pos.clone().add(new THREE.Vector3(0, 0, 0.3)));
      const stream = Array.from({ length: 4 }, (_, k) => {
        const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: KIND_COLOR[p.kind], transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
        s.scale.set(0.7, 0.7, 1);
        scene.add(s);
        return { s, t: k / 4, v: 0.18 + rnd() * 0.12, curve };
      });
      return { p, pos, ring, lab: labSp.material as THREE.SpriteMaterial, watch, stream };
    });

    // ── The generated-domain burst at port 53, and the detection ring ──
    const dns = sockets.find(s => s.p.port === "53")!;
    const burst = Array.from({ length: 26 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.5, 0.5, 1);
      scene.add(s);
      return { s, a: rnd() * Math.PI * 2, r: 6 + rnd() * 8, t: rnd() };
    });
    const detector = new THREE.Mesh(new THREE.TorusGeometry(1.7, 0.07, 8, 48), additive(A, 0));
    detector.position.copy(dns.pos).add(new THREE.Vector3(0, 0, 1.6));
    scene.add(detector);

    // label anchors per station: the web group, the remote doors, the wall top, port 53
    const anchors = [
      sockets[1].pos.clone().add(new THREE.Vector3(0, 1.4, 0.6)),
      sockets[7].pos.clone().add(new THREE.Vector3(0, -2.2, 0.6)),
      new THREE.Vector3(-6.5, H + 1.2, 0.6),
      dns.pos.clone().add(new THREE.Vector3(0, 2.2, 1.6)),
    ];

    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 30, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 52 : asp < 1.5 ? 32 : 26; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.12 + pulse * 0.14 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.08) * 0.2;
      camera.position.set(Math.sin(yaw) * dist, dist * 0.32 + 3, Math.cos(yaw) * dist);
      camera.lookAt(0, 3.8, 0);

      sockets.forEach((so, i) => {
        const on = level[so.p.group];
        so.ring.opacity = 0.08 + on * 0.85 * (so.p.kind === "never" && !rm ? 0.6 + Math.sin(t * 6) * 0.4 : 1);
        so.lab.opacity = 0.3 + on * 0.7;
        so.watch.opacity = so.p.abused ? level[2] * (rm ? 0.9 : 0.6 + Math.sin(t * 4 + i) * 0.3) : 0;
        so.stream.forEach(st => {
          if (!rm) st.t = (st.t + dt * st.v) % 1;
          st.curve.getPoint(rm ? 0.7 : st.t, st.s.position);
          (st.s.material as THREE.SpriteMaterial).opacity = on * (rm ? 0.8 : Math.sin(st.t * Math.PI));
        });
      });

      // the burst converges on port 53 and the ring catches it
      burst.forEach(b => {
        if (!rm) b.t = (b.t + dt * 0.35) % 1;
        const u = rm ? 0.6 : b.t;
        b.s.position.set(dns.pos.x + Math.cos(b.a) * b.r * (1 - u), dns.pos.y + Math.sin(b.a) * b.r * (1 - u) * 0.6, dns.pos.z + 1.6 + (1 - u) * 6);
        (b.s.material as THREE.SpriteMaterial).opacity = Math.max(level[3], stations[3]?.status === "open" ? 0.35 * pulse : 0) * (rm ? 0.8 : Math.sin(u * Math.PI));
      });
      (detector.material as THREE.MeshBasicMaterial).opacity = level[3] * 0.9;
      if (!rm) detector.rotation.z += dt * 1.2;

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
