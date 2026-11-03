"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "First light": a hospital campus at night. The boss station is the central
 * tower with a helipad; the other stations stand on a ring around the plaza,
 * with one extra building that stays dark (the campus goes on in later rooms).
 * A cleared station powers its building back up floor by floor and a light
 * pipe runs to it from the plaza. Emergency cleared sends the ambulance out;
 * the whole room cleared turns night into dawn and lifts the helicopter.
 * Decorative only: never clickable.
 */
export default function CampusScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;
  const n = props.stations.length;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), W = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    const NIGHT_FOG = new THREE.Color(0x060b18), DAWN_FOG = new THREE.Color(0x2a2f4a);
    scene.fog = new THREE.Fog(NIGHT_FOG.clone(), 26, 70);
    const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 220);
    const glow = glowTexture();
    let seed = 7;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };

    const hemi = new THREE.HemisphereLight(0xa9bdf0, 0x0a1020, 0.8);
    scene.add(hemi);
    const moon = new THREE.DirectionalLight(0xa9bdf5, 1.5);
    moon.position.set(-10, 18, 6);
    scene.add(moon);
    const sunLight = new THREE.DirectionalLight(0xffb27a, 0);
    sunLight.position.set(0, 6, -30);
    scene.add(sunLight);

    // ── Sky dome: night to dawn with progress ──
    const skyU = { top: { value: new THREE.Color(0x03060f) }, horizon: { value: new THREE.Color(0x0b1633) } };
    const sky = new THREE.Mesh(
      new THREE.SphereGeometry(150, 32, 16),
      new THREE.ShaderMaterial({
        side: THREE.BackSide, depthWrite: false, fog: false, uniforms: skyU,
        vertexShader: "varying float h; void main(){ h = normalize(position).y; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
        fragmentShader: "uniform vec3 top; uniform vec3 horizon; varying float h; void main(){ gl_FragColor = vec4(mix(horizon, top, smoothstep(-0.05, 0.55, h)), 1.0); }",
      }),
    );
    scene.add(sky);
    const starGeo = new THREE.BufferGeometry();
    const starPos: number[] = [];
    for (let i = 0; i < 500; i++) {
      const a = rnd() * Math.PI * 2, e = 0.08 + rnd() * 1.2;
      starPos.push(Math.cos(a) * Math.cos(e) * 140, Math.sin(e) * 140, Math.sin(a) * Math.cos(e) * 140);
    }
    starGeo.setAttribute("position", new THREE.Float32BufferAttribute(starPos, 3));
    const starMat = new THREE.PointsMaterial({ color: 0xdbe7ff, size: 0.9, sizeAttenuation: true, transparent: true, opacity: 0.85, fog: false, depthWrite: false });
    scene.add(new THREE.Points(starGeo, starMat));
    const sun = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0xffa25c, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false, fog: false }));
    sun.scale.set(60, 60, 1);
    scene.add(sun);

    // ── Ground, roads and plaza ──
    const ground = new THREE.Mesh(new THREE.CircleGeometry(80, 64), new THREE.MeshStandardMaterial({ color: 0x0a1120, roughness: 0.95 }));
    ground.rotation.x = -Math.PI / 2;
    scene.add(ground);
    const roadMat = new THREE.MeshStandardMaterial({ color: 0x141d30, roughness: 0.9 });
    const ring = new THREE.Mesh(new THREE.RingGeometry(12.2, 13.6, 72), roadMat);
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.01;
    scene.add(ring);
    const plaza = new THREE.Mesh(new THREE.CircleGeometry(4.6, 48), new THREE.MeshStandardMaterial({ color: 0x18223a, roughness: 0.8 }));
    plaza.rotation.x = -Math.PI / 2; plaza.position.y = 0.012;
    scene.add(plaza);
    const laneMat = new THREE.MeshBasicMaterial({ color: 0xf5c04a, transparent: true, opacity: 0.35 });
    for (let i = 0; i < 48; i++) {
      const a = (i / 48) * Math.PI * 2;
      const d = new THREE.Mesh(new THREE.PlaneGeometry(0.7, 0.08), laneMat);
      d.rotation.x = -Math.PI / 2; d.rotation.z = -a;
      d.position.set(Math.cos(a) * 12.9, 0.02, Math.sin(a) * 12.9);
      scene.add(d);
    }
    // street lamps along the ring road and trees around the plaza
    const lampMat = new THREE.MeshStandardMaterial({ color: 0x334155 });
    for (let i = 0; i < 28; i++) {
      const a = (i / 28) * Math.PI * 2 + 0.06;
      const x = Math.cos(a) * 14.4, z = Math.sin(a) * 14.4;
      const pole = new THREE.Mesh(new THREE.CylinderGeometry(0.04, 0.05, 1.3, 6), lampMat);
      pole.position.set(x, 0.65, z);
      scene.add(pole);
      const bulb = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0xffc879, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false }));
      bulb.scale.set(1.3, 1.3, 1);
      bulb.position.set(x, 1.35, z);
      scene.add(bulb);
      const pool = new THREE.Mesh(new THREE.CircleGeometry(1.4, 20), new THREE.MeshBasicMaterial({ map: glow, color: 0xffc879, transparent: true, opacity: 0.22, blending: THREE.AdditiveBlending, depthWrite: false }));
      pool.rotation.x = -Math.PI / 2;
      pool.position.set(x, 0.025, z);
      scene.add(pool);
    }
    const treeMat = new THREE.MeshStandardMaterial({ color: 0x123a3a, roughness: 0.9 });
    for (let i = 0; i < 26; i++) {
      const a = rnd() * Math.PI * 2, r = 5.2 + rnd() * 1.4 + (i % 2) * 5.6;
      const tr = new THREE.Mesh(new THREE.ConeGeometry(0.38, 1.1, 7), treeMat);
      tr.position.set(Math.cos(a) * r, 0.55, Math.sin(a) * r);
      scene.add(tr);
    }
    // a scatter of dark city blocks beyond the ring road
    const cityMat = new THREE.MeshStandardMaterial({ color: 0x0e1626, roughness: 0.8 });
    for (let i = 0; i < 46; i++) {
      // behind the campus only, so nothing blocks the camera
      const a = Math.PI * 1.08 + rnd() * Math.PI * 0.84, r = 20 + rnd() * 26, h = 0.8 + rnd() * 4;
      const b = new THREE.Mesh(new THREE.BoxGeometry(1.4 + rnd() * 2, h, 1.4 + rnd() * 2), cityMat);
      b.position.set(Math.cos(a) * r, h / 2, Math.sin(a) * r);
      scene.add(b);
    }

    // ── Window texture: a grid of panes on a transparent wall ──
    const winTex = (() => {
      const c = document.createElement("canvas");
      c.width = 256; c.height = 64;
      const g = c.getContext("2d")!;
      for (let x = 0; x < 8; x++) {
        g.fillStyle = `rgba(255,255,255,${0.75 + ((x * 37) % 10) / 40})`;
        g.fillRect(8 + x * 31, 16, 20, 32);
      }
      const t = new THREE.CanvasTexture(c);
      t.colorSpace = THREE.SRGBColorSpace;
      return t;
    })();

    // ── Buildings: ring stations, a dark extra building, and the central tower ──
    const wall = new THREE.MeshStandardMaterial({ color: 0x34446a, emissive: 0x0a1428, metalness: 0.25, roughness: 0.6 });
    const edgeMat = new THREE.LineBasicMaterial({ color: 0x7d93c4, transparent: true, opacity: 0.5 });
    const roofMat = new THREE.MeshStandardMaterial({ color: 0x2a3757, metalness: 0.3, roughness: 0.5 });
    type Bldg = { g: THREE.Group; floors: THREE.MeshBasicMaterial[]; lit: number; h: number; anchor: THREE.Vector3; beacon: THREE.Mesh; pipe?: THREE.MeshBasicMaterial };
    const FLOOR_H = 1.1;
    function building(x: number, z: number, w: number, d: number, nf: number, faceAngle: number): Bldg {
      const g = new THREE.Group();
      g.position.set(x, 0, z);
      g.rotation.y = faceAngle;
      scene.add(g);
      const h = nf * FLOOR_H;
      const body = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), wall);
      body.position.y = h / 2;
      g.add(body);
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(body.geometry), edgeMat);
      edges.position.y = h / 2;
      g.add(edges);
      // rooftop plant: a couple of AC units
      for (let k = 0; k < 2; k++) {
        const ac = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.3, 0.4), roofMat);
        ac.position.set((k - 0.5) * w * 0.45, h + 0.4, -d * 0.2);
        g.add(ac);
      }
      const cap = new THREE.Mesh(new THREE.BoxGeometry(w + 0.3, 0.25, d + 0.3), roofMat);
      cap.position.y = h + 0.12;
      g.add(cap);
      const floors: THREE.MeshBasicMaterial[] = [];
      for (let f = 0; f < nf; f++) {
        const m = new THREE.MeshBasicMaterial({ map: winTex, color: 0x334155, transparent: true, opacity: 0.6, blending: THREE.AdditiveBlending, depthWrite: false });
        floors.push(m);
        for (const [px, pz, ry, pw] of [[0, d / 2 + 0.01, 0, w], [0, -d / 2 - 0.01, Math.PI, w], [w / 2 + 0.01, 0, Math.PI / 2, d], [-w / 2 - 0.01, 0, -Math.PI / 2, d]] as const) {
          const p = new THREE.Mesh(new THREE.PlaneGeometry(pw * 0.92, FLOOR_H * 0.62), m);
          p.position.set(px, f * FLOOR_H + FLOOR_H * 0.55, pz);
          p.rotation.y = ry;
          g.add(p);
        }
      }
      const beacon = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 7, 8, 1, true), additive(A, 0));
      beacon.position.y = h + 3.5;
      g.add(beacon);
      return { g, floors, lit: 0, h, anchor: new THREE.Vector3(), beacon };
    }

    const ringCount = Math.max(1, n - 1) + 1; // ring stations + the dark extra building
    const R = 8.4;
    const start = Math.PI / 2; // first station faces the camera
    const ringB: Bldg[] = [];
    for (let i = 0; i < ringCount; i++) {
      const a = start + (i / ringCount) * Math.PI * 2;
      const x = Math.cos(a) * R, z = Math.sin(a) * R;
      const nf = 3 + ((i * 2) % 3);
      ringB.push(building(x, z, 3.4, 2.4, nf, -a + Math.PI / 2));
    }
    const extra = ringB[ringB.length - 1];
    const stationB: Bldg[] = ringB.slice(0, n - 1);
    const tower = building(0, 0, 3.2, 3.2, 7, 0);
    stationB.push(tower);

    // Hospital cross on the tower, and a helipad with a helicopter on its roof
    const crossMat = additive(0xf43f5e, 0.35);
    for (const [cx, cy] of [[1.0, 0.24], [0.24, 1.0]]) {
      const c = new THREE.Mesh(new THREE.PlaneGeometry(cx, cy), crossMat);
      c.position.set(0, tower.h - 0.9, 1.62);
      tower.g.add(c);
    }
    const pad = new THREE.Mesh(new THREE.CircleGeometry(1.25, 32), new THREE.MeshBasicMaterial({ color: 0x1e293b }));
    pad.rotation.x = -Math.PI / 2; pad.position.y = tower.h + 0.26;
    tower.g.add(pad);
    const padRing = new THREE.Mesh(new THREE.RingGeometry(1.05, 1.2, 32), additive(0xfbbf24, 0.25));
    padRing.rotation.x = -Math.PI / 2; padRing.position.y = tower.h + 0.27;
    tower.g.add(padRing);
    const heli = new THREE.Group();
    heli.position.y = tower.h + 0.55;
    tower.g.add(heli);
    const heliMat = new THREE.MeshStandardMaterial({ color: 0xe2e8f0, metalness: 0.4, roughness: 0.35 });
    const cabin = new THREE.Mesh(new THREE.SphereGeometry(0.42, 16, 12), heliMat);
    cabin.scale.set(1.4, 0.9, 0.9);
    heli.add(cabin);
    const tail = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.12, 0.12), heliMat);
    tail.position.set(-0.95, 0.08, 0);
    heli.add(tail);
    const rotor = new THREE.Group();
    rotor.position.y = 0.45;
    heli.add(rotor);
    for (const r of [0, Math.PI / 2]) {
      const blade = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.02, 0.1), new THREE.MeshStandardMaterial({ color: 0x334155 }));
      blade.rotation.y = r;
      rotor.add(blade);
    }
    const heliLight = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0xf43f5e, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending, depthWrite: false }));
    heliLight.scale.set(0.8, 0.8, 1);
    heliLight.position.set(-1.5, 0.15, 0);
    heli.add(heliLight);

    // Light pipes from the plaza to every ring station
    const dashTex = (() => {
      const c = document.createElement("canvas");
      c.width = 64; c.height = 8;
      const g = c.getContext("2d")!;
      g.fillStyle = "#fff"; g.fillRect(0, 0, 36, 8);
      const t = new THREE.CanvasTexture(c);
      t.wrapS = THREE.RepeatWrapping;
      return t;
    })();
    stationB.slice(0, n - 1).forEach(b => {
      const len = b.g.position.length() - 1.6;
      const m = new THREE.MeshBasicMaterial({ map: dashTex.clone(), color: W, transparent: true, opacity: 0.15, blending: THREE.AdditiveBlending, depthWrite: false });
      m.map!.wrapS = THREE.RepeatWrapping;
      m.map!.repeat.set(len / 0.7, 1);
      const pipe = new THREE.Mesh(new THREE.PlaneGeometry(len, 0.22), m);
      const ang = Math.atan2(b.g.position.z, b.g.position.x);
      pipe.rotation.x = -Math.PI / 2;
      pipe.rotation.z = -ang;
      pipe.position.set(Math.cos(ang) * (len / 2 + 1.6), 0.03, Math.sin(ang) * (len / 2 + 1.6));
      scene.add(pipe);
      b.pipe = m;
    });

    // Selection ring that sits at the base of the selected building
    const selRing = new THREE.Mesh(new THREE.RingGeometry(2.5, 2.75, 48), additive(A, 0.9));
    selRing.rotation.x = -Math.PI / 2;
    selRing.position.y = 0.05;
    scene.add(selRing);

    // The ambulance: parked with lights flashing until Emergency is cleared, then it drives the ring road
    const amb = new THREE.Group();
    scene.add(amb);
    const ambBody = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.5, 0.45), new THREE.MeshStandardMaterial({ color: 0xf8fafc, roughness: 0.4 }));
    ambBody.position.y = 0.3;
    amb.add(ambBody);
    const stripe = new THREE.Mesh(new THREE.BoxGeometry(0.92, 0.08, 0.47), new THREE.MeshBasicMaterial({ color: 0xef4444 }));
    stripe.position.y = 0.32;
    amb.add(stripe);
    const lightA = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x3b82f6, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
    const lightB = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0xef4444, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
    for (const [s, x] of [[lightA, 0.2], [lightB, -0.2]] as const) { s.scale.set(0.9, 0.9, 1); s.position.set(x, 0.7, 0); amb.add(s); }
    let ambA = start + 0.32;

    let W_ = 1, H_ = 1, dist = 30;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; dist = asp < 1 ? 60 : asp < 1.5 ? 48 : 40; };
    const tmpCol = new THREE.Color();

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, selected, reducedMotion: rm } = live.current;
      const cleared = stations.filter(s => s.status === "cleared").length;
      const prog = stations.length ? cleared / stations.length : 0;
      const all = cleared === stations.length && stations.length > 0;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);

      // camera: a slow sway around the front of the campus
      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * 0.78, Math.cos(yaw) * dist);
      camera.lookAt(0, 0.5, 1.5);

      // sky, stars, fog and sun follow progress (night → dawn)
      const dawn = Math.pow(prog, 1.4);
      skyU.top.value.setRGB(0.012, 0.024, 0.06).lerp(tmpCol.setRGB(0.1, 0.16, 0.32), dawn);
      skyU.horizon.value.setRGB(0.04, 0.09, 0.2).lerp(tmpCol.setRGB(0.95, 0.55, 0.34), dawn);
      starMat.opacity = 0.85 * (1 - dawn);
      (scene.fog as THREE.Fog).color.copy(NIGHT_FOG).lerp(DAWN_FOG, dawn);
      sun.position.set(0, -10 + dawn * 16, -120);
      (sun.material as THREE.SpriteMaterial).opacity = 0.15 + dawn * 0.85;
      sunLight.intensity = dawn * 1.3;
      hemi.intensity = 0.55 + dawn * 0.5;

      stationB.forEach((b, i) => {
        const s = stations[i];
        if (!s) return;
        const target = s.status === "cleared" ? b.floors.length : 0;
        b.lit += (target - b.lit) * (rm ? 1 : 1 - Math.pow(0.35, dt));
        const pulse = rm ? 1 : 0.6 + Math.sin(t * 3.2) * 0.4;
        b.floors.forEach((m, f) => {
          if (s.status === "cleared") {
            const on = THREE.MathUtils.clamp(b.lit - f, 0, 1);
            m.color.copy(A).lerp(tmpCol.set(0xfff4d6), 0.35).multiplyScalar(1.5);
            m.opacity = 0.2 + on * 0.8;
          } else if (s.status === "open") {
            m.color.copy(A); m.opacity = 0.3 + pulse * 0.45 * ((f % 2) ? 0.8 : 1);
          } else {
            // dark building: a few windows flicker red
            const flick = rm ? 0.3 : (Math.sin(t * 7 + f * 13 + i * 5) > 0.92 ? 0.8 : 0.18);
            m.color.copy(W); m.opacity = flick * 0.6;
          }
        });
        (b.beacon.material as THREE.MeshBasicMaterial).opacity = s.status === "open" ? 0.25 * pulse : 0;
        if (b.pipe) {
          b.pipe.color.copy(s.status === "cleared" ? A : W);
          b.pipe.opacity = s.status === "cleared" ? 0.85 : 0.12;
          if (!rm && s.status === "cleared") b.pipe.map!.offset.x -= dt * 1.4;
        }
        // the tower's label rides above the helipad so it clears the ring labels
        b.g.localToWorld(b.anchor.set(0, b.h + (b === tower ? 3.4 : 1.1), 0));
        placeLabel(labelRefs.current[i], b.anchor, camera, W_, H_);
      });
      // the extra building stays dark: the campus goes on in later rooms
      extra.floors.forEach((m, f) => { m.color.copy(W); m.opacity = rm ? 0.12 : (Math.sin(t * 5 + f * 9) > 0.95 ? 0.5 : 0.1); });

      crossMat.opacity = all ? 1 : 0.35 + (rm ? 0 : Math.sin(t * 2) * 0.1);
      (padRing.material as THREE.MeshBasicMaterial).opacity = all ? 0.9 : 0.25;

      const sb = stationB[selected];
      if (sb) {
        selRing.position.x += (sb.g.position.x - selRing.position.x) * ease;
        selRing.position.z += (sb.g.position.z - selRing.position.z) * ease;
        if (!rm) selRing.rotation.z += dt * 0.6;
      }

      // helicopter: idle on the pad, lifts off at dawn
      const lift = all ? Math.min(3, (heli.userData.lift ?? 0) + dt * 0.6) : 0;
      heli.userData.lift = rm ? (all ? 3 : 0) : lift;
      heli.position.y = tower.h + 0.55 + heli.userData.lift;
      if (!rm) rotor.rotation.y += dt * (all ? 26 : 0.4);
      (heliLight.material as THREE.SpriteMaterial).opacity = rm ? 0.8 : (Math.sin(t * 6) > 0 ? 0.9 : 0.15);

      // ambulance
      const erClear = stations[1]?.status === "cleared";
      if (erClear && !rm) ambA += dt * 0.22;
      amb.position.set(Math.cos(ambA) * 12.9, 0, Math.sin(ambA) * 12.9);
      amb.rotation.y = -ambA;
      const flash = rm ? 1 : (Math.sin(t * 9) > 0 ? 1 : 0.15);
      (lightA.material as THREE.SpriteMaterial).opacity = flash;
      (lightB.material as THREE.SpriteMaterial).opacity = 1.15 - flash;
    }, fit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n, props.primary, props.secondary, props.warn]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: props.dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {props.stations.map((s, i) => (
          <div key={s.id} ref={el => { labelRefs.current[i] = el; }} className="absolute left-0 top-0 will-change-transform">
            <span className="block whitespace-nowrap rounded-md border bg-[#071021]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide sm:text-xs"
              style={{
                borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)",
                color: s.status === "locked" ? "#94a3b8" : "#fff",
                boxShadow: i === props.selected ? `0 0 18px -4px ${props.primary}` : undefined,
              }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
              <span className="ml-2 rounded px-1 text-[9px]" style={{ background: s.status === "cleared" ? "rgba(52,211,153,0.2)" : s.status === "open" ? `${props.primary}33` : "rgba(244,63,94,0.18)", color: s.status === "cleared" ? "#6ee7b7" : s.status === "open" ? props.primary : "#fda4af" }}>
                {s.status === "cleared" ? "ONLINE" : s.status === "open" ? "RESTORING" : "OFFLINE"}
              </span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
