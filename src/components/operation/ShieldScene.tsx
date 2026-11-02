"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";

/**
 * The Operation centrepiece: a holographic cyber shield over a projector
 * platform. The network nodes inside the shield light up and the platform arc
 * fills as stations are cleared, so the shield "charges" with the mission.
 *
 * Plain three.js on purpose: Next 15's app router runs React 19 internally
 * while the project declares React 18, so React Three Fiber needs peer-dep
 * overrides and its global JSX augmentation breaks unrelated `React.ElementType`
 * props. Loaded client-only (next/dynamic, ssr:false) from OperationView.
 */

interface ShieldSceneProps {
  /** Share of stations cleared, 0..1. */
  progress: number;
  primary: string;
  secondary: string;
  dimmed: boolean;
  reducedMotion: boolean;
}

const NODE_COUNT = 30;

function shieldShape(scale = 1): THREE.Shape {
  const s = new THREE.Shape();
  const p = (x: number, y: number) => [x * scale, y * scale] as const;
  s.moveTo(...p(0, 1.55));
  s.quadraticCurveTo(...p(0.7, 1.22), ...p(1.32, 1.42));
  s.lineTo(...p(1.32, 0.35));
  s.quadraticCurveTo(...p(1.26, -0.95), ...p(0, -1.62));
  s.quadraticCurveTo(...p(-1.26, -0.95), ...p(-1.32, 0.35));
  s.lineTo(...p(-1.32, 1.42));
  s.quadraticCurveTo(...p(-0.7, 1.22), ...p(0, 1.55));
  return s;
}

function inside(poly: THREE.Vector2[], x: number, y: number): boolean {
  let hit = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const a = poly[i], b = poly[j];
    if ((a.y > y) !== (b.y > y) && x < ((b.x - a.x) * (y - a.y)) / (b.y - a.y) + a.x) hit = !hit;
  }
  return hit;
}

// Deterministic scatter so the constellation is the same on every visit.
function rng(seed: number) {
  return () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
}

function glowTexture(): THREE.Texture {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d")!;
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.45)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

export default function ShieldScene({ progress, primary, secondary, dimmed, reducedMotion }: ShieldSceneProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const live = useRef({ progress, reducedMotion });
  live.current = { progress, reducedMotion };

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(primary), B = new THREE.Color(secondary), GREEN = new THREE.Color("#34d399");
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
    const glow = glowTexture();

    scene.add(new THREE.AmbientLight(0x6b7fa8, 0.9));
    const key = new THREE.PointLight(A, 30, 20); key.position.set(2.5, 3, 4); scene.add(key);
    const rim = new THREE.PointLight(B, 22, 20); rim.position.set(-3, 1, -2); scene.add(rim);

    // ── Dotted globe behind everything ──
    const globePts: number[] = [];
    for (let lat = -80; lat <= 80; lat += 8) {
      const r = Math.cos((lat * Math.PI) / 180), y = Math.sin((lat * Math.PI) / 180);
      const steps = Math.max(6, Math.round(48 * r));
      for (let k = 0; k < steps; k++) {
        const a = (k / steps) * Math.PI * 2;
        // Patchy "continents": keep a band-limited subset of dots.
        if (Math.sin(a * 3 + lat * 0.11) + Math.cos(a * 2 - lat * 0.07) < -0.2) continue;
        globePts.push(Math.cos(a) * r * 3.4, y * 3.4, Math.sin(a) * r * 3.4);
      }
    }
    const globeGeo = new THREE.BufferGeometry();
    globeGeo.setAttribute("position", new THREE.Float32BufferAttribute(globePts, 3));
    const globe = new THREE.Points(globeGeo, new THREE.PointsMaterial({ color: A, size: 0.055, transparent: true, opacity: 0.5, depthWrite: false }));
    globe.position.set(0, 0.2, -2.6);
    scene.add(globe);

    // ── Platform ──
    const platform = new THREE.Group();
    platform.position.y = -2.05;
    scene.add(platform);
    const base = new THREE.Mesh(new THREE.CylinderGeometry(2.3, 2.55, 0.32, 72), new THREE.MeshStandardMaterial({ color: 0x0b1424, metalness: 0.6, roughness: 0.45 }));
    platform.add(base);
    const top = new THREE.Mesh(new THREE.CylinderGeometry(2.0, 2.0, 0.06, 72), new THREE.MeshStandardMaterial({ color: 0x0f1d33, emissive: A, emissiveIntensity: 0.15 }));
    top.position.y = 0.19;
    platform.add(top);
    const ringMat = (c: THREE.Color, o = 0.9) => new THREE.MeshBasicMaterial({ color: c, transparent: true, opacity: o, blending: THREE.AdditiveBlending, depthWrite: false });
    const rings: THREE.Mesh[] = [];
    [[2.32, 0.025, 0.95], [1.75, 0.018, 0.55], [1.25, 0.014, 0.45]].forEach(([r, t, o], i) => {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(r, t, 8, 120, i === 1 ? Math.PI * 1.6 : Math.PI * 2), ringMat(A, o));
      ring.rotation.x = Math.PI / 2;
      ring.position.y = 0.23;
      platform.add(ring);
      rings.push(ring);
    });
    // Progress arc: fills as stations are cleared.
    const arcMat = ringMat(GREEN, 1);
    const arc = new THREE.Mesh(new THREE.TorusGeometry(2.05, 0.05, 8, 160, 0.0001), arcMat);
    arc.rotation.x = Math.PI / 2;
    arc.position.y = 0.24;
    platform.add(arc);
    let arcShown = -1;
    const floorGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }));
    floorGlow.scale.set(6.5, 1.6, 1);
    floorGlow.position.y = 0.3;
    platform.add(floorGlow);

    // ── Projector beam ──
    const beam = new THREE.Mesh(
      new THREE.CylinderGeometry(1.25, 1.95, 3.4, 64, 1, true),
      new THREE.MeshBasicMaterial({ color: A, transparent: true, opacity: 0.05, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false }),
    );
    beam.position.y = -0.3;
    scene.add(beam);

    // ── Shield ──
    const shield = new THREE.Group();
    scene.add(shield);
    const depth = 0.26;
    const geo = new THREE.ExtrudeGeometry(shieldShape(), { depth, bevelEnabled: true, bevelThickness: 0.08, bevelSize: 0.07, bevelSegments: 4, curveSegments: 40 });
    geo.translate(0, 0, -depth / 2);
    const body = new THREE.Mesh(geo, new THREE.MeshPhysicalMaterial({
      color: 0x0b4f66, emissive: A, emissiveIntensity: 0.28, metalness: 0.35, roughness: 0.18,
      transparent: true, opacity: 0.62, clearcoat: 1, clearcoatRoughness: 0.15,
    }));
    shield.add(body);
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo, 35), new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0.95 }));
    shield.add(edges);
    const zFront = depth / 2 + 0.09;
    const outlineLine = (scale: number, color: THREE.Color, opacity: number) => {
      const pts = shieldShape(scale).getPoints(80).map(v => new THREE.Vector3(v.x, v.y, zFront + 0.005));
      const l = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({ color, transparent: true, opacity }));
      shield.add(l);
      return l;
    };
    outlineLine(0.86, A, 0.9);
    outlineLine(0.8, B, 0.45);
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending, depthWrite: false }));
    halo.scale.set(6.2, 6.8, 1);
    halo.position.z = -0.4;
    shield.add(halo);

    // Network constellation inside the inner outline.
    const poly = shieldShape(0.74).getPoints(60);
    const rand = rng(7);
    const nodes: THREE.Vector3[] = [];
    for (let guard = 0; nodes.length < NODE_COUNT && guard < 4000; guard++) {
      const x = (rand() * 2 - 1) * 1.05, y = rand() * 2.6 - 1.25;
      if (!inside(poly, x, y)) continue;
      if (nodes.some(n => Math.hypot(n.x - x, n.y - y) < 0.3)) continue;
      nodes.push(new THREE.Vector3(x, y, zFront + 0.01));
    }
    // Light order: from the base of the shield upwards, like charging.
    const order = nodes.map((_, i) => i).sort((a, b) => nodes[a].y - nodes[b].y);
    const rank = new Map(order.map((idx, r) => [idx, r]));
    const linkPts: number[] = [];
    const linkCol: number[] = [];
    const links: [number, number][] = [];
    nodes.forEach((a, i) => nodes.forEach((b, j) => {
      if (j <= i || a.distanceTo(b) > 0.62) return;
      links.push([i, j]);
      linkPts.push(a.x, a.y, a.z, b.x, b.y, b.z);
      linkCol.push(0, 0, 0, 0, 0, 0);
    }));
    const linkGeo = new THREE.BufferGeometry();
    linkGeo.setAttribute("position", new THREE.Float32BufferAttribute(linkPts, 3));
    linkGeo.setAttribute("color", new THREE.Float32BufferAttribute(linkCol, 3));
    shield.add(new THREE.LineSegments(linkGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false })));
    const nodeSprites = nodes.map(n => {
      const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x475569, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
      sp.position.copy(n);
      sp.scale.setScalar(0.16);
      shield.add(sp);
      return sp;
    });

    const DIM = new THREE.Color(0x1e293b), LIT = new THREE.Color().copy(A).lerp(new THREE.Color(0xffffff), 0.35);
    let litShown = -1;
    function applyProgress(pr: number) {
      // A few nodes always glow so a fresh mission still reads as a live shield.
      const lit = Math.round(4 + (NODE_COUNT - 4) * pr);
      if (lit !== litShown) {
        litShown = lit;
        nodeSprites.forEach((sp, i) => {
          const on = rank.get(i)! < lit;
          sp.material.color.copy(on ? LIT : DIM);
          sp.scale.setScalar(on ? 0.2 : 0.12);
        });
        const col = linkGeo.getAttribute("color") as THREE.BufferAttribute;
        links.forEach(([i, j], k) => {
          const on = rank.get(i)! < lit && rank.get(j)! < lit;
          const c = on ? A : DIM;
          col.setXYZ(k * 2, c.r, c.g, c.b);
          col.setXYZ(k * 2 + 1, c.r, c.g, c.b);
        });
        col.needsUpdate = true;
      }
      if (Math.abs(pr - arcShown) > 1e-3) {
        arcShown = pr;
        arc.geometry.dispose();
        arc.geometry = new THREE.TorusGeometry(2.05, 0.05, 8, 160, Math.max(0.0001, pr * Math.PI * 2));
        arc.rotation.z = Math.PI / 2;
      }
    }

    // ── Rising particles ──
    const P = 140;
    const partPos = new Float32Array(P * 3);
    const speed = new Float32Array(P);
    const pr2 = rng(11);
    for (let i = 0; i < P; i++) {
      const a = pr2() * Math.PI * 2, r = 0.4 + pr2() * 1.6;
      partPos.set([Math.cos(a) * r, -1.8 + pr2() * 3.6, Math.sin(a) * r], i * 3);
      speed[i] = 0.15 + pr2() * 0.35;
    }
    const partGeo = new THREE.BufferGeometry();
    partGeo.setAttribute("position", new THREE.BufferAttribute(partPos, 3));
    const particles = new THREE.Points(partGeo, new THREE.PointsMaterial({ map: glow, color: A, size: 0.09, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending, depthWrite: false }));
    scene.add(particles);

    // ── Fit + pointer parallax ──
    const resize = () => {
      const w = mount.clientWidth, h = mount.clientHeight;
      if (!w || !h) return;
      renderer.setSize(w, h);
      camera.aspect = w / h;
      // Keep the whole rig (about 5.6 units tall, 5.4 wide) in frame.
      const half = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2));
      const dist = Math.max(2.75 / half, 2.9 / (half * camera.aspect));
      camera.position.set(0, 1.1, dist);
      camera.lookAt(0, -0.25, 0);
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    resize();
    const pointer = { x: 0, y: 0 };
    const onMove = (e: PointerEvent) => {
      pointer.x = (e.clientX / window.innerWidth) * 2 - 1;
      pointer.y = (e.clientY / window.innerHeight) * 2 - 1;
    };
    window.addEventListener("pointermove", onMove);

    const clock = new THREE.Clock();
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      const dt = Math.min(clock.getDelta(), 0.1);
      const t = clock.elapsedTime;
      const { progress: pr, reducedMotion: rm } = live.current;
      applyProgress(Math.min(1, Math.max(0, pr)));
      if (!rm) {
        shield.position.y = 0.25 + Math.sin(t * 1.3) * 0.08;
        shield.rotation.y += ((Math.sin(t * 0.35) * 0.45 + pointer.x * 0.25) - shield.rotation.y) * Math.min(1, dt * 3);
        shield.rotation.x += ((pointer.y * 0.08) - shield.rotation.x) * Math.min(1, dt * 3);
        rings[0].rotation.z += dt * 0.15;
        rings[1].rotation.z -= dt * 0.4;
        rings[2].rotation.z += dt * 0.25;
        globe.rotation.y += dt * 0.05;
        halo.material.opacity = 0.34 + Math.sin(t * 2) * 0.08;
        for (let i = 0; i < P; i++) {
          let y = partPos[i * 3 + 1] + speed[i] * dt;
          if (y > 2.1) y = -1.8;
          partPos[i * 3 + 1] = y;
        }
        partGeo.getAttribute("position").needsUpdate = true;
      } else {
        shield.position.y = 0.25;
      }
      renderer.render(scene, camera);
    };
    loop();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener("pointermove", onMove);
      scene.traverse(obj => {
        const m = obj as THREE.Mesh;
        m.geometry?.dispose();
        const mat = m.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach(x => x.dispose()); else mat?.dispose();
      });
      glow.dispose();
      renderer.dispose();
      mount.removeChild(renderer.domElement);
    };
  }, [primary, secondary]);

  return (
    <div className="absolute inset-0 transition-[filter] duration-700" style={{ filter: dimmed ? "blur(6px) brightness(0.4)" : "none" }} aria-hidden>
      <div ref={mountRef} className="absolute inset-0" />
    </div>
  );
}
