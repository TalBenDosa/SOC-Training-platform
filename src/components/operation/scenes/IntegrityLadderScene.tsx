"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Integrity ladder": four stacked glass decks (LOW, MEDIUM, HIGH, SYSTEM) and
 * a process orb that climbs them. Around the stack: an LSASS vault on the top
 * deck with a probing beam, a rewritten handler key on the Medium deck with a
 * bypass arc to High, an impersonation mask and a service path with spaces
 * that bridge to SYSTEM, and a verdict ring around the whole climb.
 * Stations switch each part on. Decorative only.
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

export default function IntegrityLadderScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x08040a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfce7f3, 0x08040a, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x4a1d3a, 0x170a14));
    const floor = circuitFloor(A, 44); scene.add(floor.mesh);
    const kitRack = serverRack(B, 8, "DISP-DESK-11"); kitRack.group.position.set(-6.4, 0, 2.6); kitRack.group.rotation.y = 0.5; scene.add(kitRack.group);
    const kitTerm = terminal(["C:\\> whoami /priv", "SeImpersonatePrivilege  Enabled", "SeChangeNotifyPrivilege Enabled"], B, 1.8, 1.05); kitTerm.group.position.set(5.6, 0, 3.2); kitTerm.group.rotation.y = -0.5; scene.add(kitTerm.group);
    const kitLock = padlock(Wn, 0.8); kitLock.group.position.set(1.8, 0.3 + 3 * 2.2 + 1.7, -0.8); scene.add(kitLock.group);
    const kitShield = shield(A, "check", 0.9); kitShield.group.position.set(-3.6, 0.3 + 3 * 2.2 + 1.6, 1.4); scene.add(kitShield.group);
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3f3346, emissive: 0x0c070e, metalness: 0.55, roughness: 0.4 });

    // ── 1 four decks ──
    const DY = 2.2;
    const deckMats = ["LOW", "MEDIUM", "HIGH", "SYSTEM"].map((n, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.05, transparent: true, opacity: 0.12, depthWrite: false });
      const d = new THREE.Mesh(new THREE.BoxGeometry(6, 0.12, 4), mat);
      d.position.set(0, 0.3 + i * DY, 0);
      scene.add(d);
      const l = tag(n, "#bfdbfe", 180);
      l.position.set(-3.8, 0.6 + i * DY, 1.8);
      scene.add(l);
      return mat;
    });
    [-2.9, 2.9].forEach(x => [-1.9, 1.9].forEach(z => {
      const p = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, DY * 3 + 0.4, 6), metal());
      p.position.set(x, 0.3 + DY * 1.5, z);
      scene.add(p);
    }));
    const orbMat = new THREE.MeshStandardMaterial({ color: A, emissive: A, emissiveIntensity: 0.6 });
    const orb = new THREE.Mesh(new THREE.SphereGeometry(0.32, 20, 14), orbMat);
    scene.add(orb);

    // ── 2 the LSASS vault and its probe ──
    const vault = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.2, 1.4), metal());
    vault.position.set(1.8, 0.3 + 3 * DY + 0.66, -0.8);
    scene.add(vault);
    const vl = tag("lsass.exe", "#fde68a", 200); vl.position.set(1.8, vault.position.y + 1.1, -0.8); scene.add(vl);
    const probeMat = additive(Wn, 0);
    const probe = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1, 6), probeMat);
    scene.add(probe);

    // ── 3 the rewritten handler and the bypass arc ──
    const keyMat = additive(Wn, 0.05);
    const handler = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.7, 0.1), keyMat);
    handler.position.set(4.6, 0.3 + DY + 0.7, 0.6);
    handler.rotation.y = -0.4;
    scene.add(handler);
    const hl = tag("HKCU\\...\\command", "#fde68a", 300); hl.position.set(4.6, handler.position.y + 0.8, 0.6); scene.add(hl);
    const arcMat = new THREE.LineDashedMaterial({ color: Wn, dashSize: 0.2, gapSize: 0.12, transparent: true, opacity: 0 });
    const arcPts = new THREE.QuadraticBezierCurve3(new THREE.Vector3(4.6, handler.position.y, 0.6), new THREE.Vector3(5.6, 0.3 + 2.5 * DY, 0.6), new THREE.Vector3(2.6, 0.3 + 2 * DY + 0.3, 0.6)).getPoints(30);
    const arc = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arcPts), arcMat);
    arc.computeLineDistances();
    scene.add(arc);

    // ── 4 the impersonation mask and the service path ──
    const maskMat = additive(B, 0.05);
    const mask = new THREE.Mesh(new THREE.TorusGeometry(0.5, 0.12, 8, 24, Math.PI), maskMat);
    mask.position.set(-4.8, 0.3 + 2 * DY + 0.6, -0.6);
    scene.add(mask);
    const ml = tag("SeImpersonate", "#bfdbfe", 240); ml.position.set(-6.6, mask.position.y + 0.3, -0.6); scene.add(ml);
    const pathMat = additive(Wn, 0.04);
    const segs = [0, 1, 2].map(i => {
      const s = new THREE.Mesh(new THREE.BoxGeometry(1.1, 0.25, 0.25), pathMat);
      s.position.set(-6.4 + i * 1.5, 0.3 + 3 * DY, -0.6);
      scene.add(s);
      return s;
    });
    const sp = tag("C:\\Rail Apps\\Signal Monitor", "#fde68a", 380); sp.position.set(-4.9, 0.3 + 3 * DY + 0.7, -0.6); scene.add(sp);

    // ── 5 the verdict ring ──
    const ringMat = additive(A, 0);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(4.6, 0.08, 8, 72), ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 0.3 + 1.5 * DY;
    scene.add(ring);

    const anchors = [new THREE.Vector3(0, 0.3 + DY * 0.5, 2.6), new THREE.Vector3(3.6, 0.3 + 3 * DY + 1.2, -0.8), new THREE.Vector3(5.6, 0.3 + DY + 1.9, 0.6), new THREE.Vector3(-5.6, 0.3 + 2 * DY + 0.2, -0.6), new THREE.Vector3(0, 0.3 + 1.5 * DY, 4.8)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 25, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 52 : asp < 1.5 ? 30 : 25; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }
      kitRack.tick(t, 0.4 + level[0] * 0.6, rm);
      kitTerm.screenMat.opacity = 0.3 + level[3] * 0.65;
      kitLock.setOpen(level[1]);
      kitShield.mat.opacity = 0.15 + level[4] * 0.85;
      floor.mat.opacity = 0.18 + level[4] * 0.25;

      const yaw = rm ? 0.3 : 0.3 + Math.sin(t * 0.07) * 0.25;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.45 : 0.32) + 4, Math.cos(yaw) * dist);
      camera.lookAt(0, 5.4, 0);

      // 1 decks light up as you learn to read them
      deckMats.forEach((m, i) => { m.opacity = 0.12 + level[0] * 0.18 + (i === 1 ? 0.06 : 0); m.emissiveIntensity = 0.05 + level[0] * 0.3; });
      // the orb climbs one deck per cleared station after the first
      const climb = Math.min(3, level[2] + level[3] * 2 * (level[3] > 0.5 ? 1 : 0.5) + level[0]);
      orb.position.set(0, 0.75 + climb * DY + (rm ? 0 : Math.sin(t * 2) * 0.08), 0);
      // 2 the probe reaches the vault
      probeMat.opacity = level[1] * (rm ? 0.8 : 0.4 + pulse * 0.5);
      const from = orb.position, to = vault.position;
      probe.position.copy(from).lerp(to, 0.5);
      probe.scale.y = from.distanceTo(to);
      probe.lookAt(to);
      probe.rotateX(Math.PI / 2);
      // 3 the handler glows and the arc draws to High
      keyMat.opacity = 0.05 + level[2] * 0.85;
      arcMat.opacity = level[2] * 0.9;
      // 4 the mask and the path segments
      maskMat.opacity = 0.05 + level[3] * 0.85;
      if (!rm) mask.rotation.y += dt * 0.6 * level[3];
      pathMat.opacity = 0.04 + level[3] * 0.8;
      segs.forEach((s, i) => { s.position.y = 0.3 + 3 * DY + (rm ? 0 : Math.sin(t * 2 + i) * 0.05 * level[3]); });
      // 5 the verdict ring closes around the climb
      ringMat.opacity = level[4] * 0.85;
      ring.scale.setScalar(1.4 - level[4] * 0.4);
      orbMat.emissiveIntensity = 0.6 + level[4] * 0.4;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#12070f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
