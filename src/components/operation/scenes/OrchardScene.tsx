"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The orchard": a Mac's security model laid out on a floor. A Unix core cube;
 * two doors in (a DMG disc and a PKG crate whose script line runs off to a
 * server); a Gatekeeper arch that downloads pass through wearing quarantine
 * tags, with three seals beside it (Developer ID gold, ad-hoc grey, revoked
 * red); a fake password dialog beside a Keychain vault that leaks items; a row
 * of TCC consent toggles, one flipped red; and a launchd tree whose branches
 * carry agents and daemons, one fruit glowing red. Stations switch each part
 * on. Decorative only.
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

export default function OrchardScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x06070a, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xf1f5f9, 0x06070a, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x1e293b, 0x0f1520));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x2b3240, emissive: 0x0a0d13, metalness: 0.6, roughness: 0.35 });
    const lab = (t: string, c: string, p: THREE.Vector3, w = 200) => { const s = tag(t, c, w); s.position.copy(p); scene.add(s); return s; };

    // ── 1 the Unix core ──
    const coreMat = new THREE.MeshStandardMaterial({ color: 0x2b3240, emissive: A, emissiveIntensity: 0, metalness: 0.5, roughness: 0.3 });
    const core = new THREE.Mesh(new THREE.BoxGeometry(1.6, 1.6, 1.6), coreMat);
    core.position.set(-12, 1.2, 0);
    scene.add(core);
    const ringMat = additive(B, 0);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.6, 0.04, 8, 48), ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.set(-12, 1.2, 0);
    scene.add(ring);
    lab("XNU", "#e2e8f0", new THREE.Vector3(-12, 2.6, 0), 120);

    // ── 2 two doors: DMG and PKG ──
    const dmg = new THREE.Mesh(new THREE.CylinderGeometry(0.9, 0.9, 0.25, 32), metal());
    dmg.position.set(-7.5, 0.6, -1.4);
    scene.add(dmg);
    lab("DMG", "#bfdbfe", new THREE.Vector3(-7.5, 1.4, -1.4), 100);
    const pkg = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.1, 1.1), metal());
    pkg.position.set(-7.5, 0.55, 1.4);
    scene.add(pkg);
    lab("PKG", "#bfdbfe", new THREE.Vector3(-7.5, 1.6, 1.4), 100);
    const scriptMat = new THREE.LineDashedMaterial({ color: Wn, dashSize: 0.25, gapSize: 0.15, transparent: true, opacity: 0 });
    const script = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-7.5, 1.1, 1.4), new THREE.Vector3(-6, 4, 3), new THREE.Vector3(-4.5, 5, 3.5)]), scriptMat);
    script.computeLineDistances();
    scene.add(script);

    // ── 3 Gatekeeper arch, quarantine-tagged parcels, three seals ──
    const arch = new THREE.Mesh(new THREE.TorusGeometry(1.6, 0.18, 10, 40, Math.PI), metal());
    arch.position.set(-2.5, 0, 0);
    scene.add(arch);
    const archMat = additive(A, 0);
    const archGlow = new THREE.Mesh(new THREE.TorusGeometry(1.6, 0.06, 8, 40, Math.PI), archMat);
    archGlow.position.set(-2.5, 0, 0.05);
    scene.add(archGlow);
    lab("GATEKEEPER", "#e2e8f0", new THREE.Vector3(-2.5, 2.2, 0), 240);
    const parcels = Array.from({ length: 4 }, (_, i) => {
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.4, 0.4, 0.4), new THREE.MeshStandardMaterial({ color: 0x94a3b8, transparent: true, opacity: 0 }));
      scene.add(m);
      return { m, o: i / 4 };
    });
    const seals = [[0xfbbf24, "DEV ID"], [0x94a3b8, "AD-HOC"], [0xf43f5e, "REVOKED"]].map(([c, n], i) => {
      const mat = new THREE.MeshStandardMaterial({ color: c as number, emissive: c as number, emissiveIntensity: 0, metalness: 0.7, roughness: 0.3, transparent: true, opacity: 0.3 });
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.4, 0.4, 0.08, 24), mat);
      m.rotation.x = Math.PI / 2;
      m.position.set(-0.4, 0.6 + i * 1, -1.6);
      scene.add(m);
      const l = lab(n as string, "#e2e8f0", new THREE.Vector3(0.9, 0.6 + i * 1, -1.6), 180);
      (l.material as THREE.SpriteMaterial).opacity = 0;
      return { mat, l: l.material as THREE.SpriteMaterial };
    });

    // ── 4 a fake dialog and the Keychain vault ──
    const dlgMat = new THREE.MeshStandardMaterial({ color: 0xe2e8f0, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.15 });
    const dlg = new THREE.Mesh(new THREE.BoxGeometry(2, 1.2, 0.06), dlgMat);
    dlg.position.set(3, 2.4, 0.6);
    scene.add(dlg);
    const pw = lab("password: ••••••", "#0f172a", new THREE.Vector3(3, 2.4, 1.1), 260);
    (pw.material as THREE.SpriteMaterial).opacity = 0;
    const vault = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.4, 1.4), metal());
    vault.position.set(3.4, 0.7, -1.4);
    scene.add(vault);
    lab("KEYCHAIN", "#e2e8f0", new THREE.Vector3(3.4, 1.8, -1.4), 200);
    const leaks = Array.from({ length: 6 }, (_, i) => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.3, 0.3, 1);
      scene.add(s);
      return { s, o: i / 6 };
    });

    // ── 5 TCC toggles ──
    const toggles = ["MIC", "CAMERA", "SCREEN", "ACCESS", "DISK"].map((n, i) => {
      const bad = n === "ACCESS";
      const mat = new THREE.MeshStandardMaterial({ color: 0x2b3240, emissive: bad ? Wn : 0x34d399, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.CapsuleGeometry(0.22, 0.6, 6, 12), mat);
      m.rotation.z = Math.PI / 2;
      m.position.set(7, 0.5 + i * 0.75, 0);
      scene.add(m);
      const l = lab(n, "#e2e8f0", new THREE.Vector3(8.3, 0.5 + i * 0.75, 0), 160);
      (l.material as THREE.SpriteMaterial).opacity = 0;
      return { mat, l: l.material as THREE.SpriteMaterial };
    });
    lab("TCC", "#e2e8f0", new THREE.Vector3(7, 4.4, 0), 100);

    // ── 6 the launchd tree ──
    const trunk = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.35, 4, 10), metal());
    trunk.position.set(12, 2, 0);
    scene.add(trunk);
    lab("launchd", "#e2e8f0", new THREE.Vector3(12, 4.9, 0), 160);
    const fruit = [[-1.2, 3.4, 0, false], [1.2, 3.6, 0.3, false], [-0.9, 2.5, -0.6, false], [1, 2.4, 0.8, true]].map(([dx, y, dz, bad]) => {
      const tip = new THREE.Vector3(12 + (dx as number), y as number, dz as number);
      scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(12, (y as number) - 0.6, 0), tip]), new THREE.LineBasicMaterial({ color: 0x64748b })));
      const mat = new THREE.MeshStandardMaterial({ color: bad ? Wn : B, emissive: bad ? Wn : B, emissiveIntensity: 0, transparent: true, opacity: 0.25 });
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.28, 16, 12), mat);
      m.position.copy(tip);
      scene.add(m);
      return { mat, bad: bad as boolean };
    });

    const anchors = [new THREE.Vector3(-12, 3.6, 0), new THREE.Vector3(-7.5, 2.9, 0), new THREE.Vector3(-1.6, 4.2, -1), new THREE.Vector3(3.2, 4, 0), new THREE.Vector3(7.4, 5.4, 0), new THREE.Vector3(12, 6, 0)];
    const level = [0, 0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 29, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 76 : asp < 1.5 ? 34 : 29; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 6; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(0, 2, 0);

      // 1 core
      coreMat.emissiveIntensity = level[0] * 0.5;
      ringMat.opacity = level[0] * 0.8;
      if (!rm) ring.rotation.z += dt * 0.6;
      // 2 the PKG's script line reaches out
      scriptMat.opacity = level[1] * 0.9;
      if (!rm) dmg.rotation.y += dt * 0.8 * (0.2 + level[1]);
      // 3 parcels walk through the arch; seals light one by one
      archMat.opacity = level[2] * (rm ? 0.8 : 0.5 + pulse * 0.4);
      parcels.forEach(p => {
        const u = rm ? p.o : ((t * 0.25 + p.o) % 1);
        p.m.position.set(-5.5 + u * 6, 0.25, 0);
        (p.m.material as THREE.MeshStandardMaterial).opacity = level[2] * 0.9;
      });
      seals.forEach((s, i) => {
        const v = THREE.MathUtils.clamp(level[2] * 3 - i, 0, 1);
        s.mat.opacity = 0.3 + v * 0.7;
        s.mat.emissiveIntensity = v * 0.5;
        s.l.opacity = v;
      });
      // 4 the fake dialog glows; the vault leaks
      dlgMat.opacity = 0.15 + level[3] * 0.8;
      dlgMat.emissiveIntensity = level[3] * 0.25;
      (pw.material as THREE.SpriteMaterial).opacity = level[3];
      leaks.forEach(l => {
        const u = rm ? l.o : ((t * 0.3 + l.o) % 1);
        l.s.position.set(3.4 + u * 2.4, 1.2 + u * 2.2, -1.4 + Math.sin(u * 6 + l.o * 9) * 0.4);
        (l.s.material as THREE.SpriteMaterial).opacity = level[3] * (1 - u) * 0.9;
      });
      // 5 toggles switch on, one red
      toggles.forEach((g, i) => {
        const v = THREE.MathUtils.clamp(level[4] * 5 - i, 0, 1);
        g.mat.emissiveIntensity = v * 0.7;
        g.l.opacity = v;
      });
      // 6 fruit ripens; the bad one pulses
      fruit.forEach((f, i) => {
        const v = THREE.MathUtils.clamp(level[5] * 4 - i, 0, 1);
        f.mat.opacity = 0.25 + v * 0.7;
        f.mat.emissiveIntensity = v * (f.bad ? (rm ? 0.8 : 0.5 + pulse * 0.4) : 0.4);
      });

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
            <span className="block whitespace-nowrap rounded-md border bg-[#0b0e14]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
