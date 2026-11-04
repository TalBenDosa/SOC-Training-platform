"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "Matrix wall": a curved wall of fifteen tactic columns, each a stack of
 * technique tiles. A decoder ring in front reads an ID; the column headers
 * light as the tactics are learned; a coverage layer then paints most tiles
 * and leaves a few dark gaps that pulse; one alert tile flies onto the wall;
 * finally a chain of lit tiles across columns traces a whole intrusion.
 * Stations switch each part on. Decorative only.
 */
const TACTICS = ["RECON", "RESOURCE", "INIT ACCESS", "EXECUTION", "PERSIST", "PRIV ESC", "STEALTH", "IMPAIR", "CRED ACCESS", "DISCOVERY", "LATERAL", "COLLECT", "C2", "EXFIL", "IMPACT"];
// tiles left dark by the coverage layer
const GAPS = new Set(["9-1", "10-2", "6-3", "12-1"]);
// tiles that the intrusion chain lights, in order
const CHAIN = [[2, 0], [3, 1], [8, 0], [9, 1], [10, 2], [11, 0], [13, 1]];

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

export default function MatrixWallScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0505, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xfee2e2, 0x0a0505, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x3f1d1d, 0x140909));

    // the curved wall: column i sits on an arc
    const R = 16, SPAN = 1.6;
    const colPos = (i: number) => {
      const a = ((i - 7) / 7) * (SPAN / 2);
      return { x: Math.sin(a) * R, z: -Math.cos(a) * R + R - 4, ry: -a };
    };
    const headers: THREE.SpriteMaterial[] = [];
    const tiles: { mat: THREE.MeshStandardMaterial; key: string; col: number; row: number }[] = [];
    TACTICS.forEach((n, i) => {
      const p = colPos(i);
      const h = tag(n, "#fecaca", 220);
      h.scale.multiplyScalar(0.7);
      h.position.set(p.x, 5.3, p.z);
      scene.add(h);
      headers.push(h.material as THREE.SpriteMaterial);
      for (let r = 0; r < 4; r++) {
        const mat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.04, transparent: true, opacity: 0.3 });
        const m = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.8, 0.08), mat);
        m.position.set(p.x, 4.3 - r * 1.0, p.z);
        m.rotation.y = p.ry;
        scene.add(m);
        tiles.push({ mat, key: `${i}-${r}`, col: i, row: r });
      }
    });

    // ── 1 the decoder ring ──
    const decMat = additive(A, 0.05);
    const dec = new THREE.Mesh(new THREE.TorusGeometry(1.2, 0.08, 8, 48), decMat);
    dec.position.set(-6, 1.4, 6);
    scene.add(dec);
    const decL = tag("T1021.001", "#fecaca", 220); decL.position.set(-6, 1.4, 6.05); scene.add(decL);

    // ── 4 the alert tile that flies onto the wall ──
    const alertMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.5, transparent: true, opacity: 0 });
    const alertTile = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.8, 0.08), alertMat);
    scene.add(alertTile);
    const alertFrom = new THREE.Vector3(6, 1.2, 6);
    const tgt = colPos(8);
    const alertTo = new THREE.Vector3(tgt.x, 4.3, tgt.z + 0.15);

    // ── 5 the intrusion chain ──
    const chainPts = CHAIN.map(([c, r]) => { const p = colPos(c); return new THREE.Vector3(p.x, 4.3 - r, p.z + 0.2); });
    const chainMat = new THREE.LineBasicMaterial({ color: A, transparent: true, opacity: 0 });
    const chainGeo = new THREE.BufferGeometry().setFromPoints(chainPts);
    const chain = new THREE.Line(chainGeo, chainMat);
    scene.add(chain);

    const anchors = [new THREE.Vector3(-6, 3, 6), new THREE.Vector3(-8, 6.6, -1), new THREE.Vector3(1, 6.6, -1.8), new THREE.Vector3(6, 2.6, 6), new THREE.Vector3(8.5, 6.6, -1)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 24, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 72 : asp < 1.5 ? 29 : 24; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.06) * 0.15;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.4 : 0.28) + 3, Math.cos(yaw) * dist + 4);
      camera.lookAt(0, 3, 0);

      // 1 the decoder spins
      decMat.opacity = 0.05 + level[0] * 0.85;
      if (!rm) dec.rotation.z += dt * 0.8 * level[0];
      (decL.material as THREE.SpriteMaterial).opacity = 0.2 + level[0] * 0.8;
      // 2 headers light left to right
      headers.forEach((m, i) => { m.opacity = 0.15 + THREE.MathUtils.clamp(level[1] * 15 - i, 0, 1) * 0.85; });
      // 3 coverage paints tiles; gaps stay dark and pulse
      const chainLit = new Set(CHAIN.slice(0, Math.round(level[4] * CHAIN.length)).map(([c, r]) => `${c}-${r}`));
      tiles.forEach(tl => {
        const gap = GAPS.has(tl.key);
        if (chainLit.has(tl.key)) {
          tl.mat.color.copy(A); tl.mat.emissive.copy(A);
          tl.mat.opacity = 0.95; tl.mat.emissiveIntensity = 0.6;
        } else if (gap) {
          tl.mat.color.copy(Wn); tl.mat.emissive.copy(Wn);
          tl.mat.opacity = 0.3 + level[2] * 0.4;
          tl.mat.emissiveIntensity = level[2] * (rm ? 0.3 : 0.1 + pulse * 0.4);
        } else {
          tl.mat.color.copy(B); tl.mat.emissive.copy(B);
          tl.mat.opacity = 0.3 + level[2] * 0.5;
          tl.mat.emissiveIntensity = 0.04 + level[2] * 0.2;
        }
      });
      // 4 the alert tile flies to Credential Access
      alertMat.opacity = level[3] > 0.02 ? Math.min(1, level[3] * 2) : 0;
      alertTile.position.lerpVectors(alertFrom, alertTo, level[3]);
      alertTile.rotation.y = (1 - level[3]) * 1.5 + level[3] * tgt.ry;
      // 5 the chain line
      chainMat.opacity = level[4] * 0.95;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140808]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
