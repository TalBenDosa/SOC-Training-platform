"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The zone wall": the internet on the left, an outer firewall wall, a DMZ
 * platform with a shielded web server, an inner firewall wall, and inside, a
 * row of VLAN islands behind glass partitions. Packets fly at the walls:
 * allowed ones pass through green, denied ones bounce back red. A copy line
 * runs from the outer wall to an IDS eye. One island turns red and its glass
 * holds. Finally a scanner probe sweeps the outer wall with SYN darts. Stations
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

export default function ZoneWallScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const OK = new THREE.Color(0x34d399);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x080604, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xffedd5, 0x080604, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x431407, 0x1a0f08));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3b2f26, emissive: 0x120a05, metalness: 0.55, roughness: 0.4 });

    // the internet cloud
    const cloud = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: 0x94a3b8, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending, depthWrite: false }));
    cloud.scale.set(6, 4, 1);
    cloud.position.set(-14, 3, 0);
    scene.add(cloud);
    const netLab = tag("INTERNET", "#e2e8f0", 220); netLab.position.set(-14, 5.6, 0); scene.add(netLab);

    // ── 1 the walls: outer and inner firewall ──
    const wall = (x: number) => {
      const mat = additive(A, 0.08);
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.3, 4, 9), mat);
      m.position.set(x, 2, 0);
      scene.add(m);
      return mat;
    };
    const outer = wall(-9), inner = wall(-1);
    const fwLab = tag("FIREWALL", "#fed7aa", 220); fwLab.position.set(-9, 4.7, 0); scene.add(fwLab);
    const packets = Array.from({ length: 8 }, (_, i) => {
      const mat = new THREE.SpriteMaterial({ map: glow, color: i % 3 === 0 ? Wn : OK, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
      const s = new THREE.Sprite(mat);
      s.scale.set(0.6, 0.6, 1);
      scene.add(s);
      return { s, mat, deny: i % 3 === 0, o: i / 8, z: -3 + (i % 4) * 2 };
    });

    // ── 2 the DMZ: web server, WAF shield, IDS eye on a copy line ──
    const dmz = new THREE.Mesh(new THREE.BoxGeometry(6, 0.2, 7), metal());
    dmz.position.set(-5, 0.1, 0);
    scene.add(dmz);
    const dmzLab = tag("DMZ", "#fed7aa", 120); dmzLab.position.set(-5, 0.8, 3.2); scene.add(dmzLab);
    const web = new THREE.Mesh(new THREE.BoxGeometry(1.2, 2.2, 1.2), metal());
    web.position.set(-5, 1.3, -1);
    scene.add(web);
    const wafMat = additive(B, 0);
    const waf = new THREE.Mesh(new THREE.CircleGeometry(1.1, 6), wafMat);
    waf.position.set(-6.2, 1.5, -1);
    waf.rotation.y = -Math.PI / 2;
    scene.add(waf);
    const wafLab = tag("WAF", "#a5f3fc", 120); wafLab.position.set(-6.2, 3, -1); scene.add(wafLab);
    const eyeMat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0, transparent: true, opacity: 0.3 });
    const eye = new THREE.Mesh(new THREE.SphereGeometry(0.6, 20, 14), eyeMat);
    eye.position.set(-5, 1.2, 2.2);
    scene.add(eye);
    const idsLab = tag("IDS", "#a5f3fc", 120); idsLab.position.set(-5, 2.3, 2.2); scene.add(idsLab);
    const copyMat = new THREE.LineDashedMaterial({ color: B, dashSize: 0.3, gapSize: 0.2, transparent: true, opacity: 0 });
    const copy = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-9, 1.2, 2.2), new THREE.Vector3(-5.6, 1.2, 2.2)]), copyMat);
    copy.computeLineDistances();
    scene.add(copy);

    // ── 3 the VLAN islands behind glass ──
    const islands = ["SERVERS", "STAFF", "IOT", "GUEST"].map((n, i) => {
      const mat = new THREE.MeshStandardMaterial({ color: 0x3b2f26, emissive: i === 2 ? Wn : A, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(2.6, 0.4, 2.6), mat);
      m.position.set(2.5 + (i % 2) * 3.6, 0.2, -2 + Math.floor(i / 2) * 4);
      scene.add(m);
      const l = tag(n, "#fed7aa", 180);
      l.position.set(m.position.x, 1.1, m.position.z);
      scene.add(l);
      return { m, mat };
    });
    const glassMat = new THREE.MeshStandardMaterial({ color: B, transparent: true, opacity: 0, side: THREE.DoubleSide });
    const glassX = new THREE.Mesh(new THREE.PlaneGeometry(7, 2), glassMat);
    glassX.position.set(4.3, 1, 0);
    scene.add(glassX);
    const glassZ = new THREE.Mesh(new THREE.PlaneGeometry(8, 2), glassMat);
    glassZ.position.set(4.3, 1, 0);
    glassZ.rotation.y = Math.PI / 2;
    scene.add(glassZ);
    const bounce = Array.from({ length: 5 }, () => {
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0.45, 0.45, 1);
      scene.add(s);
      return s;
    });

    // ── 4 the scanner and its SYN darts ──
    const probeMat = new THREE.MeshStandardMaterial({ color: Wn, emissive: Wn, emissiveIntensity: 0.5, transparent: true, opacity: 0 });
    const probe = new THREE.Mesh(new THREE.ConeGeometry(0.5, 1.2, 4), probeMat);
    probe.rotation.z = -Math.PI / 2;
    scene.add(probe);
    const darts = Array.from({ length: 6 }, (_, i) => {
      const mat = new THREE.MeshBasicMaterial({ color: Wn, transparent: true, opacity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.06, 0.06), mat);
      scene.add(m);
      return { m, mat, z: -3.5 + i * 1.4 };
    });
    const synLab = tag("SYN SYN SYN", "#fecdd3", 260);
    scene.add(synLab);

    const anchors = [new THREE.Vector3(-9, 5.8, -2), new THREE.Vector3(-5, 4.4, -1), new THREE.Vector3(4.3, 3.2, 0), new THREE.Vector3(-13, 7.4, -3)];
    const level = [0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 70 : asp < 1.5 ? 32 : 27; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 4; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist - 3, dist * (portrait ? 0.6 : 0.45) + 1, Math.cos(yaw) * dist + 5);
      camera.lookAt(-3, 1.6, 0);

      // 1 walls glow; packets fly in: allowed ones pass both walls, denied ones bounce at the outer wall
      outer.opacity = 0.08 + level[0] * 0.6;
      inner.opacity = 0.08 + level[0] * 0.6;
      const pk = Math.max(level[0], stations[0]?.status === "open" ? 0.5 : 0);
      packets.forEach(p => {
        const u = rm ? p.o : ((t * 0.18 + p.o) % 1);
        let x: number;
        if (p.deny) x = u < 0.5 ? -14 + u * 2 * 4.8 : -9.2 - (u - 0.5) * 2 * 4.8;
        else x = -14 + u * 16;
        p.s.position.set(x, 1.4 + (p.z > 0 ? 0.6 : 0), p.z);
        p.mat.opacity = pk * 0.9;
      });
      // 2 the DMZ, WAF and IDS
      wafMat.opacity = level[1] * (rm ? 0.6 : 0.35 + pulse * 0.3);
      eyeMat.opacity = 0.3 + level[1] * 0.6;
      eyeMat.emissiveIntensity = level[1] * 0.8;
      copyMat.opacity = level[1] * 0.9;
      // 3 the IoT island goes red; the glass holds and its probes bounce
      islands.forEach((is, i) => { is.mat.emissiveIntensity = i === 2 ? level[2] * (rm ? 0.8 : 0.5 + pulse * 0.4) : level[2] * 0.18; });
      glassMat.opacity = level[2] * 0.25;
      const src = islands[2].m.position;
      bounce.forEach((b, i) => {
        const u = rm ? 0.5 : ((t * 0.6 + i / 5) % 1);
        const dir = i % 2 ? new THREE.Vector3(0, 0, -1) : new THREE.Vector3(1, 0, 0);
        const d = u < 0.5 ? u * 2 : 2 - u * 2;
        b.position.set(src.x + dir.x * d * 1.8, 0.8, src.z + dir.z * d * 2);
        (b.material as THREE.SpriteMaterial).opacity = level[2] * 0.9;
      });
      // 4 the scanner sweeps the outer wall with SYN darts that never complete
      const sweep = rm ? 0 : Math.sin(t * 0.8) * 3;
      probe.position.set(-13, 2, sweep);
      probeMat.opacity = Math.max(level[3], stations[3]?.status === "open" ? 0.4 : 0);
      darts.forEach((d, i) => {
        const u = rm ? 0.5 : ((t * 0.9 + i / 6) % 1);
        d.m.position.set(-12.4 + u * 3.1, 2, d.z);
        d.mat.opacity = probeMat.opacity * (1 - u) * 0.9;
      });
      synLab.position.set(-13, 3.2, sweep);
      (synLab.material as THREE.SpriteMaterial).opacity = probeMat.opacity;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140c06]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
