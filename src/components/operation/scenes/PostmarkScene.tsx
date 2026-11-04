"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The postmark": an envelope flies relay tower to relay tower, picking up a
 * Received stamp at each hop. At a checkpoint gate three seals (SPF, DKIM,
 * DMARC) press onto it while a DNS signpost answers with TXT records. A mail
 * thread hangs as a chain of message cards, one of them red with a hook. At
 * the end, a payment arrow heads for a bank vault and is stopped by a shield.
 * Stations switch each part on. Decorative only.
 */
function tag(text: string, color: string, w = 220) {
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

export default function PostmarkScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0703, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xfef3c7, 0x0a0703, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x422006, 0x1c1406));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3a3022, emissive: 0x100c05, metalness: 0.55, roughness: 0.4 });

    // ── 1 relay towers and the flying envelope ──
    const hops = [new THREE.Vector3(-13, 2.6, 1), new THREE.Vector3(-9.5, 3.4, -1), new THREE.Vector3(-6, 2.8, 1)];
    const towers = hops.map((p, i) => {
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.4, p.y, 10), metal());
      m.position.set(p.x, p.y / 2, p.z);
      scene.add(m);
      const mat = additive(A, 0);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(0.5, 0.05, 8, 24), mat);
      ring.position.copy(p).add(new THREE.Vector3(0, 0.3, 0));
      ring.rotation.x = Math.PI / 2;
      scene.add(ring);
      const l = tag(`hop ${i + 1}`, "#fde68a", 120);
      l.position.copy(p).add(new THREE.Vector3(0, 1, 0));
      scene.add(l);
      return mat;
    });
    const route = new THREE.CatmullRomCurve3([...hops.map(h => h.clone().add(new THREE.Vector3(0, 0.6, 0))), new THREE.Vector3(-2, 2.4, 0)]);
    const env = new THREE.Mesh(new THREE.BoxGeometry(0.9, 0.55, 0.05), new THREE.MeshStandardMaterial({ color: 0xfef3c7, emissive: A, emissiveIntensity: 0.2 }));
    scene.add(env);

    // ── 2 the checkpoint gate, three seals, and the DNS signpost ──
    const gate = new THREE.Mesh(new THREE.TorusGeometry(1.4, 0.15, 10, 40, Math.PI), metal());
    gate.position.set(-2, 0, 0);
    scene.add(gate);
    const seals = [["SPF", 0xf59e0b], ["DKIM", 0x38bdf8], ["DMARC", 0x34d399]].map(([n, c], i) => {
      const mat = new THREE.MeshStandardMaterial({ color: c as number, emissive: c as number, emissiveIntensity: 0, transparent: true, opacity: 0.25 });
      const m = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.32, 0.08, 20), mat);
      m.rotation.x = Math.PI / 2;
      m.position.set(-3 + i * 1, 3.4, 0.4);
      scene.add(m);
      const l = tag(n as string, `#${(c as number).toString(16).padStart(6, "0")}`, 140);
      l.position.set(-3 + i * 1, 4, 0.4);
      scene.add(l);
      return mat;
    });
    const post = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.08, 3.4, 8), metal());
    post.position.set(1.4, 1.7, -1.8);
    scene.add(post);
    const txts = ["v=spf1 ... -all", "p=quarantine", "k=rsa; p=MIIB..."].map((t2, i) => {
      const s = tag(t2, "#bae6fd", 300);
      s.position.set(2.9, 3 - i * 0.7, -1.8);
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return s.material as THREE.SpriteMaterial;
    });
    const dnsLab = tag("DNS TXT", "#bae6fd", 180); dnsLab.position.set(1.4, 3.8, -1.8); scene.add(dnsLab);

    // ── 3 the hijacked thread ──
    const cards = Array.from({ length: 5 }, (_, i) => {
      const bad = i === 4;
      const mat = new THREE.MeshStandardMaterial({ color: bad ? 0x3a1015 : 0x3a3022, emissive: bad ? Wn : A, emissiveIntensity: 0 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.8, 0.05), mat);
      m.position.set(5.2, 0.8 + i * 0.9, -0.5 - i * 0.12);
      scene.add(m);
      return { mat, bad };
    });
    const hookMat = additive(Wn, 0);
    const hook = new THREE.Mesh(new THREE.TorusGeometry(0.25, 0.05, 8, 20, Math.PI * 1.4), hookMat);
    hook.position.set(6.2, 4.6, -1);
    scene.add(hook);
    const thLab = tag("Re: Re: Re:", "#fde68a", 200); thLab.position.set(5.2, 5.6, -1); scene.add(thLab);

    // ── 4 the payment arrow, the vault and the shield ──
    const vault = new THREE.Mesh(new THREE.BoxGeometry(1.6, 1.6, 1.6), metal());
    vault.position.set(11.5, 0.8, 0);
    scene.add(vault);
    const vLab = tag("$ WIRE", "#fde68a", 140); vLab.position.set(11.5, 2, 0); scene.add(vLab);
    const payMat = new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const pay = new THREE.Sprite(payMat);
    pay.scale.set(0.6, 0.6, 1);
    scene.add(pay);
    const shieldMat = additive(B, 0);
    const shield = new THREE.Mesh(new THREE.CircleGeometry(1, 6), shieldMat);
    shield.position.set(9.6, 1.2, 0.2);
    shield.rotation.y = -Math.PI / 2;
    scene.add(shield);

    const anchors = [new THREE.Vector3(-9.5, 5.2, -1), new THREE.Vector3(-2, 5, 0.4), new THREE.Vector3(5.2, 6.6, -1), new THREE.Vector3(11.5, 3.2, 0)];
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
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(-1, 2.4, 0);

      // 1 the envelope hops tower to tower to the gate
      const u = rm ? 0.6 : ((t * 0.12) % 1);
      route.getPointAt(u, env.position);
      env.rotation.y = rm ? 0 : Math.sin(t * 2) * 0.3;
      towers.forEach((m, i) => { m.opacity = level[0] * (u * 3 > i ? 0.9 : 0.3); });
      // 2 seals press on; DNS answers
      seals.forEach((m, i) => {
        const v = THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1);
        m.opacity = 0.25 + v * 0.75;
        m.emissiveIntensity = v * 0.6;
      });
      txts.forEach((m, i) => { m.opacity = THREE.MathUtils.clamp(level[1] * 3 - i, 0, 1); });
      // 3 the thread lights; the last card glows red; the hook swings
      cards.forEach((c, i) => {
        const v = THREE.MathUtils.clamp(level[2] * 5 - i, 0, 1);
        c.mat.emissiveIntensity = v * (c.bad ? (rm ? 0.8 : 0.4 + pulse * 0.5) : 0.25);
      });
      hookMat.opacity = level[2] * 0.9;
      if (!rm) hook.rotation.z = Math.sin(t * 2) * 0.3;
      // 4 the payment flies at the vault; the shield stops it once cleared
      const blocked = level[3] > 0.5;
      const w = rm ? 0.6 : ((t * 0.3) % 1);
      pay.position.set(6.5 + (blocked ? Math.min(w, 0.6) : w) * 5, 1.2, 0);
      payMat.opacity = Math.max(level[3], stations[3]?.status === "open" ? 0.5 : 0) * (blocked && w > 0.6 ? 0.2 : 0.9);
      shieldMat.opacity = level[3] * (rm ? 0.7 : 0.4 + pulse * 0.3);

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
            <span className="block whitespace-nowrap rounded-md border bg-[#140f06]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
