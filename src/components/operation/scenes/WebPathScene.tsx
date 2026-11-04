"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, glowTexture, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";

/**
 * "The request line": a browser window on the left sends request packets down
 * a glowing track through a TLS tube, a WAF gate, a web server, the app and
 * into a database drum. A packet unfolds into its parts (METHOD, PATH, QUERY,
 * HEADERS, COOKIE, BODY); a tampered packet turns red on the way; attack
 * markers land at the tier each class hits; the WAF gate flashes on what it
 * catches; and a second, rogue browser tab sends its own request that picks up
 * the victim's cookie on the way. Stations switch each part on. Decorative only.
 */
const PARTS = ["METHOD", "PATH", "QUERY", "HEADERS", "COOKIE", "BODY"];

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

export default function WebPathScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0408, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);
    const glow = glowTexture();

    scene.add(new THREE.HemisphereLight(0xfce7f3, 0x0a0408, 0.8));
    const key = new THREE.DirectionalLight(0xffffff, 1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x500724, 0x1f0712));
    const metal = () => new THREE.MeshStandardMaterial({ color: 0x3a2432, emissive: 0x12070d, metalness: 0.55, roughness: 0.4 });

    // the track and its tiers
    const X = { browser: -12, tls: -8, waf: -4, web: 0, app: 4, db: 8 };
    const track = new THREE.Mesh(new THREE.BoxGeometry(21, 0.06, 0.4), new THREE.MeshStandardMaterial({ color: 0x3a2432, emissive: A, emissiveIntensity: 0.15 }));
    track.position.set(-2, 0.5, 0);
    scene.add(track);
    const screen = new THREE.Mesh(new THREE.BoxGeometry(2.6, 1.8, 0.12), metal());
    screen.position.set(X.browser, 2, 0);
    scene.add(screen);
    const scrMat = new THREE.MeshStandardMaterial({ color: 0x1f0712, emissive: A, emissiveIntensity: 0.3 });
    const scr = new THREE.Mesh(new THREE.PlaneGeometry(2.3, 1.4), scrMat);
    scr.position.set(X.browser, 2, 0.07);
    scene.add(scr);
    const brLab = tag("BROWSER", "#fbcfe8", 200); brLab.position.set(X.browser, 3.3, 0); scene.add(brLab);
    const tube = new THREE.Mesh(new THREE.CylinderGeometry(0.7, 0.7, 3, 20, 1, true), new THREE.MeshStandardMaterial({ color: B, transparent: true, opacity: 0.15, side: THREE.DoubleSide }));
    tube.rotation.z = Math.PI / 2;
    tube.position.set(X.tls, 1, 0);
    scene.add(tube);
    const tlsLab = tag("TLS", "#a5f3fc", 100); tlsLab.position.set(X.tls, 2.1, 0); scene.add(tlsLab);
    const wafMat = additive(B, 0.05);
    const waf = new THREE.Mesh(new THREE.TorusGeometry(1, 0.1, 8, 6), wafMat);
    waf.rotation.y = Math.PI / 2;
    waf.position.set(X.waf, 1.2, 0);
    scene.add(waf);
    const wafLab = tag("WAF", "#a5f3fc", 100); wafLab.position.set(X.waf, 2.7, 0); scene.add(wafLab);
    const web = new THREE.Mesh(new THREE.BoxGeometry(1.4, 2.2, 1.4), metal());
    web.position.set(X.web, 1.1, -1.2);
    scene.add(web);
    const webLab = tag("WEB", "#fbcfe8", 100); webLab.position.set(X.web, 2.7, -1.2); scene.add(webLab);
    const app = new THREE.Mesh(new THREE.BoxGeometry(1.4, 1.6, 1.4), metal());
    app.position.set(X.app, 0.8, -1.2);
    scene.add(app);
    const appLab = tag("APP", "#fbcfe8", 100); appLab.position.set(X.app, 2.1, -1.2); scene.add(appLab);
    const db = new THREE.Mesh(new THREE.CylinderGeometry(1, 1, 1.6, 24), metal());
    db.position.set(X.db, 0.8, -1.2);
    scene.add(db);
    const dbLab = tag("DATABASE", "#fbcfe8", 200); dbLab.position.set(X.db, 2.1, -1.2); scene.add(dbLab);

    // ── 1 a packet and its parts ──
    const pktMat = new THREE.SpriteMaterial({ map: glow, color: A, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const pkt = new THREE.Sprite(pktMat);
    pkt.scale.set(0.9, 0.9, 1);
    scene.add(pkt);
    const parts = PARTS.map(p => {
      const s = tag(p, "#fbcfe8", 180);
      (s.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(s);
      return s;
    });

    // ── 2 the tampered packet ──
    const evilMat = new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const evil = new THREE.Sprite(evilMat);
    evil.scale.set(0.8, 0.8, 1);
    scene.add(evil);
    const tamperLab = tag("price=0.01", "#fecdd3", 220);
    (tamperLab.material as THREE.SpriteMaterial).opacity = 0;
    scene.add(tamperLab);

    // ── 3 attack markers at the tier each class hits ──
    const marks = [["SQLi", X.db], ["XSS", X.browser], ["TRAVERSAL", X.web], ["CMD INJ", X.app]].map(([n, x]) => {
      const mat = additive(Wn, 0);
      const m = new THREE.Mesh(new THREE.ConeGeometry(0.3, 0.9, 4), mat);
      m.rotation.x = Math.PI;
      m.position.set(x as number, 4.2, n === "XSS" ? 0 : -1.2);
      scene.add(m);
      const l = tag(n as string, "#fecdd3", 220);
      l.position.set(x as number, 5, n === "XSS" ? 0 : -1.2);
      (l.material as THREE.SpriteMaterial).opacity = 0;
      scene.add(l);
      return { mat, l: l.material as THREE.SpriteMaterial };
    });

    // ── 5 the rogue tab ──
    const rogue = new THREE.Mesh(new THREE.BoxGeometry(2, 1.3, 0.1), new THREE.MeshStandardMaterial({ color: 0x3a1020, emissive: Wn, emissiveIntensity: 0, transparent: true, opacity: 0.2 }));
    rogue.position.set(X.browser - 3, 1.4, 2.4);
    rogue.rotation.y = -0.4;
    scene.add(rogue);
    const rogueLab = tag("win-a-prize tab", "#fecdd3", 300); rogueLab.position.set(X.browser - 3, 2.5, 2.4); scene.add(rogueLab);
    const forgedMat = new THREE.SpriteMaterial({ map: glow, color: Wn, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const forged = new THREE.Sprite(forgedMat);
    forged.scale.set(0.7, 0.7, 1);
    scene.add(forged);
    const cookieMat = new THREE.SpriteMaterial({ map: glow, color: 0xfde68a, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
    const cookie = new THREE.Sprite(cookieMat);
    cookie.scale.set(0.4, 0.4, 1);
    scene.add(cookie);

    const anchors = [new THREE.Vector3(X.browser - 2.6, 3.4, 0), new THREE.Vector3(X.tls, 2.9, 1.4), new THREE.Vector3(X.web + 2, 6.2, -1.2), new THREE.Vector3(X.waf, 3.9, 0.6), new THREE.Vector3(X.browser - 3.4, -0.2, 3)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 28, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 74 : asp < 1.5 ? 33 : 28; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.2;
      camera.position.set(Math.sin(yaw) * dist - 2, dist * (portrait ? 0.6 : 0.42) + 1, Math.cos(yaw) * dist + 6);
      camera.lookAt(-2, 2, 0);

      // 1 a request travels the line; its parts fan out above it
      const u = rm ? 0.4 : ((t * 0.12) % 1);
      pkt.position.set(X.browser + u * (X.db - X.browser), 1.2, 0);
      pktMat.opacity = Math.max(level[0], stations[0]?.status === "open" ? 0.5 : 0);
      parts.forEach((p, i) => {
        p.position.set(X.browser + 4 + (i % 3) * 2.8, 7.4 - Math.floor(i / 3) * 0.8, -1);
        (p.material as THREE.SpriteMaterial).opacity = THREE.MathUtils.clamp(level[0] * 6 - i, 0, 1);
      });
      // 2 a tampered packet, red, sails past the browser's 'limits'
      const v = rm ? 0.6 : ((t * 0.15 + 0.5) % 1);
      evil.position.set(X.browser + v * (X.app - X.browser), 1.8, 0.6);
      evilMat.opacity = level[1] * 0.9;
      tamperLab.position.set(evil.position.x, 2.5, 0.6);
      (tamperLab.material as THREE.SpriteMaterial).opacity = level[1];
      // 3 attack markers drop onto their tiers
      marks.forEach((m, i) => {
        const on = THREE.MathUtils.clamp(level[2] * 4 - i, 0, 1);
        m.mat.opacity = on * (rm ? 0.9 : 0.6 + pulse * 0.4);
        m.l.opacity = on;
      });
      // 4 the WAF gate flashes as the red packet passes through it
      const near = Math.abs(evil.position.x - X.waf) < 1 ? 1 : 0;
      wafMat.opacity = 0.05 + level[3] * (0.5 + near * 0.45);
      // 5 the rogue tab fires a request; the cookie hops on as it passes the browser
      (rogue.material as THREE.MeshStandardMaterial).emissiveIntensity = level[4] * 0.6;
      (rogue.material as THREE.MeshStandardMaterial).opacity = 0.2 + level[4] * 0.7;
      const w = rm ? 0.5 : ((t * 0.18) % 1);
      const start = new THREE.Vector3(X.browser - 3, 1.4, 2.4), mid = new THREE.Vector3(X.browser + 1.5, 1.2, 0), end = new THREE.Vector3(X.app, 1.2, 0);
      if (w < 0.3) forged.position.lerpVectors(start, mid, w / 0.3);
      else forged.position.lerpVectors(mid, end, (w - 0.3) / 0.7);
      forgedMat.opacity = level[4] * 0.9;
      cookie.position.copy(forged.position).add(new THREE.Vector3(0, 0.45, 0));
      cookieMat.opacity = w > 0.3 ? level[4] : 0;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#16060f]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
