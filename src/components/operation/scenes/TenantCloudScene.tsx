"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, holoPanel, labelSprite, laptop, netNode, packet, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Inbox zero": a Microsoft 365 tenant as a ring of light over two rack rows
 * (EXCHANGE and SHAREPOINT) on a circuit floor. Four Defender nodes orbit the
 * ring; mail packets fly in through a shield gate where lookalikes are
 * stopped; an audit terminal scrolls operations; a leak of packets streams out
 * of the mail racks to an outside node until a padlock closes the tenant.
 * Stations switch each part on. Decorative only.
 */
export default function TenantCloudScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03070c, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xe0f2fe, 0x03070c, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0c4a6e, 0x08121c));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // the tenant: two rack rows under a ring of light
    const exch = [-2.6, -1.3].map(x => { const r = serverRack(A, 7); r.group.position.set(x, 0, 0); scene.add(r.group); return r; });
    const spo = [1.3, 2.6].map(x => { const r = serverRack(B, 7); r.group.position.set(x, 0, 0); scene.add(r.group); return r; });
    const el = labelSprite("EXCHANGE", "#bae6fd", 200); el.position.set(-1.95, 3, 0); scene.add(el);
    const sl = labelSprite("SHAREPOINT", "#d9f99d", 220); sl.position.set(1.95, 3, 0); scene.add(sl);
    const ringMat = additive(A, 0.15);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(4.6, 0.07, 8, 80), ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 3.8;
    scene.add(ring);
    const tl = labelSprite("fairhaven.ac.example", "#e0f2fe", 300); tl.position.set(0, 4.5, -4.6); scene.add(tl);

    // ── 1 four Defender nodes orbit the ring ──
    const fam = ["MDO", "MDE", "MDI", "MDCA"].map((n, i) => {
      const nd = netNode(i % 2 ? B : A, 0.4);
      scene.add(nd.group);
      const l = labelSprite(n, "#f1f5f9", 120);
      scene.add(l);
      return { nd, l, a0: (i / 4) * Math.PI * 2 };
    });

    // ── 2 the mail shield gate and inbound packets ──
    const gate = shield(A, "check", 1.4);
    gate.group.position.set(-7, 2, 2.6);
    gate.group.rotation.y = 0.6;
    scene.add(gate.group);
    const inbound = Array.from({ length: 6 }, (_, i) => {
      const p = packet(i === 1 || i === 4 ? Wn : A);
      scene.add(p.mesh);
      return { ...p, o: i / 6, bad: i === 1 || i === 4 };
    });
    const mails = [0, 1, 2].map(i => {
      const d = docFile(["payroll", "principal", "helpdesk"][i], i === 0 ? Wn : A);
      d.group.scale.setScalar(0.55);
      d.group.position.set(-10 + i * 0.9, 1.4 + (i % 2) * 0.3, 4 - i * 0.6);
      d.group.rotation.y = 0.5;
      scene.add(d.group);
      return d;
    });

    // ── 3 the audit terminal ──
    const audit = terminal(["Search-UnifiedAuditLog", "22:09 Add member to role", "22:14 Set-Mailbox", "  ForwardingSmtpAddress", "22:31 FileDownloaded x642"], A, 2.1, 1.3);
    audit.group.position.set(5.6, 0, 3);
    audit.group.rotation.y = -0.5;
    scene.add(audit.group);

    // ── 4 the leak: packets stream out to an outside node ──
    const outside = netNode(Wn, 0.55);
    outside.group.position.set(8.5, 2.6, -3);
    scene.add(outside.group);
    const ol = labelSprite("mailbox.example", "#fed7aa", 240); ol.position.set(8.5, 3.6, -3); scene.add(ol);
    const leak = Array.from({ length: 6 }, (_, i) => { const p = packet(Wn); scene.add(p.mesh); return { ...p, o: i / 6 }; });
    const leakPanel = holoPanel("ForwardingSmtpAddress", ["smtp:estates.archive", "DeliverToMailboxAndForward"], Wn, 2.2, 1);
    leakPanel.mesh.position.set(5.4, 4.4, -2.2);
    leakPanel.mesh.rotation.y = -0.4;
    scene.add(leakPanel.mesh);

    // ── 5 the padlock that closes the tenant ──
    const lock = padlock(A, 1.4);
    lock.group.position.set(0, 5.2, 0);
    scene.add(lock.group);
    const staff = laptop(B);
    staff.group.position.set(-4.4, 0, 4.2);
    staff.group.scale.setScalar(1.4);
    staff.group.rotation.y = 0.4;
    scene.add(staff.group);

    const anchors = [new THREE.Vector3(-4.6, 4.6, 0), new THREE.Vector3(-7, 3.8, 2.6), new THREE.Vector3(5.6, 2.8, 3), new THREE.Vector3(8.5, 4.6, -3), new THREE.Vector3(2.6, 5.6, 0)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 21, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 50 : asp < 1.5 ? 26 : 21; };

    return mountWorld(mount, camera, scene, (t, dt) => {
      const { stations, reducedMotion: rm } = live.current;
      const ease = rm ? 1 : 1 - Math.pow(0.2, dt);
      const pulse = rm ? 0.5 : 0.5 + Math.sin(t * 3) * 0.5;
      for (let k = 0; k < 5; k++) {
        const s = stations[k];
        const target = !s ? 0 : s.status === "cleared" ? 1 : s.status === "open" ? 0.1 + pulse * 0.15 : 0;
        level[k] += (target - level[k]) * ease;
      }

      const yaw = rm ? 0 : Math.sin(t * 0.07) * 0.22;
      camera.position.set(Math.sin(yaw) * dist, dist * (portrait ? 0.55 : 0.42) + 1.5, Math.cos(yaw) * dist + 2);
      camera.lookAt(0, 2.2, 0);

      exch.forEach(r => r.tick(t, 0.5 + level[2] * 0.5, rm));
      spo.forEach(r => r.tick(t, 0.5 + level[2] * 0.5, rm));
      ringMat.opacity = 0.15 + level[4] * 0.7;
      floor.mat.opacity = 0.2 + level[4] * 0.25;

      // 1 the family orbits
      fam.forEach((f, i) => {
        const a = f.a0 + (rm ? 0 : t * 0.25);
        f.nd.group.position.set(Math.cos(a) * 4.6, 3.8, Math.sin(a) * 4.6);
        f.l.position.set(Math.cos(a) * 4.6, 4.5, Math.sin(a) * 4.6);
        f.nd.wireMat.opacity = 0.2 + THREE.MathUtils.clamp(level[0] * 4 - i, 0, 1) * 0.7;
        (f.l.material as THREE.SpriteMaterial).opacity = 0.3 + level[0] * 0.7;
        if (!rm) f.nd.wire.rotation.y += dt;
      });
      // 2 mail flies at the gate; lookalikes stop there once the gate is learned
      gate.mat.opacity = 0.3 + level[1] * 0.7;
      gate.mat.emissiveIntensity = 0.15 + level[1] * 0.5;
      inbound.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.3 + p.o) % 1);
        const stop = p.bad && level[1] > 0.5;
        const uu = stop ? Math.min(u, 0.45) : u;
        p.mesh.position.lerpVectors(new THREE.Vector3(-11, 1.6, 4.5), new THREE.Vector3(-2, 1.6, 0.6), uu);
        p.mat.opacity = stop && u > 0.45 ? 0.3 : 0.95;
      });
      mails.forEach(m => { m.mat.emissiveIntensity = level[1] * 0.25; });
      // 3 the audit screen brightens
      audit.screenMat.opacity = 0.35 + level[2] * 0.6;
      // 4 the leak runs until the boss is cleared
      const leaking = Math.max(level[3], stations[3]?.status === "open" ? 0.5 : 0) * (1 - level[4]);
      leak.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.35 + p.o) % 1);
        p.mesh.position.lerpVectors(new THREE.Vector3(-1.9, 2, 0.6), outside.group.position, u);
        p.mat.opacity = leaking * 0.95;
      });
      leakPanel.mat.opacity = 0.2 + level[3] * 0.6;
      outside.wireMat.opacity = 0.3 + leaking * 0.6;
      // 5 the padlock closes
      lock.setOpen(1 - level[4]);
      lock.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      staff.screenMat.opacity = 0.4 + level[4] * 0.5;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#050c16]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
