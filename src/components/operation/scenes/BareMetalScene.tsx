"use client";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { additive, mountWorld, pad2, placeLabel, shortLabel, type WorldProps } from "./common";
import { circuitFloor, docFile, labelSprite, netNode, packet, padlock, serverRack, shield, terminal } from "./cyberProps";

/**
 * "Bare metal": the whole stack seen in section. Glass guest VMs float over a
 * row of hosts, each with a small sensor light, above a datastore slab holding
 * the disk files. vCenter hangs over it all, and a grant runs down from it. A
 * host's door opens to a shell, the guests go dark one by one while the disks'
 * locks open, and a watch shield stands to one side. Stations switch each part
 * on. Decorative only.
 */
export default function BareMetalScene(props: WorldProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<(HTMLDivElement | null)[]>([]);
  const live = useRef(props);
  live.current = props;

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const A = new THREE.Color(props.primary), B = new THREE.Color(props.secondary), Wn = new THREE.Color(props.warn);
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x03080c, 45, 110);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    scene.add(new THREE.HemisphereLight(0xcffafe, 0x03080c, 0.9));
    const key = new THREE.DirectionalLight(0xffffff, 1.1);
    key.position.set(-6, 14, 12);
    scene.add(key);
    scene.add(new THREE.GridHelper(60, 30, 0x0b3a44, 0x061218));
    const floor = circuitFloor(A, 44);
    scene.add(floor.mesh);

    // ── 1 the stack: datastore slab, hosts, glass guests with sensor lights ──
    const slabMat = new THREE.MeshStandardMaterial({ color: 0x0e4a58, emissive: A, emissiveIntensity: 0.1, transparent: true, opacity: 0.3 });
    const slab = new THREE.Mesh(new THREE.BoxGeometry(13, 0.5, 3.6), slabMat);
    slab.position.set(-1, 0.3, 0);
    scene.add(slab);
    const sl = labelSprite("VMFS DATASTORE", "#a5f3fc", 200);
    sl.position.set(-1, 0.1, 3.4);
    scene.add(sl);
    const hosts = [-5.2, -1, 3.2].map((x, i) => {
      const r = serverRack(A, 4, `esx-0${i + 1}`);
      r.group.position.set(x, 0.55, -0.4);
      r.group.scale.setScalar(0.85);
      scene.add(r.group);
      return r;
    });
    const guests = Array.from({ length: 9 }, (_, i) => {
      const col = i % 3, row = Math.floor(i / 3);
      const x = -6.6 + col * 1.4 + row * 4.2, y = 4.1 + (col % 2) * 0.35;
      const mat = new THREE.MeshStandardMaterial({ color: B, emissive: B, emissiveIntensity: 0.3, transparent: true, opacity: 0.4 });
      const m = new THREE.Mesh(new THREE.BoxGeometry(1.05, 1.05, 1.05), mat);
      m.position.set(x, y, -0.4);
      scene.add(m);
      const lightMat = new THREE.MeshBasicMaterial({ color: 0x34d399, transparent: true, opacity: 0.9 });
      const light = new THREE.Mesh(new THREE.SphereGeometry(0.11, 10, 10), lightMat);
      light.position.set(x, y + 0.72, -0.4);
      scene.add(light);
      return { mat, lightMat };
    });

    // ── 2 vCenter and the grant running down the inventory ──
    const vc = netNode(B, 1);
    vc.group.position.set(-1, 8.6, -0.4);
    scene.add(vc.group);
    const vl = labelSprite("vCenter", "#ddd6fe", 130);
    vl.position.set(-1, 10, -0.4);
    scene.add(vl);
    const grants = [-5.2, -1, 3.2].map(x => {
      const mat = additive(B, 0.05);
      const dx = x + 1, len = Math.hypot(dx, 4.1);
      const m = new THREE.Mesh(new THREE.BoxGeometry(0.05, len, 0.05), mat);
      m.position.set((x - 1) / 2, 6.55, -0.4);
      m.rotation.z = Math.atan2(dx, 4.1);
      scene.add(m);
      return mat;
    });
    const token = [-5.2, -1, 3.2].map((x, i) => { const p = packet(B); scene.add(p.mesh); return { ...p, x, o: i / 3 }; });

    // ── 3 a host's door opens onto a shell ──
    const door = padlock(Wn, 0.8);
    door.group.position.set(7.4, 3.4, -0.4);
    scene.add(door.group);
    const shellCon = terminal(["~ # esxcli system version get", "~ # vim-cmd vmsvc/getallvms"], Wn, 2.4, 1.3);
    shellCon.group.position.set(7.4, 0.2, 1);
    shellCon.group.scale.setScalar(1.15);
    scene.add(shellCon.group);

    // ── 4 disks on the slab, their locks opening as guests stop ──
    const disks = [-4.8, -1, 2.8].map((x, i) => {
      const d = docFile(`vm-0${i + 1}-flat.vmdk`, A);
      d.group.scale.setScalar(0.55);
      d.group.position.set(x, 1, 1.5);
      scene.add(d.group);
      const l = padlock(A, 0.32);
      l.group.position.set(x + 0.9, 1, 1.5);
      scene.add(l.group);
      return { d, l };
    });

    // ── 5 the watcher, reading the stack from outside ──
    const watch = shield(A, "check", 1.5);
    watch.group.position.set(-9.8, 3.4, 0.6);
    watch.group.rotation.y = 0.5;
    scene.add(watch.group);
    const wl = labelSprite("OWN LOGS", "#a5f3fc", 140);
    wl.position.set(-9.8, 1.2, 1.4);
    scene.add(wl);

    const anchors = [new THREE.Vector3(-4.6, 7.6, -0.4), new THREE.Vector3(4.2, 9.4, -0.4), new THREE.Vector3(7.4, 5, -0.4), new THREE.Vector3(4.6, -0.2, 3), new THREE.Vector3(-9.8, 5.8, 0.6)];
    const level = [0, 0, 0, 0, 0];
    let W_ = 1, H_ = 1, dist = 27, portrait = false;
    const fit = (w: number, h: number) => { W_ = w; H_ = h; const asp = w / h; portrait = asp < 1; dist = portrait ? 66 : asp < 1.5 ? 33 : 27; };

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
      camera.position.set(Math.sin(yaw) * dist - 1, dist * (portrait ? 0.5 : 0.3) + 3, Math.cos(yaw) * dist + 2);
      camera.lookAt(-1, 4, 0);

      floor.mat.opacity = 0.2 + level[4] * 0.25;
      // 1 the stack comes up, the sensors stay green throughout
      slabMat.opacity = 0.3 + level[0] * 0.3;
      slabMat.emissiveIntensity = 0.1 + level[0] * 0.2;
      hosts.forEach(r => r.tick(t, 0.4 + level[0] * 0.6, rm));
      // 2 the grant flows down from vCenter
      vc.wireMat.opacity = 0.2 + level[1] * 0.75;
      vc.coreMat.opacity = 0.15 + level[1] * 0.7;
      vc.group.rotation.y = rm ? 0 : t * 0.35;
      grants.forEach(m => { m.opacity = 0.05 + level[1] * (0.5 + pulse * 0.4); });
      const go = Math.max(level[1], stations[1]?.status === "open" ? 0.4 : 0);
      token.forEach(p => {
        const u = rm ? 0.5 : ((t * 0.3 + p.o) % 1);
        p.mesh.position.set(-1 + (p.x + 1) * u, 8.6 - u * 4.1, -0.4);
        p.mat.opacity = go * 0.9;
      });
      // 3 the door opens
      door.setOpen(level[2]);
      door.mat.opacity = 0.35 + level[2] * 0.65;
      shellCon.screenMat.opacity = 0.2 + level[2] * 0.8;
      // 4 guests stop in turn, disks unlock
      const off = level[3] * guests.length;
      guests.forEach((g, i) => {
        const dark = Math.max(0, Math.min(1, off - i));
        g.mat.opacity = 0.42 - dark * 0.28;
        g.mat.emissiveIntensity = 0.3 * (1 - dark);
        g.lightMat.opacity = 0.9 * (1 - dark);
      });
      disks.forEach(({ d, l }) => {
        d.mat.opacity = 0.25 + level[3] * 0.7;
        l.setOpen(level[3]);
        l.mat.opacity = 0.35 + level[3] * 0.6;
      });
      // 5 the watcher
      watch.mat.opacity = 0.25 + level[4] * 0.75;
      watch.mat.emissiveIntensity = 0.1 + level[4] * 0.6;
      (wl.material as THREE.SpriteMaterial).opacity = 0.25 + level[4] * 0.75;

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
            <span className="block whitespace-nowrap rounded-md border bg-[#061218]/90 px-2 py-1 font-mono text-[11px] font-black uppercase tracking-wide"
              style={{ borderColor: i === props.selected ? props.primary : "rgba(255,255,255,0.15)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
              {pad2(i + 1)} <span style={{ color: s.status === "cleared" ? "#34d399" : s.status === "open" ? props.primary : props.warn }}>{"//"}</span> {shortLabel(s.label)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
