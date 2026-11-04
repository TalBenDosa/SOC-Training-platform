import * as THREE from "three";

/**
 * Shared 3D props so every world reads as cyber at a glance: server racks
 * with blinking LEDs, terminals with code on screen, laptops, shields,
 * padlocks, network nodes, document files, holographic panels and a
 * circuit-trace floor. Each builder returns a Group plus the materials a
 * scene animates. Decorative only.
 */

const dark = () => new THREE.MeshStandardMaterial({ color: 0x1b2433, emissive: 0x070b12, metalness: 0.6, roughness: 0.35 });

function canvasTex(w: number, h: number, draw: (g: CanvasRenderingContext2D) => void) {
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  draw(c.getContext("2d")!);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  return t;
}

const hex = (c: THREE.ColorRepresentation) => `#${new THREE.Color(c).getHexString()}`;

/** A rack: dark cabinet, slotted units, a column of LEDs per unit. */
export function serverRack(accent: THREE.ColorRepresentation, units = 6, label?: string) {
  const g = new THREE.Group();
  const W = 1.2, H = units * 0.32 + 0.3, D = 1;
  const body = new THREE.Mesh(new THREE.BoxGeometry(W, H, D), dark());
  body.position.y = H / 2;
  g.add(body);
  const leds: THREE.MeshBasicMaterial[] = [];
  for (let u = 0; u < units; u++) {
    const y = 0.25 + u * 0.32;
    const slab = new THREE.Mesh(new THREE.BoxGeometry(W * 0.9, 0.24, 0.04), new THREE.MeshStandardMaterial({ color: 0x2a3547, emissive: 0x0b111c, metalness: 0.4, roughness: 0.5 }));
    slab.position.set(0, y, D / 2 + 0.01);
    g.add(slab);
    for (let k = 0; k < 3; k++) {
      const m = new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.9 });
      const led = new THREE.Mesh(new THREE.BoxGeometry(0.05, 0.05, 0.02), m);
      led.position.set(-W * 0.36 + k * 0.09, y, D / 2 + 0.04);
      g.add(led);
      leds.push(m);
    }
    const vent = new THREE.Mesh(new THREE.BoxGeometry(W * 0.45, 0.06, 0.02), new THREE.MeshBasicMaterial({ color: 0x0f172a }));
    vent.position.set(W * 0.15, y, D / 2 + 0.035);
    g.add(vent);
  }
  if (label) {
    const tag = labelSprite(label, hex(accent));
    tag.position.set(0, H + 0.35, 0);
    g.add(tag);
  }
  /** Blink the LEDs; `on` 0..1 scales how alive the rack looks. */
  const tick = (t: number, on: number, reduced = false) => {
    leds.forEach((m, i) => {
      const b = reduced ? 1 : (Math.sin(t * (3 + (i % 5)) + i * 1.7) > -0.2 ? 1 : 0.15);
      m.opacity = 0.15 + on * 0.85 * b;
    });
  };
  return { group: g, leds, tick, height: H };
}

/** A monitor on a stand with code lines on its screen. */
export function terminal(lines: string[], accent: THREE.ColorRepresentation, w = 1.8, h = 1.15) {
  const g = new THREE.Group();
  const frame = new THREE.Mesh(new THREE.BoxGeometry(w + 0.12, h + 0.12, 0.08), dark());
  frame.position.y = h / 2 + 0.6;
  g.add(frame);
  const col = hex(accent);
  const tex = canvasTex(512, 320, c => {
    c.fillStyle = "#020617"; c.fillRect(0, 0, 512, 320);
    c.fillStyle = col; c.globalAlpha = 0.9;
    c.font = "bold 22px monospace";
    lines.slice(0, 10).forEach((l, i) => c.fillText(l, 16, 34 + i * 29));
    c.globalAlpha = 0.25; c.fillRect(0, 0, 512, 4);
  });
  const screenMat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: 0.95 });
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(w, h), screenMat);
  screen.position.set(0, h / 2 + 0.6, 0.045);
  g.add(screen);
  const neck = new THREE.Mesh(new THREE.BoxGeometry(0.12, 0.5, 0.12), dark());
  neck.position.y = 0.3;
  g.add(neck);
  const foot = new THREE.Mesh(new THREE.BoxGeometry(0.7, 0.05, 0.45), dark());
  foot.position.y = 0.03;
  g.add(foot);
  return { group: g, screenMat };
}

/** An open laptop with a glowing screen; `screenMat.color` shows its state. */
export function laptop(accent: THREE.ColorRepresentation) {
  const g = new THREE.Group();
  const base = new THREE.Mesh(new THREE.BoxGeometry(1, 0.06, 0.7), dark());
  base.position.y = 0.03;
  g.add(base);
  const lid = new THREE.Group();
  const back = new THREE.Mesh(new THREE.BoxGeometry(1, 0.65, 0.04), dark());
  back.position.y = 0.33;
  lid.add(back);
  const screenMat = new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.85 });
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(0.88, 0.54), screenMat);
  screen.position.set(0, 0.33, 0.025);
  lid.add(screen);
  lid.position.set(0, 0.05, -0.33);
  lid.rotation.x = -0.25;
  g.add(lid);
  return { group: g, screenMat };
}

/** A heater-shaped shield with a raised rim and a check/alert mark. */
export function shield(color: THREE.ColorRepresentation, mark: "check" | "alert" | "none" = "none", size = 1) {
  const s = new THREE.Shape();
  s.moveTo(0, 0.6); s.lineTo(0.5, 0.45); s.lineTo(0.45, -0.1);
  s.quadraticCurveTo(0.35, -0.5, 0, -0.7); s.quadraticCurveTo(-0.35, -0.5, -0.45, -0.1);
  s.lineTo(-0.5, 0.45); s.lineTo(0, 0.6);
  const mat = new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.25, metalness: 0.5, roughness: 0.3, transparent: true, opacity: 0.95 });
  const mesh = new THREE.Mesh(new THREE.ExtrudeGeometry(s, { depth: 0.12, bevelEnabled: true, bevelSize: 0.04, bevelThickness: 0.04, bevelSegments: 2 }), mat);
  const g = new THREE.Group();
  g.add(mesh);
  if (mark !== "none") {
    const t = labelSprite(mark === "check" ? "✓" : "!", "#ffffff", 80);
    t.position.set(0, -0.02, 0.25);
    t.scale.set(0.7, 0.7, 1);
    g.add(t);
  }
  g.scale.setScalar(size);
  return { group: g, mat };
}

/** A padlock: body plus shackle; `open` lifts the shackle. */
export function padlock(color: THREE.ColorRepresentation, size = 1) {
  const g = new THREE.Group();
  const mat = new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.2, metalness: 0.7, roughness: 0.25, transparent: true, opacity: 1 });
  const body = new THREE.Mesh(new THREE.BoxGeometry(0.7, 0.55, 0.25), mat);
  g.add(body);
  const shackle = new THREE.Mesh(new THREE.TorusGeometry(0.22, 0.05, 8, 20, Math.PI), mat);
  shackle.position.y = 0.27;
  g.add(shackle);
  const hole = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 0.05, 10), new THREE.MeshBasicMaterial({ color: 0x0b1220 }));
  hole.rotation.x = Math.PI / 2;
  hole.position.set(0, -0.05, 0.13);
  g.add(hole);
  g.scale.setScalar(size);
  const setOpen = (o: number) => { shackle.position.y = 0.27 + o * 0.18; };
  return { group: g, mat, setOpen };
}

/** A network node: wireframe icosahedron around a glowing core. */
export function netNode(color: THREE.ColorRepresentation, r = 0.45) {
  const g = new THREE.Group();
  const wireMat = new THREE.MeshBasicMaterial({ color, wireframe: true, transparent: true, opacity: 0.7 });
  const wire = new THREE.Mesh(new THREE.IcosahedronGeometry(r, 1), wireMat);
  g.add(wire);
  const coreMat = new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.8 });
  const core = new THREE.Mesh(new THREE.SphereGeometry(r * 0.38, 14, 10), coreMat);
  g.add(core);
  return { group: g, wire, wireMat, coreMat };
}

/** A document with a folded corner and text lines, with a title on its face. */
export function docFile(title: string, accent: THREE.ColorRepresentation) {
  const col = hex(accent);
  const tex = canvasTex(256, 330, c => {
    c.fillStyle = "#e2e8f0"; c.fillRect(0, 0, 256, 330);
    c.fillStyle = "#cbd5e1"; c.beginPath(); c.moveTo(196, 0); c.lineTo(256, 60); c.lineTo(196, 60); c.fill();
    c.fillStyle = col; c.font = "bold 24px monospace"; c.fillText(title.slice(0, 14), 16, 44);
    c.fillStyle = "#64748b";
    for (let i = 0; i < 9; i++) c.fillRect(16, 80 + i * 26, 160 + ((i * 37) % 60), 8);
  });
  const mat = new THREE.MeshStandardMaterial({ map: tex, emissive: accent, emissiveIntensity: 0, transparent: true, opacity: 1, side: THREE.DoubleSide });
  const g = new THREE.Group();
  const page = new THREE.Mesh(new THREE.PlaneGeometry(1, 1.3), mat);
  g.add(page);
  return { group: g, mat };
}

/** A translucent holographic panel with a title and rows of text. */
export function holoPanel(title: string, rows: string[], color: THREE.ColorRepresentation, w = 2.2, h = 1.4) {
  const col = hex(color);
  const tex = canvasTex(512, 320, c => {
    c.strokeStyle = col; c.lineWidth = 4; c.globalAlpha = 0.9; c.strokeRect(4, 4, 504, 312);
    c.fillStyle = col; c.globalAlpha = 0.18; c.fillRect(4, 4, 504, 56);
    c.globalAlpha = 1; c.font = "bold 30px monospace"; c.fillText(title, 18, 44);
    c.font = "22px monospace"; c.globalAlpha = 0.85;
    rows.slice(0, 7).forEach((r, i) => c.fillText(r, 18, 96 + i * 32));
  });
  const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: 0.85, side: THREE.DoubleSide, depthWrite: false, blending: THREE.AdditiveBlending });
  const mesh = new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat);
  return { mesh, mat };
}

/** A floor of glowing circuit traces, to lay under a world. */
export function circuitFloor(color: THREE.ColorRepresentation, size = 40) {
  const col = hex(color);
  const tex = canvasTex(1024, 1024, c => {
    c.fillStyle = "#000"; c.fillRect(0, 0, 1024, 1024);
    c.strokeStyle = col; c.lineWidth = 3; c.globalAlpha = 0.55;
    let seed = 7;
    const rnd = () => { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; };
    for (let i = 0; i < 70; i++) {
      let x = rnd() * 1024, y = rnd() * 1024;
      c.beginPath(); c.moveTo(x, y);
      for (let s = 0; s < 4; s++) {
        if (rnd() > 0.5) x += (rnd() - 0.5) * 260; else y += (rnd() - 0.5) * 260;
        c.lineTo(x, y);
      }
      c.stroke();
      c.fillStyle = col; c.beginPath(); c.arc(x, y, 6, 0, Math.PI * 2); c.fill();
    }
  });
  tex.wrapS = tex.wrapT = THREE.RepeatWrapping;
  const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending, depthWrite: false });
  const mesh = new THREE.Mesh(new THREE.PlaneGeometry(size, size), mat);
  mesh.rotation.x = -Math.PI / 2;
  mesh.position.y = 0.01;
  return { mesh, mat };
}

/** A small glowing packet for data flows. */
export function packet(color: THREE.ColorRepresentation) {
  const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 });
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(0.18, 0.12, 0.12), mat);
  return { mesh, mat };
}

/** Text sprite used by the props. */
export function labelSprite(text: string, color: string, w = 220) {
  const tex = canvasTex(w, 56, c => {
    c.fillStyle = color; c.font = "bold 26px monospace"; c.textAlign = "center"; c.textBaseline = "middle";
    c.fillText(text, w / 2, 28);
  });
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  s.scale.set(w / 100, 0.56, 1);
  return s;
}
