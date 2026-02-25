// ── Perceptual color manipulation ───────────────────────────────────
// OKLCH is a color space where lightness, saturation, and hue are independent axes.
// This lets us brighten a color without washing it out (unlike blending toward white in RGB).
// Conversion chain: sRGB (0-255) → linear RGB → OKLab → OKLCH, and back.

const GLOW_MIN_LIGHTNESS = 0.65;
const GLOW_CHROMA_BOOST = 1.6;
const GLOW_MAX_CHROMA = 0.25;
const SAMPLE_SIZE = 64;
const RING_WIDTH = 5;
const MIN_CHROMA = 5;

function srgbToLinear(c: number): number {
  const v = c / 255;
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

function linearToSrgb(c: number): number {
  const v = Math.max(0, Math.min(1, c));
  return v <= 0.0031308 ? v * 12.92 : 1.055 * v ** (1 / 2.4) - 0.055;
}

function rgbToOklch(r: number, g: number, b: number): [number, number, number] {
  const lr = srgbToLinear(r), lg = srgbToLinear(g), lb = srgbToLinear(b);
  const l_ = Math.cbrt(0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb);
  const m_ = Math.cbrt(0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb);
  const s_ = Math.cbrt(0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb);
  const L = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_;
  const a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_;
  const ob = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_;
  const C = Math.sqrt(a * a + ob * ob);
  const H = (Math.atan2(ob, a) * 180 / Math.PI + 360) % 360;
  return [L, C, H];
}

function oklchToRgb(L: number, C: number, H: number): [number, number, number] {
  const hRad = H * Math.PI / 180;
  const a = C * Math.cos(hRad), ob = C * Math.sin(hRad);
  const l_ = L + 0.3963377774 * a + 0.2158037573 * ob;
  const m_ = L - 0.1055613458 * a - 0.0638541728 * ob;
  const s_ = L - 0.0894841775 * a - 1.2914855480 * ob;
  const l = l_ * l_ * l_, m = m_ * m_ * m_, s = s_ * s_ * s_;
  const lr =  4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s;
  const lg = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s;
  const lb = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s;
  return [
    Math.round(linearToSrgb(lr) * 255),
    Math.round(linearToSrgb(lg) * 255),
    Math.round(linearToSrgb(lb) * 255),
  ];
}

// Raise lightness and boost chroma to produce a vivid glow from any source color.
export function liftToGlow(r: number, g: number, b: number): [number, number, number] {
  let [L, C, H] = rgbToOklch(r, g, b);
  L = Math.max(L, GLOW_MIN_LIGHTNESS + (1 - GLOW_MIN_LIGHTNESS) * L);
  C = Math.min(C * GLOW_CHROMA_BOOST, GLOW_MAX_CHROMA);
  return oklchToRgb(L, C, H);
}

const toHex = (n: number) => Math.round(Math.min(255, Math.max(0, n))).toString(16).padStart(2, "0");

// ── Edge-ring glow extraction ───────────────────────────────────────
// Samples the 5px ring at the circular edge, weights by color intensity, brightened for dark backgrounds.

function edgeRingGlow(data: Uint8ClampedArray): string | null {
  const center = SAMPLE_SIZE / 2;
  const radius = SAMPLE_SIZE / 2;
  const inner = radius - RING_WIDTH;
  let tw = 0, wr = 0, wg = 0, wb = 0;

  for (let y = 0; y < SAMPLE_SIZE; y++) {
    for (let x = 0; x < SAMPLE_SIZE; x++) {
      const dist = Math.sqrt((x - center) ** 2 + (y - center) ** 2);
      if (dist < inner || dist > radius) continue;
      const i = (y * SAMPLE_SIZE + x) * 4;
      if (data[i + 3] < 128) continue;
      const chroma = Math.max(data[i], data[i + 1], data[i + 2])
                    - Math.min(data[i], data[i + 1], data[i + 2]);
      if (chroma < MIN_CHROMA) continue;
      const w = chroma * chroma;
      wr += data[i] * w;
      wg += data[i + 1] * w;
      wb += data[i + 2] * w;
      tw += w;
    }
  }

  if (tw < 1) return null;
  const [r, g, b] = liftToGlow(wr / tw, wg / tw, wb / tw);
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

// Extract glow color from a loaded image element.
export function extractGlowColor(img: HTMLImageElement): string | null {
  const canvas = document.createElement("canvas");
  canvas.width = SAMPLE_SIZE;
  canvas.height = SAMPLE_SIZE;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  try {
    ctx.drawImage(img, 0, 0, SAMPLE_SIZE, SAMPLE_SIZE);
    return edgeRingGlow(ctx.getImageData(0, 0, SAMPLE_SIZE, SAMPLE_SIZE).data);
  } catch {
    return null;
  }
}

// Extract glow color from raw RGBA at arbitrary resolution.
// Accepts reusable canvases to avoid allocation per call (e.g. per GIF frame).
export function extractGlowFromRgba(
  rgba: Uint8Array, w: number, h: number,
  srcCvs?: HTMLCanvasElement, dstCvs?: HTMLCanvasElement,
): string | null {
  const src = srcCvs ?? document.createElement("canvas");
  const dst = dstCvs ?? document.createElement("canvas");
  src.width = w;
  src.height = h;
  dst.width = SAMPLE_SIZE;
  dst.height = SAMPLE_SIZE;
  const srcCtx = src.getContext("2d");
  const dstCtx = dst.getContext("2d");
  if (!srcCtx || !dstCtx) return null;
  srcCtx.putImageData(new ImageData(new Uint8ClampedArray(rgba), w, h), 0, 0);
  dstCtx.drawImage(src, 0, 0, SAMPLE_SIZE, SAMPLE_SIZE);
  return edgeRingGlow(dstCtx.getImageData(0, 0, SAMPLE_SIZE, SAMPLE_SIZE).data);
}

// ── Gradient palette ────────────────────────────────────────────────
// Shared gradient palette for avatars and group icons.
// Each entry: [bright, dark, glow] — bright/dark form the gradient, glow is for active effects.
// 18 entries spaced ~20° across the hue wheel; cross-hue dark ends give depth.
const GRADIENT_SETS: [string, string, string][] = [
  ["#e05560", "#3a2464", "#ff7e92"],   // red
  ["#d07060", "#1c2844", "#ff9d83"],   // coral
  ["#e6a838", "#58122e", "#ffcc00"],   // amber
  ["#b0a840", "#241858", "#f3e400"],   // olive
  ["#80b048", "#381430", "#a7f92b"],   // lime
  ["#6aad58", "#281c3e", "#85fb63"],   // sage
  ["#48a850", "#2e1848", "#48ff61"],   // green
  ["#38c078", "#1c1c4a", "#00ff91"],   // mint
  ["#38b898", "#3a1828", "#00ffcf"],   // seafoam
  ["#40a8a8", "#401428", "#03f7f8"],   // cyan
  ["#38a8c8", "#1c4028", "#00f3ff"],   // teal
  ["#4878d8", "#2e1c1c", "#72c6ff"],   // steel
  ["#5e5ec4", "#1c7488", "#afaeff"],   // indigo
  ["#8f5fe6", "#2a2a6a", "#e4a5ff"],   // purple
  ["#a858c8", "#283018", "#ff94ff"],   // violet
  ["#b860b0", "#1c3020", "#ff8eff"],   // plum
  ["#d058a8", "#183838", "#ff85ff"],   // magenta
  ["#e05590", "#24163e", "#ff80d9"],   // pink
];

export interface Gradient {
  from: string;
  to: string;
  glow: string;
  angle: number;
}

// Deterministic gradient from any string (fingerprint, group ID, etc.)
export function hashGradient(key: string): Gradient {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) | 0;
  const set = GRADIENT_SETS[Math.abs(h) % GRADIENT_SETS.length];
  const angle = 120 + (Math.abs(h >> 8) % 90);
  return { from: set[0], to: set[1], glow: set[2], angle };
}

// Mouse-tracking flare handlers for .avatar-flare elements.
export function onFlareMove(e: MouseEvent) {
  const el = e.currentTarget as HTMLElement;
  const rect = el.getBoundingClientRect();
  const px = (e.clientX - rect.left) / rect.width;
  const py = (e.clientY - rect.top) / rect.height;
  el.style.setProperty("--flare-x", `${px * 100}%`);
  el.style.setProperty("--flare-y", `${py * 100}%`);
  el.style.setProperty("--flare-opacity", "1");
}

export function onFlareLeave(e: MouseEvent) {
  const el = e.currentTarget as HTMLElement;
  el.style.setProperty("--flare-opacity", "0");
}
