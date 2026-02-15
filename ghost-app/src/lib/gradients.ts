// Shared gradient palette for avatars and group icons.
// Each entry: [bright, dark, glow] — bright/dark form the gradient, glow is for active effects.
// 18 entries spaced ~20° across the hue wheel; cross-hue dark ends give depth.
const GRADIENT_SETS: [string, string, string][] = [
  ["#e05560", "#3a2464", "#f08088"],   // red
  ["#d07060", "#1c2844", "#f0a898"],   // coral
  ["#e6a838", "#58122e", "#ffc264"],   // amber
  ["#b0a840", "#241858", "#d0c878"],   // olive
  ["#80b048", "#381430", "#a8d080"],   // lime
  ["#6aad58", "#281c3e", "#a0d890"],   // sage
  ["#48a850", "#2e1848", "#78d088"],   // green
  ["#38c078", "#1c1c4a", "#60e098"],   // mint
  ["#38b898", "#3a1828", "#68d8b8"],   // seafoam
  ["#40a8a8", "#401428", "#68c8c8"],   // cyan
  ["#38a8c8", "#1c4028", "#64c4e6"],   // teal
  ["#4878d8", "#2e1c1c", "#88aaf0"],   // steel
  ["#5e5ec4", "#1c7488", "#ababff"],   // indigo
  ["#8f5fe6", "#2a2a6a", "#c4abff"],   // purple
  ["#a858c8", "#283018", "#c898e8"],   // violet
  ["#b860b0", "#1c3020", "#d8a0d0"],   // plum
  ["#d058a8", "#183838", "#e898c8"],   // magenta
  ["#e05590", "#24163e", "#ffabcc"],   // pink
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
// Sets CSS custom properties that the ::after pseudo-element reads.
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
