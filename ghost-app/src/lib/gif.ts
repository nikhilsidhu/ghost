import { GifReader, GifWriter } from "omggif";
import { extractGlowFromRgba } from "./gradients";

// Composited frame: full RGBA at the GIF's native resolution.
interface ComposedFrame {
  rgba: Uint8Array;
  delay: number; // milliseconds
}

// Ready-to-render frame for the Avatar canvas playback.
export interface PlaybackFrame {
  imageData: ImageData;
  glowColor: string | null;
  delay: number;
}

// Decode all GIF frames, handling disposal methods to produce full composited RGBA.
function compositeFrames(reader: GifReader): ComposedFrame[] {
  const w = reader.width;
  const h = reader.height;
  const canvas = new Uint8Array(w * h * 4);
  const frames: ComposedFrame[] = [];

  for (let i = 0; i < reader.numFrames(); i++) {
    const info = reader.frameInfo(i);
    const previous = info.disposal === 3 ? new Uint8Array(canvas) : null;

    reader.decodeAndBlitFrameRGBA(i, canvas);

    frames.push({
      rgba: new Uint8Array(canvas),
      delay: Math.max(info.delay * 10, 20),
    });

    if (info.disposal === 2) {
      for (let y = info.y; y < info.y + info.height; y++) {
        for (let x = info.x; x < info.x + info.width; x++) {
          const idx = (y * w + x) * 4;
          canvas[idx] = canvas[idx + 1] = canvas[idx + 2] = canvas[idx + 3] = 0;
        }
      }
    } else if (info.disposal === 3 && previous) {
      canvas.set(previous);
    }
  }

  return frames;
}

// Decode base64 data URL to raw bytes.
function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(",")[1];
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Prepare a GIF data URL for canvas playback — composited ImageData + glow per frame.
export function prepareGif(dataUrl: string): PlaybackFrame[] {
  const bytes = dataUrlToBytes(dataUrl);
  const reader = new GifReader(bytes as any);
  const composed = compositeFrames(reader);

  // Reuse canvases across all frames to avoid per-frame allocation
  const srcCvs = document.createElement("canvas");
  const dstCvs = document.createElement("canvas");

  return composed.map((frame) => ({
    imageData: new ImageData(new Uint8ClampedArray(frame.rgba), reader.width, reader.height),
    glowColor: extractGlowFromRgba(frame.rgba, reader.width, reader.height, srcCvs, dstCvs),
    delay: frame.delay,
  }));
}

// Weighted median-cut quantization: reduce RGBA to indexed palette.
function medianCut(entries: [number, number][], maxColors: number): number[] {
  type Box = [number, number][];
  let boxes: Box[] = [entries];

  while (boxes.length < maxColors) {
    let bestIdx = -1;
    let bestRange = 0;
    let bestCh = 0;

    for (let i = 0; i < boxes.length; i++) {
      if (boxes[i].length <= 1) continue;
      for (let ch = 0; ch < 3; ch++) {
        const shift = (2 - ch) * 8;
        let mn = 255, mx = 0;
        for (const [rgb] of boxes[i]) {
          const v = (rgb >> shift) & 0xff;
          if (v < mn) mn = v;
          if (v > mx) mx = v;
        }
        if (mx - mn > bestRange) {
          bestRange = mx - mn;
          bestIdx = i;
          bestCh = shift;
        }
      }
    }

    if (bestIdx < 0 || bestRange === 0) break;

    const box = boxes[bestIdx];
    box.sort((a, b) => ((a[0] >> bestCh) & 0xff) - ((b[0] >> bestCh) & 0xff));
    const mid = box.length >> 1;
    boxes.splice(bestIdx, 1, box.slice(0, mid), box.slice(mid));
  }

  return boxes.map((box) => {
    let tr = 0, tg = 0, tb = 0, tw = 0;
    for (const [rgb, count] of box) {
      tr += ((rgb >> 16) & 0xff) * count;
      tg += ((rgb >> 8) & 0xff) * count;
      tb += (rgb & 0xff) * count;
      tw += count;
    }
    return (Math.round(tr / tw) << 16) | (Math.round(tg / tw) << 8) | Math.round(tb / tw);
  });
}

function quantize(rgba: Uint8ClampedArray, npx: number) {
  const colorMap = new Map<number, number>();
  let hasAlpha = false;

  for (let i = 0; i < npx; i++) {
    const pi = i * 4;
    if (rgba[pi + 3] < 128) { hasAlpha = true; continue; }
    const key = (rgba[pi] << 16) | (rgba[pi + 1] << 8) | rgba[pi + 2];
    colorMap.set(key, (colorMap.get(key) || 0) + 1);
  }

  const maxPalette = hasAlpha ? 255 : 256;
  let paletteRgb: number[];

  if (colorMap.size <= maxPalette) {
    paletteRgb = [...colorMap.keys()];
  } else {
    paletteRgb = medianCut([...colorMap.entries()], maxPalette);
  }

  const palette = paletteRgb.slice();
  let transparentIndex: number | null = null;
  if (hasAlpha) {
    transparentIndex = palette.length;
    palette.push(0x000000);
  }

  // Pad to power of 2 (GIF spec requirement)
  const minSize = 1 << Math.ceil(Math.log2(Math.max(2, palette.length)));
  while (palette.length < minSize) palette.push(0);

  // Build a fast lookup for exact matches
  const exactMap = new Map<number, number>();
  for (let j = 0; j < paletteRgb.length; j++) exactMap.set(paletteRgb[j], j);

  const indices = new Uint8Array(npx);
  for (let i = 0; i < npx; i++) {
    const pi = i * 4;
    if (rgba[pi + 3] < 128) { indices[i] = transparentIndex!; continue; }

    const key = (rgba[pi] << 16) | (rgba[pi + 1] << 8) | rgba[pi + 2];
    const exact = exactMap.get(key);
    if (exact !== undefined) { indices[i] = exact; continue; }

    // Nearest color (brute force — fine for ≤256 palette)
    let best = 0, bestDist = Infinity;
    const r = rgba[pi], g = rgba[pi + 1], b = rgba[pi + 2];
    for (let j = 0; j < paletteRgb.length; j++) {
      const pr = (paletteRgb[j] >> 16) & 0xff;
      const pg = (paletteRgb[j] >> 8) & 0xff;
      const pb = paletteRgb[j] & 0xff;
      const d = (r - pr) ** 2 + (g - pg) ** 2 + (b - pb) ** 2;
      if (d < bestDist) { bestDist = d; best = j; }
    }
    indices[i] = best;
  }

  return { palette, indices, transparentIndex };
}

// Crop a GIF: decode all frames, crop each to the selected region, re-encode.
// sx, sy, sSize are in source pixel coordinates; outputSize is the output square dimension.
export function cropGif(
  srcBytes: Uint8Array,
  sx: number, sy: number, sSize: number,
  outputSize: number,
): Uint8Array {
  const reader = new GifReader(srcBytes as any);
  const composed = compositeFrames(reader);

  // Canvas for cropping each frame
  const srcCvs = document.createElement("canvas");
  srcCvs.width = reader.width;
  srcCvs.height = reader.height;
  const srcCtx = srcCvs.getContext("2d")!;

  const outCvs = document.createElement("canvas");
  outCvs.width = outputSize;
  outCvs.height = outputSize;
  const outCtx = outCvs.getContext("2d")!;

  // Generous buffer: header + per-frame overhead + pixel data (LZW compressed)
  const bufSize = outputSize * outputSize * composed.length * 2 + 32768;
  const buf = new Uint8Array(bufSize);
  const loop = reader.loopCount();
  const writer = new GifWriter(buf as any, outputSize, outputSize, { loop: loop === 0 ? 0 : loop || 0 });

  for (const frame of composed) {
    const imgData = new ImageData(new Uint8ClampedArray(frame.rgba), reader.width, reader.height);
    srcCtx.putImageData(imgData, 0, 0);

    outCtx.clearRect(0, 0, outputSize, outputSize);
    outCtx.drawImage(srcCvs, sx, sy, sSize, sSize, 0, 0, outputSize, outputSize);

    const cropped = outCtx.getImageData(0, 0, outputSize, outputSize);
    const npx = outputSize * outputSize;
    const { palette, indices, transparentIndex } = quantize(cropped.data, npx);

    const opts: { palette: number[]; delay: number; disposal: number; transparent?: number } = {
      palette,
      delay: Math.round(frame.delay / 10),
      disposal: 2,
    };
    if (transparentIndex !== null) opts.transparent = transparentIndex;

    writer.addFrame(0, 0, outputSize, outputSize, Array.from(indices), opts);
  }

  const end = writer.end();
  return buf.slice(0, end);
}
