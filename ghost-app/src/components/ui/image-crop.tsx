import { createSignal } from "solid-js";

const CROP_SIZE = 220;
const CROP_RADIUS = CROP_SIZE / 2;
const OUTPUT_SIZE = 256;
const BUTTONS_HEIGHT = 36;
const GAP = 12;
export const CROP_AREA_HEIGHT = CROP_SIZE + GAP + BUTTONS_HEIGHT;

interface ImageCropProps {
  image: HTMLImageElement;
  uploading: boolean;
  onConfirm: (bytes: number[]) => void;
  onCancel: () => void;
}

export function ImageCrop(props: ImageCropProps) {
  const [offsetX, setOffsetX] = createSignal(0);
  const [offsetY, setOffsetY] = createSignal(0);
  const [zoom, setZoom] = createSignal(1);

  // Fit short side to crop area, then apply zoom
  const scale = () =>
    (CROP_SIZE / Math.min(props.image.naturalWidth, props.image.naturalHeight)) * zoom();

  const clampOffset = (ox: number, oy: number): [number, number] => {
    const s = scale();
    return [
      Math.min(0, Math.max(CROP_SIZE - props.image.naturalWidth * s, ox)),
      Math.min(0, Math.max(CROP_SIZE - props.image.naturalHeight * s, oy)),
    ];
  };

  // Center image on mount
  const initScale = CROP_SIZE / Math.min(props.image.naturalWidth, props.image.naturalHeight);
  setOffsetX((CROP_SIZE - props.image.naturalWidth * initScale) / 2);
  setOffsetY((CROP_SIZE - props.image.naturalHeight * initScale) / 2);

  const onMouseDown = (e: MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startY = e.clientY;
    const origX = offsetX();
    const origY = offsetY();
    const onMove = (ev: MouseEvent) => {
      const [cx, cy] = clampOffset(origX + ev.clientX - startX, origY + ev.clientY - startY);
      setOffsetX(cx);
      setOffsetY(cy);
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const onWheel = (e: WheelEvent) => {
    e.preventDefault();
    const delta = -e.deltaY * 0.003;
    const newZoom = Math.max(1, Math.min(5, zoom() * Math.pow(2, delta)));

    const oldS = scale();
    const baseS = CROP_SIZE / Math.min(props.image.naturalWidth, props.image.naturalHeight);
    const newS = baseS * newZoom;
    const ratio = newS / oldS;

    const newOx = CROP_RADIUS - (CROP_RADIUS - offsetX()) * ratio;
    const newOy = CROP_RADIUS - (CROP_RADIUS - offsetY()) * ratio;

    setZoom(newZoom);
    const [cx, cy] = clampOffset(newOx, newOy);
    setOffsetX(cx);
    setOffsetY(cy);
  };

  const confirm = async () => {
    const s = scale();
    const sx = -offsetX() / s;
    const sy = -offsetY() / s;
    const sSize = CROP_SIZE / s;

    const canvas = document.createElement("canvas");
    canvas.width = OUTPUT_SIZE;
    canvas.height = OUTPUT_SIZE;
    const ctx = canvas.getContext("2d")!;
    ctx.drawImage(props.image, sx, sy, sSize, sSize, 0, 0, OUTPUT_SIZE, OUTPUT_SIZE);

    const blob = await new Promise<Blob>((resolve) =>
      canvas.toBlob((b) => resolve(b!), "image/webp", 0.85),
    );
    const bytes = Array.from(new Uint8Array(await blob.arrayBuffer()));
    props.onConfirm(bytes);
  };

  return (
    <div class="flex flex-col items-center gap-3 pt-1">
      <div
        class="relative overflow-hidden cursor-grab active:cursor-grabbing select-none"
        style={{ width: `${CROP_SIZE}px`, height: `${CROP_SIZE}px` }}
        onMouseDown={onMouseDown}
        onWheel={onWheel}
      >
        <img
          src={props.image.src}
          class="absolute pointer-events-none select-none"
          style={{
            "transform-origin": "0 0",
            transform: `translate(${offsetX()}px, ${offsetY()}px) scale(${scale()})`,
            "max-width": "none",
          }}
          draggable={false}
        />
        <div
          class="absolute inset-0 pointer-events-none rounded-full"
          style={{ "box-shadow": "0 0 0 9999px rgba(10,10,10,0.7)" }}
        />
        <div
          class="absolute inset-0 pointer-events-none rounded-full"
          style={{ border: "1px solid rgba(255,255,255,0.12)" }}
        />
      </div>
      <div class="flex gap-2">
        <button
          class="px-4 py-1.5 rounded-md text-xs font-medium text-[var(--neutral-300)] bg-[var(--neutral-800)] hover:bg-[var(--neutral-700)] cursor-pointer"
          onClick={props.onCancel}
          disabled={props.uploading}
        >
          cancel
        </button>
        <button
          class="px-4 py-1.5 rounded-md text-xs font-medium text-[var(--neutral-100)] bg-[var(--purple-600)] hover:bg-[var(--purple-500)] cursor-pointer disabled:opacity-50"
          onClick={confirm}
          disabled={props.uploading}
        >
          {props.uploading ? "uploading..." : "save"}
        </button>
      </div>
    </div>
  );
}
