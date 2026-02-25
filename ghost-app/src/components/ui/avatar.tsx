import { Show, createSignal, createEffect, onCleanup } from "solid-js";
import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { hashGradient, extractGlowColor, onFlareMove, onFlareLeave } from "../../lib/gradients";
import { avatarUrl } from "../../lib/store";
import { prepareGif } from "../../lib/gif";
import type { PlaybackFrame } from "../../lib/gif";

export type AvatarStatus = "online" | "idle" | "away";

const STATUS_COLORS: Record<AvatarStatus, string> = {
  online: "var(--emerald-400)",
  idle: "var(--amber-400)",
  away: "var(--ember-400)",
};

interface AvatarProps {
  hashKey: string;
  label: string;
  class?: string;
  square?: boolean;
  status?: AvatarStatus;
  children?: JSX.Element;
}

export function Avatar(props: AvatarProps) {
  const grad = () => hashGradient(props.hashKey);
  const [imgError, setImgError] = createSignal(false);
  const [imgGlow, setImgGlow] = createSignal<string | null>(null);
  const src = () => avatarUrl(props.hashKey);
  const showImg = () => src() && !imgError();
  const isGif = () => src()?.startsWith("data:image/gif") ?? false;

  let canvasRef: HTMLCanvasElement | undefined;

  // Static image glow extraction
  const onImgLoad = (e: Event) => {
    const color = extractGlowColor(e.target as HTMLImageElement);
    setImgGlow(color);
  };

  // GIF playback: decode, composite, drive canvas + glow in one rAF loop
  createEffect(() => {
    if (!showImg() || !isGif()) {
      setImgGlow(null);
      return;
    }

    let frames: PlaybackFrame[];
    try {
      frames = prepareGif(src()!);
    } catch {
      setImgGlow(null);
      return;
    }

    if (frames.length === 0) return;

    let frameIdx = 0;
    let lastTime = 0;
    let rafId: number;

    setImgGlow(frames[0].glowColor);

    // Set canvas dimensions once — resetting per frame clears context state
    if (canvasRef) {
      canvasRef.width = frames[0].imageData.width;
      canvasRef.height = frames[0].imageData.height;
    }

    const paint = () => {
      if (!canvasRef) return;
      const ctx = canvasRef.getContext("2d");
      if (!ctx) return;
      ctx.putImageData(frames[frameIdx].imageData, 0, 0);
    };

    paint();

    const tick = (now: number) => {
      if (!lastTime) lastTime = now;
      const elapsed = now - lastTime;
      const frame = frames[frameIdx];

      if (elapsed >= frame.delay) {
        frameIdx = (frameIdx + 1) % frames.length;
        setImgGlow(frames[frameIdx].glowColor);
        paint();
        lastTime = now;
      }

      rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);
    onCleanup(() => cancelAnimationFrame(rafId));
  });

  // Reset glow when image goes away (non-GIF path)
  createEffect(() => {
    if (!showImg() && !isGif()) setImgGlow(null);
  });

  return (
    <div
      class={cn(
        "avatar-flare relative flex items-center justify-center font-semibold flex-shrink-0",
        props.square ? "rounded-[14%]" : "rounded-full",
        props.class,
      )}
      style={{
        background: `linear-gradient(${grad().angle}deg, ${grad().from}, ${grad().to})`,
        color: "var(--neutral-100)",
        "--glow-color": imgGlow() ?? grad().glow,
      }}
      onMouseMove={onFlareMove}
      onMouseLeave={onFlareLeave}
    >
      <Show when={showImg()} fallback={props.children ?? props.label[0]?.toLowerCase()}>
        <Show
          when={isGif()}
          fallback={
            <img
              src={src()}
              alt=""
              class={cn(
                "absolute inset-0 w-full h-full object-cover",
                props.square ? "rounded-[14%]" : "rounded-full",
              )}
              onError={() => setImgError(true)}
              onLoad={onImgLoad}
            />
          }
        >
          <canvas
            ref={canvasRef}
            class={cn(
              "absolute inset-0 w-full h-full object-cover",
              props.square ? "rounded-[14%]" : "rounded-full",
            )}
          />
        </Show>
      </Show>
      <Show when={props.status}>
        <div
          class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-[var(--neutral-950)]"
          style={{ background: STATUS_COLORS[props.status!] }}
        />
      </Show>
    </div>
  );
}
