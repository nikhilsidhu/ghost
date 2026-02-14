import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { hashGradient, onFlareMove, onFlareLeave } from "../../lib/gradients";

interface AvatarProps {
  hashKey: string;
  label: string;
  class?: string;
  square?: boolean;
  active?: boolean;
  children?: JSX.Element;
}

export function Avatar(props: AvatarProps) {
  const grad = () => hashGradient(props.hashKey);

  return (
    <div
      class={cn(
        "avatar-flare flex items-center justify-center font-semibold flex-shrink-0",
        props.square ? "rounded-[14%]" : "rounded-full",
        props.class,
      )}
      classList={{ "glow-active": props.active }}
      style={{
        background: `linear-gradient(${grad().angle}deg, ${grad().from}, ${grad().to})`,
        color: "var(--neutral-100)",
        "--glow-color": grad().glow,
      }}
      onMouseMove={onFlareMove}
      onMouseLeave={onFlareLeave}
    >
      {props.children ?? props.label[0]?.toUpperCase()}
    </div>
  );
}
