import { Show } from "solid-js";
import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { hashGradient, onFlareMove, onFlareLeave } from "../../lib/gradients";

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
  active?: boolean;
  status?: AvatarStatus;
  children?: JSX.Element;
}

export function Avatar(props: AvatarProps) {
  const grad = () => hashGradient(props.hashKey);

  return (
    <div
      class={cn(
        "avatar-flare relative flex items-center justify-center font-semibold flex-shrink-0",
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
      {props.children ?? props.label[0]?.toLowerCase()}
      <Show when={props.status}>
        <div
          class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-[var(--neutral-950)]"
          style={{ background: STATUS_COLORS[props.status!] }}
        />
      </Show>
    </div>
  );
}
