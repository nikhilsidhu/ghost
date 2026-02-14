import { Tooltip as KTooltip } from "@kobalte/core/tooltip";
import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface TooltipProps {
  label: string;
  placement?: "top" | "right" | "bottom" | "left";
  children: JSX.Element;
}

export function Tooltip(props: TooltipProps) {
  return (
    <KTooltip placement={props.placement ?? "right"} gutter={8} openDelay={400}>
      <KTooltip.Trigger as="div">
        {props.children}
      </KTooltip.Trigger>
      <KTooltip.Portal>
        <KTooltip.Content
          class={cn(
            "z-50 px-2.5 py-1.5 rounded-md text-xs font-medium",
            "text-[var(--neutral-100)] border border-[var(--neutral-700)]",
            "animate-[tooltip-in_120ms_ease-out]",
          )}
          style={{
            background: "var(--neutral-800)",
            "box-shadow": "0 4px 12px rgba(0, 0, 0, 0.4)",
          }}
        >
          {props.label}
        </KTooltip.Content>
      </KTooltip.Portal>
    </KTooltip>
  );
}
