import { Tooltip as KTooltip } from "@kobalte/core/tooltip";
import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { floatingClass, floatingStyle } from "./popover";

interface TooltipProps {
  label: string;
  placement?: "top" | "right" | "bottom" | "left";
  gutter?: number;
  children: JSX.Element;
}

export function Tooltip(props: TooltipProps) {
  return (
    <KTooltip placement={props.placement ?? "right"} gutter={props.gutter ?? 12} openDelay={400}>
      <KTooltip.Trigger as="div">
        {props.children}
      </KTooltip.Trigger>
      <KTooltip.Portal>
        <KTooltip.Content class={cn(floatingClass, "px-2.5 py-1.5 text-xs font-medium animate-[tooltip-in_120ms_ease-out]")} style={floatingStyle}>
          {props.label}
        </KTooltip.Content>
      </KTooltip.Portal>
    </KTooltip>
  );
}
