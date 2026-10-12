import type { JSX } from "solid-js";
import { Popover as KPopover } from "@kobalte/core/popover";
import { cn } from "../../lib/cn";

/** The look of anything floating over the page: tooltips, dropdowns, hover cards, popovers. */
export const floatingClass = "z-50 rounded-md border border-[var(--neutral-700)] bg-[var(--neutral-800)] text-[var(--neutral-100)]";
export const floatingStyle = { "box-shadow": "var(--shadow-float)" } as const;

/** A panel that opens when its trigger is clicked. */
export function Popover(props: {
  trigger: JSX.Element;
  /** What the trigger opens, for screen readers. */
  label: string;
  triggerClass?: string;
  placement?: "top" | "right" | "bottom" | "left" | "bottom-end" | "bottom-start";
  children: JSX.Element;
}) {
  return (
    <KPopover placement={props.placement ?? "bottom-end"} gutter={6}>
      <KPopover.Trigger class={props.triggerClass} aria-label={props.label}>
        {props.trigger}
      </KPopover.Trigger>
      <KPopover.Portal>
        <KPopover.Content class={cn(floatingClass, "p-3 text-xs animate-[tooltip-in_120ms_ease-out]")} style={floatingStyle}>
          {props.children}
        </KPopover.Content>
      </KPopover.Portal>
    </KPopover>
  );
}
