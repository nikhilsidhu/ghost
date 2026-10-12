import { For } from "solid-js";
import { Tabs as KTabs } from "@kobalte/core/tabs";
import { cn } from "../../lib/cn";

type Size = "sm" | "md";

const sizeStyles: Record<Size, string> = {
  sm: "h-6 px-2 text-xs",
  md: "h-7 px-2.5 text-sm",
};

/** A row of tabs; the selected one takes the highlight of a selected channel. The caller
 * shows the content for `value`. */
export function Tabs<T extends string>(props: {
  value: T;
  onChange: (value: T) => void;
  tabs: readonly { value: T; label: string }[];
  label: string;
  size?: Size;
}) {
  return (
    <KTabs value={props.value} onChange={(value) => props.onChange(value as T)}>
      <KTabs.List class="flex items-center gap-1" aria-label={props.label}>
        <For each={props.tabs}>
          {(tab) => (
            <KTabs.Trigger
              value={tab.value}
              class={cn(
                "rounded-md cursor-pointer transition-colors duration-150 outline-none",
                "focus-visible:ring-1 focus-visible:ring-[var(--purple-400)]",
                sizeStyles[props.size ?? "md"],
                tab.value === props.value
                  ? "bg-[var(--active)] text-[var(--neutral-100)]"
                  : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
              )}
            >
              {tab.label}
            </KTabs.Trigger>
          )}
        </For>
      </KTabs.List>
    </KTabs>
  );
}
