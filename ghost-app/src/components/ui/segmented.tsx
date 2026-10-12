import { For } from "solid-js";
import { cn } from "../../lib/cn";

/** A choice between a few options shown side by side, the chosen one highlighted. */
export function Segmented<T extends string>(props: {
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <div class="flex rounded-md border border-[var(--neutral-700)] overflow-hidden flex-shrink-0" role="radiogroup" aria-label={props.label}>
      <For each={props.options}>
        {(option) => (
          <button
            role="radio"
            aria-checked={option.value === props.value}
            class={cn(
              "h-7 px-2.5 text-xs cursor-pointer transition-colors duration-150",
              "border-r border-[var(--neutral-700)] last:border-r-0",
              option.value === props.value
                ? "bg-[var(--purple-500)]/20 text-[var(--purple-400)]"
                : "bg-[var(--neutral-800)] text-[var(--neutral-400)] hover:text-[var(--neutral-200)]",
            )}
            disabled={props.disabled}
            onClick={() => props.onChange(option.value)}
          >
            {option.label}
          </button>
        )}
      </For>
    </div>
  );
}
