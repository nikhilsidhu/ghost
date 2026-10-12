import { createSignal, For, onCleanup, Show } from "solid-js";
import { ChevronDown } from "lucide-solid";
import { cn } from "../../lib/cn";
import { floatingClass, floatingStyle } from "./popover";

/** A choice from a list too long to show side by side: a button showing the chosen option
 * that drops the list below it. */
export function Select<T extends string>(props: {
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  label?: string;
  disabled?: boolean;
  /** Which edge of the button the list lines up with. */
  align?: "left" | "right";
}) {
  const [open, setOpen] = createSignal(false);
  let ref!: HTMLDivElement;

  const selected = () => props.options.find((o) => o.value === props.value);

  const handleClickOutside = (e: MouseEvent) => {
    if (open() && ref && !ref.contains(e.target as Node)) setOpen(false);
  };
  document.addEventListener("mousedown", handleClickOutside);
  onCleanup(() => document.removeEventListener("mousedown", handleClickOutside));

  return (
    <div ref={ref} class="relative flex-shrink-0">
      <button
        class={cn(
          "h-7 rounded px-2.5 text-xs flex items-center gap-1.5 cursor-pointer transition-colors duration-150",
          "bg-[var(--neutral-800)] text-[var(--neutral-200)]",
          "border border-[var(--neutral-700)]",
          "hover:border-[var(--neutral-600)]",
          open() && "border-[var(--purple-500)]",
        )}
        aria-label={props.label}
        aria-haspopup="listbox"
        aria-expanded={open()}
        disabled={props.disabled}
        onClick={() => setOpen((v) => !v)}
      >
        {selected()?.label ?? props.value}
        <ChevronDown size={12} class={cn(
          "text-[var(--neutral-500)] transition-transform duration-150",
          open() && "rotate-180",
        )} />
      </button>
      <Show when={open()}>
        <div
          role="listbox"
          class={cn(floatingClass, "absolute top-full mt-1 min-w-full py-1", props.align === "left" ? "left-0" : "right-0")}
          style={floatingStyle}
        >
          <For each={props.options}>
            {(o) => (
              <button
                role="option"
                aria-selected={o.value === props.value}
                class={cn(
                  "w-full text-left px-2.5 py-1.5 text-xs cursor-pointer transition-colors duration-100",
                  o.value === props.value
                    ? "text-[var(--purple-400)]"
                    : "text-[var(--neutral-300)] hover:bg-[var(--neutral-700)]",
                )}
                onClick={() => { props.onChange(o.value); setOpen(false); }}
              >
                {o.label}
              </button>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
