import { Show, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

/** The look of a small button in a section's title row, such as its +. */
export const navActionClass = cn(
  "w-6 h-6 flex items-center justify-center rounded-md text-sm leading-none cursor-pointer",
  "text-[var(--neutral-500)] hover:text-[var(--neutral-200)] hover:bg-[var(--hover)]",
);

/** A titled group of side list entries, with a + button when entries can be added to it
 * and room for other `actions` on the whole group before it. Collapsible when given
 * `onToggle`; the caller keeps whether it is collapsed. */
export function NavSection(props: {
  label: string;
  collapsed?: boolean;
  onToggle?: () => void;
  onAdd?: () => void;
  /** What + adds, for screen readers. */
  addLabel?: string;
  actions?: JSX.Element;
  class?: string;
  children: JSX.Element;
}) {
  return (
    <div class={props.class}>
      <div class="flex items-center justify-between px-3 py-1 min-h-8">
        <Show when={props.onToggle} fallback={<span class="text-sm font-medium text-[var(--neutral-500)]">{props.label}</span>}>
          {(toggle) => (
            <button
              class="flex items-center gap-1 text-sm font-medium text-[var(--neutral-500)] cursor-pointer hover:text-[var(--neutral-400)]"
              aria-expanded={!props.collapsed}
              onClick={() => toggle()()}
            >
              <span class="text-[10px]">{props.collapsed ? "▸" : "▾"}</span>
              {props.label}
            </button>
          )}
        </Show>
        <div class="flex items-center gap-1">
          {props.actions}
          <Show when={props.onAdd}>
            {(add) => (
              <button class={navActionClass} aria-label={props.addLabel} onClick={() => add()()}>
                +
              </button>
            )}
          </Show>
        </div>
      </div>
      <Show when={!props.collapsed}>
        <div class="px-2">{props.children}</div>
      </Show>
    </div>
  );
}
