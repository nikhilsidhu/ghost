import type { JSX } from "solid-js";

/** The top of a full-height panel: room for the overlaid title bar, which drags the
 * window, then the panel's title (after `icon`, when given) and its controls. */
export function PanelHeader(props: { title: string; icon?: JSX.Element; children?: JSX.Element }) {
  return (
    <>
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />
      <div class="h-[var(--size-lg)] flex items-center gap-2 px-4 flex-shrink-0 -mt-1">
        {props.icon}
        <span class="text-base font-semibold text-[var(--neutral-100)]">{props.title}</span>
        {props.children}
      </div>
    </>
  );
}
