import { createSignal, onMount, onCleanup, Show, For } from "solid-js";
import { Keyboard } from "lucide-solid";
import { findShortcut, type ShortcutDef } from "../lib/shortcuts";
import { KeyBadge } from "./KeyBadge";

export type { ShortcutDef };

interface Props {
  shortcuts: ShortcutDef[];
  forceOpen?: boolean;
  onClose?: () => void;
}

export function ShortcutOverlay(props: Props) {
  const [visible, setVisible] = createSignal(false);

  const isInputFocused = () => {
    const tag = document.activeElement?.tagName;
    return tag === "INPUT" || tag === "TEXTAREA";
  };

  onMount(() => {
    const def = findShortcut("shortcuts");
    const onDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && (visible() || props.forceOpen)) {
        e.preventDefault();
        setVisible(false);
        props.onClose?.();
        return;
      }
      if (def.match(e) && !isInputFocused()) {
        e.preventDefault();
        setVisible(true);
      }
    };
    const onUp = (e: KeyboardEvent) => {
      if (e.key === "Shift" || def.keys.includes(e.key)) {
        setVisible(false);
      }
    };
    document.addEventListener("keydown", onDown);
    document.addEventListener("keyup", onUp);
    onCleanup(() => {
      document.removeEventListener("keydown", onDown);
      document.removeEventListener("keyup", onUp);
    });
  });

  const shown = () => visible() || props.forceOpen;

  const handleBackdropClick = () => {
    setVisible(false);
    props.onClose?.();
  };

  return (
    <Show when={shown()}>
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
        onClick={handleBackdropClick}
      >
        <div
          class="w-96 rounded-lg border border-[var(--neutral-700)] bg-[var(--neutral-900)] p-6 shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <div class="flex items-center gap-2.5 mb-5">
            <Keyboard size={18} strokeWidth={2.5} class="text-[var(--purple-400)]" />
            <span class="text-base font-medium text-[var(--neutral-100)]">keyboard shortcuts</span>
          </div>
          <div class="flex flex-col gap-3">
            <For each={props.shortcuts}>
              {(s) => (
                <div class="flex items-center justify-between gap-4">
                  <span class="text-sm text-[var(--neutral-300)]">{s.label}</span>
                  <div class="flex items-center gap-1 flex-shrink-0">
                    <For each={s.keys}>
                      {(k) => <KeyBadge value={k} size="lg" />}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </div>
          <p class="text-xs text-[var(--neutral-600)] mt-5 text-center">
            hold <KeyBadge value="?" size="lg" /> or <span class="text-[var(--purple-400)]">/info</span> to show &middot; <KeyBadge value="Esc" size="lg" /> to dismiss
          </p>
        </div>
      </div>
    </Show>
  );
}
