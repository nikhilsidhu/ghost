import { createSignal, onMount, onCleanup, Show, For } from "solid-js";
import {
  Search, Terminal, ArrowUp, ArrowDown, CornerDownLeft,
  Keyboard, MessageSquare, X, TabletSmartphone,
} from "lucide-solid";
import type { JSX } from "solid-js";

const isMac = navigator.platform.includes("Mac");
const mod = isMac ? "\u2318" : "Ctrl";

interface Shortcut {
  keys: string[];
  label: string;
  icon: () => JSX.Element;
}

const shortcuts: Shortcut[] = [
  {
    keys: [mod, "K"],
    label: "Search groups",
    icon: () => <Search size={14} />,
  },
  {
    keys: [mod, "\u21e7", "K"],
    label: "Command palette",
    icon: () => <Terminal size={14} />,
  },
  {
    keys: ["\u21b5"],
    label: "Send message / confirm",
    icon: () => <CornerDownLeft size={14} />,
  },
  {
    keys: ["\u2191", "\u2193"],
    label: "Navigate lists",
    icon: () => <ArrowUp size={14} />,
  },
  {
    keys: ["Tab"],
    label: "Autocomplete",
    icon: () => <TabletSmartphone size={14} />,
  },
  {
    keys: ["Esc"],
    label: "Close dialog",
    icon: () => <X size={14} />,
  },
  {
    keys: ["?"],
    label: "Show this overlay",
    icon: () => <Keyboard size={14} />,
  },
];

function Kbd(props: { children: string }) {
  return (
    <kbd class="inline-flex items-center justify-center min-w-[22px] h-[22px] px-1.5 rounded text-[11px] font-medium bg-[var(--neutral-700)] text-[var(--neutral-300)] border border-[var(--neutral-600)]">
      {props.children}
    </kbd>
  );
}

interface Props {
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
    const onDown = (e: KeyboardEvent) => {
      if (e.key === "?" && !isInputFocused() && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        setVisible(true);
      }
    };
    const onUp = (e: KeyboardEvent) => {
      if (e.key === "?" || e.key === "Shift") {
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
          class="w-80 rounded-lg border border-[var(--neutral-700)] bg-[var(--neutral-900)] p-5 shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <div class="flex items-center gap-2 mb-4">
            <Keyboard size={16} class="text-[var(--purple-400)]" />
            <span class="text-sm font-medium text-[var(--neutral-100)]">keyboard shortcuts</span>
          </div>
          <div class="flex flex-col gap-2.5">
            <For each={shortcuts}>
              {(s) => (
                <div class="flex items-center gap-3">
                  <span class="text-[var(--purple-400)] flex-shrink-0 w-4">{s.icon()}</span>
                  <span class="flex-1 text-xs text-[var(--neutral-400)]">{s.label}</span>
                  <div class="flex items-center gap-0.5">
                    <For each={s.keys}>
                      {(k) => <Kbd>{k}</Kbd>}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </div>
          <p class="text-[10px] text-[var(--neutral-600)] mt-4 text-center">
            hold <Kbd>?</Kbd> to show &middot; release to dismiss
          </p>
        </div>
      </div>
    </Show>
  );
}
