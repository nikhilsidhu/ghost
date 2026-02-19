import { createSignal, onMount, onCleanup, Show } from "solid-js";
import { getKeybinds, setKeybind } from "../../lib/api";
import { setPttShortcut } from "../../lib/keybinds";
import { SettingGroup } from "./controls";
import { cn } from "../../lib/cn";
import { X } from "lucide-solid";

// Maps browser KeyboardEvent to tauri global-shortcut format
function formatShortcut(e: KeyboardEvent): string | null {
  const key = e.key;

  const parts: string[] = [];
  if (e.ctrlKey) parts.push("Control");
  if (e.altKey) parts.push("Alt");
  if (e.shiftKey) parts.push("Shift");
  if (e.metaKey) parts.push("Super");

  // Global shortcuts need at least one modifier
  if (parts.length === 0) return null;

  let normalized = key;
  if (key === " ") normalized = "Space";
  else if (key.length === 1) normalized = key.toUpperCase();

  parts.push(normalized);
  return parts.join("+");
}

export default function KeybindsSettings() {
  const [shortcut, setShortcut] = createSignal<string | null>(null);
  const [recording, setRecording] = createSignal(false);
  const [hint, setHint] = createSignal<string | null>(null);

  onMount(async () => {
    const kb = await getKeybinds();
    setShortcut(kb.push_to_talk);
  });

  const handleKeyDown = (e: KeyboardEvent) => {
    if (!recording()) return;
    e.preventDefault();
    e.stopPropagation();

    if (e.key === "Escape") {
      setRecording(false);
      setHint(null);
      return;
    }

    // Ignore bare modifier presses — wait for the full combo
    if (["Control", "Shift", "Alt", "Meta"].includes(e.key)) return;

    const combo = formatShortcut(e);
    if (!combo) {
      setHint("use a modifier (alt, ctrl, shift, cmd) + key");
      return;
    }

    setRecording(false);
    setHint(null);
    setShortcut(combo);
    setKeybind("push_to_talk", combo).catch(() => {});
    setPttShortcut(combo);
  };

  // Always attached, gated by recording() check inside
  window.addEventListener("keydown", handleKeyDown, { capture: true });
  onCleanup(() => window.removeEventListener("keydown", handleKeyDown, { capture: true }));

  const clearShortcut = () => {
    setShortcut(null);
    setKeybind("push_to_talk", null).catch(() => {});
    setPttShortcut(null);
  };

  const displayShortcut = () => {
    const s = shortcut();
    if (!s) return "not set";
    return s.replace(/\+/g, " + ");
  };

  return (
    <div>
      <SettingGroup label="voice">
        <div class="py-3 border-b border-[var(--neutral-800)] last:border-b-0">
          <div class="flex items-center justify-between gap-4">
            <div class="min-w-0">
              <div class="text-sm text-[var(--neutral-200)]">push to talk</div>
              <div class="text-xs text-[var(--neutral-500)] mt-0.5">
                hold to unmute while in a voice call
              </div>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              <Show when={shortcut() && !recording()}>
                <button
                  class="text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer transition-colors duration-150"
                  onClick={clearShortcut}
                  title="clear"
                >
                  <X size={13} />
                </button>
              </Show>
              <button
                class={cn(
                  "h-7 rounded px-3 text-xs cursor-pointer transition-all duration-150 min-w-[100px]",
                  "border",
                  recording()
                    ? "bg-[var(--neutral-800)] text-[var(--purple-400)] border-[var(--purple-500)] animate-pulse"
                    : shortcut()
                      ? "bg-[var(--neutral-800)] text-[var(--neutral-200)] border-[var(--neutral-700)] hover:border-[var(--neutral-600)]"
                      : "bg-[var(--neutral-800)] text-[var(--neutral-500)] border-[var(--neutral-700)] hover:border-[var(--neutral-600)]",
                )}
                onClick={() => { setRecording(true); setHint(null); }}
              >
                {recording() ? "press a key..." : displayShortcut()}
              </button>
            </div>
          </div>
          <Show when={hint()}>
            <div class="text-xs text-[var(--amber-400)] mt-2">{hint()}</div>
          </Show>
        </div>
      </SettingGroup>
    </div>
  );
}
