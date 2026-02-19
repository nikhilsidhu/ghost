import { Show } from "solid-js";
import { Dynamic } from "solid-js/web";
import { X } from "lucide-solid";
import { ScrollArea } from "./ui/scroll-area";
import { settingsCategory } from "../lib/store";
import { sections } from "../lib/settings-registry";

export function SettingsPanel(props: { onClose: () => void }) {
  const activeSection = () => sections().find((s) => s.id === settingsCategory());

  return (
    <div class="w-full h-full flex flex-col min-h-0 bg-[var(--neutral-950)]">
      <div class="h-7 flex-shrink-0" />

      <div class="h-[var(--size-lg)] flex items-center justify-between px-4 flex-shrink-0 -mt-1">
        <span class="text-base font-semibold text-[var(--neutral-100)]">settings</span>
        <button
          class="w-6 h-6 flex items-center justify-center rounded-md text-[var(--neutral-500)] hover:text-[var(--neutral-300)] hover:bg-[var(--hover)] cursor-pointer transition-colors duration-150"
          onClick={props.onClose}
        >
          <X size={14} />
        </button>
      </div>

      <Show when={activeSection()}>
        {(section) => (
          <>
            <div class="h-[var(--size-lg)] flex items-center px-4 flex-shrink-0">
              <span class="text-sm text-[var(--neutral-400)]">{section().label}</span>
            </div>
            <div class="relative flex-1 min-h-0">
              <ScrollArea class="h-full pb-6">
                <Dynamic component={section().render} />
              </ScrollArea>
              <div
                class="absolute top-0 left-0 right-0 h-4 pointer-events-none z-10"
                style={{ background: "linear-gradient(to top, transparent, var(--neutral-950))" }}
              />
              <div
                class="absolute bottom-0 left-0 right-0 h-6 pointer-events-none z-10"
                style={{ background: "linear-gradient(to bottom, transparent, var(--neutral-950))" }}
              />
            </div>
          </>
        )}
      </Show>
    </div>
  );
}
