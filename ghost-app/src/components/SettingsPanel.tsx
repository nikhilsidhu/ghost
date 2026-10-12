import { Show } from "solid-js";
import { Dynamic } from "solid-js/web";
import { X } from "lucide-solid";
import { FadedScrollArea } from "./ui/scroll-area";
import { PanelHeader } from "./ui/panel-header";
import { settingsCategory } from "../lib/store";
import { sections } from "../lib/settings-registry";

export function SettingsPanel(props: { onClose: () => void }) {
  const activeSection = () => sections().find((s) => s.id === settingsCategory());

  return (
    <div class="w-full h-full flex flex-col min-h-0 bg-[var(--neutral-950)]">
      <PanelHeader title="settings">
        <div class="flex-1" />
        <button
          class="w-6 h-6 flex items-center justify-center rounded-md text-[var(--neutral-500)] hover:text-[var(--neutral-300)] hover:bg-[var(--hover)] cursor-pointer transition-colors duration-150"
          onClick={props.onClose}
        >
          <X size={14} />
        </button>
      </PanelHeader>

      <Show when={activeSection()}>
        {(section) => (
          <>
            <div class="h-[var(--size-lg)] flex items-center px-4 flex-shrink-0">
              <span class="text-sm text-[var(--neutral-400)]">{section().label}</span>
            </div>
            <FadedScrollArea class="pb-6">
              <Dynamic component={section().render} />
            </FadedScrollArea>
          </>
        )}
      </Show>
    </div>
  );
}
