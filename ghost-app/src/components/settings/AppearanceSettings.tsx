import { createEffect, createRoot } from "solid-js";
import { createSetting } from "../../lib/store";
import { SettingGroup, SettingToggle, SettingSelect } from "./controls";
export const [fontSize, setFontSize] = createSetting<string>("font-size", "medium");
export const [compact, setCompact] = createSetting("compact", false);
export const [showTimestamps, setShowTimestamps] = createSetting("show-timestamps", true);

const fontSizes = { small: "14px", medium: "16px", large: "18px" } as const;
const fontOptions = Object.keys(fontSizes).map((k) => ({ value: k, label: k }));

// Global effects — apply saved preferences to the document regardless of settings panel state
createRoot(() => {
  createEffect(() => {
    const key = fontSize() as keyof typeof fontSizes;
    document.documentElement.style.fontSize = fontSizes[key] ?? fontSizes.medium;
  });
  createEffect(() => document.documentElement.classList.toggle("compact", compact()));
});

export default function AppearanceSettings() {
  return (
    <div class="pb-4">
      <SettingGroup label="text">
        <SettingSelect
          label="font size"
          value={fontSize()}
          options={fontOptions}
          onChange={setFontSize}
        />
      </SettingGroup>
      <SettingGroup label="messages">
        <SettingToggle
          label="compact mode"
          description="reduce spacing in message list"
          checked={compact()}
          onChange={setCompact}
        />
        <SettingToggle
          label="show timestamps"
          description="display time next to messages"
          checked={showTimestamps()}
          onChange={setShowTimestamps}
        />
      </SettingGroup>
    </div>
  );
}
