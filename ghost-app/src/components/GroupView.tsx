import { selectedChannelName, settingsOpen } from "../lib/store";
import { MessageView } from "./MessageView";

export function GroupView() {
  return (
    <div class="flex-1 flex flex-col min-h-0 overflow-hidden">
      <div
        class="flex-shrink-0"
        style={{
          transform: settingsOpen() ? "translateY(-100%)" : "translateY(0)",
          transition: "transform var(--duration-slow) var(--ease-out)",
        }}
      >
        <div class="h-14 flex-shrink-0 flex items-center px-4">
          <span class="text-sm text-[var(--neutral-500)] mr-1">#</span>
          <span class="text-base font-medium text-[var(--neutral-200)]">
            {selectedChannelName()}
          </span>
        </div>
        <div class="divider-h" />
      </div>
      <MessageView />
    </div>
  );
}
