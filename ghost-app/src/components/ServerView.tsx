import { Show } from "solid-js";
import { selectedChannelName, selectedServer, dmViewActive } from "../lib/store";
import { MessageView } from "./MessageView";

export function ServerView() {
  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div class="h-14 flex-shrink-0 flex items-center px-4">
        <Show when={dmViewActive()} fallback={
          <>
            <span class="text-sm text-[var(--neutral-500)] mr-1">#</span>
            <span class="text-base font-medium text-[var(--neutral-200)]">
              {selectedChannelName()}
            </span>
          </>
        }>
          <span class="text-base font-medium text-[var(--neutral-200)]">
            {selectedServer()?.name}
          </span>
        </Show>
      </div>
      <div class="divider-h" />
      <MessageView />
    </div>
  );
}
