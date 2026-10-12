import { For } from "solid-js";
import { AlertCircle, X } from "lucide-solid";
import { dismissNotice, notices } from "../lib/notices";

/** Banners for failures the user would otherwise never see, each for a while. */
export function Notices() {
  return (
    <div class="flex flex-col gap-1 px-3 pt-1">
      <For each={notices()}>
        {(notice) => (
          <div
            role="alert"
            class="flex items-center gap-2 rounded px-3 py-2 text-xs border bg-[var(--red-500)]/10 border-[var(--red-500)]/30 text-[var(--red-400)]"
          >
            <AlertCircle size={14} class="flex-shrink-0" />
            <span class="flex-1">{notice.message}</span>
            <button
              class="flex-shrink-0 text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer"
              onClick={() => dismissNotice(notice.id)}
              aria-label="dismiss"
            >
              <X size={14} />
            </button>
          </div>
        )}
      </For>
    </div>
  );
}
