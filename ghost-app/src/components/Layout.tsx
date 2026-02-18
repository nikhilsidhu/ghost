import { onMount, Show, For } from "solid-js";
import { Dynamic } from "solid-js/web";
import "../lib/commands";
import {
  selectedGroup, selectedChannelId,
  inviteLink, showInfo, settingsOpen, settingsCategory,
  initialize, seedAndRefresh, startDevSession,
  setInviteLink, setShowInfo,
} from "../lib/store";
import { sections } from "../lib/settings-registry";
import { slideDuration } from "../lib/constants";
import { Sidebar } from "./Sidebar";
import { GroupView } from "./GroupView";
import { MemberPanel } from "./MemberPanel";
import { CommandPalette } from "./CommandPalette";
import { InviteDialog } from "./InviteDialog";
import { ShortcutOverlay } from "./ShortcutOverlay";
import { KeyBadge } from "./KeyBadge";
import { shortcuts as shortcutDefs } from "../lib/shortcuts";

export function Layout() {
  onMount(initialize);

  const overlayShortcuts = shortcutDefs.filter((s) => s.id !== "shortcuts");

  return (
    <div class="h-screen flex relative" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="absolute inset-x-0 top-0 h-7 z-10" />
      <Sidebar />
      <div class="divider-v" />
      <main class="flex-1 min-w-0 pt-7 relative overflow-hidden">
        {/* Main content — slides up when settings open */}
        <div
          class={settingsOpen() ? "pointer-events-none" : undefined}
          style={{
            position: "absolute",
            inset: "0",
            display: "flex",
            "flex-direction": "column",
            transform: settingsOpen() ? "translateY(-100%)" : "translateY(0)",
            opacity: settingsOpen() ? "0" : "1",
            transition: `transform ${slideDuration(sections().length)} var(--ease-out), opacity var(--duration-fast) var(--ease-out)`,
          }}
        >
          <Show
            when={selectedGroup()}
            fallback={
              <div class="flex-1 flex items-center justify-center">
                <div class="flex flex-col items-center gap-5">
                  <span class="text-sm text-[var(--neutral-400)]">select a group</span>
                  <div class="flex flex-col gap-2.5">
                    <For each={shortcutDefs}>
                      {(s) => (
                        <div class="flex items-center gap-3">
                          <div class="flex items-center gap-1 w-[76px] justify-end">
                            <For each={s.keys}>
                              {(k) => <KeyBadge value={k} />}
                            </For>
                          </div>
                          <span class="text-xs text-[var(--neutral-500)]">{s.label.toLowerCase()}</span>
                        </div>
                      )}
                    </For>
                  </div>
                  <div class="flex gap-2 mt-1">
                    <button
                      class="px-3 py-1.5 rounded-md text-xs text-[var(--neutral-400)] hover:bg-[var(--hover)] cursor-pointer"
                      style={{ border: "1px solid var(--neutral-700)" }}
                      onClick={async () => { try { await startDevSession(); } catch {} }}
                    >
                      start dev session
                    </button>
                    <button
                      class="px-3 py-1.5 rounded-md text-xs text-[var(--neutral-400)] hover:bg-[var(--hover)] cursor-pointer"
                      style={{ border: "1px solid var(--neutral-700)" }}
                      onClick={async () => { try { await seedAndRefresh(); } catch {} }}
                    >
                      seed test data
                    </button>
                  </div>
                </div>
              </div>
            }
          >
            <Show
              when={selectedChannelId()}
              fallback={
                <div class="flex-1 flex items-center justify-center">
                  <div class="text-center">
                    <span class="text-sm text-[var(--neutral-400)]">select a channel</span>
                    <span class="text-xs block mt-1 text-[var(--neutral-600)]">from the sidebar</span>
                  </div>
                </div>
              }
            >
              <GroupView />
            </Show>
          </Show>
        </div>

        {/* Settings preview — slides down from top when settings open */}
        <div
          class={!settingsOpen() ? "pointer-events-none" : undefined}
          style={{
            position: "absolute",
            inset: "0",
            display: "flex",
            "flex-direction": "column",
            transform: settingsOpen() ? "translateY(0)" : "translateY(-100%)",
            transition: `transform ${slideDuration(sections().length)} var(--ease-out)`,
          }}
        >
          <Show when={settingsOpen()}>
            {(() => {
              const preview = () => sections().find((s) => s.id === settingsCategory())?.preview;
              return (
                <Show when={preview()}>
                  {(p) => <Dynamic component={p()} />}
                </Show>
              );
            })()}
          </Show>
        </div>
      </main>
      <Show when={selectedGroup()}>
        <div class="divider-v" />
        <div
          class="overflow-hidden flex-shrink-0"
          style={{
            width: settingsOpen() ? "0px" : "224px",
            opacity: settingsOpen() ? "0" : "1",
            transform: settingsOpen() ? "translateX(2rem)" : "translateX(0)",
            transition: `all ${slideDuration(sections().length)} var(--ease-out)`,
          }}
        >
          <MemberPanel />
        </div>
      </Show>
      <CommandPalette />
      <InviteDialog link={inviteLink()} onClose={() => setInviteLink(null)} />
      <ShortcutOverlay shortcuts={overlayShortcuts} forceOpen={showInfo()} onClose={() => setShowInfo(false)} />
    </div>
  );
}
