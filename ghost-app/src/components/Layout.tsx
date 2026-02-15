import { onMount, Show, For } from "solid-js";
import "../lib/commands";
import {
  selectedGroup, selectedChannelId,
  inviteLink, showInfo, settingsOpen,
  initialize, seedAndRefresh,
  setInviteLink, setShowInfo,
} from "../lib/store";
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
      <main class="flex-1 flex flex-col min-w-0 pt-7">
        <Show
          when={selectedGroup() || settingsOpen()}
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
                <button
                  class="mt-1 px-3 py-1.5 rounded-md text-xs text-[var(--neutral-400)] hover:bg-[var(--hover)] cursor-pointer"
                  style={{ border: "1px solid var(--neutral-700)" }}
                  onClick={async () => { try { await seedAndRefresh(); } catch {} }}
                >
                  seed test data
                </button>
              </div>
            </div>
          }
        >
          <Show when={!settingsOpen()}>
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
        </Show>
      </main>
      <Show when={selectedGroup() && !settingsOpen()}>
        <div class="divider-v" />
        <MemberPanel />
      </Show>
      <CommandPalette />
      <InviteDialog link={inviteLink()} onClose={() => setInviteLink(null)} />
      <ShortcutOverlay shortcuts={overlayShortcuts} forceOpen={showInfo()} onClose={() => setShowInfo(false)} />
    </div>
  );
}
