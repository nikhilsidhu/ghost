import { createSignal, For, Show, onCleanup } from "solid-js";
import { Portal } from "solid-js/web";
import { ScrollArea } from "./ui/scroll-area";
import { Avatar } from "./ui/avatar";
import type { AvatarStatus } from "./ui/avatar";
import { identity, members, selectedServerId, selectedServer, onlinePresence } from "../lib/store";
import { kickMember } from "../lib/api";

const STATUS_ORDER: Record<string, number> = { online: 0, idle: 1, away: 2 };

export function MemberPanel() {
  const [ctxMenu, setCtxMenu] = createSignal<{ x: number; y: number; fingerprint: string } | null>(null);

  const isCreator = () => identity()?.fingerprint === selectedServer()?.creator_fp;
  const memberStatus = (fp: string) => onlinePresence().get(fp)?.status as AvatarStatus | undefined;
  const memberStatusMessage = (fp: string) => onlinePresence().get(fp)?.status_message;

  const sortedMembers = () => {
    const presence = onlinePresence();
    return [...members()].sort((a, b) => {
      const aStatus = presence.get(a.fingerprint)?.status;
      const bStatus = presence.get(b.fingerprint)?.status;
      const aOrder = aStatus ? (STATUS_ORDER[aStatus] ?? 99) : 99;
      const bOrder = bStatus ? (STATUS_ORDER[bStatus] ?? 99) : 99;
      return aOrder - bOrder;
    });
  };

  const onRightClick = (fingerprint: string, role: string, e: MouseEvent) => {
    if (!isCreator() || role === "creator") return;
    e.preventDefault();
    const menuW = 140, menuH = 40;
    const x = Math.min(e.clientX, window.innerWidth - menuW);
    const y = Math.min(e.clientY, window.innerHeight - menuH);
    setCtxMenu({ x, y, fingerprint });
  };

  const handleKick = async () => {
    const menu = ctxMenu();
    const sid = selectedServerId();
    if (!menu || !sid) return;
    setCtxMenu(null);
    try {
      await kickMember(sid, menu.fingerprint);
    } catch (e) {
      console.error("kick failed:", e);
    }
  };

  const dismiss = () => setCtxMenu(null);

  window.addEventListener("click", dismiss);
  onCleanup(() => window.removeEventListener("click", dismiss));

  return (
    <div
      class="w-56 flex-shrink-0 flex flex-col"
      style={{ background: "var(--neutral-950)" }}
    >
      <div class="h-7 flex-shrink-0" />
      <div class="h-10 flex-shrink-0 flex items-center px-3">
        <span class="text-sm font-medium text-[var(--neutral-500)]">
          members — {members().length}
        </span>
      </div>
      <ScrollArea class="flex-1">
        <div class="px-2 py-1">
          <For each={sortedMembers()}>
            {(m) => (
              <div
                class="flex items-center gap-2.5 px-2 py-1.5 rounded-md hover:bg-[var(--hover)]"
                onContextMenu={(e) => onRightClick(m.fingerprint, m.role, e)}
              >
                <Avatar
                  hashKey={m.fingerprint}
                  label={m.display_name}
                  class="w-[var(--size-md)] h-[var(--size-md)] text-xs transition-all duration-200 opacity-85 hover:opacity-100 hover:scale-105"
                  status={memberStatus(m.fingerprint)}
                />
                <div class="flex-1 min-w-0">
                  <div class="text-sm text-[var(--neutral-200)] truncate">
                    {m.display_name}
                  </div>
                  <Show when={memberStatusMessage(m.fingerprint)}>
                    {(msg) => (
                      <div class="text-[11px] text-[var(--neutral-500)] truncate leading-tight">{msg()}</div>
                    )}
                  </Show>
                  <Show when={!memberStatusMessage(m.fingerprint) && m.role === "creator"}>
                    <div class="text-[11px] text-[var(--purple-400)] leading-tight">creator</div>
                  </Show>
                </div>
              </div>
            )}
          </For>
        </div>
      </ScrollArea>

      <Portal>
        <Show when={ctxMenu()}>
          {(menu) => (
            <div
              class="fixed z-50 min-w-32 rounded-md border border-[var(--neutral-700)] py-1 shadow-lg"
              style={{
                background: "var(--neutral-800)",
                left: `${menu().x}px`,
                top: `${menu().y}px`,
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <button
                class="w-full px-3 py-1.5 text-left text-sm text-red-400 hover:bg-[var(--neutral-700)] cursor-pointer"
                onClick={handleKick}
              >
                Kick
              </button>
            </div>
          )}
        </Show>
      </Portal>
    </div>
  );
}
