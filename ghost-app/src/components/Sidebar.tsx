import { createSignal, For, Show, onMount, onCleanup } from "solid-js";
import type { Identity, Group } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { CreateGroupDialog } from "./CreateGroupDialog";
import { cn } from "../lib/cn";
import { Pin, PinOff } from "lucide-solid";

interface SidebarProps {
  identity: Identity | null;
  groups: Group[];
  pinnedGroupIds: Set<string>;
  selectedGroupId: string | null;
  onSelectGroup: (id: string) => void;
  onGroupCreated: () => void;
  onTogglePin: (id: string) => void;
}

export function Sidebar(props: SidebarProps) {
  const [focusedIndex, setFocusedIndex] = createSignal(-1);

  const sortedGroups = () => {
    const all = props.groups;
    const pinIds = props.pinnedGroupIds;
    const pinned = all.filter((g) => pinIds.has(g.group_id));
    const unpinned = all.filter((g) => !pinIds.has(g.group_id));
    return [...pinned, ...unpinned];
  };

  onMount(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;

      const list = sortedGroups();
      if (!list.length) return;

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedIndex((i) => Math.min(i + 1, list.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && focusedIndex() >= 0) {
        e.preventDefault();
        props.onSelectGroup(list[focusedIndex()].group_id);
      }
    };
    document.addEventListener("keydown", handler);
    onCleanup(() => document.removeEventListener("keydown", handler));
  });

  return (
    <div
      class="w-64 flex-shrink-0 flex flex-col border-r border-[var(--neutral-800)]"
      style={{ background: "var(--neutral-900)" }}
    >
      <div class="h-7 flex-shrink-0" />

      <Show when={props.identity}>
        {(id) => (
          <div class="h-14 flex-shrink-0 flex items-center gap-3 px-3">
            <div
              class="w-8 h-8 rounded-full flex items-center justify-center text-sm flex-shrink-0"
              style={{ background: "var(--purple-700)", color: "var(--purple-200)" }}
            >
              {id().display_name[0]}
            </div>
            <div class="min-w-0">
              <div class="text-sm text-[var(--neutral-200)] truncate leading-tight">
                {id().display_name}
              </div>
              <div class="text-xs text-[var(--neutral-500)] truncate leading-tight">
                {id().fingerprint_short}
              </div>
            </div>
          </div>
        )}
      </Show>

      <div class="px-3 py-2 flex items-center justify-between">
        <span class="text-xs uppercase tracking-wider text-[var(--neutral-500)]">
          groups
        </span>
        <CreateGroupDialog onCreated={props.onGroupCreated} />
      </div>

      <ScrollArea class="flex-1">
        <div class="px-1.5">
          <For each={sortedGroups()}>
            {(group, idx) => {
              const isPinned = () => props.pinnedGroupIds.has(group.group_id);
              const isSelected = () => group.group_id === props.selectedGroupId;
              const isFocused = () => idx() === focusedIndex() && !isSelected();

              return (
                <div
                  class={cn(
                    "group relative flex items-center mx-1.5 px-2.5 py-2 rounded text-sm cursor-pointer transition-colors",
                    isSelected()
                      ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                      : "text-[var(--neutral-400)] hover:bg-[var(--neutral-800)] hover:text-[var(--neutral-200)]",
                    isFocused() ? "ring-1 ring-[var(--purple-500)]" : "",
                  )}
                  onClick={() => props.onSelectGroup(group.group_id)}
                >
                  <span class="truncate flex-1">{group.name}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); props.onTogglePin(group.group_id); }}
                    class="flex-shrink-0 ml-1 p-0.5 rounded cursor-pointer"
                    title={isPinned() ? "unpin" : "pin"}
                  >
                    <Show when={isPinned()} fallback={
                      // Not pinned: Pin icon, hidden until row hover
                      <Pin size={13} class="opacity-0 group-hover:opacity-100 transition-opacity text-[var(--neutral-500)] hover:text-[var(--purple-400)]" />
                    }>
                      {/* Pinned: dim Pin indicator normally, swaps to PinOff on row hover */}
                      <span class="relative flex items-center justify-center w-[13px] h-[13px]">
                        <Pin size={13} class="absolute inset-0 opacity-40 group-hover:opacity-0 transition-opacity text-[var(--purple-400)]" />
                        <PinOff size={13} class="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity text-[var(--neutral-400)] hover:text-[var(--neutral-200)]" />
                      </span>
                    </Show>
                  </button>
                </div>
              );
            }}
          </For>
        </div>
      </ScrollArea>
    </div>
  );
}
