import { For, Show } from "solid-js";
import type { Identity, Group } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { CreateGroupDialog } from "./CreateGroupDialog";
import { cn } from "../lib/cn";

interface SidebarProps {
  identity: Identity | null;
  groups: Group[];
  selectedGroupId: string | null;
  onSelectGroup: (id: string) => void;
  onGroupCreated: () => void;
}

export function Sidebar(props: SidebarProps) {
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
          <For each={props.groups}>
            {(group) => (
              <button
                onClick={() => props.onSelectGroup(group.group_id)}
                class={cn(
                  "w-full text-left px-2.5 py-2 rounded text-sm truncate transition-colors cursor-pointer",
                  group.group_id === props.selectedGroupId
                    ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                    : "text-[var(--neutral-400)] hover:bg-[var(--neutral-800)] hover:text-[var(--neutral-200)]",
                )}
              >
                {group.name}
              </button>
            )}
          </For>
        </div>
      </ScrollArea>
    </div>
  );
}
