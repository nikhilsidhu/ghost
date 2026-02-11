import { createSignal, createEffect, For, Show, onMount, onCleanup } from "solid-js";
import type { Group } from "../lib/types";
import { Dialog, DialogContent } from "./ui/dialog";
import { Input } from "./ui/input";
import { cn } from "../lib/cn";
import { Pin } from "lucide-solid";

interface Props {
  groups: Group[];
  pinnedGroupIds: Set<string>;
  onSelectGroup: (id: string) => void;
}

export function CommandPalette(props: Props) {
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [focusedIndex, setFocusedIndex] = createSignal(0);

  onMount(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen(true);
        setQuery("");
        setFocusedIndex(0);
      }
    };
    document.addEventListener("keydown", handler);
    onCleanup(() => document.removeEventListener("keydown", handler));
  });

  const filtered = () => {
    const q = query().toLowerCase().trim();
    let list = props.groups;
    if (q) {
      list = list
        .filter((g) => g.name.toLowerCase().includes(q))
        .sort((a, b) => {
          const aExact = a.name.toLowerCase() === q ? 0 : 1;
          const bExact = b.name.toLowerCase() === q ? 0 : 1;
          if (aExact !== bExact) return aExact - bExact;
          // prefer starts-with over contains
          const aStarts = a.name.toLowerCase().startsWith(q) ? 0 : 1;
          const bStarts = b.name.toLowerCase().startsWith(q) ? 0 : 1;
          return aStarts - bStarts;
        });
    }
    const pinned = list.filter((g) => props.pinnedGroupIds.has(g.group_id));
    const rest = list.filter((g) => !props.pinnedGroupIds.has(g.group_id));
    return [...pinned, ...rest];
  };

  let listRef!: HTMLDivElement;

  createEffect(() => {
    query();
    setFocusedIndex(0);
  });

  createEffect(() => {
    const i = focusedIndex();
    if (!listRef) return;
    const el = listRef.children[i] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  });

  const select = (id: string) => {
    props.onSelectGroup(id);
    setOpen(false);
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    const list = filtered();
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((i) => Math.min(i + 1, list.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && list.length > 0) {
      e.preventDefault();
      select(list[focusedIndex()].group_id);
    }
  };

  return (
    <Dialog open={open()} onOpenChange={setOpen}>
      <DialogContent class="max-w-sm p-0 overflow-hidden">
        <div class="p-3 border-b border-[var(--neutral-600)]">
          <Input
            placeholder="switch to group..."
            value={query()}
            onInput={(e: InputEvent) => setQuery((e.currentTarget as HTMLInputElement).value)}
            onKeyDown={handleKeyDown}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
            autofocus
          />
        </div>
        <div ref={listRef} class="max-h-64 overflow-y-auto py-1">
          <Show
            when={filtered().length > 0}
            fallback={
              <div class="px-3 py-4 text-xs text-[var(--neutral-500)] text-center">
                no groups found
              </div>
            }
          >
            <For each={filtered()}>
              {(group, idx) => (
                <button
                  onClick={() => select(group.group_id)}
                  onMouseEnter={() => setFocusedIndex(idx())}
                  class={cn(
                    "w-full text-left px-3 py-2 text-sm flex items-center gap-2 cursor-pointer transition-colors",
                    idx() === focusedIndex()
                      ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                      : "text-[var(--neutral-400)] hover:bg-[var(--neutral-700)]",
                  )}
                >
                  <Show when={props.pinnedGroupIds.has(group.group_id)}>
                    <Pin size={12} class="text-[var(--purple-400)] flex-shrink-0" />
                  </Show>
                  <span class="truncate">{group.name}</span>
                </button>
              )}
            </For>
          </Show>
        </div>
      </DialogContent>
    </Dialog>
  );
}
