import { createSignal, For, Show, onMount, onCleanup } from "solid-js";
import type { Identity, Group } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { cn } from "../lib/cn";
import { Pin, PinOff } from "lucide-solid";

interface SidebarProps {
  identity: Identity | null;
  groups: Group[];
  pinnedGroupIds: Set<string>;
  selectedGroupId: string | null;
  onSelectGroup: (id: string) => void;
  onCreateGroup: () => void;
  onTogglePin: (id: string) => void;
}

export function Sidebar(props: SidebarProps) {
  const [activeIndex, setActiveIndex] = createSignal(-1);
  const [inputMode, setInputMode] = createSignal<"mouse" | "keyboard">("mouse");

  const sortedGroups = () => {
    const all = props.groups;
    const pinIds = props.pinnedGroupIds;
    const pinned = all.filter((g) => pinIds.has(g.group_id));
    const unpinned = all.filter((g) => !pinIds.has(g.group_id));
    return [...pinned, ...unpinned];
  };

  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;

      const list = sortedGroups();
      if (!list.length) return;

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setInputMode("keyboard");
        setActiveIndex((i) => Math.min(i + 1, list.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setInputMode("keyboard");
        setActiveIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && activeIndex() >= 0) {
        e.preventDefault();
        props.onSelectGroup(list[activeIndex()].group_id);
      }
    };

    const onMouseMove = () => {
      if (inputMode() === "keyboard") {
        setInputMode("mouse");
      }
    };

    document.addEventListener("keydown", onKey);
    document.addEventListener("mousemove", onMouseMove);
    onCleanup(() => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousemove", onMouseMove);
    });
  });

  // Unified highlight: keyboard sets activeIndex via J/K, mouse sets it via mouseenter/leave
  const isHighlighted = (idx: number) => idx === activeIndex();
  const isHovered = isHighlighted; // alias: true when row is active, regardless of selection

  return (
    <div
      class="w-64 flex-shrink-0 flex flex-col border-r border-[var(--neutral-800)]"
      style={{ background: "var(--neutral-900)" }}
    >
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />

      <Show when={props.identity}>
        {(id) => {
          const [copied, setCopied] = createSignal(false);
          const copyFp = () => {
            navigator.clipboard.writeText(id().fingerprint);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          };
          return (
            <div class="h-14 flex-shrink-0 flex items-center gap-3 px-3 cursor-pointer" onClick={copyFp}>
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
                  {copied() ? "copied" : id().fingerprint_short}
                </div>
              </div>
            </div>
          );
        }}
      </Show>

      <div class="px-3 py-2 flex items-center justify-between">
        <span class="text-xs uppercase tracking-wider text-[var(--neutral-500)]">
          groups
        </span>
        <button
          onClick={() => props.onCreateGroup()}
          class="w-6 h-6 flex items-center justify-center rounded text-base leading-none text-[var(--neutral-400)] hover:text-[var(--neutral-200)] hover:bg-[var(--neutral-700)] cursor-pointer transition-colors"
        >
          +
        </button>
      </div>

      <ScrollArea class="flex-1">
        <div class="px-1.5">
          <For each={sortedGroups()}>
            {(group, idx) => {
              const isPinned = () => props.pinnedGroupIds.has(group.group_id);
              const isSelected = () => group.group_id === props.selectedGroupId;
              const lit = () => !isSelected() && isHighlighted(idx());
              const active = () => isHovered(idx());

              return (
                <div
                  class={cn(
                    "relative flex items-center mx-1.5 px-2.5 py-2 rounded text-sm cursor-pointer",
                    isSelected()
                      ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                      : lit()
                        ? "bg-[var(--neutral-800)] text-[var(--neutral-200)]"
                        : "text-[var(--neutral-400)]",
                  )}
                  onMouseEnter={() => { if (inputMode() === "mouse") setActiveIndex(idx()); }}
                  onMouseLeave={() => { if (inputMode() === "mouse") setActiveIndex(-1); }}
                  onClick={() => props.onSelectGroup(group.group_id)}
                >
                  <span class="truncate flex-1">{group.name}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); props.onTogglePin(group.group_id); }}
                    class="flex-shrink-0 ml-1 p-0.5 rounded cursor-pointer"
                    title={isPinned() ? "unpin" : "pin"}
                  >
                    <Show when={isPinned()} fallback={
                      <Pin size={13} class={cn(
                        "transition-opacity text-[var(--neutral-500)]",
                        active() ? "opacity-100" : "opacity-0",
                      )} />
                    }>
                      <span class="relative flex items-center justify-center w-[13px] h-[13px]">
                        <Pin size={13} class={cn(
                          "absolute inset-0 transition-opacity text-[var(--purple-400)]",
                          active() ? "opacity-0" : "opacity-40",
                        )} />
                        <PinOff size={13} class={cn(
                          "absolute inset-0 transition-opacity text-[var(--neutral-400)]",
                          active() ? "opacity-100" : "opacity-0",
                        )} />
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
