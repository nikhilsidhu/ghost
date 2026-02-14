import { createSignal, createEffect, createMemo, For, Show, onMount, onCleanup, batch } from "solid-js";
import type { Group, Channel } from "../lib/types";
import { Dialog as KDialog } from "@kobalte/core/dialog";
import { X } from "lucide-solid";
import { cn } from "../lib/cn";
import { recordUsage, frecencyScore } from "../lib/frecency";
import { findShortcut } from "../lib/shortcuts";
import { hashGradient } from "../lib/gradients";
import { KeyBadge } from "./KeyBadge";

// --- Public types for command definitions ---

export interface SelectOption {
  label: string;
  value: string;
  iconKey?: string;
  iconLabel?: string;
}

export interface ArgDef {
  name: string;
  placeholder: string;
  complete?: (query: string) => SelectOption[];
  defaultValue?: () => string | null;
  onConfirm?: (value: string) => void;
}

export interface CommandDef {
  id: string;
  command: string;
  args: ArgDef[];
  execute: (args: Record<string, string>) => void | Promise<void>;
  shortcut?: string[];
}

// --- Props ---

interface Props {
  groups: Group[];
  channels: Channel[];
  pinnedGroupIds: Set<string>;
  commands: CommandDef[];
  onSelectGroup: (id: string) => void;
  onSelectChannel: (channelId: string) => void;
  openCommandId?: string | null;
  onOpenCommandHandled?: () => void;
}

// --- Highlight matching text ---

function CommandHighlight(props: { command: string; query: string }) {
  const parts = createMemo(() => {
    const q = props.query.toLowerCase();
    const cmd = props.command;
    const idx = cmd.toLowerCase().indexOf(q);
    if (!q || idx === -1) return { before: "", match: "", after: cmd };
    return {
      before: cmd.slice(0, idx),
      match: cmd.slice(idx, idx + q.length),
      after: cmd.slice(idx + q.length),
    };
  });

  return (
    <span class="truncate">
      <span class="text-[var(--purple-300)]">/</span>
      <span class="text-[var(--neutral-500)]">{parts().before}</span>
      <span class="text-[var(--purple-300)]">{parts().match}</span>
      <span class="text-[var(--neutral-500)]">{parts().after}</span>
    </span>
  );
}

// --- Longest common prefix helper ---

function longestCommonPrefix(items: string[]): string {
  if (items.length === 0) return "";
  let prefix = items[0];
  for (let i = 1; i < items.length; i++) {
    let j = 0;
    while (j < prefix.length && j < items[i].length && prefix[j].toLowerCase() === items[i][j].toLowerCase()) j++;
    prefix = prefix.slice(0, j);
  }
  return prefix;
}

// --- Main component ---

export function CommandPalette(props: Props) {
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [focusedIndex, setFocusedIndex] = createSignal(0);

  // Args state — activeCommand being non-null means we're collecting args
  const [activeCommand, setActiveCommand] = createSignal<CommandDef | null>(null);
  const [argIndex, setArgIndex] = createSignal(0);
  const [collectedArgs, setCollectedArgs] = createSignal<Record<string, string>>({});

  // Mode derived purely from state: args if command resolved, else query prefix
  const mode = createMemo(() => {
    if (activeCommand()) return "args" as const;
    return query().startsWith("/") ? "command" as const : "search" as const;
  });

  const commandQuery = createMemo(() => query().slice(1).toLowerCase().trim());

  const currentArg = createMemo(() => {
    const cmd = activeCommand();
    if (!cmd || mode() !== "args") return null;
    return cmd.args[argIndex()] ?? null;
  });

  // --- Reset helpers ---

  const resetAll = () => {
    batch(() => {
      setActiveCommand(null);
      setArgIndex(0);
      setCollectedArgs({});
      setQuery("");
      setFocusedIndex(0);
    });
  };

  const activateCommand = (cmd: CommandDef) => {
    if (cmd.args.length === 0) {
      setOpen(false);
      recordUsage(cmd.id);
      cmd.execute({});
      return;
    }

    // Auto-confirm leading args where defaultValue matches a completion
    let idx = 0;
    const autoArgs: Record<string, string> = {};
    while (idx < cmd.args.length) {
      const arg = cmd.args[idx];
      const val = arg.defaultValue?.();
      if (!val || !arg.complete) break;
      if (!arg.complete("").some((c) => c.value === val)) break;
      autoArgs[arg.name] = val;
      arg.onConfirm?.(val);
      idx++;
    }

    if (idx >= cmd.args.length) {
      setOpen(false);
      recordUsage(cmd.id);
      cmd.execute(autoArgs);
      return;
    }

    batch(() => {
      setActiveCommand(cmd);
      setArgIndex(idx);
      setCollectedArgs(autoArgs);
      setFocusedIndex(0);
      const nextArg = cmd.args[idx];
      const defaultVal = nextArg.defaultValue?.() ?? null;
      setQuery(defaultVal ?? "");
    });
  };

  // --- Keyboard shortcut ---

  onMount(() => {
    const searchDef = findShortcut("search");
    const commandsDef = findShortcut("commands");
    const handler = (e: KeyboardEvent) => {
      if (commandsDef.match(e)) {
        e.preventDefault();
        batch(() => { resetAll(); setQuery("/"); setOpen(true); });
      } else if (searchDef.match(e)) {
        e.preventDefault();
        batch(() => { resetAll(); setOpen(true); });
      }
    };
    document.addEventListener("keydown", handler);
    onCleanup(() => document.removeEventListener("keydown", handler));
  });

  // --- External trigger (+ button) ---

  createEffect(() => {
    const cmdId = props.openCommandId;
    if (!cmdId) return;
    const cmd = props.commands.find((c) => c.id === cmdId);
    if (cmd) {
      setOpen(true);
      activateCommand(cmd);
    }
    props.onOpenCommandHandled?.();
  });

  // --- Filtered lists ---

  type SearchItem =
    | { kind: "group"; group: Group }
    | { kind: "channel"; channel: Channel; groupName: string };

  const searchResults = createMemo((): SearchItem[] => {
    const q = query().toLowerCase().trim();
    // Groups
    let gList = props.groups;
    if (q) {
      gList = gList
        .filter((g) => g.name.toLowerCase().includes(q))
        .sort((a, b) => {
          const aExact = a.name.toLowerCase() === q ? 0 : 1;
          const bExact = b.name.toLowerCase() === q ? 0 : 1;
          if (aExact !== bExact) return aExact - bExact;
          const aStarts = a.name.toLowerCase().startsWith(q) ? 0 : 1;
          const bStarts = b.name.toLowerCase().startsWith(q) ? 0 : 1;
          return aStarts - bStarts;
        });
    }
    const pinned = gList.filter((g) => props.pinnedGroupIds.has(g.group_id));
    const rest = gList.filter((g) => !props.pinnedGroupIds.has(g.group_id));
    const groups: SearchItem[] = [...pinned, ...rest].map((g) => ({ kind: "group", group: g }));

    // Channels (only when query is non-empty to avoid clutter)
    if (!q) return groups;
    const groupMap = new Map(props.groups.map((g) => [g.group_id, g.name]));
    const chList = props.channels
      .filter((ch) => ch.name.toLowerCase().includes(q))
      .map((ch): SearchItem => ({
        kind: "channel",
        channel: ch,
        groupName: groupMap.get(ch.group_id) ?? "",
      }));

    return [...groups, ...chList];
  });

  const filteredCommands = createMemo(() => {
    const q = commandQuery();
    if (!q) return [...props.commands].sort((a, b) => frecencyScore(b.id) - frecencyScore(a.id));
    return props.commands
      .filter((c) => c.command.toLowerCase().includes(q))
      .sort((a, b) => {
        const aStarts = a.command.toLowerCase().startsWith(q) ? 0 : 1;
        const bStarts = b.command.toLowerCase().startsWith(q) ? 0 : 1;
        if (aStarts !== bStarts) return aStarts - bStarts;
        return frecencyScore(b.id) - frecencyScore(a.id);
      });
  });

  const argCompletions = createMemo(() => {
    const arg = currentArg();
    if (!arg?.complete) return [];
    return arg.complete(query().trim());
  });

  const itemCount = createMemo(() => {
    const m = mode();
    if (m === "search") return searchResults().length;
    if (m === "command") return filteredCommands().length;
    return argCompletions().length;
  });

  // --- Scroll into view ---

  let inputRef!: HTMLInputElement;
  let listRef!: HTMLDivElement;

  createEffect(() => {
    query();
    setFocusedIndex(0);
  });

  // Focus and move cursor to end when dialog opens
  createEffect(() => {
    if (open() && inputRef) {
      setTimeout(() => {
        inputRef.focus();
        inputRef.setSelectionRange(inputRef.value.length, inputRef.value.length);
      }, 0);
    }
  });

  createEffect(() => {
    const i = focusedIndex();
    if (!listRef) return;
    const el = listRef.children[i] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  });

  // --- Selection handlers ---

  const selectGroup = (id: string) => {
    props.onSelectGroup(id);
    setOpen(false);
  };

  const confirmArg = (value: string) => {
    const cmd = activeCommand();
    if (!cmd) return;
    const arg = currentArg();
    if (!arg) return;

    const trimmed = value.trim();
    if (!trimmed) return;

    arg.onConfirm?.(trimmed);
    const next = argIndex() + 1;
    const newArgs = { ...collectedArgs(), [arg.name]: trimmed };

    if (next >= cmd.args.length) {
      // All args collected — reset state then execute
      resetAll();
      setOpen(false);
      recordUsage(cmd.id);
      cmd.execute(newArgs);
      return;
    }

    // Advance to next arg
    batch(() => {
      setCollectedArgs(newArgs);
      setArgIndex(next);
      setFocusedIndex(0);
      const nextArg = cmd.args[next];
      const defaultVal = nextArg.defaultValue?.() ?? null;
      setQuery(defaultVal ?? "");
    });
  };

  // --- Key handling ---

  const handleKeyDown = (e: KeyboardEvent) => {
    const m = mode();

    // Tab autocomplete
    if (e.key === "Tab") {
      e.preventDefault();
      if (m === "command") {
        const cmds = filteredCommands();
        if (cmds.length === 0) return;
        if (cmds.length === 1) {
          activateCommand(cmds[0]);
          return;
        }
        const prefix = longestCommonPrefix(cmds.map((c) => c.command));
        if (prefix.length > commandQuery().length) {
          setQuery("/" + prefix);
        }
      } else if (m === "args") {
        const completions = argCompletions();
        if (completions.length === 0) return;
        if (completions.length === 1) {
          confirmArg(completions[0].value);
          return;
        }
        const prefix = longestCommonPrefix(completions.map((c) => c.label));
        if (prefix.length > query().trim().length) {
          setQuery(prefix);
        }
      }
      return;
    }

    // Backspace on empty in args phase — go back
    if (e.key === "Backspace" && query() === "" && m=== "args") {
      e.preventDefault();
      const idx = argIndex();
      if (idx === 0) {
        // Back to command phase
        batch(() => {
          setActiveCommand(null);
          setQuery("/" + (activeCommand()?.command ?? ""));
          setFocusedIndex(0);
        });
      } else {
        // Back to previous arg
        const cmd = activeCommand()!;
        const prevArg = cmd.args[idx - 1];
        const prevVal = collectedArgs()[prevArg.name] ?? "";
        batch(() => {
          const newArgs = { ...collectedArgs() };
          delete newArgs[prevArg.name];
          setCollectedArgs(newArgs);
          setArgIndex(idx - 1);
          // Completer args use IDs — show empty to re-select; free text keeps the value
          setQuery(prevArg.complete ? "" : prevVal);
          setFocusedIndex(0);
        });
      }
      return;
    }

    // Arrow navigation
    const count = itemCount();
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((i) => Math.min(i + 1, count - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && (count > 0 || m=== "args")) {
      e.preventDefault();
      if (m === "search" && count > 0) {
        const item = searchResults()[focusedIndex()];
        if (item.kind === "group") selectGroup(item.group.group_id);
        else { props.onSelectGroup(item.channel.group_id); props.onSelectChannel(item.channel.channel_id); setOpen(false); }
      } else if (m === "command" && count > 0) {
        activateCommand(filteredCommands()[focusedIndex()]);
      } else if (m === "args") {
        const completions = argCompletions();
        if (completions.length > 0 && focusedIndex() < completions.length) {
          confirmArg(completions[focusedIndex()].value);
        } else if (!currentArg()?.complete) {
          // Free text only for args without a completer
          confirmArg(query());
        }
      }
    }
  };

  // --- Close handler ---

  const handleOpenChange = (v: boolean) => {
    setOpen(v);
    if (!v) resetAll();
  };

  // --- Placeholder text ---

  const placeholder = createMemo(() => {
    const m = mode();
    if (m === "args") {
      const arg = currentArg();
      return arg?.placeholder ?? "...";
    }
    if (m === "command") return "/command...";
    return "search...";
  });

  // --- Render ---

  return (
    <KDialog open={open()} onOpenChange={handleOpenChange}>
      <KDialog.Portal>
        <KDialog.Overlay
          data-palette-overlay
          class="fixed inset-0 z-50"
          style={{ background: "var(--palette-overlay)", animation: "overlay-fade 180ms ease-out" }}
        />
        <div class="fixed inset-0 z-50 flex items-center justify-center">
          <KDialog.Content
            data-palette-content
            class="w-full max-w-[40rem] rounded-xl overflow-hidden"
            style:max-width="calc(100vw - 3rem)"
            style={{
              background: "var(--palette-bg)",
              "backdrop-filter": "blur(16px) saturate(180%)",
              "-webkit-backdrop-filter": "blur(16px) saturate(180%)",
              border: "1px solid var(--neutral-700)",
              "box-shadow": "var(--palette-shadow)",
              animation: "palette-in 180ms ease-out",
            }}
          >
            {/* Input with inline token pills */}
            <div class="p-3 flex items-center gap-1.5 flex-wrap">
              <Show when={mode() === "args" && activeCommand()}>
                <For each={activeCommand()!.command.split(" ")}>
                  {(word, wordIdx) => {
                    const words = () => activeCommand()!.command.split(" ");
                    return (
                      <span
                        class="group/pill inline-flex items-center h-6 rounded-md text-xs font-medium text-[var(--purple-300)] flex-shrink-0 cursor-pointer transition-all duration-150"
                        style={{ background: "var(--pill-purple)" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          // X on word i → back to command mode with words before i as prefix
                          const prefix = words().slice(0, wordIdx()).join(" ");
                          batch(() => {
                            setActiveCommand(null);
                            setCollectedArgs({});
                            setArgIndex(0);
                            setQuery("/" + prefix);
                            setFocusedIndex(0);
                          });
                          inputRef?.focus();
                        }}
                      >
                        <span class="px-2">{wordIdx() === 0 ? `/${word}` : word}</span>
                        <span class="w-0 overflow-hidden group-hover/pill:w-5 transition-all duration-150 flex items-center justify-center">
                          <X size={12} strokeWidth={2.5} class="text-[var(--purple-400)]" />
                        </span>
                      </span>
                    );
                  }}
                </For>
                <For each={Object.entries(collectedArgs())}>
                  {([name, val]) => {
                    const arg = activeCommand()!.args.find((a) => a.name === name);
                    const label = arg?.complete?.("").find((c) => c.value === val)?.label ?? val;
                    const argIdx = activeCommand()!.args.findIndex((a) => a.name === name);
                    return (
                      <span
                        class="group/pill inline-flex items-center h-6 rounded-md text-xs flex-shrink-0 cursor-pointer transition-all duration-150"
                        style={{ background: "var(--pill-ember)" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          // Remove this arg and all after it
                          const cmd = activeCommand()!;
                          const newArgs: Record<string, string> = {};
                          for (let j = 0; j < argIdx; j++) {
                            const n = cmd.args[j].name;
                            if (collectedArgs()[n] !== undefined) newArgs[n] = collectedArgs()[n];
                          }
                          batch(() => {
                            setCollectedArgs(newArgs);
                            setArgIndex(argIdx);
                            setQuery("");
                            setFocusedIndex(0);
                          });
                          inputRef?.focus();
                        }}
                      >
                        <span class="inline-flex items-center gap-1 px-2">
                          <span class="text-[var(--ember-500)]">{name}:</span>
                          <span class="font-medium text-[var(--ember-300)]">{label}</span>
                        </span>
                        <span class="w-0 overflow-hidden group-hover/pill:w-5 transition-all duration-150 flex items-center justify-center">
                          <X size={12} strokeWidth={2.5} class="text-[var(--ember-400)]" />
                        </span>
                      </span>
                    );
                  }}
                </For>
              </Show>
              <input
                ref={inputRef}
                placeholder={placeholder()}
                value={query()}
                onInput={(e) => setQuery(e.currentTarget.value)}
                onKeyDown={handleKeyDown}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
                class="h-8 flex-1 min-w-[80px] bg-transparent text-sm text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)] outline-none"
              />
            </div>

            {/* Results list */}
            <div ref={listRef} class="max-h-64 overflow-y-auto py-1">
              {/* Search mode: groups + channels */}
              <Show when={mode() === "search"}>
                <Show
                  when={searchResults().length > 0}
                  fallback={<div class="px-3 py-4 text-xs text-[var(--neutral-500)] text-center">no results</div>}
                >
                  <For each={searchResults()}>
                    {(item, idx) => {
                      const focused = () => idx() === focusedIndex();
                      const rowClass = () => cn(
                        "w-full text-left px-3 py-2 text-sm flex items-center gap-2 cursor-pointer transition-colors",
                        focused()
                          ? "bg-[var(--active)] text-[var(--neutral-100)]"
                          : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
                      );
                      if (item.kind === "group") {
                        const grad = hashGradient(item.group.group_id);
                        return (
                          <button
                            onClick={() => selectGroup(item.group.group_id)}
                            onMouseEnter={() => setFocusedIndex(idx())}
                            class={rowClass()}
                          >
                            <div
                              class="w-4 h-4 rounded-[3px] flex items-center justify-center text-[9px] font-bold flex-shrink-0"
                              style={{ background: `linear-gradient(${grad.angle}deg, ${grad.from}, ${grad.to})`, color: "var(--neutral-100)" }}
                            >
                              {item.group.name[0]?.toUpperCase()}
                            </div>
                            <span class="truncate">{item.group.name}</span>
                          </button>
                        );
                      }
                      return (
                        <button
                          onClick={() => { props.onSelectGroup(item.channel.group_id); props.onSelectChannel(item.channel.channel_id); setOpen(false); }}
                          onMouseEnter={() => setFocusedIndex(idx())}
                          class={rowClass()}
                        >
                          <span class="text-[var(--neutral-500)] flex-shrink-0">{item.channel.kind === "text" ? "#" : "\u266a"}</span>
                          <span class="truncate">{item.channel.name}</span>
                          <span
                            class="ml-auto text-[10px] px-1.5 py-0.5 rounded text-[var(--neutral-500)] flex-shrink-0"
                            style={{ background: "var(--neutral-800)" }}
                          >
                            {item.groupName}
                          </span>
                        </button>
                      );
                    }}
                  </For>
                </Show>
              </Show>

              {/* Command mode: commands */}
              <Show when={mode() === "command"}>
                <Show
                  when={filteredCommands().length > 0}
                  fallback={<div class="px-3 py-4 text-xs text-[var(--neutral-500)] text-center">no commands found</div>}
                >
                  <For each={filteredCommands()}>
                    {(cmd, idx) => (
                      <button
                        onClick={() => activateCommand(cmd)}
                        onMouseEnter={() => setFocusedIndex(idx())}
                        class={cn(
                          "w-full text-left px-3 py-2 text-sm flex items-center cursor-pointer transition-colors",
                          idx() === focusedIndex()
                            ? "bg-[var(--active)]"
                            : "hover:bg-[var(--hover)]",
                        )}
                      >
                        <CommandHighlight command={cmd.command} query={commandQuery()} />
                        <Show when={cmd.shortcut}>
                          <div class="ml-auto flex items-center gap-0.5 pl-3">
                            <For each={cmd.shortcut!}>
                              {(k) => <KeyBadge value={k} size="sm" />}
                            </For>
                          </div>
                        </Show>
                      </button>
                    )}
                  </For>
                </Show>
              </Show>

              {/* Args mode: completions */}
              <Show when={mode() === "args"}>
                <Show when={argCompletions().length > 0}>
                  <For each={argCompletions()}>
                    {(opt, idx) => {
                      const grad = opt.iconKey ? hashGradient(opt.iconKey) : null;
                      return (
                        <button
                          onClick={() => confirmArg(opt.value)}
                          onMouseEnter={() => setFocusedIndex(idx())}
                          class={cn(
                            "w-full text-left px-3 py-2 text-sm flex items-center gap-2 cursor-pointer transition-colors",
                            idx() === focusedIndex()
                              ? "bg-[var(--active)] text-[var(--neutral-100)]"
                              : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
                          )}
                        >
                          <Show when={grad}>
                            {(g) => (
                              <div
                                class="w-4 h-4 rounded-[3px] flex items-center justify-center text-[9px] font-bold flex-shrink-0"
                                style={{ background: `linear-gradient(${g().angle}deg, ${g().from}, ${g().to})`, color: "var(--neutral-100)" }}
                              >
                                {opt.iconLabel}
                              </div>
                            )}
                          </Show>
                          <span class="truncate">{opt.label}</span>
                        </button>
                      );
                    }}
                  </For>
                </Show>
              </Show>
            </div>
          </KDialog.Content>
        </div>
      </KDialog.Portal>
    </KDialog>
  );
}
