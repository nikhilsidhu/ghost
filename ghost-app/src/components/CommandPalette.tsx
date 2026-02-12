import { createSignal, createEffect, createMemo, For, Show, onMount, onCleanup, batch } from "solid-js";
import type { Group } from "../lib/types";
import { Dialog, DialogContent } from "./ui/dialog";
import { Input } from "./ui/input";
import { cn } from "../lib/cn";
import { findShortcut } from "../lib/shortcuts";
import { Pin } from "lucide-solid";

// --- Public types for command definitions ---

export interface SelectOption {
  label: string;
  value: string;
}

export interface ArgDef {
  name: string;
  placeholder: string;
  complete?: (query: string) => SelectOption[];
  defaultValue?: () => string | null;
}

export interface CommandDef {
  id: string;
  command: string;
  args: ArgDef[];
  execute: (args: Record<string, string>) => void | Promise<void>;
}

// --- Props ---

interface Props {
  groups: Group[];
  pinnedGroupIds: Set<string>;
  commands: CommandDef[];
  onSelectGroup: (id: string) => void;
  openCommandId?: string | null;
  onOpenCommandHandled?: () => void;
}

// --- Highlight component for command phase ---

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

  // Args state — resolvedCommand being non-null means we're collecting args
  const [resolvedCommand, setResolvedCommand] = createSignal<CommandDef | null>(null);
  const [argIndex, setArgIndex] = createSignal(0);
  const [collectedArgs, setCollectedArgs] = createSignal<Record<string, string>>({});

  // Mode derived purely from state: args if command resolved, else query prefix
  const mode = createMemo(() => {
    if (resolvedCommand()) return "args" as const;
    return query().startsWith("/") ? "command" as const : "search" as const;
  });

  const commandQuery = createMemo(() => query().slice(1).toLowerCase().trim());

  const currentArg = createMemo(() => {
    const cmd = resolvedCommand();
    if (!cmd || mode() !== "args") return null;
    return cmd.args[argIndex()] ?? null;
  });

  // --- Reset helpers ---

  const resetAll = () => {
    batch(() => {
      setResolvedCommand(null);
      setArgIndex(0);
      setCollectedArgs({});
      setQuery("");
      setFocusedIndex(0);
    });
  };

  const enterArgsPhase = (cmd: CommandDef) => {
    if (cmd.args.length === 0) {
      setOpen(false);
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
      idx++;
    }

    if (idx >= cmd.args.length) {
      setOpen(false);
      cmd.execute(autoArgs);
      return;
    }

    batch(() => {
      setResolvedCommand(cmd);
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
      enterArgsPhase(cmd);
    }
    props.onOpenCommandHandled?.();
  });

  // --- Filtered lists ---

  const filteredGroups = createMemo(() => {
    const q = query().toLowerCase().trim();
    let list = props.groups;
    if (q) {
      list = list
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
    const pinned = list.filter((g) => props.pinnedGroupIds.has(g.group_id));
    const rest = list.filter((g) => !props.pinnedGroupIds.has(g.group_id));
    return [...pinned, ...rest];
  });

  const filteredCommands = createMemo(() => {
    const q = commandQuery();
    if (!q) return props.commands;
    return props.commands
      .filter((c) => c.command.toLowerCase().includes(q))
      .sort((a, b) => {
        const aStarts = a.command.toLowerCase().startsWith(q) ? 0 : 1;
        const bStarts = b.command.toLowerCase().startsWith(q) ? 0 : 1;
        return aStarts - bStarts;
      });
  });

  const argCompletions = createMemo(() => {
    const arg = currentArg();
    if (!arg?.complete) return [];
    return arg.complete(query().trim());
  });

  const itemCount = createMemo(() => {
    const ep = mode();
    if (ep === "search") return filteredGroups().length;
    if (ep === "command") return filteredCommands().length;
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

  const resolveCommand = (cmd: CommandDef) => {
    enterArgsPhase(cmd);
  };

  const confirmArg = (value: string) => {
    const cmd = resolvedCommand();
    if (!cmd) return;
    const arg = currentArg();
    if (!arg) return;

    const trimmed = value.trim();
    if (!trimmed) return;

    const next = argIndex() + 1;
    const newArgs = { ...collectedArgs(), [arg.name]: trimmed };

    if (next >= cmd.args.length) {
      // All args collected — reset state then execute
      resetAll();
      setOpen(false);
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
    const ep = mode();

    // Tab autocomplete
    if (e.key === "Tab") {
      e.preventDefault();
      if (ep === "command") {
        const cmds = filteredCommands();
        if (cmds.length === 0) return;
        if (cmds.length === 1) {
          resolveCommand(cmds[0]);
          return;
        }
        const prefix = longestCommonPrefix(cmds.map((c) => c.command));
        if (prefix.length > commandQuery().length) {
          setQuery("/" + prefix);
        }
      } else if (ep === "args") {
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
    if (e.key === "Backspace" && query() === "" && ep === "args") {
      e.preventDefault();
      const idx = argIndex();
      if (idx === 0) {
        // Back to command phase
        batch(() => {
          setResolvedCommand(null);
          setQuery("/" + (resolvedCommand()?.command ?? ""));
          setFocusedIndex(0);
        });
      } else {
        // Back to previous arg
        const cmd = resolvedCommand()!;
        const prevArg = cmd.args[idx - 1];
        const prevVal = collectedArgs()[prevArg.name] ?? "";
        batch(() => {
          const newArgs = { ...collectedArgs() };
          delete newArgs[prevArg.name];
          setCollectedArgs(newArgs);
          setArgIndex(idx - 1);
          setQuery(prevVal);
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
    } else if (e.key === "Enter" && (count > 0 || ep === "args")) {
      e.preventDefault();
      if (ep === "search" && count > 0) {
        selectGroup(filteredGroups()[focusedIndex()].group_id);
      } else if (ep === "command" && count > 0) {
        resolveCommand(filteredCommands()[focusedIndex()]);
      } else if (ep === "args") {
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
    const ep = mode();
    if (ep === "args") {
      const arg = currentArg();
      return arg?.placeholder ?? "...";
    }
    if (ep === "command") return "/command...";
    return "search groups...";
  });

  // --- Render ---

  return (
    <Dialog open={open()} onOpenChange={handleOpenChange}>
      <DialogContent class="max-w-sm p-0 overflow-hidden">
        {/* Breadcrumbs */}
        <Show when={mode() === "args" && resolvedCommand()}>
          <div class="px-3 pt-3 pb-0 flex items-center gap-1 flex-wrap">
            <span class="text-xs text-[var(--purple-300)]">/{resolvedCommand()!.command}</span>
            <For each={Object.entries(collectedArgs())}>
              {([, val]) => (
                <>
                  <span class="text-xs text-[var(--neutral-600)]">&rsaquo;</span>
                  <span class="text-xs text-[var(--neutral-400)]">{val}</span>
                </>
              )}
            </For>
            <span class="text-xs text-[var(--neutral-600)]">&rsaquo;</span>
          </div>
        </Show>

        {/* Input */}
        <div class={cn("p-3 border-b border-[var(--neutral-600)]", mode() === "args" ? "pt-1.5" : "")}>
          <Input
            ref={inputRef}
            placeholder={placeholder()}
            value={query()}
            onInput={(e: InputEvent) => setQuery((e.currentTarget as HTMLInputElement).value)}
            onKeyDown={handleKeyDown}
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>

        {/* Results list */}
        <div ref={listRef} class="max-h-64 overflow-y-auto py-1">
          {/* Search mode: groups */}
          <Show when={mode() === "search"}>
            <Show
              when={filteredGroups().length > 0}
              fallback={<div class="px-3 py-4 text-xs text-[var(--neutral-500)] text-center">no groups found</div>}
            >
              <For each={filteredGroups()}>
                {(group, idx) => (
                  <button
                    onClick={() => selectGroup(group.group_id)}
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
                    onClick={() => resolveCommand(cmd)}
                    onMouseEnter={() => setFocusedIndex(idx())}
                    class={cn(
                      "w-full text-left px-3 py-2 text-sm flex items-center cursor-pointer transition-colors",
                      idx() === focusedIndex()
                        ? "bg-[var(--purple-800)]"
                        : "hover:bg-[var(--neutral-700)]",
                    )}
                  >
                    <CommandHighlight command={cmd.command} query={commandQuery()} />
                  </button>
                )}
              </For>
            </Show>
          </Show>

          {/* Args mode: completions */}
          <Show when={mode() === "args"}>
            <Show when={argCompletions().length > 0}>
              <For each={argCompletions()}>
                {(opt, idx) => (
                  <button
                    onClick={() => confirmArg(opt.value)}
                    onMouseEnter={() => setFocusedIndex(idx())}
                    class={cn(
                      "w-full text-left px-3 py-2 text-sm flex items-center cursor-pointer transition-colors",
                      idx() === focusedIndex()
                        ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                        : "text-[var(--neutral-400)] hover:bg-[var(--neutral-700)]",
                    )}
                  >
                    <span class="truncate">{opt.label}</span>
                  </button>
                )}
              </For>
            </Show>
          </Show>
        </div>
      </DialogContent>
    </Dialog>
  );
}
