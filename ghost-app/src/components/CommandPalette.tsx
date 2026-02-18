import { createSignal, createEffect, createMemo, For, Show, onMount, onCleanup, batch } from "solid-js";
import { Dialog as KDialog } from "@kobalte/core/dialog";
import { X } from "lucide-solid";
import { cn } from "../lib/cn";
import { recordUsage, frecencyScore } from "../lib/frecency";
import { findShortcut } from "../lib/shortcuts";
import { hashGradient } from "../lib/gradients";
import { KeyBadge } from "./KeyBadge";
import { commands, providers, triggeredCommandId, clearTriggeredCommand } from "../lib/registry";
import type { CommandDef, SearchResult } from "../lib/registry";

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

// --- Main component ---

export function CommandPalette() {
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [focusedIndex, setFocusedIndex] = createSignal(0);

  // Two pill arrays — one source of truth for each token type
  const [cmdPills, setCmdPills] = createSignal<string[]>([]);
  const [argPills, setArgPills] = createSignal<{ name: string; value: string }[]>([]);

  // Dangerous command confirmation
  const [pendingExec, setPendingExec] = createSignal<{ cmd: CommandDef; args: Record<string, string> } | null>(null);

  // --- Derived state ---

  const resolvedCommand = createMemo((): CommandDef | null => {
    const text = cmdPills().join(" ").toLowerCase();
    if (!text) return null;
    return commands().find((c) => c.command.toLowerCase() === text) ?? null;
  });

  const mode = createMemo(() => {
    if (pendingExec()) return "confirm" as const;
    if (resolvedCommand()) return "args" as const;
    if (cmdPills().length > 0 || query().startsWith("/")) return "command" as const;
    return "search" as const;
  });

  const commandQuery = createMemo(() => {
    if (cmdPills().length > 0) return query().toLowerCase().trim();
    return query().slice(1).toLowerCase().trim();
  });

  const currentArg = createMemo(() => {
    const cmd = resolvedCommand();
    if (!cmd) return null;
    return cmd.args[argPills().length] ?? null;
  });

  const runCommand = (cmd: CommandDef, args: Record<string, string>) => {
    recordUsage(cmd.id);
    try {
      const result = cmd.execute(args);
      if (result instanceof Promise) result.catch((e) => console.error(`command "${cmd.command}" failed:`, e));
    } catch (e) {
      console.error(`command "${cmd.command}" failed:`, e);
    }
  };

  const executeOrConfirm = (cmd: CommandDef, args: Record<string, string>) => {
    if (cmd.dangerous) {
      setPendingExec({ cmd, args });
      return;
    }
    setOpen(false);
    runCommand(cmd, args);
  };

  // --- Reset ---

  const resetAll = () => {
    batch(() => {
      setCmdPills([]);
      setArgPills([]);
      setQuery("");
      setFocusedIndex(0);
      setPendingExec(null);
    });
  };

  // --- Auto-confirm helper ---

  const autoConfirmArgs = (cmd: CommandDef, existing: { name: string; value: string }[]): { pills: { name: string; value: string }[]; nextQuery: string } => {
    const result = [...existing];
    let idx = result.length;
    while (idx < cmd.args.length) {
      const arg = cmd.args[idx];
      const val = arg.defaultValue?.();
      if (!val || !arg.complete) break;
      const collected = Object.fromEntries(result.map((p) => [p.name, p.value]));
      if (!arg.complete("", collected).some((c) => c.value === val)) break;
      result.push({ name: arg.name, value: val });
      idx++;
    }
    const nextArg = cmd.args[result.length];
    return { pills: result, nextQuery: nextArg?.defaultValue?.() ?? "" };
  };

  // --- Activate / submit ---

  const activateCommand = (cmd: CommandDef) => {
    const words = cmd.command.split(" ");

    if (cmd.args.length === 0) {
      resetAll();
      executeOrConfirm(cmd, {});
      return;
    }

    const { pills, nextQuery } = autoConfirmArgs(cmd, []);

    if (pills.length >= cmd.args.length) {
      resetAll();
      executeOrConfirm(cmd, Object.fromEntries(pills.map((p) => [p.name, p.value])));
      return;
    }

    batch(() => {
      setCmdPills(words);
      setArgPills(pills);
      setFocusedIndex(0);
      setQuery(nextQuery);
    });
  };

  const submitArg = (value: string, autoConfirm = true) => {
    const cmd = resolvedCommand();
    if (!cmd) return;
    const argDef = currentArg();
    if (!argDef) return;

    const trimmed = value.trim();
    if (!trimmed) return;

    const newArgPills = [...argPills(), { name: argDef.name, value: trimmed }];
    const { pills, nextQuery } = autoConfirm ? autoConfirmArgs(cmd, newArgPills) : { pills: newArgPills, nextQuery: cmd.args[newArgPills.length]?.defaultValue?.() ?? "" };

    if (pills.length >= cmd.args.length) {
      const args = Object.fromEntries(pills.map((p) => [p.name, p.value]));
      resetAll();
      executeOrConfirm(cmd, args);
      return;
    }

    batch(() => {
      setArgPills(pills);
      setFocusedIndex(0);
      setQuery(nextQuery);
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
    const cmdId = triggeredCommandId();
    if (!cmdId) return;
    const cmd = commands().find((c) => c.id === cmdId);
    if (cmd) {
      setOpen(true);
      activateCommand(cmd);
    }
    clearTriggeredCommand();
  });

  // --- Filtered lists ---

  const searchResults = createMemo((): SearchResult[] => {
    const q = query().toLowerCase().trim();
    const seen = new Set<string>();
    return providers().flatMap((p) => p(q))
      .filter((r) => { if (seen.has(r.id)) return false; seen.add(r.id); return true; })
      .sort((a, b) => frecencyScore(b.id) - frecencyScore(a.id));
  });

  const filteredCommands = createMemo(() => {
    const pills = cmdPills();
    const q = commandQuery();

    if (pills.length === 0) {
      if (!q) return [...commands()].sort((a, b) => frecencyScore(b.id) - frecencyScore(a.id));
      return commands()
        .filter((c) => c.command.toLowerCase().includes(q))
        .sort((a, b) => {
          const aStarts = a.command.toLowerCase().startsWith(q) ? 0 : 1;
          const bStarts = b.command.toLowerCase().startsWith(q) ? 0 : 1;
          if (aStarts !== bStarts) return aStarts - bStarts;
          return frecencyScore(b.id) - frecencyScore(a.id);
        });
    }

    const prefix = pills.join(" ").toLowerCase();
    return commands()
      .filter((c) => {
        const cmd = c.command.toLowerCase();
        if (!cmd.startsWith(prefix)) return false;
        const remainder = cmd.slice(prefix.length).trimStart();
        return !q || remainder.includes(q);
      })
      .sort((a, b) => frecencyScore(b.id) - frecencyScore(a.id));
  });

  // For dropdown highlighting — includes pilled words so they show as matched
  const highlightQuery = createMemo(() => {
    const pills = cmdPills();
    const q = commandQuery();
    if (pills.length === 0) return q;
    return q ? pills.join(" ") + " " + q : pills.join(" ");
  });

  const argCompletions = createMemo(() => {
    const arg = currentArg();
    if (!arg?.complete) return [];
    const collected = Object.fromEntries(argPills().map((p) => [p.name, p.value]));
    return arg.complete(query().trim(), collected);
  });

  const itemCount = createMemo(() => {
    const m = mode();
    if (m === "search") return searchResults().length;
    if (m === "command") return filteredCommands().length;
    if (m === "confirm") return 0;
    return argCompletions().length;
  });

  // --- Scroll into view ---

  let inputRef!: HTMLInputElement;
  let listRef!: HTMLDivElement;

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

  // --- Key handling ---

  const handleKeyDown = (e: KeyboardEvent) => {
    const m = mode();
    // Confirm mode
    if (m === "confirm") {
      if (e.key === "Enter") {
        e.preventDefault();
        const pending = pendingExec()!;
        resetAll();
        setOpen(false);
        runCommand(pending.cmd, pending.args);
      } else if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        setPendingExec(null);
      }
      return;
    }

    // Tab — pill exactly one token from the focused dropdown item
    if (e.key === "Tab") {
      e.preventDefault();
      if (m === "command") {
        const cmds = filteredCommands();
        if (cmds.length === 0) return;
        const focused = cmds[Math.min(focusedIndex(), cmds.length - 1)];
        const pills = cmdPills();
        const words = focused.command.split(" ");
        const nextIdx = pills.length;
        if (nextIdx >= words.length) return;
        batch(() => {
          setCmdPills([...pills, words[nextIdx]]);
          setQuery("");
          setFocusedIndex(0);
        });
      } else if (m === "args") {
        const completions = argCompletions();
        if (completions.length === 0) {
          if (!currentArg()?.complete) submitArg(query(), false);
          return;
        }
        submitArg(completions[Math.min(focusedIndex(), completions.length - 1)].value, false);
      }
      return;
    }

    // Backspace on empty — pop last pill
    if (e.key === "Backspace" && query() === "") {
      if (argPills().length > 0) {
        e.preventDefault();
        const pills = argPills();
        const cmd = resolvedCommand()!;
        const argDef = cmd.args[pills.length - 1];
        batch(() => {
          setArgPills(pills.slice(0, -1));
          setQuery(argDef.complete ? "" : pills[pills.length - 1].value);
          setFocusedIndex(0);
        });
        return;
      }

      if (cmdPills().length > 0) {
        e.preventDefault();
        const pills = cmdPills();
        batch(() => {
          setCmdPills(pills.slice(0, -1));
          setQuery(pills.length === 1 ? "/" : "");
          setFocusedIndex(0);
        });
        return;
      }
    }

    // Arrow navigation
    const count = itemCount();
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((i) => Math.min(i + 1, count - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && (count > 0 || m === "args")) {
      e.preventDefault();
      const idx = Math.min(focusedIndex(), count - 1);
      if (m === "search" && count > 0) {
        const result = searchResults()[idx];
        recordUsage(result.id);
        result.onSelect();
        setOpen(false);
      } else if (m === "command" && count > 0) {
        activateCommand(filteredCommands()[idx]);
      } else if (m === "args") {
        const completions = argCompletions();
        if (completions.length > 0) {
          submitArg(completions[Math.min(idx, completions.length - 1)].value);
        } else if (!currentArg()?.complete) {
          submitArg(query());
        }
      }
    }
  };

  // --- Close handler ---

  const handleOpenChange = (v: boolean) => {
    setOpen(v);
    if (!v) resetAll();
  };

  // --- Ghost text: what Tab would complete ---

  const ghostText = createMemo(() => {
    const m = mode();
    if (m === "command") {
      const cmds = filteredCommands();
      if (cmds.length === 0) return "";
      const focused = cmds[Math.min(focusedIndex(), cmds.length - 1)];
      const pills = cmdPills();
      const words = focused.command.split(" ");
      const nextIdx = pills.length;
      if (nextIdx >= words.length) return "";
      const nextWord = words[nextIdx];
      const q = commandQuery();
      if (q && nextWord.toLowerCase().startsWith(q)) return nextWord.slice(q.length);
      return q ? "" : nextWord;
    }
    if (m === "args") {
      const q = query().trim();
      if (!q) return ""; // placeholder handles empty state
      const completions = argCompletions();
      if (completions.length === 0) return "";
      const focused = completions[Math.min(focusedIndex(), completions.length - 1)];
      if (focused.label.toLowerCase().startsWith(q.toLowerCase())) return focused.label.slice(q.length);
      return "";
    }
    return "";
  });

  // --- Placeholder text ---

  const placeholder = createMemo(() => {
    const m = mode();
    if (m === "args") {
      const arg = currentArg();
      return arg?.placeholder ?? "...";
    }
    if (m === "command") return cmdPills().length > 0 ? "" : "/command...";
    return "search...";
  });

  // --- Render ---

  return (
    <KDialog open={open()} onOpenChange={handleOpenChange}>
      <KDialog.Portal>
        <KDialog.Overlay
          data-palette-overlay
          class="fixed inset-0 z-50"
          style={{ background: "var(--palette-overlay)", animation: "overlay-fade var(--duration-fast) ease-out" }}
        />
        <div class="fixed inset-0 z-50 flex items-start justify-center pt-[18vh]">
          <KDialog.Content
            data-palette-content
            class="relative w-full max-w-[40rem] rounded-xl overflow-hidden"
            style:max-width="calc(100vw - 3rem)"
            style={{
              background: "radial-gradient(ellipse at 50% 0%, var(--palette-highlight), transparent 60%), var(--palette-bg)",
              "box-shadow": "var(--palette-shadow)",
              animation: "palette-in var(--duration-fast) ease-out",
            }}
          >
            {/* Input with inline token pills */}
            <div class="p-3 flex items-center gap-1.5 flex-wrap">
              {/* Command word pills */}
              <Show when={cmdPills().length > 0}>
                <For each={cmdPills()}>
                  {(word, wordIdx) => (
                    <span
                      class="group/pill inline-flex items-center h-7 rounded-md text-xs font-medium text-[var(--purple-300)] flex-shrink-0 cursor-pointer transition-all duration-150"
                      style={{ background: "var(--pill-purple)" }}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (wordIdx() === 0) {
                          batch(() => { setCmdPills([]); setArgPills([]); setQuery("/"); setFocusedIndex(0); });
                        } else {
                          batch(() => { setCmdPills(cmdPills().slice(0, wordIdx())); setArgPills([]); setQuery(""); setFocusedIndex(0); });
                        }
                        inputRef?.focus();
                      }}
                    >
                      <span class="px-2">{wordIdx() === 0 ? `/${word}` : word}</span>
                      <span class="w-0 overflow-hidden group-hover/pill:w-5 transition-all duration-150 flex items-center justify-center">
                        <X size={12} strokeWidth={2.5} class="text-[var(--purple-400)]" />
                      </span>
                    </span>
                  )}
                </For>
              </Show>
              {/* Arg pills */}
              <Show when={resolvedCommand() && argPills().length > 0}>
                <For each={argPills()}>
                  {(pill, i) => {
                    const cmd = () => resolvedCommand()!;
                    const argDef = () => cmd().args[i()];
                    const label = () => {
                      const collected = Object.fromEntries(argPills().slice(0, i() + 1).map((p) => [p.name, p.value]));
                      return argDef().complete?.("", collected).find((c) => c.value === pill.value)?.label ?? pill.value;
                    };
                    return (
                      <span
                        class="group/pill inline-flex items-center h-7 rounded-md text-xs flex-shrink-0 cursor-pointer transition-all duration-150"
                        style={{ background: "var(--pill-ember)" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          batch(() => {
                            setPendingExec(null);
                            setArgPills(argPills().slice(0, i()));
                            setQuery("");
                            setFocusedIndex(0);
                          });
                          inputRef?.focus();
                        }}
                      >
                        <span class="inline-flex items-center gap-1 px-2">
                          <span class="text-[var(--ember-500)]">{argDef().name}:</span>
                          <span class="font-medium text-[var(--ember-300)]">{label()}</span>
                        </span>
                        <span class="w-0 overflow-hidden group-hover/pill:w-5 transition-all duration-150 flex items-center justify-center">
                          <X size={12} strokeWidth={2.5} class="text-[var(--ember-400)]" />
                        </span>
                      </span>
                    );
                  }}
                </For>
              </Show>
              <Show
                when={mode() !== "confirm"}
                fallback={
                  <span
                    tabIndex={0}
                    ref={(el) => setTimeout(() => el.focus(), 0)}
                    on:keydown={handleKeyDown}
                    class="h-7 flex items-center text-sm text-[var(--red-400)] outline-none"
                  >
                    press <KeyBadge value="Enter" size="sm" /> to confirm or <KeyBadge value="Esc" size="sm" /> to cancel
                  </span>
                }
              >
                <div class="relative flex-1 min-w-[80px] flex items-center">
                  <input
                    ref={inputRef}
                    on:keydown={handleKeyDown}
                    placeholder={placeholder()}
                    value={query()}
                    onInput={(e) => { setQuery(e.currentTarget.value); setFocusedIndex(0); }}
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck={false}
                    class="h-7 w-full bg-transparent text-sm text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)] outline-none relative z-10"
                  />
                  <Show when={ghostText()}>
                    <span class="absolute inset-0 flex items-center h-7 text-sm text-[var(--neutral-500)] pointer-events-none select-none">
                      <span class="invisible whitespace-pre">{query()}</span>
                      <span>{ghostText()}</span>
                    </span>
                  </Show>
                </div>
                <Show when={ghostText()}>
                  <KeyBadge value="Tab" size="sm" />
                </Show>
              </Show>
            </div>

            {/* Results list */}
            <Show when={itemCount() > 0}>
            <div ref={listRef} class="scrollarea max-h-64 overflow-y-auto py-1">
              {/* Search mode */}
              <Show when={mode() === "search"}>
                  <For each={searchResults()}>
                    {(item, idx) => {
                      const focused = () => idx() === focusedIndex();
                      const rowClass = () => cn(
                        "w-full text-left px-3 py-2 text-sm flex items-center gap-2 cursor-pointer transition-colors",
                        focused()
                          ? "bg-[var(--active)] text-[var(--neutral-100)]"
                          : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
                      );
                      const grad = item.iconKey ? hashGradient(item.iconKey) : null;
                      return (
                        <button
                          onClick={() => { recordUsage(item.id); item.onSelect(); setOpen(false); }}
                          onMouseEnter={() => setFocusedIndex(idx())}
                          class={rowClass()}
                        >
                          <Show when={grad}>
                            {(g) => (
                              <div
                                class="w-4 h-4 rounded-[3px] flex items-center justify-center text-[9px] font-bold flex-shrink-0"
                                style={{ background: `linear-gradient(${g().angle}deg, ${g().from}, ${g().to})`, color: "var(--neutral-100)" }}
                              >
                                {item.iconLabel}
                              </div>
                            )}
                          </Show>
                          <Show when={item.prefix}>
                            <span class="text-[var(--neutral-500)] flex-shrink-0">{item.prefix}</span>
                          </Show>
                          <span class="truncate">{item.label}</span>
                          <Show when={item.badge}>
                            <span class="ml-auto flex items-center gap-1.5 flex-shrink-0">
                              <span
                                class="text-[10px] px-1.5 py-0.5 rounded text-[var(--neutral-500)]"
                                style={{ background: "var(--neutral-800)" }}
                              >
                                {item.badge}
                              </span>
                              <Show when={item.badgeIconKey}>
                                {(key) => {
                                  const bg = hashGradient(key());
                                  return (
                                    <div
                                      class="w-4 h-4 rounded-[3px] flex items-center justify-center text-[9px] font-bold"
                                      style={{ background: `linear-gradient(${bg.angle}deg, ${bg.from}, ${bg.to})`, color: "var(--neutral-100)" }}
                                    >
                                      {item.badge![0]}
                                    </div>
                                  );
                                }}
                              </Show>
                            </span>
                          </Show>
                        </button>
                      );
                    }}
                  </For>
              </Show>

              {/* Command mode */}
              <Show when={mode() === "command"}>
                  <For each={filteredCommands()}>
                    {(cmd, idx) => {
                      const preview = () => {
                        if (cmd.args.length === 0) return [];
                        const { pills } = autoConfirmArgs(cmd, []);
                        return pills.map((p) => {
                          const argDef = cmd.args.find((a) => a.name === p.name);
                          const label = argDef?.complete?.("", {}).find((c) => c.value === p.value)?.label ?? p.value;
                          return { name: p.name, label };
                        });
                      };
                      return (
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
                        <CommandHighlight command={cmd.command} query={highlightQuery()} />
                        <Show when={preview().length > 0}>
                          <div class="flex items-center gap-1 ml-2">
                            <For each={preview()}>
                              {(p) => (
                                <span class="text-[10px] px-1.5 py-0.5 rounded text-[var(--neutral-500)] flex-shrink-0" style={{ background: "var(--neutral-800)" }}>
                                  {p.name}: {p.label}
                                </span>
                              )}
                            </For>
                          </div>
                        </Show>
                        <Show when={cmd.shortcut}>
                          <div class="ml-auto flex items-center gap-0.5 pl-3">
                            <For each={cmd.shortcut!}>
                              {(k) => <KeyBadge value={k} size="sm" />}
                            </For>
                          </div>
                        </Show>
                      </button>
                      );
                    }}
                  </For>
              </Show>

              {/* Args mode: completions */}
              <Show when={mode() === "args"}>
                <Show when={argCompletions().length > 0}>
                  <For each={argCompletions()}>
                    {(opt, idx) => {
                      const grad = opt.iconKey ? hashGradient(opt.iconKey) : null;
                      return (
                        <button
                          onClick={() => submitArg(opt.value)}
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
            </Show>
          </KDialog.Content>
        </div>
      </KDialog.Portal>
    </KDialog>
  );
}
