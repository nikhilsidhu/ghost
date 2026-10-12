// Blueprints: worlds to start from. Built-in ones are made by a plan through the real
// relays; saved ones are whatever was set up by hand. Pick one from the list to see each
// window it opens, as it will open; using it replaces everything.

import { createSignal, For, Match, Show, Switch } from "solid-js";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { PanelHeader } from "../components/ui/panel-header";
import { FadedScrollArea } from "../components/ui/scroll-area";
import { cn } from "../lib/cn";
import type { Actions } from "./actions";
import { blueprintDelete, blueprintPreview, blueprintSave, blueprintUse } from "./api";
import type { BlueprintView } from "./generated/BlueprintView";
import type { Counts } from "./generated/Counts";
import type { LauncherView } from "./generated/LauncherView";
import type { Note } from "./generated/Note";
import type { Preview } from "./generated/Preview";
import type { SizeLimits } from "./generated/SizeLimits";
import type { Sizes } from "./generated/Sizes";
import { LogPanel } from "./LogPanel";
import { ConfirmButton } from "../components/ui/confirm-button";
import { isRunning } from "./parts";
import { NoteFlag, WindowPreview } from "./WindowPreview";

export const REPLACES_EVERYTHING = "replaces every profile and relay";
const SAVE_KEY = "save blueprint";
const SIZE_FIELDS = ["members", "channels", "messages"] as const;
/** The counts in the order the page always shows them, with their words. */
const COUNT_WORDS: { key: keyof Counts; one: string; many: string }[] = [
  { key: "relays", one: "relay", many: "relays" },
  { key: "windows", one: "window", many: "windows" },
  { key: "people", one: "person", many: "people" },
  { key: "servers", one: "server", many: "servers" },
  { key: "channels", one: "channel", many: "channels" },
  { key: "roles", one: "role", many: "roles" },
  { key: "dms", one: "DM", many: "DMs" },
  { key: "messages", one: "message", many: "messages" },
];

const plural = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

/** Use `blueprint`, with `sizes` when it takes them, and show its progress. */
export function applyBlueprint(actions: Actions, blueprint: BlueprintView, sizes: Sizes | null) {
  actions.open({ kind: "blueprints" });
  return actions.run(`blueprint ${blueprint.id}`, () => blueprintUse(blueprint.id, sizes));
}

/** When a blueprint was saved: the time today, else the day. */
function savedAt(ms: number): string {
  const at = new Date(ms);
  const today = new Date().toDateString() === at.toDateString();
  return today
    ? `today at ${at.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`
    : at.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** What a blueprint is: a built-in one's purpose, or when a saved one was saved. */
export function blueprintNote(blueprint: BlueprintView): string {
  return blueprint.source.kind === "built_in" ? `for ${blueprint.source.purpose}` : `saved ${savedAt(blueprint.source.saved_at_ms)}`;
}

/** Each kind of note a blueprint's windows carry, once. */
function distinctNotes(preview: Preview): Note[] {
  const seen = new Set<string>();
  return preview.windows.flatMap((w) => w.notes).filter((note) => !seen.has(note.label) && seen.add(note.label));
}

function CountsLine(props: { counts: Counts }) {
  return (
    <div class="flex flex-wrap gap-x-3.5 gap-y-1 text-xs tabular-nums">
      <For each={COUNT_WORDS}>
        {(c) => {
          const n = () => props.counts[c.key];
          return (
            <span class={n() ? "text-[var(--neutral-400)]" : "text-[var(--neutral-500)]"}>
              <b class={n() ? "font-medium text-[var(--neutral-100)]" : "font-normal"}>{n().toLocaleString()}</b> {n() === 1 ? c.one : c.many}
            </span>
          );
        }}
      </For>
    </div>
  );
}

/** Members, channels and messages for a blueprint that takes sizes, kept within its limits. */
function SizesEditor(props: { limits: SizeLimits; sizes: Sizes; onChange: (sizes: Sizes) => void }) {
  return (
    <div class="flex flex-wrap gap-x-3.5 gap-y-2">
      <For each={SIZE_FIELDS}>
        {(key) => (
          <label class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
            <Input
              type="number"
              min={props.limits.min[key]}
              max={props.limits.max[key]}
              class="h-7 w-20 px-2 text-xs tabular-nums"
              value={props.sizes[key]}
              onChange={(e) => {
                const { min, max } = props.limits;
                const value = Math.min(max[key], Math.max(min[key], Math.round(Number(e.currentTarget.value)) || min[key]));
                e.currentTarget.value = String(value);
                props.onChange({ ...props.sizes, [key]: value });
              }}
            />
            {key}
          </label>
        )}
      </For>
    </div>
  );
}

function SectionTitle(props: { children: string }) {
  return (
    <div class="flex items-center gap-2 text-[11px] text-[var(--neutral-500)]">
      {props.children}
      <span class="flex-1 h-px bg-[var(--neutral-800)]" />
    </div>
  );
}

function BlueprintList(props: { view: LauncherView; selected: string; onSelect: (id: string) => void; actions: Actions }) {
  const [name, setName] = createSignal("");
  const busy = () => isRunning(props.view.blueprint.status);
  const save = () =>
    props.actions.run(SAVE_KEY, async () => {
      await blueprintSave(name().trim());
      setName("");
    });
  const item = (blueprint: BlueprintView) => {
    const counts = blueprint.preview.counts;
    return (
      <button
        class={cn(
          "w-full text-left px-2.5 py-2 rounded-md flex flex-col gap-0.5 cursor-pointer",
          blueprint.id === props.selected ? "bg-[var(--active)]" : "hover:bg-[var(--hover)]",
        )}
        onClick={() => props.onSelect(blueprint.id)}
      >
        <span class="text-sm text-[var(--neutral-100)] flex items-center gap-1.5 flex-wrap">
          {blueprint.name}
          <For each={distinctNotes(blueprint.preview)}>{(note) => <NoteFlag note={note} />}</For>
        </span>
        <span class="text-[11px] text-[var(--neutral-500)] tabular-nums">
          {plural(counts.windows, "window", "windows")} · {plural(counts.servers, "server", "servers")} · {plural(counts.messages, "message", "messages")}
        </span>
      </button>
    );
  };
  return (
    <Card class="p-1.5 flex flex-col gap-0.5">
      <For each={props.view.blueprints.filter((b) => b.source.kind === "built_in")}>{item}</For>
      <span class="text-[11px] text-[var(--neutral-500)] px-2.5 pt-2.5 pb-1">saved</span>
      <For each={props.view.blueprints.filter((b) => b.source.kind === "saved")} fallback={<span class="text-[11px] text-[var(--neutral-500)] px-2.5 pb-1">none yet</span>}>
        {item}
      </For>
      <div class="flex flex-col gap-1.5 p-2.5 mt-1.5 border-t border-[var(--neutral-800)]">
        <Input
          class="h-7 text-xs px-2"
          placeholder="name what is set up now"
          aria-label="Blueprint name"
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
          onKeyDown={(e) => e.key === "Enter" && name().trim() && !busy() && save()}
        />
        <Button variant="outline" size="sm" disabled={!name().trim() || busy()} onClick={save}>
          {props.actions.busy(SAVE_KEY) ? "saving…" : "save as blueprint"}
        </Button>
      </div>
    </Card>
  );
}

function BlueprintDetail(props: { blueprint: BlueprintView; view: LauncherView; actions: Actions }) {
  const limits = () => (props.blueprint.source.kind === "built_in" ? props.blueprint.source.sizes : null);
  /** Sizes changed on the page, with what they open once the launcher says; kept by id,
   * since every refresh of the launcher view brings new objects. */
  const [edited, setEdited] = createSignal<{ id: string; sizes: Sizes; preview: Preview | null } | null>(null);
  const ownEdit = () => (edited()?.id === props.blueprint.id ? edited() : null);
  const sizes = () => ownEdit()?.sizes ?? limits()?.default ?? null;
  const preview = () => ownEdit()?.preview ?? props.blueprint.preview;
  const busy = () => isRunning(props.view.blueprint.status);
  const windows = () => preview().windows.map((w) => w.profile);

  const changeSizes = (next: Sizes) => {
    const id = props.blueprint.id;
    setEdited({ id, sizes: next, preview: ownEdit()?.preview ?? null });
    blueprintPreview(id, next).then((opens) => setEdited((e) => (e?.id === id && e.sizes === next ? { ...e, preview: opens } : e)));
  };

  return (
    <Card class="p-[18px] flex flex-col gap-5 min-w-0">
      <div class="flex items-start gap-3">
        <div class="flex-1 min-w-0 flex flex-col gap-0.5">
          <span class="text-[15px] font-medium text-[var(--neutral-100)]">{props.blueprint.name}</span>
          <span class="text-xs text-[var(--neutral-400)]">{blueprintNote(props.blueprint)}</span>
        </div>
        <Show when={props.blueprint.source.kind === "saved"}>
          <ConfirmButton label="delete" confirm="delete it?" onConfirm={() => props.actions.run(`delete ${props.blueprint.id}`, () => blueprintDelete(props.blueprint.id))} />
        </Show>
        <Button size="sm" disabled={busy()} onClick={() => applyBlueprint(props.actions, props.blueprint, sizes())}>
          {props.actions.busy(`blueprint ${props.blueprint.id}`) ? "using…" : "use"}
        </Button>
      </div>
      <div class="flex flex-wrap gap-x-4 gap-y-1 px-2.5 py-2 rounded-md bg-[var(--neutral-800)] text-xs text-[var(--neutral-400)]">
        <span>
          opens <b class="font-medium text-[var(--neutral-100)]">{plural(windows().length, "window", "windows")}</b>
          {windows().length ? `: ${windows().join(", ")}` : ""}
        </span>
        <span>{REPLACES_EVERYTHING}</span>
      </div>
      <Show when={limits()}>{(bounds) => <SizesEditor limits={bounds()} sizes={sizes() ?? bounds().default} onChange={changeSizes} />}</Show>

      {/* A blueprint at work or one that failed is followed here; a finished one is a click away. */}
      <Switch>
        <Match when={busy() || props.view.blueprint.status.state === "failed"}>
          <LogPanel process={props.view.blueprint.process} label="blueprint log" class="h-56 mx-0" />
        </Match>
        <Match when={props.view.blueprint.status.state === "exited"}>
          <div class="flex items-center gap-2 text-xs text-[var(--neutral-500)]">
            the last blueprint used finished
            <Button variant="ghost" size="sm" onClick={() => props.actions.openProcess(props.view.blueprint.process)}>
              log
            </Button>
          </div>
        </Match>
      </Switch>

      <div class="flex flex-col gap-2.5">
        <SectionTitle>the windows it opens</SectionTitle>
        <Show when={preview().windows.length} fallback={<span class="text-xs text-[var(--neutral-500)]">no profiles</span>}>
          <div class="grid grid-cols-2 gap-2.5">
            <For each={preview().windows}>{(window) => <WindowPreview window={window} />}</For>
          </div>
        </Show>
      </div>
      <div class="flex flex-col gap-2.5">
        <SectionTitle>in numbers</SectionTitle>
        <CountsLine counts={preview().counts} />
        <Show when={props.blueprint.source.kind === "saved"}>
          <span class="text-[11px] text-[var(--neutral-500)]">read from each profile's data when it was saved</span>
        </Show>
      </div>
    </Card>
  );
}

export function BlueprintsPage(props: { view: LauncherView; actions: Actions }) {
  const [selected, setSelected] = createSignal(props.view.blueprints[0]?.id ?? "");
  const current = () => props.view.blueprints.find((b) => b.id === selected()) ?? props.view.blueprints[0];

  return (
    <div class="flex-1 min-w-0 flex flex-col">
      <PanelHeader title="blueprints" />
      <FadedScrollArea>
        <div class="pb-6 px-4 grid grid-cols-[220px_minmax(0,1fr)] gap-3 items-start">
          <BlueprintList view={props.view} selected={current()?.id ?? ""} onSelect={setSelected} actions={props.actions} />
          <Show when={current()}>{(blueprint) => <BlueprintDetail blueprint={blueprint()} view={props.view} actions={props.actions} />}</Show>
        </div>
      </FadedScrollArea>
    </div>
  );
}
