// The launcher's side list: the overview and blueprints pages, every relay and profile with
// its state, adding a profile and tiling their windows, and the dev server and build at the
// foot.

import { createSignal, For, Show } from "solid-js";
import { Grid2x2, LayoutGrid, LayoutTemplate } from "lucide-solid";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { NavItem } from "../components/ui/nav-item";
import { navActionClass, NavSection } from "../components/ui/nav-section";
import { PanelHeader } from "../components/ui/panel-header";
import { ScrollArea } from "../components/ui/scroll-area";
import { Segmented } from "../components/ui/segmented";
import { pageKey, type Actions, type Page } from "./actions";
import { profileAdd, windowsTile } from "./api";
import type { LauncherView } from "./generated/LauncherView";
import type { ProcessView } from "./generated/ProcessView";
import { isRunning, RebuildButton, StatusDot } from "./parts";

/** A launcher process at the foot of the list: its state, and its page when clicked. */
function FootProcess(props: { label: string; process: ProcessView; actions: Actions }) {
  return (
    <button
      class="flex items-center gap-1.5 text-xs whitespace-nowrap text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer"
      onClick={() => props.actions.openProcess(props.process.process)}
    >
      <StatusDot status={props.process.status} /> {props.label}
    </button>
  );
}

export function LauncherNav(props: { view: LauncherView; page: Page; actions: Actions }) {
  const [adding, setAdding] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [newRelay, setNewRelay] = createSignal(props.view.relays[0]?.name ?? "");
  const relayOptions = () => props.view.relays.map((relay) => ({ value: relay.name, label: `relay ${relay.name}` }));
  const is = (page: Page) => pageKey(page) === pageKey(props.page);

  const addProfile = () => {
    const name = newName().trim();
    props.actions.run("add profile", async () => {
      await profileAdd(name, newRelay());
      setNewName("");
      setAdding(false);
      props.actions.open({ kind: "profile", name });
    });
  };

  return (
    <aside class="w-64 flex-shrink-0 flex flex-col border-r border-[var(--neutral-800)]">
      <PanelHeader title="ghost dev" />
      <ScrollArea class="flex-1 min-h-0">
        <div class="px-2 flex flex-col">
          <NavItem selected={is({ kind: "overview" })} onClick={() => props.actions.open({ kind: "overview" })}>
            <LayoutGrid size={14} />
            overview
          </NavItem>
          <NavItem selected={is({ kind: "blueprints" })} onClick={() => props.actions.open({ kind: "blueprints" })}>
            <LayoutTemplate size={14} />
            <span class="flex-1 truncate">blueprints</span>
            {/* Only a blueprint at work or one that failed is worth a glance from here. */}
            <Show when={isRunning(props.view.blueprint.status) || props.view.blueprint.status.state === "failed"}>
              <StatusDot status={props.view.blueprint.status} />
            </Show>
          </NavItem>
        </div>

        <NavSection class="mt-3" label="relays">
          <For each={props.view.relays}>
            {(relay) => (
              <NavItem selected={is({ kind: "relay", name: relay.name })} onClick={() => props.actions.open({ kind: "relay", name: relay.name })}>
                <StatusDot status={relay.status} />
                <span class="flex-1 truncate">relay {relay.name}</span>
                <span class="text-xs text-[var(--neutral-500)] tabular-nums">{relay.port}</span>
              </NavItem>
            )}
          </For>
        </NavSection>

        <NavSection
          class="mt-2"
          label="profiles"
          onAdd={() => setAdding((open) => !open)}
          addLabel="Add a profile"
          actions={
            <button class={navActionClass} title="Tile the running profiles' windows" aria-label="Tile the running profiles' windows" onClick={() => props.actions.run("tile", windowsTile)}>
              <Grid2x2 size={13} />
            </button>
          }
        >
          <Show when={adding()}>
            <div class="flex flex-col gap-2 px-2 py-2">
              <Input
                class="h-7 text-xs"
                placeholder="name"
                aria-label="New profile name"
                autofocus
                value={newName()}
                onInput={(e) => setNewName(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && newName().trim()) addProfile();
                  if (e.key === "Escape") setAdding(false);
                }}
              />
              <div class="flex items-center gap-2">
                <Segmented value={newRelay()} options={relayOptions()} onChange={setNewRelay} label="Home relay" />
                <Button variant="outline" size="sm" class="ml-auto" disabled={!newName().trim() || props.actions.busy("add profile")} onClick={addProfile}>
                  add
                </Button>
              </div>
            </div>
          </Show>
          <For each={props.view.profiles}>
            {(profile) => (
              <NavItem selected={is({ kind: "profile", name: profile.name })} onClick={() => props.actions.open({ kind: "profile", name: profile.name })}>
                <StatusDot status={profile.status} />
                <span class="flex-1 truncate">{profile.name}</span>
                <Show when={profile.call}>
                  {(call) => (
                    <span class="text-[11px] text-[var(--emerald-400)]" title={`in a call in ${call().server} › ${call().channel}`}>
                      in call
                    </span>
                  )}
                </Show>
              </NavItem>
            )}
          </For>
        </NavSection>
      </ScrollArea>

      <div class="flex items-center gap-3 px-4 py-3 border-t border-[var(--neutral-800)]">
        <FootProcess label="dev server" process={props.view.dev_server} actions={props.actions} />
        <FootProcess label="build" process={props.view.build} actions={props.actions} />
        <RebuildButton actions={props.actions} variant="ghost" class="ml-auto" />
      </div>
    </aside>
  );
}
