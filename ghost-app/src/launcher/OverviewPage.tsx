// Everything at a glance: start from a blueprint, every relay and profile with its state and
// the one action most often wanted, and whatever ended badly.

import { createSignal, For, Show } from "solid-js";
import { SettingGroup } from "../components/settings/controls";
import { Button } from "../components/ui/button";
import { PanelHeader } from "../components/ui/panel-header";
import { FadedScrollArea } from "../components/ui/scroll-area";
import { Select } from "../components/ui/select";
import type { Actions } from "./actions";
import { profileStart, profileStop, profileWindow, relayStart, relayStop } from "./api";
import { applyBlueprint, blueprintNote, REPLACES_EVERYTHING } from "./BlueprintsPage";
import type { LauncherView } from "./generated/LauncherView";
import { isRunning, PageLink, profilePlace, Row, StartStopButton, StatusDot, statusText } from "./parts";

export function OverviewPage(props: { view: LauncherView; actions: Actions }) {
  const [chosen, setChosen] = createSignal(props.view.blueprints[0]?.id ?? "");
  const blueprint = () => props.view.blueprints.find((b) => b.id === chosen());
  const options = () =>
    props.view.blueprints.map((b) => ({ value: b.id, label: b.source.kind === "saved" ? `${b.name} · saved` : b.name }));

  return (
    <div class="flex-1 min-w-0 flex flex-col">
      <PanelHeader title="overview" />
      <FadedScrollArea>
        <div class="pb-6 px-2">
          <SettingGroup label="start from a blueprint" footer={REPLACES_EVERYTHING}>
            <div class="flex items-center gap-3 py-3">
              <Select value={chosen()} options={options()} onChange={setChosen} label="Blueprint" align="left" />
              <span class="flex-1 min-w-0 text-xs text-[var(--neutral-500)]">
                <Show when={blueprint()}>{(current) => blueprintNote(current())}</Show>
              </span>
              <Show when={blueprint()}>
                {(current) => (
                  <Button size="sm" disabled={isRunning(props.view.blueprint.status)} onClick={() => applyBlueprint(props.actions, current(), null)}>
                    use
                  </Button>
                )}
              </Show>
            </div>
          </SettingGroup>

          {/* Each group first in its own cell, so both take the same top margin. */}
          <div class="grid grid-cols-2 mt-2">
            <div>
              <SettingGroup label="relays">
                <For each={props.view.relays}>
                  {(relay) => (
                    <Row
                      actions={
                        <StartStopButton process={relay.process} status={relay.status} actions={props.actions} start={() => relayStart(relay.name)} stop={() => relayStop(relay.name)} />
                      }
                    >
                      <StatusDot status={relay.status} />
                      <PageLink onClick={() => props.actions.open({ kind: "relay", name: relay.name })}>relay {relay.name}</PageLink>
                      <span class="text-xs text-[var(--neutral-500)] truncate tabular-nums">
                        {relay.port} · voice {relay.voice_port}
                      </span>
                    </Row>
                  )}
                </For>
              </SettingGroup>
            </div>

            <div>
              <SettingGroup label="profiles">
                <For each={props.view.profiles}>
                  {(profile) => (
                    <Row
                      actions={
                        <Show
                          when={isRunning(profile.status)}
                          fallback={
                            <StartStopButton process={profile.process} status={profile.status} actions={props.actions} start={() => profileStart(profile.name)} stop={() => profileStop(profile.name)} />
                          }
                        >
                          <Button variant="ghost" size="sm" onClick={() => props.actions.run(`focus ${profile.process}`, () => profileWindow(profile.name, "focus"))}>
                            focus
                          </Button>
                        </Show>
                      }
                    >
                      <StatusDot status={profile.status} />
                      <PageLink onClick={() => props.actions.open({ kind: "profile", name: profile.name })}>{profile.name}</PageLink>
                      <span class="text-xs text-[var(--neutral-500)] truncate">{profilePlace(profile)}</span>
                    </Row>
                  )}
                </For>
              </SettingGroup>
            </div>
          </div>

          <Show when={props.view.failures.length > 0}>
            <SettingGroup label="needs attention">
              <For each={props.view.failures}>
                {(failure) => (
                  <Row
                    actions={
                      <Button variant="ghost" size="sm" onClick={() => props.actions.openProcess(failure.process)}>
                        open log
                      </Button>
                    }
                  >
                    <StatusDot status={failure.status} />
                    <span class="text-sm text-[var(--neutral-200)] whitespace-nowrap">{failure.process}</span>
                    <span class="text-xs text-[var(--red-400)] truncate" title={failure.last_line ?? undefined}>
                      {statusText(failure.status)}
                      {failure.last_line ? `: ${failure.last_line}` : ""}
                    </span>
                  </Row>
                )}
              </For>
            </SettingGroup>
          </Show>
        </div>
      </FadedScrollArea>
    </div>
  );
}
