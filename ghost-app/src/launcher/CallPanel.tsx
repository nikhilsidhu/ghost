// A profile's call: everyone in it with the network each has on the hosting relay, its
// test callers (at home on either relay, each with its own tone as a voice), and adding
// more. The profile's profiler shows the effect.

import { createEffect, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import { SettingGroup } from "../components/settings/controls";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Segmented } from "../components/ui/segmented";
import type { Actions } from "./actions";
import { callerAdd, callerRemove, callerVoice, callView, setNetwork } from "./api";
import type { CallerView } from "./generated/CallerView";
import type { CallView } from "./generated/CallView";
import type { LauncherView } from "./generated/LauncherView";
import type { NetworkView } from "./generated/NetworkView";
import type { ParticipantKind } from "./generated/ParticipantKind";
import type { ParticipantView } from "./generated/ParticipantView";
import type { Voice } from "./generated/Voice";
import { Row, StatusDot } from "./parts";

/** How often the call's participants are read again. */
const REFRESH_MS = 2000;
const VOICES = [
  { value: "steady", label: "steady" },
  { value: "spurts", label: "talk spurts" },
  { value: "silent", label: "silent" },
] as const;
const KIND_LABELS: Record<ParticipantKind, string> = { own: "this profile", profile: "profile", caller: "test caller", other: "not from the launcher" };
const NETWORK_FIELDS = [
  { key: "loss_percent", label: "loss", unit: "%", max: 100 },
  { key: "delay_ms", label: "delay", unit: "ms", max: 2000 },
  { key: "jitter_ms", label: "jitter", unit: "ms", max: 1000 },
] as const;

/** A test caller's voice, log and removal, on a line of their own under its name. */
function CallerControls(props: { caller: CallerView; actions: Actions; onRemoved: () => void }) {
  const id = () => props.caller.id;
  return (
    <div class="flex items-center gap-1">
      <Segmented value={props.caller.voice} options={VOICES} onChange={(next) => props.actions.run(`voice ${id()}`, () => callerVoice(id(), next))} label="Voice" />
      <Button variant="ghost" size="sm" onClick={() => props.actions.openProcess(props.caller.process)}>
        log
      </Button>
      <Button variant="ghost" size="sm" onClick={() => props.actions.run(`remove ${id()}`, () => callerRemove(id()).then(props.onRemoved))}>
        remove
      </Button>
    </div>
  );
}

/** Loss, delay and jitter for one participant, applied as each field is changed. */
function NetworkEditor(props: { network: NetworkView; disabled: boolean; onChange: (network: NetworkView) => void }) {
  return (
    <div class="flex items-center gap-3">
      <For each={NETWORK_FIELDS}>
        {(field) => (
          <label class="flex items-center gap-1 text-xs text-[var(--neutral-500)]">
            {field.label}
            <Input
              type="number"
              min="0"
              max={field.max}
              class="h-7 w-16 px-2 text-xs tabular-nums"
              value={props.network[field.key]}
              disabled={props.disabled}
              onChange={(e) => {
                const value = Math.min(field.max, Math.max(0, Number(e.currentTarget.value) || 0));
                props.onChange({ ...props.network, [field.key]: value });
              }}
            />
            {field.unit}
          </label>
        )}
      </For>
    </div>
  );
}

export function CallPanel(props: { profile: string; view: LauncherView; actions: Actions }) {
  const [call, setCall] = createSignal<CallView | null>(null);
  const [callerRelay, setCallerRelay] = createSignal(props.view.relays[0]?.name ?? "");
  const [voice, setVoice] = createSignal<Voice>("spurts");
  const relayOptions = () => props.view.relays.map((relay) => ({ value: relay.name, label: `from relay ${relay.name}` }));
  const callers = () => props.view.callers.filter((caller) => caller.profile === props.profile);
  const run = props.actions.run;

  /** Read the call again, dropping an answer that arrives after the page moved on. */
  const readCall = () => {
    const profile = props.profile;
    const settle = (call: CallView | null) => profile === props.profile && setCall(call);
    return callView(profile).then(settle, () => settle(null));
  };

  // Another profile's page reuses the panel: show its call, not the last one's.
  createEffect(
    on(
      () => props.profile,
      () => {
        setCall(null);
        readCall();
      },
    ),
  );
  onMount(() => {
    const timer = setInterval(readCall, REFRESH_MS);
    onCleanup(() => clearInterval(timer));
  });

  const changeNetwork = (participant: ParticipantView, network: NetworkView) => {
    const relay = call()?.relay;
    if (relay) run(`network ${participant.slot}`, () => setNetwork(relay, participant.slot, network).then(readCall));
  };

  const callerOf = (participant: ParticipantView) => callers().find((caller) => caller.id === participant.caller);
  /** Test callers that are not, or no longer, in the call: still starting, or stopped. */
  const outside = () => callers().filter((caller) => !call()?.participants.some((p) => p.caller === caller.id));

  return (
    <Show when={call()}>
      {(current) => (
        <SettingGroup
          label={current().relay ? `in the call · hosted on relay ${current().relay}` : "in the call"}
          footer={current().relay ? "loss, delay and jitter apply both ways, to everything to and from that participant" : "the call is on a relay the launcher does not run, so its network cannot be changed here"}
        >
          <For each={current().participants}>
            {(participant) => (
              <Row actions={<NetworkEditor network={participant.network} disabled={!current().relay} onChange={(network) => changeNetwork(participant, network)} />}>
                <div class="flex flex-col gap-1.5 py-1 min-w-0">
                  <div class="flex items-center gap-3 min-w-0">
                    <span class="text-sm text-[var(--neutral-200)] truncate">{participant.name}</span>
                    <span class="text-xs text-[var(--neutral-500)] whitespace-nowrap">
                      {KIND_LABELS[participant.kind]} · slot {participant.slot}
                      <Show when={callerOf(participant)}>{(caller) => ` · from relay ${caller().relay}`}</Show>
                    </span>
                  </div>
                  <Show when={callerOf(participant)}>{(caller) => <CallerControls caller={caller()} actions={props.actions} onRemoved={readCall} />}</Show>
                </div>
              </Row>
            )}
          </For>
          <For each={outside()}>
            {(caller) => (
              <Row>
                <div class="flex flex-col gap-1.5 py-1 min-w-0">
                  <div class="flex items-center gap-3 min-w-0">
                    <StatusDot status={caller.status} />
                    <span class="text-sm text-[var(--neutral-200)] truncate">{caller.name}</span>
                    <span class="text-xs text-[var(--neutral-500)] whitespace-nowrap">test caller · not in the call</span>
                  </div>
                  <CallerControls caller={caller} actions={props.actions} onRemoved={readCall} />
                </div>
              </Row>
            )}
          </For>
          <div class="flex items-center gap-2 py-3">
            <span class="text-xs text-[var(--neutral-500)]">add a test caller</span>
            <Segmented value={callerRelay()} options={relayOptions()} onChange={setCallerRelay} label="Caller's home relay" />
            <Segmented value={voice()} options={VOICES} onChange={setVoice} label="Voice" />
            <Button
              variant="outline"
              size="sm"
              disabled={props.actions.busy("add caller")}
              onClick={() => run("add caller", () => callerAdd(props.profile, callerRelay(), voice()).then(readCall))}
            >
              {props.actions.busy("add caller") ? "joining…" : "add caller"}
            </Button>
          </div>
        </SettingGroup>
      )}
    </Show>
  );
}
