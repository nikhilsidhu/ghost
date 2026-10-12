// The page for one thing the launcher runs: a relay, a profile (with its call when it is
// in one), or another process (the dev server, the build, a blueprint, a test caller).
// Each shows its state and actions at the top and its log below.

import { children, Show, type JSX } from "solid-js";
import { Button } from "../components/ui/button";
import { PanelHeader } from "../components/ui/panel-header";
import type { Actions } from "./actions";
import { profileRemove, profileReset, profileStart, profileStop, profileWindow, relayReset, relayStart, relayStop } from "./api";
import { CallPanel } from "./CallPanel";
import type { LauncherView } from "./generated/LauncherView";
import type { ProfileView } from "./generated/ProfileView";
import type { RelayView } from "./generated/RelayView";
import type { Status } from "./generated/Status";
import { LogPanel } from "./LogPanel";
import { ConfirmButton } from "../components/ui/confirm-button";
import { isRunning, profilePlace, RebuildButton, StartStopButton, StatusDot, statusText } from "./parts";

/** A detail page: its header with the state dot, a note and actions, then `children`
 * above the log of `process`. */
function DetailPage(props: { title: string; status: Status; note: string; noteTitle?: string; process: string; actions?: JSX.Element; children?: JSX.Element }) {
  const body = children(() => props.children);
  return (
    <div class="flex-1 min-w-0 flex flex-col">
      <PanelHeader title={props.title} icon={<StatusDot status={props.status} />}>
        <span class="text-xs text-[var(--neutral-500)] truncate ml-1" title={props.noteTitle}>
          {props.note}
        </span>
        <div class="flex-1" />
        <div class="flex items-center gap-1 flex-shrink-0">{props.actions}</div>
      </PanelHeader>
      <Show when={body()}>
        <div class="flex-shrink-0 max-h-[55%] overflow-y-auto scrollarea px-2">{body()}</div>
      </Show>
      <LogPanel process={props.process} class="flex-1 min-h-40 mt-4 mb-4 px-2" />
    </div>
  );
}

export function RelayPage(props: { relay: RelayView; actions: Actions }) {
  const relay = () => props.relay;
  return (
    <DetailPage
      title={`relay ${relay().name}`}
      status={relay().status}
      note={`${relay().url} · voice ${relay().voice_port}`}
      process={relay().process}
      actions={
        <>
          <StartStopButton process={relay().process} status={relay().status} actions={props.actions} start={() => relayStart(relay().name)} stop={() => relayStop(relay().name)} />
          <ConfirmButton label="reset" confirm="delete its data?" onConfirm={() => props.actions.run(`reset ${relay().process}`, () => relayReset(relay().name))} />
        </>
      }
    />
  );
}

export function ProfilePage(props: { profile: ProfileView; view: LauncherView; actions: Actions }) {
  const profile = () => props.profile;
  const running = () => isRunning(profile().status);
  const window = (cmd: "focus" | "open_profiler") => props.actions.run(`${cmd} ${profile().process}`, () => profileWindow(profile().name, cmd));
  const remove = () =>
    props.actions.run(`remove ${profile().process}`, async () => {
      await profileRemove(profile().name);
      props.actions.open({ kind: "overview" });
    });

  return (
    <DetailPage
      title={profile().name}
      status={profile().status}
      note={profilePlace(profile())}
      noteTitle={profile().data_dir}
      process={profile().process}
      actions={
        <>
          <Show when={running()}>
            <Button variant="ghost" size="sm" onClick={() => window("focus")}>
              focus
            </Button>
            <Button variant="ghost" size="sm" onClick={() => window("open_profiler")}>
              profiler
            </Button>
          </Show>
          <StartStopButton process={profile().process} status={profile().status} actions={props.actions} start={() => profileStart(profile().name)} stop={() => profileStop(profile().name)} />
          <ConfirmButton label="reset" confirm="delete account?" onConfirm={() => props.actions.run(`reset ${profile().process}`, () => profileReset(profile().name))} />
          <ConfirmButton label="remove" confirm="remove profile?" onConfirm={remove} />
        </>
      }
    >
      <Show when={running()}>
        <Show
          when={profile().call}
          fallback={<div class="mx-4 mt-2 text-xs text-[var(--neutral-500)]">not in a call: join a voice channel in its window to add test callers and change networks here</div>}
        >
          <CallPanel profile={profile().name} view={props.view} actions={props.actions} />
        </Show>
      </Show>
    </DetailPage>
  );
}

export function ProcessPage(props: { process: string; status: Status; view: LauncherView; actions: Actions }) {
  const isBuild = () => props.process === props.view.build.process;
  return (
    <DetailPage
      title={props.process}
      status={props.status}
      note={statusText(props.status)}
      process={props.process}
      actions={
        <Show when={isBuild()}>
          <RebuildButton actions={props.actions} variant="outline" />
        </Show>
      }
    />
  );
}
