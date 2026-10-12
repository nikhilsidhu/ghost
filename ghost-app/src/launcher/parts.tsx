// Small pieces the launcher's pages share.

import { Show, type JSX } from "solid-js";
import { Button } from "../components/ui/button";
import type { Actions } from "./actions";
import { rebuild } from "./api";
import type { ProfileView } from "./generated/ProfileView";
import type { Status } from "./generated/Status";

export const isRunning = (status: Status) => status.state === "running";

/** Running is green, a clean finish quiet, a crash or a failed start red. */
function statusColor(status: Status): string {
  switch (status.state) {
    case "running":
      return "var(--emerald-400)";
    case "stopped":
      return "var(--neutral-600)";
    case "exited":
      return status.code === 0 ? "var(--neutral-500)" : "var(--red-400)";
    case "failed":
      return "var(--red-400)";
  }
}

export function statusText(status: Status): string {
  switch (status.state) {
    case "running":
      return "running";
    case "stopped":
      return "stopped";
    case "exited":
      return status.code === 0 ? "finished" : `exited${status.code === null ? "" : ` with ${status.code}`}`;
    case "failed":
      return status.message;
  }
}

/** A process's state at a glance, its words on hover. */
export function StatusDot(props: { status: Status }) {
  return (
    <span
      class="w-2 h-2 rounded-full flex-shrink-0"
      style={{ background: statusColor(props.status) }}
      title={statusText(props.status)}
      aria-label={statusText(props.status)}
    />
  );
}

/** Start `process` when it is stopped, stop it when it runs. */
export function StartStopButton(props: {
  process: string;
  status: Status;
  actions: Actions;
  start: () => Promise<unknown>;
  stop: () => Promise<unknown>;
}) {
  const starting = () => props.actions.busy(`start ${props.process}`);
  return (
    <Show
      when={isRunning(props.status)}
      fallback={
        <Button variant="outline" size="sm" disabled={starting()} onClick={() => props.actions.run(`start ${props.process}`, props.start)}>
          {starting() ? "starting…" : "start"}
        </Button>
      }
    >
      <Button variant="outline" size="sm" onClick={() => props.actions.run(`stop ${props.process}`, props.stop)}>
        stop
      </Button>
    </Show>
  );
}

/** Where a profile is: in a call, or else its home relay. */
export function profilePlace(profile: ProfileView): string {
  return profile.call ? `in a call · ${profile.call.server} › ${profile.call.channel}` : `home on relay ${profile.relay}`;
}

/** The name of something with its own page, opening it when clicked. */
export function PageLink(props: { onClick: () => void; children: JSX.Element }) {
  return (
    <button class="text-sm text-[var(--neutral-200)] hover:text-[var(--neutral-50)] cursor-pointer truncate" onClick={props.onClick}>
      {props.children}
    </button>
  );
}

/** The action key of a rebuild, wherever its button is. */
const REBUILD = "rebuild";

/** Build the app, relay and headless device again. */
export function RebuildButton(props: { actions: Actions; variant: "ghost" | "outline"; class?: string }) {
  const building = () => props.actions.busy(REBUILD);
  return (
    <Button variant={props.variant} size="sm" class={props.class} disabled={building()} onClick={() => props.actions.run(REBUILD, rebuild)}>
      {building() ? "building…" : "rebuild"}
    </Button>
  );
}

/** A small label naming something a row involves: a profile, a relay. */
export function Chip(props: { children: JSX.Element }) {
  return <span class="text-[11px] text-[var(--neutral-400)] bg-[var(--neutral-800)] px-1.5 py-0.5 rounded">{props.children}</span>;
}

/** One row of a launcher list: what it is on the left, what can be done on the right. */
export function Row(props: { children: JSX.Element; actions?: JSX.Element }) {
  return (
    <div class="flex items-center gap-3 py-2 border-b border-[var(--neutral-800)] last:border-b-0 min-h-11">
      <div class="flex items-center gap-3 flex-1 min-w-0">{props.children}</div>
      <Show when={props.actions}>
        <div class="flex items-center gap-1 flex-shrink-0">{props.actions}</div>
      </Show>
    </div>
  );
}
