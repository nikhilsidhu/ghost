// Ghost Dev: run Ghost for development. The side list holds the overview, the blueprints,
// every relay and profile, and the dev server and build; the page beside it shows whichever
// is chosen, with its actions and its log.

import { createMemo, createSignal, Match, onCleanup, onMount, Show, Switch } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { createActions, type Page } from "./actions";
import { CHANGED_EVENT, launcherView } from "./api";
import { BlueprintsPage } from "./BlueprintsPage";
import { ProcessPage, ProfilePage, RelayPage } from "./DetailPages";
import type { LauncherView } from "./generated/LauncherView";
import type { Status } from "./generated/Status";
import { LauncherNav } from "./LauncherNav";
import { OverviewPage } from "./OverviewPage";

/** The state of `process`, among the processes the launcher shows. */
function statusOf(view: LauncherView, process: string): Status {
  const own = [view.dev_server, view.build, view.blueprint].find((p) => p.process === process);
  const caller = view.callers.find((c) => c.process === process);
  return own?.status ?? caller?.status ?? { state: "stopped" };
}

export default function Launcher() {
  const [view, setView] = createSignal<LauncherView | null>(null);
  const [chosen, setChosen] = createSignal<Page>({ kind: "overview" });
  const [error, setError] = createSignal<string | null>(null);

  const refresh = () => launcherView().then(setView).catch((e) => setError(String(e)));

  const actions = createActions({
    onError: setError,
    onDone: refresh,
    open: setChosen,
    pageFor: (process) => {
      const current = view();
      const relay = current?.relays.find((r) => r.process === process);
      if (relay) return { kind: "relay", name: relay.name };
      const profile = current?.profiles.find((p) => p.process === process);
      if (profile) return { kind: "profile", name: profile.name };
      return { kind: "process", process };
    },
  });

  onMount(() => {
    refresh();
    const unlisten = listen(CHANGED_EVENT, () => refresh());
    onCleanup(() => unlisten.then((stop) => stop()));
  });

  // A page for a relay or profile that has gone shows the overview instead.
  const page = createMemo((): Page => {
    const current = view();
    const page = chosen();
    if (page.kind === "relay" && !current?.relays.some((r) => r.name === page.name)) return { kind: "overview" };
    if (page.kind === "profile" && !current?.profiles.some((p) => p.name === page.name)) return { kind: "overview" };
    return page;
  });
  const relay = () => {
    const p = page();
    return p.kind === "relay" ? view()?.relays.find((r) => r.name === p.name) : undefined;
  };
  const profile = () => {
    const p = page();
    return p.kind === "profile" ? view()?.profiles.find((r) => r.name === p.name) : undefined;
  };
  const process = () => {
    const p = page();
    return p.kind === "process" ? p.process : undefined;
  };

  return (
    <div class="h-screen flex bg-[var(--neutral-950)] text-[var(--neutral-200)]">
      <Show when={view()}>
        {(current) => (
          <>
            <LauncherNav view={current()} page={page()} actions={actions} />
            <main class="relative flex-1 min-w-0 flex">
              <Switch>
                <Match when={page().kind === "overview"}>
                  <OverviewPage view={current()} actions={actions} />
                </Match>
                <Match when={page().kind === "blueprints"}>
                  <BlueprintsPage view={current()} actions={actions} />
                </Match>
                <Match when={relay()}>{(relay) => <RelayPage relay={relay()} actions={actions} />}</Match>
                <Match when={profile()}>{(profile) => <ProfilePage profile={profile()} view={current()} actions={actions} />}</Match>
                <Match when={process()}>
                  {(process) => <ProcessPage process={process()} status={statusOf(current(), process())} view={current()} actions={actions} />}
                </Match>
              </Switch>

              <Show when={error()}>
                <div class="absolute left-4 right-4 bottom-4 px-3 py-2 rounded-md text-xs text-[var(--red-400)] bg-[var(--neutral-900)] border border-[var(--neutral-800)] flex items-center gap-3">
                  <span class="flex-1 break-words">{error()}</span>
                  <button class="text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer" onClick={() => setError(null)}>
                    dismiss
                  </button>
                </div>
              </Show>
            </main>
          </>
        )}
      </Show>
    </div>
  );
}
