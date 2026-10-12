import { createSignal, onMount, Show } from "solid-js";
import { getAccountStatus } from "./lib/api";
import { deviceRemoved } from "./lib/alerts";
import { listenForLiveState } from "./lib/store";
import { Layout } from "./components/Layout";
import { SetupScreen } from "./components/SetupScreen";
import { RemovedScreen } from "./components/AccountScreens";
import type { AccountPhase } from "./lib/types";

export default function App() {
  const [phase, setPhase] = createSignal<AccountPhase | null>(null);

  const refresh = async () => {
    const status = await getAccountStatus();
    setPhase(status.phase);
  };

  onMount(async () => {
    listenForLiveState();
    await refresh();
  });

  return (
    <Show when={phase()}>
      {(current) => (
        <Show when={!deviceRemoved()} fallback={<RemovedScreen />}>
          <Show when={current() === "ready"} fallback={<SetupScreen onComplete={refresh} />}>
            <Layout />
          </Show>
        </Show>
      )}
    </Show>
  );
}
