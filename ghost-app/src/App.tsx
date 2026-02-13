import { createSignal, onMount, Show } from "solid-js";
import { getConfig } from "./lib/api";
import { Layout } from "./components/Layout";
import { SetupScreen } from "./components/SetupScreen";

export default function App() {
  const [ready, setReady] = createSignal(false);
  const [needsSetup, setNeedsSetup] = createSignal(false);

  onMount(async () => {
    const cfg = await getConfig();
    if (!cfg.display_name) {
      setNeedsSetup(true);
    }
    setReady(true);
  });

  const handleSetupComplete = () => {
    setNeedsSetup(false);
  };

  return (
    <Show when={ready()}>
      <Show when={needsSetup()} fallback={<Layout />}>
        <SetupScreen onComplete={handleSetupComplete} />
      </Show>
    </Show>
  );
}
