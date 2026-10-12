import { createSignal, Show } from "solid-js";
import { deviceRemoved, describeRemoval } from "../lib/alerts";
import { resetDevice } from "../lib/api";
import { forgetUsage } from "../lib/frecency";
import { Button } from "./ui/button";

function Frame(props: { children: any }) {
  return (
    <div class="h-screen flex flex-col" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />
      <div class="flex-1 flex items-center justify-center">
        <div class="w-80 flex flex-col gap-6">
          <div class="text-center">
            <h1 class="text-lg font-semibold text-[var(--neutral-100)]">ghost</h1>
          </div>
          {props.children}
        </div>
      </div>
    </div>
  );
}

/** This device was removed from its account; nothing here works any more. */
export function RemovedScreen() {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const reset = async () => {
    setBusy(true);
    try {
      // The old account's channels go with it; the backend forgets the rest.
      forgetUsage();
      await resetDevice();
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };
  return (
    <Frame>
      <div class="flex flex-col gap-3">
        <p class="text-sm text-[var(--neutral-200)]">this device was removed from your account.</p>
        <p class="text-xs text-[var(--neutral-400)]">{describeRemoval(deviceRemoved())}</p>
        <p class="text-xs text-[var(--neutral-400)]">
          nothing this device holds opens anything written since, and relays no longer serve it.
        </p>
        <p class="text-xs text-[var(--neutral-400)]">
          resetting forgets the account here, so this device can make a new one, link to an account or recover one.
        </p>
        <Show when={error()}>
          <p class="text-xs text-[var(--red-400)]">{error()}</p>
        </Show>
        <Button size="lg" class="w-full" onClick={reset} disabled={busy()}>
          {busy() ? "resetting…" : "reset this device"}
        </Button>
      </div>
    </Frame>
  );
}
