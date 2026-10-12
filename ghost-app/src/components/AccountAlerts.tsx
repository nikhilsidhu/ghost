import { For, Show, createSignal } from "solid-js";
import { Info, ShieldAlert, X } from "lucide-solid";
import { accountAlerts, describeAlert, dismissAlert } from "../lib/alerts";
import { revokeDevice } from "../lib/api";
import { Button } from "./ui/button";

/** Banners for what happened to the account elsewhere, each until dismissed. */
export function AccountAlerts() {
  const [busy, setBusy] = createSignal<number | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  const removeDevice = async (id: number, deviceKey: string) => {
    setBusy(id);
    setError(null);
    try {
      await revokeDevice(deviceKey);
      dismissAlert(id);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div class="flex flex-col gap-1 px-3 pt-1">
      <For each={accountAlerts()}>
        {(shown) => {
          const warning = () => ["bad_account_key", "device_removed", "removal_refused", "split_view"].includes(shown.alert.kind);
          return (
            <div
              role={warning() ? "alert" : "status"}
              class={`flex items-center gap-2 rounded px-3 py-2 text-xs border ${
                warning()
                  ? "bg-[var(--red-500)]/10 border-[var(--red-500)]/30 text-[var(--red-400)]"
                  : "bg-[var(--neutral-800)] border-[var(--neutral-700)] text-[var(--neutral-300)]"
              }`}
            >
              {warning() ? <ShieldAlert size={14} class="flex-shrink-0" /> : <Info size={14} class="flex-shrink-0" />}
              <span class="flex-1">{describeAlert(shown.alert)}</span>
              <Show when={shown.alert.kind === "bad_account_key" && shown.alert.device_key}>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy() === shown.id}
                  onClick={() => removeDevice(shown.id, shown.alert.device_key!)}
                >
                  {busy() === shown.id ? "removing…" : `remove ${shown.alert.device_label || "it"}`}
                </Button>
              </Show>
              <button
                class="flex-shrink-0 text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer"
                onClick={() => dismissAlert(shown.id)}
                aria-label="dismiss"
              >
                <X size={14} />
              </button>
            </div>
          );
        }}
      </For>
      <Show when={error()}>
        <p class="text-xs text-[var(--red-400)] px-3">{error()}</p>
      </Show>
    </div>
  );
}
