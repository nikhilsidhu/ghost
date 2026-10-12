import { createSignal, onMount, Show } from "solid-js";
import { getConfig, setRelayUrl } from "../../lib/api";
import { errorCode } from "../../lib/invoke";
import { setSettingsCategory } from "../../lib/store";
import { Button } from "../ui/button";
import { SettingGroup, SettingInput } from "./controls";

export default function NetworkSettings() {
  const [relay, setRelay] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  // The address named another relay: moving the account's home there is the way.
  const [offerMove, setOfferMove] = createSignal(false);

  onMount(async () => {
    const config = await getConfig();
    setRelay(config.relay_url);
  });

  const save = async (url: string) => {
    try {
      await setRelayUrl(url);
      setError(null);
      setOfferMove(false);
    } catch (e) {
      setError(String(e));
      setOfferMove(errorCode(e) === "wrong_relay");
    }
  };

  return (
    <div class="pb-4">
      <SettingGroup>
        <SettingInput
          label="home relay address"
          description="where your account's home relay is reached; it must be the same relay"
          value={relay()}
          onSave={save}
        />
        <Show when={error()}>
          <div class="flex items-center gap-2 pb-2">
            <p class="text-xs text-[var(--red-400)] flex-1">{error()}</p>
            <Show when={offerMove()}>
              <Button size="sm" variant="outline" onClick={() => setSettingsCategory("devices")}>
                move home instead
              </Button>
            </Show>
          </div>
        </Show>
      </SettingGroup>
    </div>
  );
}
