import { createSignal, onMount } from "solid-js";
import { getConfig, setRelayUrl } from "../../lib/api";
import { SettingInput } from "./controls";

export default function NetworkSettings() {
  const [relay, setRelay] = createSignal("");

  onMount(async () => {
    const config = await getConfig();
    if (config.relay_url) setRelay(config.relay_url);
  });

  return (
    <div class="px-4">
      <SettingInput
        label="relay url"
        description="server used for message delivery"
        value={relay()}
        onSave={(v) => setRelayUrl(v)}
      />
    </div>
  );
}
