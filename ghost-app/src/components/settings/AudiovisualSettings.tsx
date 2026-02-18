import { createSignal, createEffect, on, onMount, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { startMicTest, stopMicTest, playTestTone, listAudioDevices, setInputDevice, setOutputDevice, setNoiseSuppression, setAgc, getConfig } from "../../lib/api";
import { settingsOpen, settingsCategory } from "../../lib/store";
import { SettingGroup, SettingSelect } from "./controls";
import { cn } from "../../lib/cn";

export default function AudiovisualSettings() {
  const [micTesting, setMicTesting] = createSignal(false);
  const [micLevel, setMicLevel] = createSignal(0);
  const [tonePlaying, setTonePlaying] = createSignal(false);

  const [inputDevices, setInputDevices] = createSignal<{ value: string; label: string }[]>([]);
  const [outputDevices, setOutputDevices] = createSignal<{ value: string; label: string }[]>([]);
  const [selectedInput, setSelectedInput] = createSignal("default");
  const [selectedOutput, setSelectedOutput] = createSignal("default");
  const [selectedNs, setSelectedNs] = createSignal("nnnoiseless");
  const [selectedAgc, setSelectedAgc] = createSignal("auto");

  onMount(async () => {
    const [devices, config] = await Promise.all([listAudioDevices(), getConfig()]);

    const defaultInLabel = devices.default_input ? `default (${devices.default_input})` : "default";
    const defaultOutLabel = devices.default_output ? `default (${devices.default_output})` : "default";

    setInputDevices([
      { value: "default", label: defaultInLabel },
      ...devices.inputs.map((name) => ({ value: name, label: name })),
    ]);
    setOutputDevices([
      { value: "default", label: defaultOutLabel },
      ...devices.outputs.map((name) => ({ value: name, label: name })),
    ]);

    setSelectedInput(config.input_device ?? "default");
    setSelectedOutput(config.output_device ?? "default");
    setSelectedNs(config.noise_suppression);
    setSelectedAgc(config.agc);
  });

  let unlisten: (() => void) | null = null;

  const toggleMicTest = async () => {
    if (micTesting()) {
      await stopMicTest();
      setMicTesting(false);
      setMicLevel(0);
      if (unlisten) { unlisten(); unlisten = null; }
    } else {
      const unsub = await listen<number>("mic-level", (e) => {
        setMicLevel(e.payload);
      });
      unlisten = unsub;
      setMicTesting(true);
      await startMicTest();
    }
  };

  const handleTestTone = async () => {
    if (tonePlaying()) return;
    setTonePlaying(true);
    try {
      await playTestTone();
    } finally {
      // Tone plays for 2s on the backend
      setTimeout(() => setTonePlaying(false), 2100);
    }
  };

  // Stop mic test when leaving audiovisual tab or closing settings
  createEffect(on(
    () => settingsOpen() && settingsCategory() === "audiovisual",
    (active) => {
      if (!active && micTesting()) {
        stopMicTest().catch(() => {});
        setMicTesting(false);
        setMicLevel(0);
        if (unlisten) { unlisten(); unlisten = null; }
      }
    },
    { defer: true },
  ));

  const handleInputChange = async (v: string) => {
    setSelectedInput(v);
    await setInputDevice(v === "default" ? null : v);
  };

  const handleOutputChange = async (v: string) => {
    setSelectedOutput(v);
    await setOutputDevice(v === "default" ? null : v);
  };

  const handleNsChange = async (v: string) => {
    setSelectedNs(v);
    await setNoiseSuppression(v);
  };

  const handleAgcChange = async (v: string) => {
    setSelectedAgc(v);
    await setAgc(v);
  };

  return (
    <div>
      <SettingGroup label="devices">
        <SettingSelect
          label="input device"
          description="microphone used for voice chat"
          value={selectedInput()}
          options={inputDevices()}
          onChange={handleInputChange}
        />
        <SettingSelect
          label="output device"
          description="speakers used for voice chat"
          value={selectedOutput()}
          options={outputDevices()}
          onChange={handleOutputChange}
        />
      </SettingGroup>

      <SettingGroup label="voice processing">
        <SettingSelect
          label="noise suppression"
          description="reduces background noise during calls"
          value={selectedNs()}
          options={[
            { value: "nnnoiseless", label: "nnnoiseless" },
            { value: "off", label: "off" },
          ]}
          onChange={handleNsChange}
        />
        <SettingSelect
          label="auto gain control"
          description="normalizes microphone volume automatically"
          value={selectedAgc()}
          options={[
            { value: "auto", label: "auto" },
            { value: "off", label: "off" },
          ]}
          onChange={handleAgcChange}
        />
      </SettingGroup>

      <SettingGroup label="microphone">
        <div class="py-3 border-b border-[var(--neutral-800)] last:border-b-0">
          <div class="flex items-center justify-between gap-4">
            <div class="min-w-0">
              <div class="text-sm text-[var(--neutral-200)]">input level</div>
              <div class="text-xs text-[var(--neutral-500)] mt-0.5">
                test your microphone
              </div>
            </div>
            <button
              class={cn(
                "h-7 rounded px-3 text-xs cursor-pointer transition-colors duration-150 flex-shrink-0",
                "border border-[var(--neutral-700)]",
                micTesting()
                  ? "bg-[var(--neutral-800)] text-[var(--emerald-400)] border-[var(--emerald-400)]/30"
                  : "bg-[var(--neutral-800)] text-[var(--neutral-200)] hover:border-[var(--neutral-600)]",
              )}
              onClick={toggleMicTest}
            >
              {micTesting() ? "stop" : "test"}
            </button>
          </div>
          <Show when={micTesting()}>
            <div class="mt-3 h-2 rounded-full bg-[var(--neutral-800)] overflow-hidden">
              <div
                class="h-full rounded-full transition-[width] duration-75"
                style={{
                  width: `${Math.round(micLevel() * 100)}%`,
                  background: micLevel() > 0.8
                    ? "var(--amber-400)"
                    : micLevel() > 0.01
                      ? "var(--emerald-400)"
                      : "var(--neutral-600)",
                }}
              />
            </div>
          </Show>
        </div>
      </SettingGroup>

      <SettingGroup label="speakers">
        <div class="py-3 border-b border-[var(--neutral-800)] last:border-b-0">
          <div class="flex items-center justify-between gap-4">
            <div class="min-w-0">
              <div class="text-sm text-[var(--neutral-200)]">test tone</div>
              <div class="text-xs text-[var(--neutral-500)] mt-0.5">
                plays a short 440hz tone
              </div>
            </div>
            <button
              class={cn(
                "h-7 rounded px-3 text-xs cursor-pointer transition-colors duration-150 flex-shrink-0",
                "border border-[var(--neutral-700)]",
                tonePlaying()
                  ? "bg-[var(--neutral-800)] text-[var(--purple-400)] border-[var(--purple-400)]/30"
                  : "bg-[var(--neutral-800)] text-[var(--neutral-200)] hover:border-[var(--neutral-600)]",
              )}
              onClick={handleTestTone}
              disabled={tonePlaying()}
            >
              {tonePlaying() ? "playing..." : "play"}
            </button>
          </div>
        </div>
      </SettingGroup>
    </div>
  );
}
