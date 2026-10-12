import { createSignal, createEffect, on, onCleanup, onMount, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { startMicTest, stopMicTest, playTestTone, listAudioDevices, setInputDevice, setOutputDevice, setNoiseSuppression, setAgc, setInputMode, setVadThreshold, setInputGain, setAutoMuteOnIdle, getConfig, getKeybinds } from "../../lib/api";
import { settingsOpen, settingsCategory, setSettingsCategory, setIsPttMode } from "../../lib/store";
import { setInputMode as setKeybindInputMode } from "../../lib/keybinds";
import { SettingGroup, SettingSelect, SettingSegmented, SettingSlider, SettingToggle } from "./controls";
import { cn } from "../../lib/cn";
import type { Agc, Config, InputMode, NoiseSuppression } from "../../lib/types";

const VAD_DEBOUNCE_MS = 200;

export default function AudiovisualSettings() {
  const [micTesting, setMicTesting] = createSignal(false);
  const [micLevel, setMicLevel] = createSignal(0);
  /** Why the last mic test ended on its own, if its devices failed. */
  const [micTestFailure, setMicTestFailure] = createSignal<string | null>(null);
  const [tonePlaying, setTonePlaying] = createSignal(false);

  const [inputDevices, setInputDevices] = createSignal<{ value: string; label: string }[]>([]);
  const [outputDevices, setOutputDevices] = createSignal<{ value: string; label: string }[]>([]);
  const [selectedInput, setSelectedInput] = createSignal("default");
  const [selectedOutput, setSelectedOutput] = createSignal("default");
  const [selectedNs, setSelectedNs] = createSignal<NoiseSuppression>("nnnoiseless");
  const [selectedAgc, setSelectedAgc] = createSignal<Agc>("auto");
  const [autoMuteOnIdle, setAutoMuteOnIdleLocal] = createSignal(true);
  const [selectedInputMode, setSelectedInputMode] = createSignal<InputMode>("voice_activity");
  const [pttKeyBound, setPttKeyBound] = createSignal(false);
  const [vadThreshold, setVadThresholdLocal] = createSignal(0.85);
  const [inputGainLocal, setInputGainLocal] = createSignal(1.0);

  let vadTimer: ReturnType<typeof setTimeout> | null = null;
  let gainTimer: ReturnType<typeof setTimeout> | null = null;

  const showConfig = (config: Config) => {
    setSelectedInput(config.input_device ?? "default");
    setSelectedOutput(config.output_device ?? "default");
    setSelectedNs(config.noise_suppression);
    setSelectedAgc(config.agc);
    setAutoMuteOnIdleLocal(config.auto_mute_on_idle);
    setSelectedInputMode(config.input_mode);
    setVadThresholdLocal(config.vad_threshold);
    setInputGainLocal(config.input_gain);
  };

  // A setting another device changed shows here at once.
  onMount(() => {
    const synced = listen<string>("sync-pref", () => { getConfig().then(showConfig).catch(() => {}); });
    onCleanup(() => { synced.then((stop) => stop()); });
  });

  onMount(async () => {
    const [devices, config, keybinds] = await Promise.all([listAudioDevices(), getConfig(), getKeybinds()]);

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

    showConfig(config);
    setPttKeyBound(!!keybinds.push_to_talk);
  });

  let unlisten: (() => void) | null = null;

  const micTestOver = () => {
    setMicTesting(false);
    setMicLevel(0);
    if (unlisten) { unlisten(); unlisten = null; }
  };

  // The test ends on its own when a call takes the microphone or its devices fail.
  onMount(() => {
    const ended = listen<string | null>("mic-test-ended", (e) => {
      micTestOver();
      setMicTestFailure(e.payload);
    });
    onCleanup(() => { ended.then((stop) => stop()); });
  });

  const toggleMicTest = async () => {
    if (micTesting()) {
      await stopMicTest();
      micTestOver();
    } else {
      const unsub = await listen<number>("mic-level", (e) => {
        setMicLevel(e.payload);
      });
      unlisten = unsub;
      setMicTestFailure(null);
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
      setTimeout(() => setTonePlaying(false), 2100);
    }
  };

  // Stop mic test when leaving audiovisual tab or closing settings
  createEffect(on(
    () => settingsOpen() && settingsCategory() === "audiovisual",
    (active) => {
      if (!active && micTesting()) {
        stopMicTest().catch(() => {});
        micTestOver();
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

  const handleNsChange = async (v: NoiseSuppression) => {
    setSelectedNs(v);
    await setNoiseSuppression(v);
  };

  const handleAgcChange = async (v: Agc) => {
    setSelectedAgc(v);
    await setAgc(v);
  };

  const handleInputModeChange = async (v: InputMode) => {
    setSelectedInputMode(v);
    setIsPttMode(v === "push_to_talk");
    setKeybindInputMode(v);
    await setInputMode(v);
  };

  const handleVadChange = (v: number) => {
    setVadThresholdLocal(v);
    if (vadTimer) clearTimeout(vadTimer);
    vadTimer = setTimeout(() => setVadThreshold(v).catch(() => {}), VAD_DEBOUNCE_MS);
  };

  const handleGainChange = (v: number) => {
    setInputGainLocal(v);
    if (gainTimer) clearTimeout(gainTimer);
    gainTimer = setTimeout(() => setInputGain(v).catch(() => {}), VAD_DEBOUNCE_MS);
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
        <SettingSegmented
          label="input mode"
          description="how your microphone activates"
          value={selectedInputMode()}
          options={[
            { value: "voice_activity", label: "voice activity" },
            { value: "push_to_talk", label: "push to talk" },
          ]}
          onChange={handleInputModeChange}
        >
          <Show when={selectedInputMode() === "push_to_talk" && !pttKeyBound()}>
            <div class="text-xs text-[var(--amber-400)] mt-2">
              no key bound —{" "}
              <button
                class="underline cursor-pointer hover:text-[var(--amber-300)]"
                onClick={() => setSettingsCategory("keybinds")}
              >
                set in keybinds
              </button>
            </div>
          </Show>
        </SettingSegmented>
        <Show when={selectedInputMode() === "voice_activity"}>
          <SettingSlider
            label="input sensitivity"
            description="how loud you need to be to activate"
            value={vadThreshold()}
            min={0}
            max={1}
            step={0.01}
            defaultValue={0.85}
            displayValue={`${Math.round(vadThreshold() * 100)}%`}
            onChange={handleVadChange}
          />
        </Show>
        <SettingSlider
          label="input volume"
          description="pre-processing microphone gain"
          value={inputGainLocal()}
          min={0}
          max={2}
          step={0.01}
          defaultValue={1.0}
          displayValue={`${Math.round(inputGainLocal() * 100)}%`}
          onChange={handleGainChange}
        />
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
        <SettingToggle
          label="mute when idle"
          description="mute the microphone after ten minutes without keyboard or mouse input"
          checked={autoMuteOnIdle()}
          onChange={(v) => {
            setAutoMuteOnIdleLocal(v);
            setAutoMuteOnIdle(v).catch(() => {});
          }}
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
          <Show when={micTestFailure()}>
            <div role="alert" class="mt-2 text-xs text-[var(--red-400)] break-words">{micTestFailure()}</div>
          </Show>
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
