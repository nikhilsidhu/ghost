import { createSignal, onCleanup, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { startMicTest, stopMicTest, playTestTone } from "../../lib/api";
import { SettingGroup } from "./controls";
import { cn } from "../../lib/cn";

export default function AudiovisualSettings() {
  const [micTesting, setMicTesting] = createSignal(false);
  const [micLevel, setMicLevel] = createSignal(0);
  const [tonePlaying, setTonePlaying] = createSignal(false);

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

  onCleanup(() => {
    if (micTesting()) stopMicTest().catch(() => {});
    if (unlisten) unlisten();
  });

  return (
    <div>
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
