import { createSignal, Show } from "solid-js";
import { setDisplayName, setRelayUrl, joinByInvite, joinAsNewDevice } from "../lib/api";
import { Loader, MonitorSmartphone, ArrowLeft } from "lucide-solid";

interface Props {
  onComplete: () => void;
}

type Mode = "new" | "link";

export function SetupScreen(props: Props) {
  const [mode, setMode] = createSignal<Mode>("new");
  const [name, setName] = createSignal("");
  const [inviteOrRelay, setInviteOrRelay] = createSignal("");
  const [pairingCode, setPairingCode] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [linkStatus, setLinkStatus] = createSignal<string | null>(null);

  const handleNewAccount = async () => {
    const trimmedName = name().trim();
    if (!trimmedName) return;

    setLoading(true);
    setError(null);

    try {
      await setDisplayName(trimmedName);

      const input = inviteOrRelay().trim();
      if (input) {
        // Try parsing as invite link first
        try {
          const url = new URL(input);
          const relay = url.searchParams.get("relay");
          const token = url.searchParams.get("token");
          if (relay && token) {
            await setRelayUrl(relay);
            await joinByInvite(relay, token);
            props.onComplete();
            return;
          }
        } catch {
          // Not a URL with params — treat as relay URL
        }

        await setRelayUrl(input);
      }

      props.onComplete();
    } catch (e: any) {
      setError(String(e));
      setLoading(false);
    }
  };

  const handleLinkDevice = async () => {
    const code = pairingCode().trim();
    if (!code) return;

    setLoading(true);
    setError(null);
    setLinkStatus("connecting to relay…");

    try {
      await joinAsNewDevice(code);
      props.onComplete();
    } catch (e: any) {
      setError(String(e));
      setLinkStatus(null);
      setLoading(false);
    }
  };

  const inputClass =
    "w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none";

  return (
    <div class="h-screen flex flex-col" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />
      <div class="flex-1 flex items-center justify-center">
        <div class="w-80 flex flex-col gap-6">
          <div class="text-center">
            <h1 class="text-lg font-semibold text-[var(--neutral-100)]">ghost</h1>
            <p class="text-xs text-[var(--neutral-500)] mt-1">encrypted chat</p>
          </div>

          <Show when={mode() === "new"} fallback={
            /* ── Link device mode ────────────────────── */
            <div class="flex flex-col gap-3">
              <button
                class="flex items-center gap-1 text-xs text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer w-fit"
                onClick={() => { setMode("new"); setError(null); }}
              >
                <ArrowLeft size={12} />
                back
              </button>

              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">pairing code</label>
                <input
                  class={inputClass}
                  placeholder="paste code from your other device"
                  value={pairingCode()}
                  onInput={(e) => setPairingCode(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleLinkDevice(); }}
                  autofocus
                />
              </div>

              <Show when={linkStatus()}>
                <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
                  <Loader size={12} class="animate-spin" />
                  <span>{linkStatus()}</span>
                </div>
              </Show>

              {error() && (
                <p class="text-xs text-[var(--red-400)]">{error()}</p>
              )}

              <button
                class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] disabled:opacity-50 cursor-pointer disabled:cursor-default"
                onClick={handleLinkDevice}
                disabled={!pairingCode().trim() || loading()}
              >
                {loading() ? "linking…" : "link device"}
              </button>
            </div>
          }>
            {/* ── New account mode ────────────────────── */}
            <div class="flex flex-col gap-3">
              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">display name</label>
                <input
                  class={inputClass}
                  placeholder="what should people call you?"
                  value={name()}
                  onInput={(e) => setName(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleNewAccount(); }}
                  autofocus
                />
              </div>

              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">invite link or relay url</label>
                <input
                  class={inputClass}
                  placeholder="paste invite link or http://relay:7700"
                  value={inviteOrRelay()}
                  onInput={(e) => setInviteOrRelay(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleNewAccount(); }}
                />
                <p class="text-xs text-[var(--neutral-600)] mt-1">optional — you can set this later</p>
              </div>

              {error() && (
                <p class="text-xs text-[var(--red-400)]">{error()}</p>
              )}

              <button
                class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] disabled:opacity-50 cursor-pointer disabled:cursor-default"
                onClick={handleNewAccount}
                disabled={!name().trim() || loading()}
              >
                {loading() ? "setting up…" : "get started"}
              </button>

              <button
                class="w-full flex items-center justify-center gap-1.5 h-9 rounded text-sm text-[var(--neutral-400)] hover:text-[var(--neutral-200)] border border-[var(--neutral-700)] hover:border-[var(--neutral-600)] cursor-pointer transition-colors duration-150"
                onClick={() => { setMode("link"); setError(null); }}
              >
                <MonitorSmartphone size={14} />
                link existing account
              </button>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
