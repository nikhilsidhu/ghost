import { createSignal } from "solid-js";
import { setDisplayName, setRelayUrl, joinByInvite } from "../lib/api";

interface Props {
  onComplete: () => void;
}

export function SetupScreen(props: Props) {
  const [name, setName] = createSignal("");
  const [inviteOrRelay, setInviteOrRelay] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async () => {
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

        // Treat as raw relay URL
        await setRelayUrl(input);
      }

      props.onComplete();
    } catch (e: any) {
      setError(String(e));
      setLoading(false);
    }
  };

  return (
    <div class="h-screen flex flex-col" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />
      <div class="flex-1 flex items-center justify-center">
      <div class="w-80 flex flex-col gap-6">
        <div class="text-center">
          <h1 class="text-lg font-semibold text-[var(--neutral-100)]">ghost</h1>
          <p class="text-xs text-[var(--neutral-500)] mt-1">encrypted group chat</p>
        </div>

        <div class="flex flex-col gap-3">
          <div>
            <label class="text-xs text-[var(--neutral-400)] mb-1 block">display name</label>
            <input
              class="w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none"
              placeholder="what should people call you?"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }}
              autofocus
            />
          </div>

          <div>
            <label class="text-xs text-[var(--neutral-400)] mb-1 block">invite link or relay url</label>
            <input
              class="w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none"
              placeholder="paste invite link or http://relay:7700"
              value={inviteOrRelay()}
              onInput={(e) => setInviteOrRelay(e.currentTarget.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }}
            />
            <p class="text-xs text-[var(--neutral-600)] mt-1">optional — you can set this later</p>
          </div>
        </div>

        {error() && (
          <p class="text-xs text-[var(--red-400)]">{error()}</p>
        )}

        <button
          class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] disabled:opacity-50 cursor-pointer disabled:cursor-default"
          onClick={handleSubmit}
          disabled={!name().trim() || loading()}
        >
          {loading() ? "setting up..." : "get started"}
        </button>
      </div>
      </div>
    </div>
  );
}
