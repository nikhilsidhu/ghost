import { createSignal, Show, onCleanup } from "solid-js";
import { setDisplayName, setRelayUrl, joinByInvite, joinAsNewDevice, setRecoveryPassphrase, skipRecoverySetup, recoverAccount } from "../lib/api";
import { Loader, MonitorSmartphone, ArrowLeft, Copy, Check, ShieldAlert } from "lucide-solid";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

interface Props {
  onComplete: () => void;
}

type Mode = "new" | "link" | "set-recovery-pass" | "recover";

const FLASH_MS = 1200;

export function SetupScreen(props: Props) {
  const [mode, setMode] = createSignal<Mode>("new");
  const [name, setName] = createSignal("");
  const [inviteOrRelay, setInviteOrRelay] = createSignal("");
  const [pairingCode, setPairingCode] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [linkStatus, setLinkStatus] = createSignal<string | null>(null);

  // Recovery setup state
  const [passphrase, setPassphrase] = createSignal("");
  const [passphraseConfirm, setPassphraseConfirm] = createSignal("");
  const [recoveryCode, setRecoveryCode] = createSignal<string | null>(null);
  const [codeCopied, setCodeCopied] = createSignal(false);

  // Recover account state
  const [recoverCode, setRecoverCode] = createSignal("");
  const [recoverPassphrase, setRecoverPassphrase] = createSignal("");

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
            setMode("set-recovery-pass");
            setLoading(false);
            return;
          }
        } catch {
          // Not a URL with params — treat as relay URL
        }

        await setRelayUrl(input);
      }

      setMode("set-recovery-pass");
      setLoading(false);
    } catch (e: any) {
      setError(String(e));
      setLoading(false);
    }
  };

  const ppLongEnough = () => passphrase().length >= 12;
  const ppMatch = () => passphraseConfirm().length === 0 || passphrase() === passphraseConfirm();
  const ppReady = () => ppLongEnough() && passphraseConfirm().length > 0 && ppMatch();

  const handleSetPassphrase = async () => {
    if (!ppReady()) return;

    setLoading(true);
    setError(null);
    try {
      const code = await setRecoveryPassphrase(passphrase());
      setPassphrase("");
      setPassphraseConfirm("");
      setRecoveryCode(code);
      setLoading(false);
    } catch (e: any) {
      setError(String(e));
      setLoading(false);
    }
  };

  const handleSkipRecovery = async () => {
    try {
      await skipRecoverySetup();
      props.onComplete();
    } catch (e: any) {
      setError(String(e));
    }
  };

  const copyRecoveryCode = () => {
    const code = recoveryCode();
    if (!code) return;
    navigator.clipboard.writeText(code).catch(() => {});
    setCodeCopied(true);
    setTimeout(() => setCodeCopied(false), FLASH_MS);
  };

  const handleRecoverAccount = async () => {
    const code = recoverCode().trim();
    const pp = recoverPassphrase();
    if (!code || !pp) return;

    setLoading(true);
    setError(null);
    try {
      await recoverAccount(code, pp);
      setRecoverPassphrase("");
      setLoading(false);
      props.onComplete();
    } catch (e: any) {
      const msg = String(e).toLowerCase();
      if (msg.includes("404") || msg.includes("no recovery blob")) {
        setError("no recovery blob found for this account");
      } else if (msg.includes("decrypt") || msg.includes("aead") || msg.includes("passphrase")) {
        setError("wrong passphrase");
      } else if (msg.includes("invalid recovery code")) {
        setError("invalid recovery code format");
      } else if (msg.includes("bad fingerprint")) {
        setError("invalid recovery code format");
      } else {
        setError(String(e));
      }
      setLoading(false);
    }
  };

  let statusUnlisten: UnlistenFn | undefined;
  onCleanup(() => statusUnlisten?.());

  const validatePairingCode = (code: string): string | null => {
    const hexRegex = /^[0-9a-f]{64}$/i;
    const parts = code.split("#");
    if (parts.length !== 3) return "invalid format — should be relay_url#fingerprint#secret";
    if (!parts[0].startsWith("http")) return "invalid relay url in pairing code";
    if (!hexRegex.test(parts[1])) return "invalid fingerprint in pairing code";
    if (!hexRegex.test(parts[2])) return "invalid secret in pairing code";
    return null;
  };

  const handleLinkDevice = async () => {
    const code = pairingCode().trim();
    if (!code) return;

    const validationError = validatePairingCode(code);
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError(null);
    setLinkStatus("connecting…");

    statusUnlisten = await listen<string>("link-status", (e) => {
      setLinkStatus(e.payload);
    });

    try {
      await joinAsNewDevice(code);
      props.onComplete();
    } catch (e: any) {
      const msg = String(e);
      if (msg.includes("fetch offer: ")) {
        setError("couldn't reach relay. check your connection and try again.");
      } else if (msg.includes("404") || msg.includes("NotFound")) {
        setError("pairing code expired. generate a new code on your other device.");
      } else if (msg.includes("timed out")) {
        setError("other device didn't respond. try again.");
      } else {
        setError(msg);
      }
      setLinkStatus(null);
      setLoading(false);
    } finally {
      statusUnlisten?.();
      statusUnlisten = undefined;
    }
  };

  const inputClass =
    "w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none";

  const backButton = (target: Mode) => (
    <button
      class="flex items-center gap-1 text-xs text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer w-fit"
      onClick={() => { setMode(target); setError(null); setLoading(false); setLinkStatus(null); setPassphrase(""); setPassphraseConfirm(""); setRecoverPassphrase(""); setRecoverCode(""); setPairingCode(""); }}
    >
      <ArrowLeft size={12} />
      back
    </button>
  );

  return (
    <div class="h-screen flex flex-col" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />
      <div class="flex-1 flex items-center justify-center">
        <div class="w-80 flex flex-col gap-6">
          <div class="text-center">
            <h1 class="text-lg font-semibold text-[var(--neutral-100)]">ghost</h1>
            <p class="text-xs text-[var(--neutral-500)] mt-1">encrypted chat</p>
          </div>

          {/* ── Recovery passphrase setup (after account creation) ── */}
          <Show when={mode() === "set-recovery-pass"}>
            <Show when={!recoveryCode()} fallback={
              /* ── Recovery code confirmation ── */
              <div class="flex flex-col gap-3">
                <p class="text-xs text-[var(--neutral-400)]">recovery configured. save this code — you'll need it along with your passphrase to recover your account.</p>
                <div class="flex items-center gap-2 p-2.5 rounded bg-[var(--neutral-800)] border border-[var(--neutral-700)]">
                  <span class="text-xs text-[var(--neutral-200)] font-mono break-all flex-1">{recoveryCode()}</span>
                  <button
                    class="flex-shrink-0 text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer"
                    onClick={copyRecoveryCode}
                  >
                    {codeCopied() ? <Check size={14} class="text-[var(--emerald-400)]" /> : <Copy size={14} />}
                  </button>
                </div>
                <button
                  class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] cursor-pointer"
                  onClick={() => props.onComplete()}
                >
                  continue
                </button>
              </div>
            }>
              {/* ── Passphrase input ── */}
              <div class="flex flex-col gap-3">
                <p class="text-xs text-[var(--neutral-400)]">set a recovery passphrase so you can recover your account if you lose all your devices.</p>
                <div>
                  <label class="text-xs text-[var(--neutral-400)] mb-1 block">recovery passphrase</label>
                  <input
                    class={inputClass}
                    type="password"
                    placeholder="at least 12 characters"
                    value={passphrase()}
                    onInput={(e) => setPassphrase(e.currentTarget.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") handleSetPassphrase(); }}
                    autofocus
                  />
                  <Show when={passphrase().length > 0}>
                    <p class={`text-xs mt-1 ${ppLongEnough() ? "text-[var(--emerald-400)]" : "text-[var(--neutral-600)]"}`}>
                      {passphrase().length} / 12 characters
                    </p>
                  </Show>
                </div>
                <div>
                  <label class="text-xs text-[var(--neutral-400)] mb-1 block">confirm passphrase</label>
                  <input
                    class={inputClass}
                    type="password"
                    placeholder="type it again"
                    value={passphraseConfirm()}
                    onInput={(e) => setPassphraseConfirm(e.currentTarget.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") handleSetPassphrase(); }}
                  />
                  <Show when={passphraseConfirm().length > 0 && !ppMatch()}>
                    <p class="text-xs mt-1 text-[var(--red-400)]">passphrases don't match</p>
                  </Show>
                </div>

                {error() && (
                  <p class="text-xs text-[var(--red-400)]">{error()}</p>
                )}

                <button
                  class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] disabled:opacity-50 cursor-pointer disabled:cursor-default"
                  onClick={handleSetPassphrase}
                  disabled={!ppReady() || loading()}
                >
                  {loading() ? "encrypting…" : "set recovery passphrase"}
                </button>

                <button
                  class="w-full h-9 rounded text-sm text-[var(--neutral-400)] hover:text-[var(--neutral-200)] border border-[var(--neutral-700)] hover:border-[var(--neutral-600)] cursor-pointer transition-colors duration-150"
                  onClick={handleSkipRecovery}
                >
                  skip
                </button>
                <p class="text-xs text-[var(--neutral-600)] text-center">if you skip, you won't be able to recover your account if you lose all your devices</p>
              </div>
            </Show>
          </Show>

          {/* ── Link device mode ── */}
          <Show when={mode() === "link"}>
            <div class="flex flex-col gap-3">
              {backButton("new")}

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
          </Show>

          {/* ── Recover account mode ── */}
          <Show when={mode() === "recover"}>
            <div class="flex flex-col gap-3">
              {backButton("new")}

              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">recovery code</label>
                <input
                  class={inputClass}
                  placeholder="relay.example.com#abc123..."
                  value={recoverCode()}
                  onInput={(e) => setRecoverCode(e.currentTarget.value)}
                  autofocus
                />
              </div>

              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">recovery passphrase</label>
                <input
                  class={inputClass}
                  type="password"
                  placeholder="the passphrase you set during setup"
                  value={recoverPassphrase()}
                  onInput={(e) => setRecoverPassphrase(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleRecoverAccount(); }}
                />
              </div>

              <Show when={loading()}>
                <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
                  <Loader size={12} class="animate-spin" />
                  <span>recovering account…</span>
                </div>
              </Show>

              {error() && (
                <p class="text-xs text-[var(--red-400)]">{error()}</p>
              )}

              <button
                class="w-full h-9 rounded text-sm font-medium bg-[var(--purple-600)] text-white hover:bg-[var(--purple-500)] disabled:opacity-50 cursor-pointer disabled:cursor-default"
                onClick={handleRecoverAccount}
                disabled={!recoverCode().trim() || !recoverPassphrase() || loading()}
              >
                {loading() ? "recovering…" : "recover account"}
              </button>
            </div>
          </Show>

          {/* ── New account mode (default) ── */}
          <Show when={mode() === "new"}>
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

              <button
                class="w-full flex items-center justify-center gap-1.5 h-9 rounded text-sm text-[var(--neutral-400)] hover:text-[var(--neutral-200)] border border-[var(--neutral-700)] hover:border-[var(--neutral-600)] cursor-pointer transition-colors duration-150"
                onClick={() => { setMode("recover"); setError(null); }}
              >
                <ShieldAlert size={14} />
                recover account
              </button>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
