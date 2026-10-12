import { createSignal, Show, onCleanup, onMount } from "solid-js";
import {
  getAccountStatus, joinByInvite, joinAsNewDevice, beginCreateAccount, confirmNewAccount, cancelCreateAccount,
  beginRecovery, confirmRecovery, recoverThroughRelay, cancelRecovery, resumeUnfinishedAccount,
} from "../lib/api";
import { Loader, MonitorSmartphone, ArrowLeft, ShieldAlert } from "lucide-solid";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Button } from "./ui/button";
import { RecoveryKeySteps, inputClass } from "./RecoveryKeySteps";
import { errorCode } from "../lib/invoke";
import type { RecoveryOutcome, SnapshotRestore } from "../lib/types";

/** Linking failed: what the user can do about it, by the failure's code. */
const describeLinkError = (e: unknown): string => {
  switch (errorCode(e)) {
    case "network":
      return "couldn't reach the relay. check your connection and try again.";
    case "not_found":
      return "the pairing ended on your other device, or the code expired. generate a new code there.";
    case "timed_out":
      return "your other device didn't confirm. try again.";
    default:
      return String(e);
  }
};

/** What a recovery did not bring back, for the user to hear; null when it all came back. */
const describeRestore = (restore: SnapshotRestore | null): string | null => {
  switch (restore) {
    case "missing":
      return "no saved list of your servers was found, so they aren't back yet. ask someone in each server for a new invite.";
    case "unreadable":
      return "the saved list of your servers was sealed with a key this recovery couldn't open, so they aren't back yet. ask someone in each server for a new invite.";
    case "not_reached":
      return "your relay didn't hand over your servers and settings yet. they come back on their own once it does.";
    default:
      return null;
  }
};

interface Props {
  onComplete: () => void;
}

type Mode = "new" | "new-key" | "link" | "recover" | "recover-key" | "recover-home" | "done";

/** An invite link's parts, when `input` is one. */
function parseInvite(input: string): { relay: string; token: string; key: string; r: string | null } | null {
  try {
    const url = new URL(input);
    const relay = url.searchParams.get("relay");
    const token = url.searchParams.get("token");
    const key = url.searchParams.get("k");
    if (relay && token && key) return { relay, token, key, r: url.searchParams.get("r") };
  } catch {
    // not a URL
  }
  return null;
}

export function SetupScreen(props: Props) {
  const [mode, setMode] = createSignal<Mode>("new");
  const [name, setName] = createSignal("");
  /** What this device is called in the account's device list; the machine's name unless changed. */
  const [deviceLabel, setDeviceLabel] = createSignal("");
  const [inviteOrRelay, setInviteOrRelay] = createSignal("");
  const [defaultRelay, setDefaultRelay] = createSignal("");
  const [pairingCode, setPairingCode] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [linkStatus, setLinkStatus] = createSignal<string | null>(null);
  const [linkCode, setLinkCode] = createSignal<string | null>(null);
  /** The new recovery key being shown, for a new or a recovered account. */
  const [shownKey, setShownKey] = createSignal<string | null>(null);
  /** An invite to join once the account exists. */
  let pendingInvite: ReturnType<typeof parseInvite> = null;

  // Recover account state
  const [recoverKey, setRecoverKey] = createSignal("");
  const [recoverRelay, setRecoverRelay] = createSignal("");
  const [unreachableHome, setUnreachableHome] = createSignal<string | null>(null);
  /** Made or recovered, with something the user should hear before going on. */
  const [done, setDone] = createSignal<{ title: string; note: string } | null>(null);
  /** An account made here whose relay did not answer when the app last closed. */
  const [unfinishedAt, setUnfinishedAt] = createSignal<string | null>(null);

  /** Finish an account this device was making when the app last closed. */
  const resumeUnfinished = async () => {
    try {
      const outcome = await resumeUnfinishedAccount();
      if (outcome.outcome === "finished") {
        props.onComplete();
        return;
      }
      setUnfinishedAt(outcome.outcome === "waiting" ? outcome.relay_url : null);
    } catch (e) {
      setError(String(e));
    }
  };

  onMount(async () => {
    try {
      const status = await getAccountStatus();
      setDefaultRelay(status.relay_url);
      setRecoverRelay(status.relay_url);
      setDeviceLabel(status.device_label);
    } catch {
      // the fields stay empty
    }
    await resumeUnfinished();
  });

  const finishWith = (title: string, note: string | null) => {
    if (!note) {
      props.onComplete();
      return;
    }
    setDone({ title, note });
    setMode("done");
  };

  const reset = (target: Mode) => {
    setMode(target);
    setError(null);
    setLoading(false);
    setLinkStatus(null);
    setLinkCode(null);
    setShownKey(null);
    setUnreachableHome(null);
  };

  // ── New account ──

  const handleNewAccount = async () => {
    const trimmedName = name().trim();
    if (!trimmedName) return;
    setLoading(true);
    setError(null);
    try {
      const input = inviteOrRelay().trim();
      pendingInvite = parseInvite(input);
      const relay = pendingInvite?.relay ?? (input || defaultRelay());
      const key = await beginCreateAccount(trimmedName, relay, deviceLabel());
      setShownKey(key);
      setMode("new-key");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const confirmAccount = async (typed: string) => {
    await confirmNewAccount(typed);
    let note: string | null = null;
    if (pendingInvite) {
      const invite = pendingInvite;
      pendingInvite = null;
      try {
        await joinByInvite(invite.relay, invite.token, invite.key, invite.r);
      } catch (e) {
        // The account exists; the invite can be used again from inside the app.
        note = `the invite didn't work: ${String(e)}. use it again from inside the app.`;
      }
    }
    finishWith("your account is made.", note);
  };

  const cancelAccount = async () => {
    await cancelCreateAccount().catch(() => {});
    reset("new");
  };

  // ── Link ──

  let unlisteners: UnlistenFn[] = [];
  const stopListening = () => {
    unlisteners.forEach((u) => u());
    unlisteners = [];
  };
  onCleanup(stopListening);

  const validatePairingCode = (code: string): string | null => {
    const parts = code.split("#");
    if (parts.length < 4) return "that doesn't look like a pairing code";
    if (!parts[0].startsWith("http")) return "invalid relay url in pairing code";
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
    unlisteners.push(await listen<string>("link-status", (e) => setLinkStatus(e.payload)));
    unlisteners.push(await listen<string>("link-code", (e) => setLinkCode(e.payload)));
    try {
      await joinAsNewDevice(code, deviceLabel());
      props.onComplete();
    } catch (e) {
      setError(describeLinkError(e));
      setLinkStatus(null);
      setLinkCode(null);
      setLoading(false);
    } finally {
      stopListening();
    }
  };

  // ── Recover ──

  const handleBeginRecovery = async () => {
    const key = recoverKey().trim();
    const relay = recoverRelay().trim();
    if (!key || !relay) return;
    setLoading(true);
    setError(null);
    try {
      setShownKey(await beginRecovery(key, relay, deviceLabel()));
      setMode("recover-key");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  /** Recovered: on into the app, unless the user is to hear what did not come back. */
  const recovered = (outcome: RecoveryOutcome) => finishWith("your account is recovered.", describeRestore(outcome.restore));

  const confirmRecoveredKey = async (typed: string) => {
    const outcome = await confirmRecovery(typed);
    if (outcome.outcome === "home_unreachable") {
      setUnreachableHome(outcome.home_url ?? "your home relay");
      setMode("recover-home");
      return;
    }
    recovered(outcome);
  };

  const recoverHere = async () => {
    setLoading(true);
    setError(null);
    try {
      recovered(await recoverThroughRelay());
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  };

  const cancelRecover = async () => {
    await cancelRecovery().catch(() => {});
    reset("recover");
  };

  /** The field naming this device, on every form that makes it part of an account. */
  const deviceLabelField = () => (
    <div>
      <label class="text-xs text-[var(--neutral-400)] mb-1 block">this device's name</label>
      <input
        data-testid="setup-device-label"
        class={inputClass}
        placeholder="how your other devices will list this one"
        value={deviceLabel()}
        onInput={(e) => setDeviceLabel(e.currentTarget.value)}
        disabled={loading()}
      />
    </div>
  );

  const backButton = (target: Mode) => (
    <button
      class="flex items-center gap-1 text-xs text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer w-fit"
      onClick={() => reset(target)}
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

          {/* ── New account: the recovery key, before anything is sent ── */}
          <Show when={mode() === "new-key" && shownKey()}>
            {(key) => (
              <RecoveryKeySteps
                shown={key()}
                purpose="this is your recovery key: the only way back into your account if you lose every device."
                confirm={confirmAccount}
                onCancel={cancelAccount}
                confirmLabel="create account"
              />
            )}
          </Show>

          {/* ── Link device ── */}
          <Show when={mode() === "link"}>
            <div class="flex flex-col gap-3">
              {backButton("new")}
              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">pairing code</label>
                <input
                  class={inputClass}
                  placeholder="paste the code from your other device"
                  value={pairingCode()}
                  onInput={(e) => setPairingCode(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleLinkDevice(); }}
                  disabled={loading()}
                  autofocus
                />
              </div>
              {deviceLabelField()}
              <Show when={linkCode()}>
                <div class="flex flex-col gap-1 p-3 rounded bg-[var(--neutral-800)] border border-[var(--neutral-700)]">
                  <p class="text-xs text-[var(--neutral-400)]">your other device shows a code. it should be:</p>
                  <p data-testid="link-code" class="text-2xl text-center font-mono tracking-widest text-[var(--neutral-100)]">{linkCode()}</p>
                  <p class="text-xs text-[var(--neutral-500)]">confirm there, only if they match.</p>
                </div>
              </Show>
              <Show when={linkStatus()}>
                <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
                  <Loader size={12} class="animate-spin" />
                  <span>{linkStatus()}</span>
                </div>
              </Show>
              {error() && <p class="text-xs text-[var(--red-400)]">{error()}</p>}
              <Button size="lg" class="w-full" onClick={handleLinkDevice} disabled={!pairingCode().trim() || loading()}>
                {loading() ? "linking…" : "link device"}
              </Button>
            </div>
          </Show>

          {/* ── Recover: key and relay ── */}
          <Show when={mode() === "recover"}>
            <div class="flex flex-col gap-3">
              {backButton("new")}
              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">recovery key</label>
                <input
                  class={`${inputClass} font-mono`}
                  placeholder="XXXX-XXXX-XXXX-…"
                  value={recoverKey()}
                  onInput={(e) => setRecoverKey(e.currentTarget.value)}
                  autofocus
                />
              </div>
              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">a relay your account uses</label>
                <input
                  class={inputClass}
                  placeholder="http://relay:7700"
                  value={recoverRelay()}
                  onInput={(e) => setRecoverRelay(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleBeginRecovery(); }}
                />
                <p class="text-xs text-[var(--neutral-600)] mt-1">your home relay, or any relay hosting a server you're in</p>
              </div>
              {deviceLabelField()}
              {error() && <p class="text-xs text-[var(--red-400)]">{error()}</p>}
              <Button size="lg" class="w-full" onClick={handleBeginRecovery} disabled={!recoverKey().trim() || !recoverRelay().trim() || loading()}>
                {loading() ? "looking up your account…" : "recover account"}
              </Button>
            </div>
          </Show>

          {/* ── Recover: the new key every recovery sets ── */}
          <Show when={mode() === "recover-key" && shownKey()}>
            {(key) => (
              <RecoveryKeySteps
                shown={key()}
                purpose="recovering sets a new recovery key. the key you just used stops working once this is done."
                confirm={confirmRecoveredKey}
                onCancel={cancelRecover}
                confirmLabel="recover account"
              />
            )}
          </Show>

          {/* ── Recover: the home relay did not answer ── */}
          <Show when={mode() === "recover-home"}>
            <div class="flex flex-col gap-3">
              <p class="text-xs text-[var(--neutral-400)]">
                your home relay, {unreachableHome()}, doesn't answer. you can recover through {recoverRelay()} and make it your home.
                servers made on the old home stay there and come back if it does; everything else carries on from the new home.
              </p>
              <p class="text-xs text-[var(--neutral-400)]">if the home is only down for a moment, try again later instead.</p>
              {error() && <p class="text-xs text-[var(--red-400)]">{error()}</p>}
              <Button size="lg" class="w-full" onClick={recoverHere} disabled={loading()}>
                {loading() ? "recovering…" : "make it my home and recover"}
              </Button>
              <Button variant="outline" size="lg" class="w-full" onClick={cancelRecover} disabled={loading()}>
                try again later
              </Button>
            </div>
          </Show>

          {/* ── Made or recovered, with something to hear first ── */}
          <Show when={mode() === "done" && done()}>
            {(shown) => (
              <div class="flex flex-col gap-3">
                <p class="text-sm text-[var(--neutral-200)]">{shown().title}</p>
                <p data-testid="done-note" class="text-xs text-[var(--neutral-400)]">{shown().note}</p>
                <Button size="lg" class="w-full" onClick={() => props.onComplete()}>
                  continue
                </Button>
              </div>
            )}
          </Show>

          {/* ── An account made here that its relay has not confirmed yet ── */}
          <Show when={unfinishedAt() && mode() !== "done"}>
            <div class="flex items-center gap-2 p-3 rounded bg-[var(--neutral-800)] border border-[var(--neutral-700)]">
              <p class="text-xs text-[var(--neutral-400)] flex-1">
                an account was being made on this device at {unfinishedAt()} when ghost closed, and that relay doesn't answer yet.
                it's finished here once it does.
              </p>
              <Button size="sm" variant="outline" onClick={resumeUnfinished}>try again</Button>
            </div>
          </Show>

          {/* ── New account mode (default) ── */}
          <Show when={mode() === "new"}>
            <div class="flex flex-col gap-3">
              <div>
                <label class="text-xs text-[var(--neutral-400)] mb-1 block">display name</label>
                <input
                  data-testid="setup-name"
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
                  placeholder={defaultRelay() || "paste invite link or http://relay:7700"}
                  value={inviteOrRelay()}
                  onInput={(e) => setInviteOrRelay(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleNewAccount(); }}
                />
                <p class="text-xs text-[var(--neutral-600)] mt-1">your account lives on this relay; leave it to use the default</p>
              </div>
              {deviceLabelField()}
              {error() && <p class="text-xs text-[var(--red-400)]">{error()}</p>}
              <Button data-testid="setup-start" size="lg" class="w-full" onClick={handleNewAccount} disabled={!name().trim() || loading()}>
                {loading() ? "contacting relay…" : "get started"}
              </Button>
              <Button variant="outline" size="lg" class="w-full" onClick={() => reset("link")}>
                <MonitorSmartphone size={14} />
                link existing account
              </Button>
              <Button variant="outline" size="lg" class="w-full" onClick={() => reset("recover")}>
                <ShieldAlert size={14} />
                recover account
              </Button>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
