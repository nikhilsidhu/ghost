import { createSignal, createMemo, For, Show, onMount, onCleanup, type Component } from "solid-js";
import {
  getDevices, revokeDevice, startPairing, checkPairing, confirmPairing, cancelPairing,
  checkRecoveryKey, beginReplaceRecoveryKey, confirmNewRecoveryKey, cancelNewRecoveryKey, moveHome, getAccountStatus, renameDevice,
} from "../../lib/api";
import { SettingGroup } from "./controls";
import { cn } from "../../lib/cn";
import { KeySquare, Check, Monitor, Smartphone, Plus, X, Loader, QrCode, Link2, Pencil } from "lucide-solid";
import { Button } from "../ui/button";
import { Tooltip } from "../ui/tooltip";
import { encode } from "uqr";
import type { Device, PairingStatus, RevokeOutcome } from "../../lib/types";
import { PAIRING_TTL_MS } from "../../lib/types";
import { RecoveryKeySteps } from "../RecoveryKeySteps";
import { connectivity } from "../../lib/store";
import { errorCode } from "../../lib/invoke";

/** What became of a removal, when there is more to say than that it is done. */
const describeRevoke = (outcome: RevokeOutcome): string | null => {
  switch (outcome.outcome) {
    case "leaves_left":
      return `removed. ${outcome.servers.join(", ") || "some servers"} still hold it until their relays take it out, which they do on their own.`;
    case "log_pending":
      return "your home relay can't be reached, so the removal waits for it. it finishes, and sync resumes, once it is back.";
    default:
      return null;
  }
};

const FLASH_MS = 1200;
const POLL_INTERVAL = 2000;
// The relay ends the session then, and the new device waits at least as long.
const PAIRING_TIMEOUT = PAIRING_TTL_MS;

function deviceIcon(label: string): Component<{ size: number }> {
  const lower = label.toLowerCase();
  if (lower === "ios" || lower === "android") return Smartphone;
  return Monitor;
}

function PairingQr(props: { data: string; size: number }) {
  const matrix = createMemo(() => encode(props.data));

  return (
    <svg
      viewBox={`0 0 ${matrix().size} ${matrix().size}`}
      width={props.size}
      height={props.size}
      class="rounded-lg"
      style={{ background: "var(--neutral-50)" }}
    >
      {matrix().data.map((row, y) =>
        row.map((cell, x) =>
          cell ? (
            <rect x={x} y={y} width={1} height={1} fill="var(--neutral-950)" />
          ) : null,
        ),
      )}
    </svg>
  );
}

const inputClass = "w-full h-8 rounded px-3 text-xs bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none";

export default function DevicesSettings() {
  const [devices, setDevices] = createSignal<Device[]>([]);
  // Whether the list is the home's word now, rather than as this device last saw it.
  const [listCurrent, setListCurrent] = createSignal(true);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const homeDown = () => !connectivity().home;
  const [revoking, setRevoking] = createSignal<string | null>(null);
  const [copiedKey, setCopiedKey] = createSignal<string | null>(null);
  // The device whose label is being edited, and the label as typed so far.
  const [renaming, setRenaming] = createSignal<string | null>(null);
  const [newLabel, setNewLabel] = createSignal("");
  const [homeRelay, setHomeRelay] = createSignal("");

  // Pairing state
  const [pairingCode, setPairingCode] = createSignal<string | null>(null);
  const [pairing, setPairing] = createSignal<PairingStatus | null>(null);
  const [pairingError, setPairingError] = createSignal<string | null>(null);
  const [linkedLabel, setLinkedLabel] = createSignal<string | null>(null);
  const [showQr, setShowQr] = createSignal(false);
  const [linkCopied, setLinkCopied] = createSignal(false);
  const [pairingStarting, setPairingStarting] = createSignal(false);
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;

  // Recovery key state
  const [keyToCheck, setKeyToCheck] = createSignal("");
  const [checkResult, setCheckResult] = createSignal<"current" | "not" | null>(null);
  // Whether the check read the home's log now, rather than this device's last look.
  const [checkedNow, setCheckedNow] = createSignal(true);
  const [replacing, setReplacing] = createSignal(false);
  const [currentForReplace, setCurrentForReplace] = createSignal("");
  const [shownNewKey, setShownNewKey] = createSignal<string | null>(null);
  const [keyError, setKeyError] = createSignal<string | null>(null);
  const [keyBusy, setKeyBusy] = createSignal(false);
  const [replaced, setReplaced] = createSignal(false);

  // Home relay state
  const [moving, setMoving] = createSignal(false);
  const [moveKey, setMoveKey] = createSignal("");
  const [moveRelay, setMoveRelay] = createSignal("");
  const [moveError, setMoveError] = createSignal<string | null>(null);
  const [moveBusy, setMoveBusy] = createSignal(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await getDevices();
      list.devices.sort((a, b) => a.added_at_seq - b.added_at_seq);
      setDevices(list.devices);
      setListCurrent(list.current);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  onMount(() => {
    load();
    getAccountStatus().then((s) => setHomeRelay(s.relay_url)).catch(() => {});
  });

  onCleanup(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (timeoutTimer) clearTimeout(timeoutTimer);
  });

  const copyDeviceKey = (key: string) => {
    navigator.clipboard.writeText(key).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), FLASH_MS);
  };

  const [revokeLoading, setRevokeLoading] = createSignal(false);

  const startRename = (device: Device) => {
    setNewLabel(device.label);
    setRenaming(device.device_key);
  };

  const finishRename = async (device: Device) => {
    const label = newLabel().trim();
    setRenaming(null);
    if (!label || label === device.label) return;
    try {
      await renameDevice(device.device_key, label);
      await load();
    } catch (e) {
      setError(String(e));
    }
  };

  const handleRevoke = async (key: string) => {
    if (revoking() === key) {
      if (revokeLoading()) return;
      setRevokeLoading(true);
      try {
        const outcome = await revokeDevice(key);
        setRevoking(null);
        await load();
        setNotice(describeRevoke(outcome));
      } catch (e) {
        setError(String(e));
      } finally {
        setRevokeLoading(false);
      }
    } else {
      setRevoking(key);
    }
  };

  // ── Pairing ──

  const stopPairing = () => {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
    if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = undefined; }
  };

  const endPairing = (err: string | null) => {
    stopPairing();
    setPairingCode(null);
    setPairing(null);
    setShowQr(false);
    setPairingError(err);
  };

  const pollPairing = async () => {
    try {
      const status = await checkPairing();
      setPairing(status);
      if (status.stage === "linked") {
        stopPairing();
        setLinkedLabel(status.label);
        setPairingCode(null);
        setPairing(null);
        setPairingError(null);
        await load();
      }
    } catch (e) {
      switch (errorCode(e)) {
        // The pairing was ended here.
        case "wrong_state":
          endPairing(null);
          break;
        // The relay's session is gone: nothing more can come of it.
        case "not_found":
          endPairing(String(e));
          break;
        default:
          setPairingError(String(e));
      }
    }
  };

  const handleStartPairing = async () => {
    if (pairingCode()) return;
    setPairingStarting(true);
    setPairingError(null);
    setLinkedLabel(null);
    try {
      const code = await startPairing();
      setPairingCode(code);
      setPairing({ stage: "waiting", code: null, label: null });
      setShowQr(false);
      timeoutTimer = setTimeout(() => {
        endPairing("pairing timed out. start again on both devices.");
        cancelPairing().catch(() => {});
      }, PAIRING_TIMEOUT);
      pollTimer = setInterval(pollPairing, POLL_INTERVAL);
    } catch (e) {
      setPairingError(String(e));
    } finally {
      setPairingStarting(false);
    }
  };

  const handleCodesMatch = async () => {
    try {
      await confirmPairing();
      setPairing((p) => (p ? { ...p, stage: "signing" } : p));
    } catch (e) {
      setPairingError(String(e));
    }
  };

  const handleCancelPairing = async () => {
    endPairing(null);
    await cancelPairing().catch(() => {});
  };

  const copyLink = () => {
    const code = pairingCode();
    if (!code) return;
    navigator.clipboard.writeText(code).catch(() => {});
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), FLASH_MS);
  };

  // ── Recovery key ──

  const handleCheckKey = async () => {
    const key = keyToCheck().trim();
    if (!key) return;
    setKeyBusy(true);
    setKeyError(null);
    setCheckResult(null);
    try {
      const check = await checkRecoveryKey(key);
      setCheckResult(check.matches ? "current" : "not");
      setCheckedNow(check.current);
    } catch (e) {
      setKeyError(String(e));
    } finally {
      setKeyBusy(false);
    }
  };

  const handleBeginReplace = async () => {
    const current = currentForReplace().trim();
    if (!current) return;
    setKeyBusy(true);
    setKeyError(null);
    try {
      setShownNewKey(await beginReplaceRecoveryKey(current));
      setCurrentForReplace("");
    } catch (e) {
      setKeyError(String(e));
    } finally {
      setKeyBusy(false);
    }
  };

  const confirmReplacement = async (typed: string) => {
    await confirmNewRecoveryKey(typed);
    setShownNewKey(null);
    setReplacing(false);
    setReplaced(true);
    setTimeout(() => setReplaced(false), 3000);
  };

  const cancelReplacement = async () => {
    await cancelNewRecoveryKey().catch(() => {});
    setShownNewKey(null);
    setReplacing(false);
    setKeyError(null);
  };

  // ── Home relay ──

  const handleMoveHome = async () => {
    const key = moveKey().trim();
    const relay = moveRelay().trim();
    if (!key || !relay) return;
    setMoveBusy(true);
    setMoveError(null);
    try {
      await moveHome(key, relay);
      setHomeRelay(relay);
      setMoving(false);
      setMoveKey("");
      setMoveRelay("");
    } catch (e) {
      setMoveError(String(e));
    } finally {
      setMoveBusy(false);
    }
  };

  return (
    <div class="pb-4">
      <SettingGroup label="linked devices">
        <Show when={homeDown()}>
          <div class="py-2 text-xs text-[var(--amber-400)]">
            your home relay can't be reached. linking a device waits for it, and a removal is recorded once it is back.
          </div>
        </Show>
        <Show when={!loading() && !listCurrent()}>
          <div class="py-2 text-xs text-[var(--neutral-500)]">this is your device list as this device last saw it.</div>
        </Show>
        <Show when={notice()}>
          <div class="py-2 text-xs text-[var(--neutral-400)]">{notice()}</div>
        </Show>
        <Show when={loading()}>
          <div class="py-3 text-xs text-[var(--neutral-500)]">loading…</div>
        </Show>
        <Show when={error()}>
          <div class="py-3 text-xs text-[var(--red-400)]">{error()}</div>
        </Show>
        <Show when={!loading() && !error()}>
          <Show when={devices().length === 0}>
            <div class="py-3 text-xs text-[var(--neutral-500)]">no devices found</div>
          </Show>
          <For each={devices()}>
            {(device) => {
              const Icon = deviceIcon(device.label);
              return (
                <div class="py-3 border-b border-[var(--neutral-800)] last:border-b-0 flex items-center justify-between gap-3">
                  <div class="min-w-0 flex items-center gap-2.5">
                    <div class="text-[var(--neutral-500)] flex-shrink-0">
                      <Icon size={16} />
                    </div>
                    <div class="min-w-0">
                      <div class="flex items-center gap-2">
                        <Show
                          when={renaming() === device.device_key}
                          fallback={<span class="text-sm text-[var(--neutral-200)]">{device.label}</span>}
                        >
                          <input
                            class={cn(inputClass, "h-7 w-44")}
                            value={newLabel()}
                            maxLength={64}
                            autofocus
                            onInput={(e) => setNewLabel(e.currentTarget.value)}
                            onBlur={() => finishRename(device)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") finishRename(device);
                              if (e.key === "Escape") setRenaming(null);
                            }}
                          />
                        </Show>
                        <Show when={device.is_current}>
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-[var(--purple-500)]/20 text-[var(--purple-400)]">
                            this device
                          </span>
                        </Show>
                        <Show when={!device.is_active}>
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-[var(--red-500)]/20 text-[var(--red-400)]">
                            removed
                          </span>
                        </Show>
                        <Show when={device.removal_pending}>
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-[var(--amber-500)]/20 text-[var(--amber-400)]">
                            removal waiting
                          </span>
                        </Show>
                      </div>
                      <Show when={device.removal_refused}>
                        <p class="text-xs text-[var(--red-400)] mt-0.5">
                          your home relay refused to record its removal: {device.removal_refused}. sync stays paused until one of your devices records it.
                        </p>
                      </Show>
                    </div>
                  </div>
                  <div class="flex items-center gap-2 flex-shrink-0">
                    <Show when={device.is_active && renaming() !== device.device_key}>
                      <Tooltip label="rename" placement="top">
                        <button
                          class="flex items-center justify-center text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer"
                          onClick={() => startRename(device)}
                        >
                          <Pencil size={14} />
                        </button>
                      </Tooltip>
                    </Show>
                    <Tooltip label="copy device key" placement="top">
                      <button
                        class="flex items-center justify-center text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer"
                        onClick={() => copyDeviceKey(device.device_key)}
                      >
                        {copiedKey() === device.device_key
                          ? <Check size={14} class="text-[var(--emerald-400)]" />
                          : <KeySquare size={14} />}
                      </button>
                    </Tooltip>
                    <Show when={device.is_active && !device.is_current && !device.removal_pending}>
                      <button
                        class={cn(
                          "text-xs px-2.5 py-1 rounded cursor-pointer transition-colors duration-150",
                          revoking() === device.device_key
                            ? "bg-[var(--red-500)]/20 text-[var(--red-400)] border border-[var(--red-500)]/40"
                            : "text-[var(--neutral-400)] hover:text-[var(--neutral-200)] border border-[var(--neutral-700)]",
                        )}
                        onClick={() => handleRevoke(device.device_key)}
                        onMouseLeave={() => setRevoking(null)}
                      >
                        {revoking() === device.device_key ? "confirm removal" : "remove"}
                      </button>
                    </Show>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </SettingGroup>

      {/* Pairing section */}
      <SettingGroup label="link new device">
        <Show when={pairingError() && !pairingCode()}>
          <div class="py-3 flex items-center gap-2">
            <p class="text-xs text-[var(--red-400)] flex-1">{pairingError()}</p>
            <Button variant="outline" size="sm" onClick={() => { setPairingError(null); handleStartPairing(); }}>
              retry
            </Button>
          </div>
        </Show>
        <Show when={linkedLabel() && !pairingCode()}>
          <p class="py-3 text-xs text-[var(--emerald-400)]">{linkedLabel()} is linked.</p>
        </Show>
        <Show when={!pairingCode() && !pairingError()} fallback={
          <Show when={pairingCode()}>
            <div class="py-3">
              <div class="flex items-center justify-between mb-3">
                <div class="flex flex-col gap-1">
                  <Show when={pairing()?.stage !== "confirm"}>
                    <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
                      <Loader size={12} class="animate-spin" />
                      <span>{pairing()?.stage === "signing" ? "waiting for the new device to sign…" : "waiting for the new device…"}</span>
                    </div>
                  </Show>
                  <Show when={pairingError()}>
                    <p class="text-xs text-[var(--red-400)]">{pairingError()}</p>
                  </Show>
                </div>
                <div class="flex items-center gap-1.5">
                  <Tooltip label="show qr code" placement="top">
                    <button
                      class={cn(
                        "flex items-center justify-center cursor-pointer transition-colors duration-150",
                        showQr()
                          ? "text-[var(--purple-400)]"
                          : "text-[var(--neutral-500)] hover:text-[var(--neutral-400)]",
                      )}
                      onClick={() => setShowQr((v) => !v)}
                    >
                      <QrCode size={14} />
                    </button>
                  </Tooltip>
                  <Tooltip label="copy code" placement="top">
                    <button
                      class="flex items-center justify-center text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer transition-colors duration-150"
                      onClick={copyLink}
                    >
                      {linkCopied()
                        ? <Check size={14} class="text-[var(--emerald-400)]" />
                        : <Link2 size={14} />}
                    </button>
                  </Tooltip>
                  <Tooltip label="cancel" placement="top">
                    <button
                      class="flex items-center justify-center text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer transition-colors duration-150"
                      onClick={handleCancelPairing}
                    >
                      <X size={14} />
                    </button>
                  </Tooltip>
                </div>
              </div>
              <Show when={pairing()?.stage === "confirm"}>
                <div class="flex flex-col gap-2 p-3 mb-3 rounded bg-[var(--neutral-800)] border border-[var(--neutral-700)]">
                  <p class="text-xs text-[var(--neutral-400)]">the new device shows a code. does it match this one?</p>
                  <p data-testid="pairing-code" class="text-2xl text-center font-mono tracking-widest text-[var(--neutral-100)]">{pairing()?.code}</p>
                  <div class="flex gap-2">
                    <Button size="sm" class="flex-1" onClick={handleCodesMatch}>they match</Button>
                    <Button size="sm" variant="outline" class="flex-1" onClick={handleCancelPairing}>they don't</Button>
                  </div>
                  <p class="text-xs text-[var(--neutral-600)]">a different code means someone else answered your pairing code. cancel and start again.</p>
                </div>
              </Show>
              <Show when={showQr()}>
                <div class="flex justify-center mb-3">
                  <PairingQr data={pairingCode()!} size={180} />
                </div>
              </Show>
            </div>
          </Show>
        }>
          <div class="py-3">
            <Button variant="outline" size="sm" onClick={handleStartPairing} disabled={pairingStarting() || homeDown()}>
              <Plus size={12} />
              {pairingStarting() ? "starting…" : "link new device"}
            </Button>
          </div>
        </Show>
      </SettingGroup>

      {/* Recovery key section */}
      <SettingGroup label="recovery key">
        <div class="py-3 flex flex-col gap-3">
          <p class="text-xs text-[var(--neutral-400)]">
            your recovery key is the only way back into your account if you lose every device. nobody stores it for you.
            replacing it needs the current one.
          </p>
          <Show when={!replacing()}>
            <div class="flex flex-col gap-2">
              <label class="text-xs text-[var(--neutral-400)]">check a key against this account</label>
              <div class="flex gap-2">
                <input
                  class={`${inputClass} font-mono`}
                  placeholder="XXXX-XXXX-XXXX-…"
                  value={keyToCheck()}
                  onInput={(e) => { setKeyToCheck(e.currentTarget.value); setCheckResult(null); }}
                  onKeyDown={(e) => { if (e.key === "Enter") handleCheckKey(); }}
                />
                <Button size="sm" variant="outline" onClick={handleCheckKey} disabled={!keyToCheck().trim() || keyBusy()}>check</Button>
              </div>
              <Show when={checkResult() === "current"}>
                <p class="text-xs text-[var(--emerald-400)] flex items-center gap-1"><Check size={12} /> that is this account's current recovery key</p>
              </Show>
              <Show when={checkResult() === "not"}>
                <p class="text-xs text-[var(--red-400)]">that key does not open this account</p>
              </Show>
              <Show when={checkResult() && !checkedNow()}>
                <p class="text-xs text-[var(--neutral-500)]">your home relay can't be reached, so this is as of this device's last look at your account.</p>
              </Show>
            </div>
            <div class="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => { setReplacing(true); setKeyError(null); }}>
                replace recovery key
              </Button>
              <Show when={replaced()}>
                <span class="text-xs text-[var(--emerald-400)] flex items-center gap-1"><Check size={12} /> key replaced</span>
              </Show>
            </div>
          </Show>
          <Show when={replacing() && !shownNewKey()}>
            <div class="flex flex-col gap-2">
              <label class="text-xs text-[var(--neutral-400)]">current recovery key</label>
              <input
                class={`${inputClass} font-mono`}
                placeholder="XXXX-XXXX-XXXX-…"
                value={currentForReplace()}
                onInput={(e) => setCurrentForReplace(e.currentTarget.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleBeginReplace(); }}
                autofocus
              />
              <div class="flex gap-2">
                <Button size="sm" onClick={handleBeginReplace} disabled={!currentForReplace().trim() || keyBusy()}>
                  {keyBusy() ? "checking…" : "continue"}
                </Button>
                <Button variant="outline" size="sm" onClick={cancelReplacement}>cancel</Button>
              </div>
            </div>
          </Show>
          <Show when={shownNewKey()}>
            {(key) => (
              <RecoveryKeySteps
                shown={key()}
                purpose="this is your new recovery key. the old one stops working once you confirm it."
                confirm={confirmReplacement}
                onCancel={cancelReplacement}
                confirmLabel="replace key"
              />
            )}
          </Show>
          <Show when={keyError()}>
            <p class="text-xs text-[var(--red-400)]">{keyError()}</p>
          </Show>
        </div>
      </SettingGroup>

      {/* Home relay section */}
      <SettingGroup label="home relay">
        <div class="py-3 flex flex-col gap-3">
          <p class="text-xs text-[var(--neutral-400)]">
            your account lives on <span class="font-mono text-[var(--neutral-300)]">{homeRelay() || "…"}</span>. it records your devices and
            carries sync between them. moving it needs your recovery key; servers you made there stay on it.
          </p>
          <Show when={!moving()}>
            <div>
              <Button variant="outline" size="sm" onClick={() => setMoving(true)}>move home relay</Button>
            </div>
          </Show>
          <Show when={moving()}>
            <div class="flex flex-col gap-2">
              <input
                class={inputClass}
                placeholder="new relay url, e.g. http://relay:7700"
                value={moveRelay()}
                onInput={(e) => setMoveRelay(e.currentTarget.value)}
                autofocus
              />
              <input
                class={`${inputClass} font-mono`}
                placeholder="recovery key"
                value={moveKey()}
                onInput={(e) => setMoveKey(e.currentTarget.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleMoveHome(); }}
              />
              <Show when={moveError()}>
                <p class="text-xs text-[var(--red-400)]">{moveError()}</p>
              </Show>
              <div class="flex gap-2">
                <Button size="sm" onClick={handleMoveHome} disabled={!moveKey().trim() || !moveRelay().trim() || moveBusy()}>
                  {moveBusy() ? "moving…" : "move"}
                </Button>
                <Button variant="outline" size="sm" onClick={() => { setMoving(false); setMoveError(null); setMoveKey(""); }}>cancel</Button>
              </div>
            </div>
          </Show>
        </div>
      </SettingGroup>
    </div>
  );
}
