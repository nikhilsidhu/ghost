import { createSignal, createMemo, For, Show, onMount, onCleanup, type Component } from "solid-js";
import { getDevices, revokeDevice, startPairing, checkPairing, cancelPairing } from "../../lib/api";
import { SettingGroup } from "./controls";
import { cn } from "../../lib/cn";
import { KeySquare, Check, Monitor, Smartphone, Plus, X, Loader, QrCode, Link2 } from "lucide-solid";
import { Tooltip } from "../ui/tooltip";
import { encode } from "uqr";
import type { Device } from "../../lib/types";

const FLASH_MS = 1200;
const POLL_INTERVAL = 3000;
const PAIRING_TIMEOUT = 5 * 60 * 1000; // 5 minutes

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

export default function DevicesSettings() {
  const [devices, setDevices] = createSignal<Device[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [revoking, setRevoking] = createSignal<string | null>(null);
  const [copiedKey, setCopiedKey] = createSignal<string | null>(null);

  // Pairing state
  const [pairingCode, setPairingCode] = createSignal<string | null>(null);
  const [pairingStatus, setPairingStatus] = createSignal<string>("waiting for new device…");
  const [pairingError, setPairingError] = createSignal<string | null>(null);
  const [showQr, setShowQr] = createSignal(false);
  const [linkCopied, setLinkCopied] = createSignal(false);
  const [pairingStarting, setPairingStarting] = createSignal(false);
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await getDevices();
      list.sort((a, b) => a.added_at_seq - b.added_at_seq);
      setDevices(list);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  onMount(load);

  onCleanup(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (timeoutTimer) clearTimeout(timeoutTimer);
  });

  const copyDeviceKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), FLASH_MS);
  };

  const handleRevoke = async (key: string) => {
    if (revoking() === key) {
      try {
        await revokeDevice(key);
        setRevoking(null);
        await load();
      } catch (e) {
        setError(String(e));
      }
    } else {
      setRevoking(key);
    }
  };

  const stopPairing = () => {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
    if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = undefined; }
  };

  const handleStartPairing = async () => {
    if (pairingCode()) return; // already active
    setPairingStarting(true);
    setPairingError(null);
    setPairingStatus("waiting for new device…");
    try {
      const code = await startPairing();
      setPairingCode(code);
      setShowQr(false);

      // 5-minute timeout
      timeoutTimer = setTimeout(() => {
        stopPairing();
        setPairingCode(null);
        setPairingError("pairing session expired. try again.");
        cancelPairing().catch(() => {});
      }, PAIRING_TIMEOUT);

      pollTimer = setInterval(async () => {
        try {
          const label = await checkPairing();
          if (label) {
            stopPairing();
            setPairingStatus("device linked!");
            setPairingCode(null);
            setPairingError(null);
            await load();
          }
        } catch (e) {
          const msg = String(e);
          // "no active pairing session" means we already completed or cancelled
          if (msg.includes("no active pairing")) {
            stopPairing();
            setPairingCode(null);
          } else {
            // transient error — keep polling, show error
            setPairingError(msg);
          }
        }
      }, POLL_INTERVAL);
    } catch (e) {
      setPairingError(String(e));
    } finally {
      setPairingStarting(false);
    }
  };

  const handleCancelPairing = async () => {
    stopPairing();
    setPairingCode(null);
    setPairingError(null);
    setShowQr(false);
    await cancelPairing().catch(() => {});
  };

  const copyLink = () => {
    const code = pairingCode();
    if (!code) return;
    navigator.clipboard.writeText(code);
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), FLASH_MS);
  };

  return (
    <div class="pb-4">
      <SettingGroup label="linked devices">
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
                        <span class="text-sm text-[var(--neutral-200)]">{device.label}</span>
                        <Show when={device.is_current}>
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-[var(--purple-500)]/20 text-[var(--purple-400)]">
                            this device
                          </span>
                        </Show>
                        <Show when={!device.is_active}>
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-[var(--red-500)]/20 text-[var(--red-400)]">
                            revoked
                          </span>
                        </Show>
                      </div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2 flex-shrink-0">
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
                    <Show when={device.is_active && !device.is_current}>
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
                        {revoking() === device.device_key ? "confirm revoke" : "revoke"}
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
            <button
              class="text-xs px-2.5 py-1 rounded cursor-pointer text-[var(--neutral-300)] hover:text-[var(--neutral-100)] border border-[var(--neutral-700)] hover:border-[var(--neutral-600)] transition-colors duration-150"
              onClick={() => { setPairingError(null); handleStartPairing(); }}
            >
              retry
            </button>
          </div>
        </Show>
        <Show when={!pairingCode() && !pairingError()} fallback={
          <Show when={pairingCode()}>
            <div class="py-3">
              <div class="flex items-center justify-between mb-3">
                <div class="flex flex-col gap-1">
                  <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)]">
                    <Loader size={12} class="animate-spin" />
                    <span>{pairingStatus()}</span>
                  </div>
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
                  <Tooltip label="copy link" placement="top">
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
              <Show when={showQr()}>
                <div class="flex justify-center mb-3">
                  <PairingQr data={pairingCode()!} size={180} />
                </div>
              </Show>
            </div>
          </Show>
        }>
          <div class="py-3">
            <button
              class={cn(
                "flex items-center gap-1.5 text-xs px-3 py-1.5 rounded cursor-pointer transition-colors duration-150",
                "text-[var(--neutral-300)] hover:text-[var(--neutral-100)]",
                "border border-[var(--neutral-700)] hover:border-[var(--neutral-600)]",
              )}
              onClick={handleStartPairing}
              disabled={pairingStarting()}
            >
              <Plus size={12} />
              {pairingStarting() ? "starting…" : "link new device"}
            </button>
          </div>
        </Show>
      </SettingGroup>
    </div>
  );
}
