import { createSignal, createEffect, on, onCleanup, For, Show } from "solid-js";
import { Avatar } from "./ui/avatar";
import { X, Fingerprint, Check, Infinity, Timer } from "lucide-solid";
import { Tooltip } from "./ui/tooltip";
import { cn } from "../lib/cn";
import { identity, profileOpen, setProfileOpen, ownStatus, setOwnStatus, ownStatusMessage, setOwnStatusMessage, selectedExpiry, setSelectedExpiry, expiresAt, setExpiresAt, rebuildPresence, setAutoMuted } from "../lib/store";
import { setDisplayName, setStatus as apiSetStatus, setStatusMessage as apiSetStatusMessage } from "../lib/api";

const STATUS_OPTIONS = [
  { value: "online", label: "Online", color: "var(--emerald-400)" },
  { value: "away", label: "Away", color: "var(--ember-400)" },
  { value: "invisible", label: "Invisible", color: "var(--neutral-500)" },
];

const EXPIRY_PILLS = [
  { ms: 30 * 60 * 1000, label: "30m" },
  { ms: 60 * 60 * 1000, label: "1h" },
  { ms: 4 * 60 * 60 * 1000, label: "4h" },
  { ms: -1, label: "today" },
] as const;

function msUntilEndOfDay(): number {
  const now = new Date();
  const end = new Date(now);
  end.setHours(23, 59, 59, 999);
  return end.getTime() - now.getTime();
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "expired";
  const totalMin = Math.ceil(ms / 60_000);
  if (totalMin < 60) return `${totalMin}m`;
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export function ProfilePanel() {
  const [editingName, setEditingName] = createSignal(false);
  const [nameInput, setNameInput] = createSignal("");
  const [copied, setCopied] = createSignal(false);
  const [remaining, setRemaining] = createSignal<string | null>(null);

  // Countdown timer — ticks every second when an expiry is active
  createEffect(on(expiresAt, (exp) => {
    if (!exp) { setRemaining(null); return; }
    const tick = () => {
      const left = exp - Date.now();
      if (left <= 0) {
        setRemaining(null);
        setExpiresAt(null);
        setSelectedExpiry(0);
      } else {
        setRemaining(formatRemaining(left));
      }
    };
    tick();
    const id = setInterval(tick, 1_000);
    onCleanup(() => clearInterval(id));
  }));

  const copyFingerprint = () => {
    const fp = identity()?.fingerprint;
    if (!fp) return;
    navigator.clipboard.writeText(fp);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const startEditName = () => {
    setNameInput(identity()?.display_name ?? "");
    setEditingName(true);
  };

  const saveName = async () => {
    const name = nameInput().trim();
    if (name && name !== identity()?.display_name) {
      await setDisplayName(name).catch(() => {});
    }
    setEditingName(false);
  };

  const onNameKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter") saveName();
    if (e.key === "Escape") setEditingName(false);
  };

  const onStatusChange = (value: string) => {
    setOwnStatus(value);
    setAutoMuted(false);
    rebuildPresence();
    apiSetStatus(value).catch(() => {});
  };

  const computeExpiry = (): number | null => {
    const sel = selectedExpiry();
    if (sel === 0) return null;
    if (sel === -1) return Date.now() + msUntilEndOfDay();
    return Date.now() + sel;
  };

  const commitStatusMessage = () => {
    const msg = ownStatusMessage().trim() || null;
    const expiry = msg ? computeExpiry() : null;
    setExpiresAt(expiry);
    rebuildPresence();
    apiSetStatusMessage(msg, expiry).catch(() => {});
  };

  const clearStatus = () => {
    setOwnStatusMessage("");
    setSelectedExpiry(0);
    setExpiresAt(null);
    rebuildPresence();
    apiSetStatusMessage(null, null).catch(() => {});
  };

  const onExpiryPick = (ms: number) => {
    if (!ownStatusMessage().trim()) return;
    setSelectedExpiry(ms);
    commitStatusMessage();
  };

  const pillClass = (active: boolean) => cn(
    "flex-1 flex items-center justify-center gap-1.5 px-2 py-1 rounded-md text-xs cursor-pointer outline-none transition-colors duration-[var(--duration-fast)]",
    active
      ? "text-[var(--neutral-100)] bg-[var(--neutral-700)]"
      : "text-[var(--neutral-500)] hover:text-[var(--neutral-300)]",
  );

  return (
    <div
      class="absolute bottom-0 left-0 right-0 z-30"
      style={{
        "max-height": profileOpen() ? "400px" : "0px",
        transition: "max-height var(--duration-slow) var(--ease-out)",
        overflow: "hidden",
      }}
    >
      <div
        class="h-8 pointer-events-none"
        style={{ background: "linear-gradient(to bottom, transparent, var(--neutral-950))" }}
      />

      <div
        class="px-4 pb-4 pt-1"
        style={{ background: "var(--neutral-950)" }}
      >
        <Show when={identity()}>
          {(id) => (
            <div class="flex flex-col gap-3">
              {/* Avatar + name + fingerprint + close */}
              <div class="flex items-center gap-3">
                <Avatar
                  hashKey={id().fingerprint}
                  label={id().display_name}
                  class="w-12 h-12 text-base flex-shrink-0"
                />
                <div class="flex-1 min-w-0">
                  <Show
                    when={editingName()}
                    fallback={
                      <button
                        class="text-sm font-semibold text-[var(--neutral-100)] truncate block cursor-pointer hover:underline decoration-[var(--neutral-600)] underline-offset-2"
                        onClick={startEditName}
                      >
                        {id().display_name}
                      </button>
                    }
                  >
                    <input
                      class="w-full text-sm font-semibold text-[var(--neutral-100)] bg-[var(--neutral-800)] border border-[var(--neutral-600)] rounded-md px-2 py-0.5 outline-none focus:border-[var(--neutral-400)]"
                      value={nameInput()}
                      onInput={(e) => setNameInput(e.currentTarget.value)}
                      onBlur={saveName}
                      onKeyDown={onNameKeyDown}
                      maxLength={32}
                      ref={(el) => setTimeout(() => el.focus(), 0)}
                    />
                  </Show>
                </div>
                <button
                  class="flex items-center justify-center text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer flex-shrink-0"
                  onClick={copyFingerprint}
                  title="copy fingerprint"
                >
                  {copied() ? <Check size={14} /> : <Fingerprint size={14} />}
                </button>
                <button
                  class="w-6 h-6 flex items-center justify-center rounded-md text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer hover:bg-[var(--hover)] flex-shrink-0"
                  onClick={() => setProfileOpen(false)}
                >
                  <X size={14} />
                </button>
              </div>

              {/* Status pills */}
              <div
                class="flex gap-1 rounded-lg p-0.5"
                style={{ background: "var(--neutral-900)" }}
              >
                <For each={STATUS_OPTIONS}>
                  {(opt) => (
                    <button
                      class={pillClass(ownStatus() === opt.value)}
                      onClick={() => onStatusChange(opt.value)}
                    >
                      <div
                        class="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ background: opt.color }}
                      />
                      {opt.label}
                    </button>
                  )}
                </For>
              </div>

              {/* Status message + expiry pills */}
              <div class="flex flex-col gap-2">
                <div class="flex items-center gap-2">
                  <input
                    class="flex-1 min-w-0 text-sm text-[var(--neutral-200)] bg-transparent border border-[var(--neutral-800)] hover:border-[var(--neutral-700)] focus:border-[var(--neutral-600)] rounded-md px-3 py-2 outline-none placeholder:text-[var(--neutral-600)]"
                    placeholder="set a status message..."
                    value={ownStatusMessage()}
                    onInput={(e) => setOwnStatusMessage(e.currentTarget.value)}
                    onBlur={commitStatusMessage}
                    onKeyDown={(e) => { if (e.key === "Enter") { e.currentTarget.blur(); } }}
                    maxLength={128}
                  />
                  <Show when={remaining()}>
                    <Tooltip label={`expires in ${remaining()}`} placement="top" gutter={6}>
                      <div class="flex-shrink-0 text-[var(--neutral-500)]">
                        <Timer size={16} />
                      </div>
                    </Tooltip>
                  </Show>
                </div>
                <div class="flex items-center gap-1">
                  <button
                    class={cn(
                      "px-2 py-1 rounded-md text-xs cursor-pointer transition-colors duration-[var(--duration-fast)]",
                      !ownStatusMessage().trim()
                        ? "text-[var(--neutral-700)] cursor-default"
                        : "text-[var(--neutral-500)] hover:text-[var(--neutral-300)] hover:bg-[var(--neutral-800)]",
                    )}
                    onClick={clearStatus}
                    disabled={!ownStatusMessage().trim()}
                  >
                    clear
                  </button>
                  <div
                    class="flex gap-1 rounded-lg p-0.5 flex-1"
                    style={{ background: "var(--neutral-900)" }}
                  >
                    <For each={EXPIRY_PILLS}>
                      {(pill) => (
                        <button
                          class={pillClass(selectedExpiry() === pill.ms)}
                          onClick={() => onExpiryPick(pill.ms)}
                        >
                          {pill.label}
                        </button>
                      )}
                    </For>
                    <button
                      class={pillClass(selectedExpiry() === 0)}
                      onClick={() => onExpiryPick(0)}
                    >
                      <Infinity size={14} />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}
