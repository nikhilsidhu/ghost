import { createSignal, createEffect, Show, For, onCleanup, type JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { Check, Copy, ChevronDown } from "lucide-solid";

const DEBOUNCE_MS = 600;
const FLASH_MS = 1500;

// --- Layout ---

export function SettingGroup(props: { label: string; children: JSX.Element }) {
  return (
    <div class="mt-6 first:mt-0">
      <div class="text-[11px] font-medium text-[var(--neutral-500)] tracking-wide mb-1">
        {props.label}
      </div>
      {props.children}
    </div>
  );
}

function SettingRow(props: { disabled?: boolean; children: JSX.Element }) {
  return (
    <div
      class={cn(
        "py-3 border-b border-[var(--neutral-800)] last:border-b-0",
        props.disabled && "opacity-50 cursor-not-allowed",
      )}
    >
      {props.children}
    </div>
  );
}

// --- Toggle ---

function ToggleSwitch(props: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      role="switch"
      aria-checked={props.checked}
      disabled={props.disabled}
      class={cn(
        "relative w-8 h-[18px] rounded-full transition-colors duration-200 cursor-pointer flex-shrink-0",
        props.checked ? "bg-[var(--purple-500)]" : "bg-[var(--neutral-600)]",
        props.disabled && "opacity-50 cursor-not-allowed",
      )}
      onClick={() => !props.disabled && props.onChange(!props.checked)}
    >
      <div
        class="absolute top-[3px] w-3 h-3 rounded-full bg-white transition-transform duration-200"
        style={{ transform: props.checked ? "translateX(17px)" : "translateX(3px)" }}
      />
    </button>
  );
}

export function SettingToggle(props: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <SettingRow disabled={props.disabled}>
      <div class="flex items-center justify-between gap-4">
        <div class="min-w-0">
          <div class="text-sm text-[var(--neutral-200)]">{props.label}</div>
          <Show when={props.description}>
            <div class="text-xs text-[var(--neutral-500)] mt-0.5">{props.description}</div>
          </Show>
        </div>
        <ToggleSwitch checked={props.checked} onChange={props.onChange} disabled={props.disabled} />
      </div>
    </SettingRow>
  );
}

// --- Input with debounced save ---

export function SettingInput(props: {
  label: string;
  description?: string;
  value: string;
  onSave: (v: string) => void | Promise<void>;
  placeholder?: string;
  debounceMs?: number;
  disabled?: boolean;
}) {
  const [local, setLocal] = createSignal(props.value);
  const [saved, setSaved] = createSignal(false);
  let timer: ReturnType<typeof setTimeout>;

  createEffect(() => setLocal(props.value));

  const handleInput = (v: string) => {
    setLocal(v);
    clearTimeout(timer);
    timer = setTimeout(async () => {
      await props.onSave(v);
      setSaved(true);
      setTimeout(() => setSaved(false), FLASH_MS);
    }, props.debounceMs ?? DEBOUNCE_MS);
  };

  return (
    <SettingRow disabled={props.disabled}>
      <div class="flex items-center gap-2">
        <div class="min-w-0 flex-1">
          <div class="text-sm text-[var(--neutral-200)]">{props.label}</div>
          <Show when={props.description}>
            <div class="text-xs text-[var(--neutral-500)] mt-0.5">{props.description}</div>
          </Show>
        </div>
        <Show when={saved()}>
          <Check size={14} class="text-[var(--emerald-400)] flex-shrink-0" />
        </Show>
      </div>
      <input
        class={cn(
          "mt-2 h-8 w-full rounded px-3 text-sm",
          "bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)]",
          "border border-[var(--neutral-700)] outline-none",
          "focus:border-[var(--purple-500)]",
        )}
        value={local()}
        placeholder={props.placeholder}
        onInput={(e) => handleInput(e.currentTarget.value)}
        disabled={props.disabled}
      />
    </SettingRow>
  );
}

// --- Select ---

export function SettingSelect(props: {
  label: string;
  description?: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = createSignal(false);
  let ref!: HTMLDivElement;

  const selected = () => props.options.find((o) => o.value === props.value);

  const handleClickOutside = (e: MouseEvent) => {
    if (open() && ref && !ref.contains(e.target as Node)) setOpen(false);
  };
  document.addEventListener("mousedown", handleClickOutside);
  onCleanup(() => document.removeEventListener("mousedown", handleClickOutside));

  return (
    <SettingRow disabled={props.disabled}>
      <div class="flex items-center justify-between gap-4">
        <div class="min-w-0">
          <div class="text-sm text-[var(--neutral-200)]">{props.label}</div>
          <Show when={props.description}>
            <div class="text-xs text-[var(--neutral-500)] mt-0.5">{props.description}</div>
          </Show>
        </div>
        <div ref={ref} class="relative">
          <button
            class={cn(
              "h-7 rounded px-2.5 text-xs flex items-center gap-1.5 cursor-pointer transition-colors duration-150",
              "bg-[var(--neutral-800)] text-[var(--neutral-200)]",
              "border border-[var(--neutral-700)]",
              "hover:border-[var(--neutral-600)]",
              open() && "border-[var(--purple-500)]",
            )}
            disabled={props.disabled}
            onClick={() => setOpen((v) => !v)}
          >
            {selected()?.label ?? props.value}
            <ChevronDown size={12} class={cn(
              "text-[var(--neutral-500)] transition-transform duration-150",
              open() && "rotate-180",
            )} />
          </button>
          <Show when={open()}>
            <div
              class="absolute right-0 top-full mt-1 min-w-full rounded-md py-1 z-50"
              style={{
                background: "var(--neutral-800)",
                border: "1px solid var(--neutral-700)",
                "box-shadow": "0 4px 12px rgba(0,0,0,0.4)",
              }}
            >
              <For each={props.options}>
                {(o) => (
                  <button
                    class={cn(
                      "w-full text-left px-2.5 py-1.5 text-xs cursor-pointer transition-colors duration-100",
                      o.value === props.value
                        ? "text-[var(--purple-400)]"
                        : "text-[var(--neutral-300)] hover:bg-[var(--neutral-700)]",
                    )}
                    onClick={() => { props.onChange(o.value); setOpen(false); }}
                  >
                    {o.label}
                  </button>
                )}
              </For>
            </div>
          </Show>
        </div>
      </div>
    </SettingRow>
  );
}

// --- Readonly with optional copy ---

export function SettingReadonly(props: {
  label: string;
  description?: string;
  value: string;
  copyable?: boolean;
  mono?: boolean;
}) {
  const [copied, setCopied] = createSignal(false);

  const copy = async () => {
    await navigator.clipboard.writeText(props.value);
    setCopied(true);
    setTimeout(() => setCopied(false), FLASH_MS);
  };

  return (
    <SettingRow>
      <div class="flex items-center justify-between gap-4">
        <div class="min-w-0">
          <div class="text-sm text-[var(--neutral-200)]">{props.label}</div>
          <Show when={props.description}>
            <div class="text-xs text-[var(--neutral-500)] mt-0.5">{props.description}</div>
          </Show>
        </div>
        <Show when={props.copyable}>
          <button
            class="flex-shrink-0 text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer transition-colors duration-150"
            onClick={copy}
          >
            <Show when={copied()} fallback={<Copy size={13} />}>
              <Check size={13} class="text-[var(--emerald-400)]" />
            </Show>
          </button>
        </Show>
      </div>
      <div
        class={cn(
          "mt-1 text-xs text-[var(--neutral-400)] break-all",
          props.mono && "font-mono",
        )}
      >
        {props.value}
      </div>
    </SettingRow>
  );
}
