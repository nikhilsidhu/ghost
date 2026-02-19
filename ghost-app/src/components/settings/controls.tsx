import { createSignal, createEffect, Show, For, onCleanup, type JSX } from "solid-js";
import { cn } from "../../lib/cn";
import { Check, Copy, ChevronDown, RotateCcw } from "lucide-solid";

const DEBOUNCE_MS = 600;
const FLASH_MS = 1500;

// Toggle geometry — thumb slides inside track with TOGGLE_INSET padding
const TOGGLE_W = 32;
const TOGGLE_THUMB = 12;
const TOGGLE_INSET = 3;
const TOGGLE_ON = TOGGLE_W - TOGGLE_THUMB - TOGGLE_INSET;

// --- Layout ---

export function SettingGroup(props: { label?: string; footer?: string; children: JSX.Element }) {
  return (
    <div class="mt-4 first:mt-2 mx-2">
      <Show when={props.label}>
        <div class="text-xs text-[var(--neutral-500)] mb-1.5 px-3">
          {props.label}
        </div>
      </Show>
      <div class="rounded-lg bg-[var(--neutral-900)] px-3">
        {props.children}
      </div>
      <Show when={props.footer}>
        <div class="text-xs text-[var(--neutral-500)] mt-1.5 px-3">{props.footer}</div>
      </Show>
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
        "relative w-8 h-[18px] rounded-full transition-colors duration-[var(--duration-mid)] cursor-pointer flex-shrink-0",
        props.checked ? "bg-[var(--purple-500)]" : "bg-[var(--neutral-600)]",
        props.disabled && "opacity-50 cursor-not-allowed",
      )}
      onClick={() => !props.disabled && props.onChange(!props.checked)}
    >
      <div
        class="absolute top-[3px] w-3 h-3 rounded-full bg-[var(--neutral-50)] transition-transform duration-[var(--duration-mid)]"
        style={{ transform: `translateX(${props.checked ? TOGGLE_ON : TOGGLE_INSET}px)` }}
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
              class="absolute right-0 top-full mt-1 min-w-full rounded-md py-1 z-50 bg-[var(--neutral-800)] border border-[var(--neutral-700)]"
              style={{ "box-shadow": "var(--shadow-float)" }}
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

// --- Segmented control ---

export function SettingSegmented(props: {
  label: string;
  description?: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  disabled?: boolean;
  children?: JSX.Element;
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
        <div class="flex rounded-md border border-[var(--neutral-700)] overflow-hidden flex-shrink-0">
          <For each={props.options}>
            {(o) => (
              <button
                class={cn(
                  "h-7 px-2.5 text-xs cursor-pointer transition-colors duration-150",
                  "border-r border-[var(--neutral-700)] last:border-r-0",
                  o.value === props.value
                    ? "bg-[var(--purple-500)]/20 text-[var(--purple-400)]"
                    : "bg-[var(--neutral-800)] text-[var(--neutral-400)] hover:text-[var(--neutral-200)]",
                )}
                disabled={props.disabled}
                onClick={() => props.onChange(o.value)}
              >
                {o.label}
              </button>
            )}
          </For>
        </div>
      </div>
      {props.children}
    </SettingRow>
  );
}

// --- Slider ---

export function SettingSlider(props: {
  label: string;
  description?: string;
  value: number;
  min: number;
  max: number;
  step: number;
  displayValue?: string;
  defaultValue?: number;
  onChange: (v: number) => void;
  onChangeEnd?: (v: number) => void;
  disabled?: boolean;
}) {
  const pct = () => ((props.value - props.min) / (props.max - props.min)) * 100;
  const defaultPct = () =>
    props.defaultValue != null
      ? ((props.defaultValue - props.min) / (props.max - props.min)) * 100
      : null;
  const isDefault = () =>
    props.defaultValue == null || Math.abs(props.value - props.defaultValue) < props.step * 0.5;

  const reset = () => {
    if (props.defaultValue != null) {
      props.onChange(props.defaultValue);
      props.onChangeEnd?.(props.defaultValue);
    }
  };

  return (
    <SettingRow disabled={props.disabled}>
      <div class="flex items-center justify-between gap-4">
        <div class="min-w-0">
          <div class="text-sm text-[var(--neutral-200)]">{props.label}</div>
          <Show when={props.description}>
            <div class="text-xs text-[var(--neutral-500)] mt-0.5">{props.description}</div>
          </Show>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
          <Show when={!isDefault()}>
            <button
              class="text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer transition-colors duration-150"
              onClick={reset}
            >
              <RotateCcw size={11} />
            </button>
          </Show>
          <Show when={props.displayValue}>
            <span class="text-xs text-[var(--neutral-400)] tabular-nums">{props.displayValue}</span>
          </Show>
        </div>
      </div>
      <div class="mt-2 relative h-5 flex items-center">
        <div class="absolute inset-x-0 h-1.5 rounded-full bg-[var(--neutral-800)]">
          <div
            class="h-full rounded-full bg-[var(--purple-500)]"
            style={{ width: `${pct()}%` }}
          />
        </div>
        <Show when={defaultPct() != null}>
          <div
            class="absolute w-0.5 h-2.5 rounded-full bg-[var(--neutral-600)] pointer-events-none z-[1]"
            style={{ left: `${defaultPct()}%`, transform: "translateX(-50%)" }}
          />
        </Show>
        <input
          type="range"
          min={props.min}
          max={props.max}
          step={props.step}
          value={props.value}
          disabled={props.disabled}
          class="slider-input absolute inset-x-0 w-full h-5 appearance-none bg-transparent cursor-pointer z-[2]"
          onInput={(e) => props.onChange(parseFloat(e.currentTarget.value))}
          onChange={(e) => props.onChangeEnd?.(parseFloat(e.currentTarget.value))}
        />
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
