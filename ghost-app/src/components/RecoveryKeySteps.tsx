import { createSignal, Show } from "solid-js";
import { Check, Copy } from "lucide-solid";
import { Button } from "./ui/button";

const FLASH_MS = 1200;

export const inputClass =
  "w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-600)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none";

/** A recovery key as the user reads it: fourteen groups of four, three to a line. */
export function RecoveryKeyDisplay(props: { value: string }) {
  const [copied, setCopied] = createSignal(false);
  const copy = () => {
    navigator.clipboard.writeText(props.value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), FLASH_MS);
  };
  return (
    <div class="flex items-start gap-2 p-3 rounded bg-[var(--neutral-800)] border border-[var(--neutral-700)]">
      <span data-testid="recovery-key" class="text-sm text-[var(--neutral-100)] font-mono tracking-wider leading-relaxed flex-1 break-words">
        {props.value}
      </span>
      <button class="flex-shrink-0 mt-0.5 text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer" onClick={copy} aria-label="copy">
        {copied() ? <Check size={14} class="text-[var(--emerald-400)]" /> : <Copy size={14} />}
      </button>
    </div>
  );
}

interface Props {
  /** The key shown, as the backend encoded it. */
  shown: string;
  /** What the key is for, in one sentence. */
  purpose: string;
  /** Called with what the user typed; throws with a message when it is not the key. */
  confirm: (typed: string) => Promise<void>;
  onCancel?: () => void;
  confirmLabel?: string;
}

/**
 * The two steps every new recovery key goes through: it is shown once, then typed back
 * in full before anything is sent. Nothing exists remotely until the second step passes.
 */
export function RecoveryKeySteps(props: Props) {
  const [step, setStep] = createSignal<"show" | "type">("show");
  const [typed, setTyped] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const submit = async () => {
    if (!typed().trim() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await props.confirm(typed());
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <div class="flex flex-col gap-3">
      <Show when={step() === "show"}>
        <p class="text-xs text-[var(--neutral-400)]">{props.purpose}</p>
        <p class="text-xs text-[var(--neutral-400)]">
          write it down or save it somewhere safe. it is shown once, and nobody can replace it for you: without it, your account
          lasts only as long as one of your devices does.
        </p>
        <RecoveryKeyDisplay value={props.shown} />
        <Button data-testid="recovery-key-saved" size="lg" class="w-full" onClick={() => setStep("type")}>
          I've saved it
        </Button>
        <Show when={props.onCancel}>
          <Button variant="outline" size="lg" class="w-full" onClick={props.onCancel}>
            cancel
          </Button>
        </Show>
      </Show>
      <Show when={step() === "type"}>
        <p class="text-xs text-[var(--neutral-400)]">type the key back, so you know your copy is right.</p>
        <input
          data-testid="recovery-key-typed"
          class={`${inputClass} font-mono`}
          placeholder="XXXX-XXXX-XXXX-…"
          value={typed()}
          onInput={(e) => setTyped(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
          autofocus
        />
        <Show when={error()}>
          <p class="text-xs text-[var(--red-400)]">{error()}</p>
        </Show>
        <Button data-testid="recovery-key-confirm" size="lg" class="w-full" onClick={submit} disabled={!typed().trim() || busy()}>
          {busy() ? "working…" : props.confirmLabel ?? "continue"}
        </Button>
        <Button variant="outline" size="lg" class="w-full" onClick={() => { setStep("show"); setError(null); }}>
          show the key again
        </Button>
      </Show>
    </div>
  );
}
