import { createSignal, Show } from "solid-js";
import { Avatar } from "./ui/avatar";
import { X, Fingerprint, Check, ChevronDown } from "lucide-solid";
import { cn } from "../lib/cn";
import { identity, profileOpen, setProfileOpen } from "../lib/store";
import { setDisplayName } from "../lib/api";

type Status = "online" | "away" | "invisible";

const STATUS_OPTIONS: { value: Status; label: string; color: string }[] = [
  { value: "online", label: "Online", color: "var(--emerald-400)" },
  { value: "away", label: "Away", color: "var(--amber-400)" },
  { value: "invisible", label: "Invisible", color: "var(--neutral-500)" },
];

export function ProfilePanel() {
  const [status, setStatus] = createSignal<Status>("online");
  const [statusMessage, setStatusMessage] = createSignal("");
  const [statusDropdownOpen, setStatusDropdownOpen] = createSignal(false);
  const [editingName, setEditingName] = createSignal(false);
  const [nameInput, setNameInput] = createSignal("");
  const [copied, setCopied] = createSignal(false);

  const currentStatus = () => STATUS_OPTIONS.find((o) => o.value === status())!;

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

  return (
    <div
      class="absolute bottom-0 left-0 right-0 z-30 pointer-events-none"
      style={{
        "max-height": profileOpen() ? "360px" : "0px",
        transition: "max-height var(--duration-slow) var(--ease-out)",
        overflow: "hidden",
      }}
    >
      {/* Top gradient fade */}
      <div
        class="h-8 pointer-events-none"
        style={{ background: "linear-gradient(to bottom, transparent, var(--neutral-950))" }}
      />

      {/* Panel content */}
      <div
        class="pointer-events-auto px-4 pb-4 pt-1"
        style={{ background: "var(--neutral-950)" }}
      >
        <Show when={identity()}>
          {(id) => (
            <div class="flex flex-col gap-4">
              {/* Avatar + name + close */}
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

                  <button
                    class="flex items-center gap-1 mt-1 text-[var(--neutral-500)] hover:text-[var(--neutral-400)] cursor-pointer"
                    onClick={copyFingerprint}
                    title="copy fingerprint"
                  >
                    {copied() ? <Check size={14} /> : <Fingerprint size={14} />}
                  </button>
                </div>
                <button
                  class="w-6 h-6 flex items-center justify-center rounded-md text-[var(--neutral-500)] hover:text-[var(--neutral-300)] cursor-pointer hover:bg-[var(--hover)] flex-shrink-0 self-start"
                  onClick={() => setProfileOpen(false)}
                >
                  <X size={14} />
                </button>
              </div>

              {/* Status selector */}
              <div class="relative">
                <button
                  class="w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm cursor-pointer hover:bg-[var(--hover)] border border-[var(--neutral-800)] hover:border-[var(--neutral-700)]"
                  onClick={() => setStatusDropdownOpen((v) => !v)}
                >
                  <div
                    class="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ background: currentStatus().color }}
                  />
                  <span class="text-[var(--neutral-200)]">{currentStatus().label}</span>
                  <ChevronDown size={14} class="ml-auto text-[var(--neutral-500)]" />
                </button>

                <Show when={statusDropdownOpen()}>
                  <div
                    class="absolute top-full left-0 right-0 mt-1 rounded-md border border-[var(--neutral-700)] py-1 z-50"
                    style={{ background: "var(--neutral-800)", "box-shadow": "var(--shadow-float)" }}
                  >
                    {STATUS_OPTIONS.map((opt) => (
                      <button
                        class={cn(
                          "w-full flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer hover:bg-[var(--hover)]",
                          status() === opt.value ? "text-[var(--neutral-100)]" : "text-[var(--neutral-400)]",
                        )}
                        onClick={() => {
                          setStatus(opt.value);
                          setStatusDropdownOpen(false);
                        }}
                      >
                        <div
                          class="w-2.5 h-2.5 rounded-full flex-shrink-0"
                          style={{ background: opt.color }}
                        />
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </Show>
              </div>

              {/* Status message */}
              <input
                class="w-full text-sm text-[var(--neutral-200)] bg-transparent border border-[var(--neutral-800)] hover:border-[var(--neutral-700)] focus:border-[var(--neutral-600)] rounded-md px-3 py-2 outline-none placeholder:text-[var(--neutral-600)]"
                placeholder="set a status message..."
                value={statusMessage()}
                onInput={(e) => setStatusMessage(e.currentTarget.value)}
                maxLength={128}
              />
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}
