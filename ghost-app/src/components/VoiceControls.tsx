import { createSignal, createEffect, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import type { Channel, VoiceQuality } from "../lib/types";
import { Avatar } from "./ui/avatar";
import { Tooltip } from "./ui/tooltip";
import { HoverCard as KHoverCard } from "@kobalte/core/hover-card";
import { cn } from "../lib/cn";
import {
  AudioLines, Mic, MicOff, Headphones, HeadphoneOff, PhoneOff, Signal,
} from "lucide-solid";
import {
  isInCall, isMuted, isDeafened, isPttMode, isPttKeyHeld, pttMuteAttempt, toggleMute, toggleDeafen, endCall,
  voiceParticipants, members, isSpeaking, voiceMuteStates, voiceQuality, identity,
} from "../lib/store";
import {
  createSortable,
  transformStyle,
} from "@thisbeyond/solid-dnd";

const ICON_SIZE = 18;
const FALLBACK_NAME_LEN = 8;

// Mute, deafen, end-call buttons for the activity bar dock
export function VoiceDock() {
  const [shaking, setShaking] = createSignal(false);
  const [pttHint, setPttHint] = createSignal(false);

  // Watch for blocked mute attempts in PTT mode
  createEffect(() => {
    const attempt = pttMuteAttempt();
    if (attempt > 0) {
      setShaking(true);
      setPttHint(true);
      setTimeout(() => setShaking(false), 400);
      setTimeout(() => setPttHint(false), 2000);
    }
  });

  const selfSpeaking = () => isSpeaking(identity()?.fingerprint ?? "");
  // PTT transmitting = key held; VA transmitting = not muted
  const micOn = () => isPttMode() ? isPttKeyHeld() : !isMuted();

  const micIcon = () => {
    if (!micOn()) return <MicOff size={ICON_SIZE} class="text-[var(--amber-400)]" />;
    const speaking = selfSpeaking();
    return (
      <span class="relative inline-flex items-center justify-center">
        {/* Blurred duplicate behind = smooth icon-shaped glow */}
        <Mic
          size={ICON_SIZE}
          class={cn(
            "absolute text-[var(--emerald-400)] transition-opacity duration-150",
            speaking ? "opacity-60" : "opacity-0",
          )}
          style={{ filter: "blur(5px)" }}
        />
        <Mic
          size={ICON_SIZE}
          class={cn(
            "relative transition-colors duration-75",
            speaking ? "text-[var(--emerald-400)]" : "text-[var(--neutral-300)]",
          )}
        />
      </span>
    );
  };

  return (
    <>
      <div class="relative">
        <DockButton
          active={isInCall() || isPttMode()}
          label={isPttMode() ? "push to talk" : isMuted() ? "unmute" : "mute"}
          onClick={toggleMute}
          activeIcon={micIcon()}
          inactiveIcon={<Mic size={ICON_SIZE} class="text-[var(--neutral-300)]" />}
          shake={shaking()}
        />
        <Show when={pttHint()}>
          <div
            class="absolute left-full top-1/2 -translate-y-1/2 ml-2 px-2 py-1 rounded text-xs whitespace-nowrap text-[var(--neutral-300)] bg-[var(--neutral-800)] border border-[var(--neutral-700)] z-50 animate-[tooltip-in_120ms_ease-out]"
            style={{ "box-shadow": "var(--shadow-float)" }}
          >
            hold keybind to talk
          </div>
        </Show>
      </div>
      <DockButton
        active={isDeafened()}
        label={isDeafened() ? "undeafen" : "deafen"}
        onClick={toggleDeafen}
        activeIcon={<HeadphoneOff size={ICON_SIZE} class="text-[var(--cyan-400)]" />}
        inactiveIcon={<Headphones size={ICON_SIZE} class="text-[var(--neutral-300)]" />}
        hoverReveal
      />
      <DockButton
        active={isInCall()}
        label="end call"
        onClick={endCall}
        activeIcon={<PhoneOff size={ICON_SIZE} class="text-[var(--red-400)]" />}
        inactiveIcon={<PhoneOff size={ICON_SIZE} class="text-[var(--red-400)]" />}
        activeOpacity="opacity-80"
      />
    </>
  );
}

function DockButton(props: {
  active: boolean;
  label: string;
  onClick: () => void;
  activeIcon: JSX.Element;
  inactiveIcon: JSX.Element;
  hoverReveal?: boolean;
  activeOpacity?: string;
  shake?: boolean;
}) {
  return (
    <div class={cn(
      "overflow-hidden w-[var(--size-lg)] flex items-center justify-center",
      props.active
        ? "max-h-[var(--size-lg)]"
        : props.hoverReveal
          ? "max-h-0 group-hover/dock:max-h-[var(--size-lg)]"
          : "max-h-0",
    )}
    style={{ transition: "max-height var(--duration-mid) var(--ease-out)" }}
    >
      <Tooltip label={props.label}>
        <button
          class={cn(
            "w-[var(--size-lg)] h-[var(--size-md)] rounded-lg flex items-center justify-center cursor-pointer transition-opacity duration-[var(--duration-fast)]",
            props.active
              ? `${props.activeOpacity ?? "opacity-100"} hover:brightness-125`
              : "opacity-50 hover:opacity-100",
            props.shake && "animate-[shake_300ms_ease-in-out]",
          )}
          onClick={props.onClick}
        >
          {props.active ? props.activeIcon : props.inactiveIcon}
        </button>
      </Tooltip>
    </div>
  );
}

// Voice channel row — click to join/leave
export function VoiceChannelItem(props: {
  channel: Channel;
  active: boolean;
  onToggle: () => void;
}) {
  const sortable = createSortable(props.channel.channel_id);

  return (
    <button
      ref={sortable.ref}
      class={cn(
        "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-left cursor-pointer",
        props.active
          ? "bg-[var(--active)] text-[var(--emerald-400)]"
          : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
      )}
      style={transformStyle(sortable.transform)}
      {...sortable.dragActivators}
      onClick={props.onToggle}
    >
      <AudioLines size={14} class={cn(
        "flex-shrink-0",
        props.active ? "text-[var(--emerald-400)]" : "text-[var(--neutral-500)]",
      )} />
      <span class="flex-1 truncate">{props.channel.name}</span>
      <Show when={props.active && voiceQuality()}>
        <CallQualityIndicator />
      </Show>
    </button>
  );
}

type QualityLevel = "good" | "fair" | "poor";

const LOSS_FAIR = 2;
const LOSS_POOR = 10;
const PING_FAIR = 150;
const PING_POOR = 300;
const JITTER_FAIR = 2;
const JITTER_POOR = 4;

function qualityLevel(q: VoiceQuality): QualityLevel {
  const ping = q.ping_ms ?? 0;
  const jitterOver = q.jitter_depth - q.jitter_target;
  if (q.packet_loss > LOSS_POOR || ping > PING_POOR || jitterOver > JITTER_POOR) return "poor";
  if (q.packet_loss > LOSS_FAIR || ping > PING_FAIR || jitterOver > JITTER_FAIR) return "fair";
  return "good";
}

const QUALITY_COLOR: Record<QualityLevel, string> = {
  good: "text-[var(--emerald-400)]",
  fair: "text-[var(--amber-400)]",
  poor: "text-[var(--red-400)]",
};

function StatRow(props: { label: string; value: string; color?: string }) {
  return (
    <div class="flex justify-between gap-4">
      <span class="text-[var(--neutral-500)]">{props.label}</span>
      <span class={props.color ?? "text-[var(--neutral-200)]"}>{props.value}</span>
    </div>
  );
}

export function CallQualityIndicator(props: { size?: number }) {
  const sz = () => props.size ?? 16;
  const q = voiceQuality;
  const level = () => q() ? qualityLevel(q()!) : "good" as QualityLevel;
  const color = () => QUALITY_COLOR[level()];

  const pingColor = () => {
    const ms = q()?.ping_ms;
    if (ms == null) return "text-[var(--neutral-500)]";
    if (ms <= PING_FAIR) return "text-[var(--emerald-400)]";
    if (ms <= PING_POOR) return "text-[var(--amber-400)]";
    return "text-[var(--red-400)]";
  };

  const lossColor = () => {
    const loss = q()?.packet_loss ?? 0;
    if (loss <= LOSS_FAIR) return "text-[var(--emerald-400)]";
    if (loss <= LOSS_POOR) return "text-[var(--amber-400)]";
    return "text-[var(--red-400)]";
  };

  return (
    <KHoverCard openDelay={200} closeDelay={200} placement="right" gutter={28}>
      <KHoverCard.Trigger
        as="span"
        class={cn("inline-flex items-center justify-center flex-shrink-0 cursor-pointer w-4 h-4", color())}
        onClick={(e: MouseEvent) => e.stopPropagation()}
      >
        <Signal size={sz()} />
      </KHoverCard.Trigger>
      <KHoverCard.Portal>
        <KHoverCard.Content
          class={cn(
            "z-50 px-2.5 py-1.5 rounded-md text-xs",
            "text-[var(--neutral-100)] border border-[var(--neutral-700)]",
            "animate-[tooltip-in_120ms_ease-out]",
          )}
          style={{ background: "var(--neutral-800)", "box-shadow": "var(--shadow-float)" }}
        >
          <div class="flex flex-col gap-0.5 min-w-[120px]">
            <div class="flex justify-between gap-4">
              <span class="text-[var(--neutral-500)]">Quality</span>
              <span class={color()}><Signal size={14} /></span>
            </div>
            <StatRow
              label="Relay"
              value={q()?.ping_ms != null ? `${q()!.ping_ms} ms` : "—"}
              color={pingColor()}
            />
            <StatRow
              label="Loss"
              value={q() ? `${q()!.packet_loss.toFixed(1)}%` : "—"}
              color={lossColor()}
            />
          </div>
        </KHoverCard.Content>
      </KHoverCard.Portal>
    </KHoverCard>
  );
}

// Participant avatars shown under the active voice channel
export function VoiceParticipantList() {
  const memberMap = () => new Map(members().map((m) => [m.fingerprint, m]));

  return (
    <div class="ml-1 mb-1">
      <For each={voiceParticipants()}>
        {(fp) => {
          const member = () => memberMap().get(fp);
          const speaking = () => isSpeaking(fp);
          const muteState = () => voiceMuteStates().get(fp);
          const name = () => member()?.display_name ?? fp.slice(0, FALLBACK_NAME_LEN);
          return (
            <div class="flex items-center gap-2 px-2 py-1 rounded-md">
              <div class={cn(
                "rounded-full flex-shrink-0 transition-shadow duration-[var(--duration-fast)]",
                speaking() && "ring-2 ring-[var(--emerald-400)]",
              )}>
                <Avatar hashKey={fp} label={name()} class="w-5 h-5 text-[9px]" />
              </div>
              <span class={cn(
                "text-sm truncate flex-1",
                speaking() ? "text-[var(--neutral-100)]" : "text-[var(--neutral-400)]",
              )}>
                {name()}
              </span>
              <Show when={muteState()?.deafened}>
                <HeadphoneOff size={12} class="flex-shrink-0 text-[var(--neutral-600)]" />
              </Show>
              <Show when={muteState()?.muted && !muteState()?.deafened}>
                <MicOff size={12} class="flex-shrink-0 text-[var(--neutral-600)]" />
              </Show>
            </div>
          );
        }}
      </For>
    </div>
  );
}
