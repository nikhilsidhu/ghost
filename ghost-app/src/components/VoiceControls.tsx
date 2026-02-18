import { For } from "solid-js";
import type { JSX } from "solid-js";
import type { Channel } from "../lib/types";
import { Avatar } from "./ui/avatar";
import { Tooltip } from "./ui/tooltip";
import { cn } from "../lib/cn";
import { AudioLines, Mic, MicOff, Headphones, HeadphoneOff, PhoneOff } from "lucide-solid";
import {
  isInCall, isMuted, isDeafened, toggleMute, toggleDeafen, endCall,
  voiceParticipants, members, isSpeaking,
} from "../lib/store";
import {
  createSortable,
  transformStyle,
} from "@thisbeyond/solid-dnd";

const ICON_SIZE = 18;
const FALLBACK_NAME_LEN = 8;

// Mute, deafen, end-call buttons for the activity bar dock
export function VoiceDock() {
  return (
    <>
      <DockButton
        active={isMuted()}
        label={isMuted() ? "unmute" : "mute"}
        onClick={toggleMute}
        activeIcon={<MicOff size={ICON_SIZE} class="text-[var(--amber-400)]" />}
        inactiveIcon={<Mic size={ICON_SIZE} class="text-[var(--neutral-300)]" />}
        hoverReveal
      />
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
    </button>
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
                "text-sm truncate",
                speaking() ? "text-[var(--neutral-100)]" : "text-[var(--neutral-400)]",
              )}>
                {name()}
              </span>
            </div>
          );
        }}
      </For>
    </div>
  );
}
