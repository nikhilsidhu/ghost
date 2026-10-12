// One profile's window as a blueprint opens it, drawn the way the app draws it: its
// servers down the side, the first server's channels with unread counts, the members with
// their roles, and notes on anything unusual about how it opens.

import { For, Show } from "solid-js";
import { CHANNEL_PREFIX } from "../lib/constants";
import { hashGradient } from "../lib/gradients";
import { cn } from "../lib/cn";
import type { Note } from "./generated/Note";
import type { Tone } from "./generated/Tone";
import type { WindowPreview as Window } from "./generated/WindowPreview";

/** Channels and members shown before the rest are summed up, so windows stay small. */
const MAX_CHANNELS = 7;
const MAX_MEMBERS = 5;

export const TONE_CLASS: Record<Tone, string> = {
  warn: "text-[var(--amber-400)] bg-[var(--amber-900)]",
  danger: "text-[var(--red-400)] bg-[var(--red-900)]",
  info: "text-[var(--violet-300)] bg-[var(--violet-900)]",
};

/** A note's label as a coloured flag. */
export function NoteFlag(props: { note: Note }) {
  return <span class={cn("text-[11px] font-medium px-1.5 rounded-sm whitespace-nowrap", TONE_CLASS[props.note.tone])}>{props.note.label}</span>;
}

/** A server or DM in the window's rail, coloured as the app colours it. */
function RailIcon(props: { name: string; dm?: boolean }) {
  const gradient = () => hashGradient(props.name);
  return (
    <span
      class="w-[18px] h-[18px] rounded-[5px] flex items-center justify-center text-[9px] text-[var(--neutral-50)] flex-shrink-0"
      style={{ background: props.dm ? "var(--neutral-600)" : `linear-gradient(${gradient().angle}deg, ${gradient().from}, ${gradient().to})` }}
      title={props.name}
    >
      {props.dm ? "dm" : props.name[0]}
    </span>
  );
}

export function WindowPreview(props: { window: Window }) {
  const server = () => props.window.servers[0];
  const channels = () => server()?.channels.slice(0, MAX_CHANNELS) ?? [];
  const moreChannels = () => (server()?.channels.length ?? 0) - channels().length;
  const members = () => server()?.members.slice(0, MAX_MEMBERS) ?? [];
  const moreMembers = () => (server()?.members.length ?? 0) - members().length;
  const empty = () => (props.window.dms.length ? "DMs only" : "no servers yet: create or join one");

  return (
    <div class="rounded-lg border border-[var(--neutral-600)] overflow-hidden bg-[var(--neutral-950)] flex flex-col min-w-0">
      <div class="h-[26px] flex items-center gap-1.5 px-2 bg-[var(--neutral-800)] text-[11px] text-[var(--neutral-400)]">
        <span class="flex gap-1 mr-1" aria-hidden="true">
          <i class="w-[7px] h-[7px] rounded-full bg-[var(--neutral-600)]" />
          <i class="w-[7px] h-[7px] rounded-full bg-[var(--neutral-600)]" />
          <i class="w-[7px] h-[7px] rounded-full bg-[var(--neutral-600)]" />
        </span>
        <span class="text-[var(--neutral-100)] font-medium">{props.window.profile}</span>
        <Show when={props.window.relay}>{(relay) => <span>home relay {relay()}</span>}</Show>
      </div>
      <div class="grid grid-cols-[26px_minmax(0,1fr)_100px] min-h-[150px]">
        <div class="border-r border-[var(--neutral-700)] py-1.5 flex flex-col items-center gap-1.5">
          <For each={props.window.servers}>{(s) => <RailIcon name={s.name} />}</For>
          <Show when={props.window.dms.length}>
            <RailIcon name="dm" dm />
          </Show>
        </div>
        <Show
          when={server()}
          fallback={<div class="col-span-2 px-2.5 py-3.5 text-[11px] text-[var(--neutral-500)]">{empty()}</div>}
        >
          {(s) => (
            <>
              <div class="px-2 py-1.5 flex flex-col text-[11px] min-w-0">
                <span class="text-[var(--neutral-100)] font-medium mb-0.5 truncate flex items-center gap-1.5">
                  {s().name}
                  <Show when={s().removed}>
                    <span class="text-[9px] font-normal text-[var(--red-400)]">read-only</span>
                  </Show>
                </span>
                <For each={channels()}>
                  {(channel) => (
                    <div class={cn("flex items-center gap-1.5 min-h-[18px]", channel.unread ? "text-[var(--neutral-100)] font-medium" : "text-[var(--neutral-300)]")}>
                      <span class="w-3 text-center text-[var(--neutral-500)]">{channel.voice ? CHANNEL_PREFIX.voice : CHANNEL_PREFIX.text}</span>
                      <span class="truncate">{channel.name}</span>
                      <Show when={channel.private}>
                        <span class="text-[9px] text-[var(--neutral-500)]">private</span>
                      </Show>
                      <Show when={channel.unread}>
                        <span class="ml-auto text-[9px] font-semibold text-[var(--neutral-50)] bg-[var(--purple-500)] rounded-full px-1.5">{channel.unread > 99 ? "99+" : channel.unread}</span>
                      </Show>
                    </div>
                  )}
                </For>
                <Show when={moreChannels() > 0}>
                  <span class="text-[var(--neutral-500)] min-h-[18px]">+{moreChannels()} more</span>
                </Show>
                <Show when={s().hidden_private}>
                  {(hidden) => <span class="text-[var(--neutral-500)] min-h-[18px]">{hidden()} private, not visible</span>}
                </Show>
              </div>
              <div class="border-l border-[var(--neutral-700)] px-1.5 py-1.5 flex flex-col gap-1 min-w-0">
                <span class="text-[10px] text-[var(--neutral-500)]">members — {s().members.length}</span>
                <For each={members()}>
                  {(member) => (
                    <div class="flex flex-col leading-tight min-w-0">
                      <span class="text-[11px] text-[var(--neutral-200)] truncate flex items-center gap-1">
                        {member.display}
                        <Show when={member.home_relay}>
                          {(relay) => (
                            <span class="text-[9px] text-[var(--neutral-400)] border border-[var(--neutral-600)] rounded-sm px-0.5" title={`home relay ${relay()}`}>
                              {relay()}
                            </span>
                          )}
                        </Show>
                      </span>
                      <Show when={member.role}>{(role) => <span class="text-[9px] text-[var(--purple-400)]">{role()}</span>}</Show>
                    </div>
                  )}
                </For>
                <Show when={moreMembers() > 0}>
                  <span class="text-[10px] text-[var(--neutral-500)]">+{moreMembers()} more</span>
                </Show>
              </div>
            </>
          )}
        </Show>
      </div>
      <Show when={props.window.notes.length}>
        <div class="px-2 py-1.5 border-t border-[var(--neutral-700)] flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-[var(--neutral-400)]">
          <For each={props.window.notes}>
            {(note) => (
              <span class="flex items-center gap-1.5">
                <NoteFlag note={note} />
                {note.detail}
              </span>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
