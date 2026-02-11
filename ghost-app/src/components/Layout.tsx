import { createSignal, createEffect, on, onMount, Show } from "solid-js";
import type { Identity, Group, Channel, Member } from "../lib/types";
import { getIdentity, listGroups, listChannels, listMembers } from "../lib/api";
import { Sidebar } from "./Sidebar";
import { GroupView } from "./GroupView";
import { MemberPanel } from "./MemberPanel";

export function Layout() {
  const [identity, setIdentity] = createSignal<Identity | null>(null);
  const [groups, setGroups] = createSignal<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = createSignal<string | null>(null);
  const [channels, setChannels] = createSignal<Channel[]>([]);
  const [members, setMembers] = createSignal<Member[]>([]);

  const refreshGroups = async () => {
    const gs = await listGroups();
    setGroups(gs);
  };

  onMount(async () => {
    const id = await getIdentity();
    setIdentity(id);
    await refreshGroups();
  });

  createEffect(on(selectedGroupId, async (id) => {
    if (!id) { setChannels([]); setMembers([]); return; }
    const [ch, mem] = await Promise.all([listChannels(id), listMembers(id)]);
    setChannels(ch);
    setMembers(mem);
  }));

  const selectedGroup = () => groups().find((g) => g.group_id === selectedGroupId());

  return (
    <div class="h-screen flex relative" style={{ background: "var(--neutral-950)" }}>
      <div class="absolute left-0 right-0 top-[84px] h-px bg-[var(--neutral-800)] z-10" />
      <Sidebar
        identity={identity()}
        groups={groups()}
        selectedGroupId={selectedGroupId()}
        onSelectGroup={setSelectedGroupId}
        onGroupCreated={refreshGroups}
      />
      <main class="flex-1 flex flex-col min-w-0">
        <div data-tauri-drag-region class="h-7 flex-shrink-0" />
        <Show
          when={selectedGroup()}
          fallback={
            <div class="flex-1 flex items-center justify-center">
              <span class="text-xs" style={{ color: "var(--neutral-500)" }}>
                select a group
              </span>
            </div>
          }
        >
          {(group) => <GroupView group={group()} channels={channels()} />}
        </Show>
      </main>
      <Show when={selectedGroup()}>
        <MemberPanel members={members()} />
      </Show>
    </div>
  );
}
