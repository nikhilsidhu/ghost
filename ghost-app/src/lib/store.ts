import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Identity, Group, Channel, Member, Message } from "./types";
import {
  getIdentity, listGroups, listChannels, listMembers,
  listPinnedGroups, markChannelRead, seedTestData,
} from "./api";

// Backend settings (relay URL, display name) live in ~/.ghost/config.toml.
const SETTING_PREFIX = "ghost:";

export function createSetting<T>(key: string, defaultValue: T): [() => T, (v: T) => void] {
  const stored = localStorage.getItem(SETTING_PREFIX + key);
  const initial: T = stored !== null ? JSON.parse(stored) : defaultValue;
  const [value, setValue] = createSignal<T>(initial);
  const set = (v: T) => {
    setValue(() => v);
    localStorage.setItem(SETTING_PREFIX + key, JSON.stringify(v));
  };
  return [value, set];
}

// --- Data ---

const [identity, setIdentity] = createSignal<Identity | null>(null);
const [groups, setGroups] = createSignal<Group[]>([]);
const [selectedGroupId, setSelectedGroupId] = createSignal<string | null>(null);
const [channels, setChannels] = createSignal<Channel[]>([]);
const [members, setMembers] = createSignal<Member[]>([]);
const [pinnedGroupIds, setPinnedGroupIds] = createSignal<Set<string>>(new Set());
const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
const [allChannels, setAllChannels] = createSignal<Channel[]>([]);

// --- UI ---

const [inviteLink, setInviteLink] = createSignal<string | null>(null);
const [showInfo, setShowInfo] = createSignal(false);
const [desiredChannelKind, setDesiredChannelKind] = createSignal<string>("text");
const [settingsOpen, setSettingsOpen] = createSignal(false);
const [settingsCategory, setSettingsCategory] = createSignal("appearance");

const toggleSettings = () => {
  const opening = !settingsOpen();
  setSettingsOpen(opening);
  if (opening) setSettingsCategory("appearance");
};

// --- Call state ---

const [isInCall, setIsInCall] = createSignal(false);
const [isMuted, setIsMuted] = createSignal(false);
const [isDeafened, setIsDeafened] = createSignal(false);

const toggleMute = () => { setIsMuted((v) => !v); setIsDeafened(false); };
const toggleDeafen = () => { setIsDeafened((v) => !v); setIsMuted(false); };
const endCall = () => { setIsInCall(false); setIsMuted(false); setIsDeafened(false); };

// --- Derived ---

const selectedGroup = () => groups().find((g) => g.group_id === selectedGroupId());
const selectedChannelName = () => channels().find((c) => c.channel_id === selectedChannelId())?.name ?? "";

// --- Refresh helpers ---

const refreshGroups = async () => {
  setGroups(await listGroups());
};

const refreshAllChannels = async () => {
  const gs = groups();
  if (gs.length === 0) { setAllChannels([]); return; }
  const results = await Promise.all(gs.map((g) => listChannels(g.group_id)));
  setAllChannels(results.flat());
};

const refreshChannels = async () => {
  const gid = selectedGroupId();
  if (!gid) { setChannels([]); return; }
  const ch = await listChannels(gid);
  setChannels(ch);
  setAllChannels((prev) => [...prev.filter((c) => c.group_id !== gid), ...ch]);
};

const refreshPins = async () => {
  setPinnedGroupIds(new Set(await listPinnedGroups()));
};

// --- Actions ---

const selectGroup = async (id: string | null) => {
  setSelectedGroupId(id);
  setSelectedChannelId(null);
  if (!id) { setChannels([]); setMembers([]); return; }
  const [ch, mem] = await Promise.all([listChannels(id), listMembers(id)]);
  if (selectedGroupId() !== id) return;
  setChannels(ch);
  setMembers(mem);
};

const selectChannel = (id: string) => {
  setSelectedChannelId(id);
  setChannels((prev) => {
    const updated = prev.map((c) =>
      c.channel_id === id ? { ...c, unread_count: 0 } : c
    );
    if (!updated.some((c) => c.unread_count > 0)) {
      const gid = selectedGroupId();
      if (gid) {
        setGroups((gs) => gs.map((g) =>
          g.group_id === gid ? { ...g, has_unread: false } : g
        ));
      }
    }
    return updated;
  });
  markChannelRead(id).catch(() => {});
};

const updateIdentity = async () => {
  setIdentity(await getIdentity());
};

const seedAndRefresh = async () => {
  await seedTestData();
  await refreshGroups();
  await refreshPins();
};

const initialize = async () => {
  await updateIdentity();
  await refreshGroups();
  await refreshPins();
  await refreshAllChannels();

  listen<Message>("message", (event) => {
    const msg = event.payload;
    if (msg.channel_id === selectedChannelId()) return;
    const inCurrentGroup = channels().some((c) => c.channel_id === msg.channel_id);
    if (inCurrentGroup) {
      setChannels((prev) => prev.map((c) =>
        c.channel_id === msg.channel_id ? { ...c, unread_count: c.unread_count + 1 } : c
      ));
    } else {
      refreshGroups();
    }
  });
};

export {
  identity, groups, selectedGroupId, channels, members,
  pinnedGroupIds, selectedChannelId, allChannels,
  inviteLink, showInfo, desiredChannelKind,
  selectedGroup, selectedChannelName,
  selectGroup, selectChannel, updateIdentity, initialize, seedAndRefresh,
  refreshGroups, refreshChannels, refreshPins, refreshAllChannels,
  setInviteLink, setShowInfo, setDesiredChannelKind,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  isInCall, isMuted, isDeafened, toggleMute, toggleDeafen, endCall, setIsInCall,
};
