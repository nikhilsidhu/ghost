import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Identity, Group, Channel, Member, Message, VoiceState, VoiceParticipants, VoiceSpeaking, VoiceMuteState, VoiceQuality } from "./types";
import {
  getIdentity, listGroups, listChannels, listMembers,
  listPinnedGroups, markChannelRead, seedTestData,
  joinVoice, leaveVoice, setVoiceMuted, setVoiceDeafened,
  createDevSession, readDevSession, joinByInvite, getConfig,
} from "./api";
import { initKeybinds, onPttActiveChange } from "./keybinds";
import { sections } from "./settings-registry";

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
const [settingsCategory, setSettingsCategory] = createSignal("");

const toggleSettings = () => {
  const opening = !settingsOpen();
  setSettingsOpen(opening);
  if (opening) setSettingsCategory(sections()[0]?.id ?? "");
};

// --- Voice state (driven by backend events) ---

const [voiceConnected, setVoiceConnected] = createSignal(false);
const [voiceGroupId, setVoiceGroupId] = createSignal<string | null>(null);
const [voiceChannelId, setVoiceChannelId] = createSignal<string | null>(null);
const [isMuted, setIsMuted] = createSignal(false);
const [isDeafened, setIsDeafened] = createSignal(false);
const [voiceParticipants, setVoiceParticipants] = createSignal<string[]>([]);
const [speakingSet, setSpeakingSet] = createSignal<Set<string>>(new Set());
const [voiceError, setVoiceError] = createSignal<string | null>(null);
// Persists after disconnect so we can still show who's in the channel
const [voiceParticipantChannelId, setVoiceParticipantChannelId] = createSignal<string | null>(null);
// Per-participant mute/deafen state from relay
const [voiceMuteStates, setVoiceMuteStates] = createSignal<Map<string, { muted: boolean; deafened: boolean }>>(new Map());
// Call quality metrics from audio pipeline
const [voiceQuality, setVoiceQuality] = createSignal<VoiceQuality | null>(null);

const isInCall = voiceConnected;
const [isPttMode, setIsPttMode] = createSignal(false);
const [isPttKeyHeld, setIsPttKeyHeld] = createSignal(false);
// Bumped to trigger shake animation when user clicks mute in PTT mode
const [pttMuteAttempt, setPttMuteAttempt] = createSignal(0);

const toggleMute = () => {
  if (isPttMode()) {
    setPttMuteAttempt((n) => n + 1);
    return;
  }
  setVoiceMuted(!isMuted()).catch(() => {});
};
const toggleDeafen = () => { setVoiceDeafened(!isDeafened()).catch(() => {}); };
const endCall = () => { leaveVoice().catch(() => {}); };

const joinVoiceChannel = (groupId: string, channelId: string) => {
  joinVoice(groupId, channelId).catch(() => {});
};

const isSpeaking = (fingerprint: string) => speakingSet().has(fingerprint);
const isInVoiceChannel = (channelId: string) => voiceChannelId() === channelId;

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

const refreshMembers = async () => {
  const gid = selectedGroupId();
  if (!gid) return;
  setMembers(await listMembers(gid));
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

const startDevSession = async () => {
  const group = await createDevSession();
  await refreshGroups();
  await selectGroup(group.group_id);
};

// Poll for a dev session file and auto-join if this instance has no groups yet
const tryDevJoin = async (): Promise<boolean> => {
  if (groups().length > 0) return true;
  const session = await readDevSession();
  if (!session) return false;
  try {
    const group = await joinByInvite(session.relay_url, session.token);
    await refreshGroups();
    await selectGroup(group.group_id);
    return true;
  } catch {
    return false;
  }
};

const initialize = async () => {
  await updateIdentity();
  await refreshGroups();
  await refreshPins();
  await refreshAllChannels();

  listen<string>("sync", (event) => {
    const gid = event.payload;
    if (gid === selectedGroupId()) {
      refreshChannels();
      refreshMembers();
    }
    refreshGroups();
  });

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

  listen<VoiceState>("voice-state", (event) => {
    const s = event.payload;
    setVoiceConnected(s.connected);
    setVoiceGroupId(s.group_id);
    setVoiceChannelId(s.channel_id);
    setIsMuted(s.muted);
    setIsDeafened(s.deafened);
    if (s.channel_id) setVoiceParticipantChannelId(s.channel_id);
    if (s.connected) {
      // Update self mute state in the per-participant map
      const selfFp = identity()?.fingerprint;
      if (selfFp) {
        setVoiceMuteStates(prev => {
          const next = new Map(prev);
          next.set(selfFp, { muted: s.muted, deafened: s.deafened });
          return next;
        });
      }
    } else {
      // Remove self from participants but keep others visible
      const selfFp = identity()?.fingerprint;
      if (selfFp) setVoiceParticipants(prev => prev.filter(fp => fp !== selfFp));
      setSpeakingSet(new Set<string>());
      setVoiceQuality(null);
    }
  });

  listen<VoiceParticipants>("voice-participants", (event) => {
    setVoiceParticipants(event.payload.participants);
  });

  listen<VoiceSpeaking>("voice-speaking", (event) => {
    const { fingerprint, speaking } = event.payload;
    setSpeakingSet((prev) => {
      const next = new Set(prev);
      if (speaking) next.add(fingerprint); else next.delete(fingerprint);
      return next;
    });
  });

  listen<VoiceMuteState>("voice-mute-state", (event) => {
    const { fingerprint, muted, deafened } = event.payload;
    setVoiceMuteStates(prev => {
      const next = new Map(prev);
      next.set(fingerprint, { muted, deafened });
      return next;
    });
  });

  listen<VoiceQuality>("voice-quality", (event) => {
    setVoiceQuality(event.payload);
  });

  listen<string>("voice-error", (event) => {
    console.error("voice:", event.payload);
    setVoiceError(event.payload);
    setTimeout(() => setVoiceError(null), 5000);
  });

  onPttActiveChange((active) => setIsPttKeyHeld(active));
  initKeybinds().catch((e) => console.error("keybinds init failed:", e));
  getConfig().then((c) => setIsPttMode(c.input_mode === "push_to_talk")).catch(() => {});

  // Dev mode: poll for a dev session file and auto-join
  if (import.meta.env.DEV) {
    const joined = await tryDevJoin();
    if (!joined) {
      const interval = setInterval(async () => {
        if (await tryDevJoin()) clearInterval(interval);
      }, 3000);
    }
  }
};

export {
  identity, groups, selectedGroupId, channels, members,
  pinnedGroupIds, selectedChannelId, allChannels,
  inviteLink, showInfo, desiredChannelKind,
  selectedGroup, selectedChannelName,
  selectGroup, selectChannel, updateIdentity, initialize, seedAndRefresh, startDevSession,
  refreshGroups, refreshChannels, refreshPins, refreshAllChannels,
  setInviteLink, setShowInfo, setDesiredChannelKind,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  isInCall, isMuted, isDeafened, isPttMode, setIsPttMode, isPttKeyHeld, pttMuteAttempt, toggleMute, toggleDeafen, endCall,
  voiceChannelId, voiceGroupId, voiceParticipants, speakingSet, voiceError,
  joinVoiceChannel, isSpeaking, isInVoiceChannel,
  voiceParticipantChannelId, voiceMuteStates, voiceQuality,
};
