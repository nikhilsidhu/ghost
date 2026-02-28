import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Identity, Server, Channel, Member, Message, VoiceState, VoiceParticipants, VoiceSpeaking, VoiceMuteState, VoiceQuality, OnlinePresenceEvent } from "./types";
import {
  getIdentity, listServers, listChannels, listMembers,
  markChannelRead,
  joinVoice, leaveVoice, setVoiceMuted, setVoiceDeafened,
  getConfig,
  getCachedAvatar,
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
const [servers, setServers] = createSignal<Server[]>([]);
const [selectedServerId, setSelectedServerId] = createSignal<string | null>(null);
const [channels, setChannels] = createSignal<Channel[]>([]);
const [members, setMembers] = createSignal<Member[]>([]);
const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
const [allChannels, setAllChannels] = createSignal<Channel[]>([]);
const [allMembers, setAllMembers] = createSignal<Member[]>([]);

// --- UI ---

const [inviteLink, setInviteLink] = createSignal<string | null>(null);
const [showInfo, setShowInfo] = createSignal(false);
const [desiredChannelKind, setDesiredChannelKind] = createSignal<string>("text");
const [settingsOpen, setSettingsOpen] = createSignal(false);
const [settingsCategory, setSettingsCategory] = createSignal("");
const [dmViewActive, setDmViewActive] = createSignal(false);
const [profileOpen, setProfileOpen] = createSignal(false);
const toggleProfile = () => setProfileOpen((v) => !v);
const [relayConnected, setRelayConnected] = createSignal(false);
const INVISIBLE = "invisible" as const;
const [ownStatus, setOwnStatus] = createSignal<string>("online");
const [ownStatusMessage, setOwnStatusMessage] = createSignal<string>("");
const [selectedExpiry, setSelectedExpiry] = createSignal<number>(0);
const [expiresAt, setExpiresAt] = createSignal<number | null>(null);
const [autoMuted, setAutoMuted] = createSignal(false);
const presenceByServer = new Map<string, Map<string, { status: string; status_message: string | null }>>();
const [onlinePresence, setOnlinePresence] = createSignal<Map<string, { status: string; status_message: string | null }>>(new Map());

// Avatar data URLs keyed by fingerprint
const [avatarUrls, setAvatarUrls] = createSignal<Map<string, string>>(new Map());
const avatarUrl = (fp: string) => avatarUrls().get(fp);
const loadAvatar = async (fp: string) => {
  const dataUrl = await getCachedAvatar(fp).catch(() => null);
  setAvatarUrls(prev => {
    const next = new Map(prev);
    if (dataUrl) { next.set(fp, dataUrl); } else { next.delete(fp); }
    return next;
  });
};

const rebuildPresence = () => {
  const flat = new Map<string, { status: string; status_message: string | null }>();
  for (const [, smap] of presenceByServer) {
    for (const [fp, info] of smap) flat.set(fp, info);
  }
  const fp = identity()?.fingerprint;
  if (fp && ownStatus() !== INVISIBLE) {
    flat.set(fp, { status: ownStatus(), status_message: ownStatusMessage() || null });
  } else if (fp) {
    flat.delete(fp);
  }
  setOnlinePresence(flat);
};

const toggleSettings = () => {
  const opening = !settingsOpen();
  setSettingsOpen(opening);
  if (opening) setSettingsCategory(sections()[0]?.id ?? "");
};

// --- Voice state (driven by backend events) ---

const [voiceConnected, setVoiceConnected] = createSignal(false);
const [voiceServerId, setVoiceServerId] = createSignal<string | null>(null);
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
// Per-channel voice members from mailbox WS (visible to all server members)
const [voiceChannelMembers, setVoiceChannelMembers] = createSignal<Map<string, Array<{ fingerprint: string; muted: boolean; deafened: boolean }>>>(new Map());

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
  const next = !isMuted();
  setIsMuted(next);
  if (voiceConnected()) setVoiceMuted(next).catch(() => {});
};
const toggleDeafen = () => {
  const next = !isDeafened();
  setIsDeafened(next);
  if (voiceConnected()) setVoiceDeafened(next).catch(() => {});
};
const endCall = () => { leaveVoice().catch(() => {}); };

const joinVoiceChannel = (serverId: string, channelId: string) => {
  joinVoice(serverId, channelId, isMuted(), isDeafened()).catch(() => {});
};

const isSpeaking = (fingerprint: string) => speakingSet().has(fingerprint);
const isInVoiceChannel = (channelId: string) => voiceChannelId() === channelId;

// --- Derived ---

const selectedServer = () => servers().find((s) => s.server_id === selectedServerId());
const selectedChannelName = () => channels().find((c) => c.channel_id === selectedChannelId())?.name ?? "";
const dms = () => servers().filter((s) => s.kind === "dm" || s.kind === "group");
const serverList = () => servers().filter((s) => s.kind === "server");

// Known contacts: all members across servers, deduplicated, excluding self
const contacts = () => {
  const selfFp = identity()?.fingerprint;
  const seen = new Map<string, { fingerprint: string; display_name: string }>();
  for (const m of allMembers()) {
    if (m.fingerprint === selfFp) continue;
    if (!seen.has(m.fingerprint)) seen.set(m.fingerprint, { fingerprint: m.fingerprint, display_name: m.display_name });
  }
  return [...seen.values()];
};

// --- Refresh helpers ---

const refreshServers = async () => {
  setServers(await listServers());
};

const refreshAllChannels = async () => {
  const ss = servers();
  if (ss.length === 0) { setAllChannels([]); return; }
  const results = await Promise.all(ss.map((s) => listChannels(s.server_id)));
  setAllChannels(results.flat());
};

const refreshChannels = async () => {
  const sid = selectedServerId();
  if (!sid) { setChannels([]); return; }
  const ch = await listChannels(sid);
  setChannels(ch);
  setAllChannels((prev) => [...prev.filter((c) => c.server_id !== sid), ...ch]);
};

const refreshAllMembers = async () => {
  const ss = servers();
  if (ss.length === 0) { setAllMembers([]); return; }
  const results = await Promise.all(ss.map((s) => listMembers(s.server_id)));
  setAllMembers(results.flat());
};


const refreshMembers = async () => {
  const sid = selectedServerId();
  if (!sid) return;
  setMembers(await listMembers(sid));
};

// --- Actions ---

const selectServer = async (id: string | null) => {
  setDmViewActive(false);
  setSelectedServerId(id);
  setSelectedChannelId(null);
  if (!id) { setChannels([]); setMembers([]); return; }
  const [ch, mem] = await Promise.all([listChannels(id), listMembers(id)]);
  if (selectedServerId() !== id) return;
  setChannels(ch);
  setMembers(mem);
};

const activateDmView = () => {
  setDmViewActive(true);
  setSelectedServerId(null);
  setSelectedChannelId(null);
  setChannels([]);
  setMembers([]);
};

const selectDm = async (serverId: string) => {
  setDmViewActive(true);
  setSelectedServerId(serverId);
  setSelectedChannelId(null);
  const [ch, mem] = await Promise.all([listChannels(serverId), listMembers(serverId)]);
  if (selectedServerId() !== serverId) return;
  setChannels(ch);
  setMembers(mem);
  // Auto-select the single text channel
  const textCh = ch.find((c) => c.kind === "text");
  if (textCh) selectChannel(textCh.channel_id);
};

const selectChannel = (id: string) => {
  setSelectedChannelId(id);
  setChannels((prev) => {
    const updated = prev.map((c) =>
      c.channel_id === id ? { ...c, unread_count: 0 } : c
    );
    if (!updated.some((c) => c.unread_count > 0)) {
      const sid = selectedServerId();
      if (sid) {
        setServers((ss) => ss.map((s) =>
          s.server_id === sid ? { ...s, has_unread: false } : s
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


const initialize = async () => {
  await updateIdentity();
  await refreshServers();
  await refreshAllChannels();
  await refreshAllMembers();

  listen<string>("sync", (event) => {
    const sid = event.payload;
    if (sid === "all") {
      refreshServers();
      refreshAllChannels();
      refreshAllMembers();
      return;
    }
    if (sid === selectedServerId()) {
      refreshChannels();
      refreshMembers();
    }
    refreshServers();
    refreshAllMembers();
  });

  listen<string>("display-name-sync", () => {
    updateIdentity();
    refreshMembers();
    refreshAllMembers();
  });

  listen("sync-read-state", () => {
    refreshChannels();
    refreshServers();
  });

  listen<Message>("message", (event) => {
    const msg = event.payload;
    if (msg.channel_id === selectedChannelId()) return;
    const inCurrentServer = channels().some((c) => c.channel_id === msg.channel_id);
    if (inCurrentServer) {
      setChannels((prev) => prev.map((c) =>
        c.channel_id === msg.channel_id ? { ...c, unread_count: c.unread_count + 1 } : c
      ));
    } else {
      refreshServers();
    }
  });

  listen<VoiceState>("voice-state", (event) => {
    const s = event.payload;
    setVoiceConnected(s.connected);
    setVoiceServerId(s.server_id);
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

  listen<{ channel_id: string; members: Array<{ fingerprint: string; muted: boolean; deafened: boolean }> }>("voice-channel-members", (event) => {
    const { channel_id, members } = event.payload;
    setVoiceChannelMembers(prev => {
      const next = new Map(prev);
      if (members.length === 0) next.delete(channel_id);
      else next.set(channel_id, members);
      return next;
    });
  });

  listen<string>("voice-takeover", (event) => {
    const channelId = event.payload;
    if (voiceChannelId() === channelId) {
      leaveVoice().catch(() => {});
    }
  });

  listen<string>("kicked", (event) => {
    const sid = event.payload;
    if (selectedServerId() === sid) {
      setSelectedServerId(null);
      setSelectedChannelId(null);
      setChannels([]);
      setMembers([]);
    }
    refreshServers();
    refreshAllChannels();
    refreshAllMembers();
  });

  listen<boolean>("relay-connectivity", (event) => {
    setRelayConnected(event.payload);
    if (event.payload) rebuildPresence();
  });

  listen<OnlinePresenceEvent>("online-presence", (event) => {
    const { server_id, members } = event.payload;
    const serverMap = new Map<string, { status: string; status_message: string | null }>();
    for (const member of members) {
      serverMap.set(member.fingerprint, { status: member.status, status_message: member.status_message });
      // Load avatar for members that have one cached but not yet loaded
      if (member.avatar_hash && !avatarUrl(member.fingerprint)) {
        loadAvatar(member.fingerprint);
      }
    }
    presenceByServer.set(server_id, serverMap);
    rebuildPresence();
  });

  listen<string>("voice-error", (event) => {
    console.error("voice:", event.payload);
    setVoiceError(event.payload);
    setTimeout(() => setVoiceError(null), 5000);
  });

  onPttActiveChange((active) => setIsPttKeyHeld(active));
  initKeybinds().catch((e) => console.error("keybinds init failed:", e));
  getConfig().then((c) => {
    setIsPttMode(c.input_mode === "push_to_talk");
    if (c.status) setOwnStatus(c.status);
    if (c.status_message) setOwnStatusMessage(c.status_message);
    rebuildPresence();
  }).catch(() => {});

  listen<string>("idle-transition", (event) => {
    setOwnStatus(event.payload);
    rebuildPresence();
  });

  listen<boolean>("auto-muted", () => {
    setIsMuted(true);
    setAutoMuted(true);
  });

  listen<string>("avatar-updated", (event) => {
    loadAvatar(event.payload);
  });

  listen<string>("avatar-cleared", (event) => {
    setAvatarUrls(prev => { const next = new Map(prev); next.delete(event.payload); return next; });
  });

  // Load own cached avatar
  const selfFpInit = identity()?.fingerprint;
  if (selfFpInit) loadAvatar(selfFpInit);

  listen("status-message-cleared", () => {
    setOwnStatusMessage("");
    setSelectedExpiry(0);
    setExpiresAt(null);
    rebuildPresence();
  });

};

export {
  identity, servers, selectedServerId, channels, members,
  selectedChannelId, allChannels,
  inviteLink, showInfo, desiredChannelKind,
  selectedServer, selectedChannelName,
  dmViewActive, dms, serverList, contacts,
  selectServer, selectChannel, selectDm, activateDmView,
  updateIdentity, initialize,
  refreshServers, refreshChannels, refreshAllChannels, refreshAllMembers,
  setInviteLink, setShowInfo, setDesiredChannelKind,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  profileOpen, setProfileOpen, toggleProfile, relayConnected, onlinePresence,
  INVISIBLE, ownStatus, setOwnStatus, ownStatusMessage, setOwnStatusMessage, selectedExpiry, setSelectedExpiry, expiresAt, setExpiresAt, rebuildPresence, autoMuted, setAutoMuted,
  isInCall, isMuted, isDeafened, isPttMode, setIsPttMode, isPttKeyHeld, pttMuteAttempt, toggleMute, toggleDeafen, endCall,
  voiceChannelId, voiceServerId, voiceParticipants, speakingSet, voiceError,
  joinVoiceChannel, isSpeaking, isInVoiceChannel,
  voiceParticipantChannelId, voiceMuteStates, voiceQuality,
  voiceChannelMembers,
  avatarUrl, loadAvatar,
};
