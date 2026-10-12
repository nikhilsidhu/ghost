import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type {
  Identity, Server, Channel, Member, Message, VoiceState, CallPhase, MediaPath, VoiceParticipants, VoiceSpeaking, VoiceMuteState, VoiceQuality,
  OnlinePresenceEvent, ServerRoles, VoiceChannelMembers, VoiceChannelMember, OnlineStatus, PresenceStatus, Connectivity,
  LiveState, Invite, ChannelWaiting,
} from "./types";
import {
  getIdentity, listServers, listChannels, listMembers, getServerRoles,
  markChannelRead, forgetServer as forgetServerCommand,
  joinVoice, leaveVoice, setVoiceMuted, setVoiceDeafened,
  getConfig,
  getCachedAvatar,
} from "./api";
import { liveState, noteActivity } from "./api";
import { applyAlertsSnapshot, listenForAccountAlerts } from "./alerts";
import { initKeybinds, onPttActiveChange, setInputMode as setKeybindInputMode } from "./keybinds";
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
// Roles of the selected server, for role names and permission checks in the UI
const [serverRoles, setServerRoles] = createSignal<ServerRoles | null>(null);
const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
const [allChannels, setAllChannels] = createSignal<Channel[]>([]);
/** Members of every server, for contacts; fetched when first wanted, again after a change. */
const [allMembers, setAllMembers] = createSignal<Member[]>([]);
let contactsStale = true;
let contactsLoading: Promise<void> | null = null;

// --- UI ---

/** The invite just made, shown with its link and when it ends. */
const [invite, setInvite] = createSignal<Invite | null>(null);
/** Private channels whose messages wait for a change to their server's group. */
const [waitingChannels, setWaitingChannels] = createSignal<Set<string>>(new Set());

const applyChannelWaiting = (event: ChannelWaiting) =>
  setWaitingChannels((prev) => {
    const next = new Set(prev);
    if (event.waiting) next.add(event.channel_id);
    else next.delete(event.channel_id);
    return next;
  });
/** Link a server's creator shares after moving it to another relay. */
const [moveLink, setMoveLink] = createSignal<string | null>(null);
const [showInfo, setShowInfo] = createSignal(false);
const [desiredChannelKind, setDesiredChannelKind] = createSignal<string>("text");
const [settingsOpen, setSettingsOpen] = createSignal(false);
const [settingsCategory, setSettingsCategory] = createSignal("");
const [dmViewActive, setDmViewActive] = createSignal(false);
const [profileOpen, setProfileOpen] = createSignal(false);
const toggleProfile = () => setProfileOpen((v) => !v);
const NO_CONNECTIVITY: Connectivity = { home: false, any: false, relays_down: [], relays_refusing: [], catching_up: false };
const [connectivity, setConnectivity] = createSignal<Connectivity>(NO_CONNECTIVITY);
const relayConnected = () => connectivity().any;
const INVISIBLE: OnlineStatus = "invisible";
const [ownStatus, setOwnStatus] = createSignal<OnlineStatus>("online");
const [ownStatusMessage, setOwnStatusMessage] = createSignal<string>("");
const [selectedExpiry, setSelectedExpiry] = createSignal<number>(0);
const [expiresAt, setExpiresAt] = createSignal<number | null>(null);
const [autoMuted, setAutoMuted] = createSignal(false);
/** A member's presence as shown: their status, and this device's own as it chose it. */
interface ShownPresence {
  status: PresenceStatus | OnlineStatus;
  status_message: string | null;
}
const presenceByServer = new Map<string, Map<string, ShownPresence>>();
const [onlinePresence, setOnlinePresence] = createSignal<Map<string, ShownPresence>>(new Map());

// Avatar object URLs keyed by fingerprint, each revoked once replaced.
const [avatarUrls, setAvatarUrls] = createSignal<Map<string, string>>(new Map());
const avatarUrl = (fp: string) => avatarUrls().get(fp);
const loadAvatar = async (fp: string) => {
  const bytes = await getCachedAvatar(fp).catch(() => new ArrayBuffer(0));
  setAvatarUrls((prev) => {
    const next = new Map(prev);
    const previous = next.get(fp);
    if (previous) URL.revokeObjectURL(previous);
    if (bytes.byteLength > 0) next.set(fp, URL.createObjectURL(new Blob([bytes])));
    else next.delete(fp);
    return next;
  });
};

const rebuildPresence = () => {
  const flat = new Map<string, ShownPresence>();
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
/** Where this device's call stands: joining, live or reconnecting. */
const [voicePhase, setVoicePhase] = createSignal<CallPhase | null>(null);
/** Whether the call's media reaches the voice server. */
const [voiceMediaPath, setVoiceMediaPath] = createSignal<MediaPath | null>(null);
const [isMuted, setIsMuted] = createSignal(false);
const [isDeafened, setIsDeafened] = createSignal(false);
const [voiceParticipants, setVoiceParticipants] = createSignal<string[]>([]);
const [speakingSet, setSpeakingSet] = createSignal<Set<string>>(new Set());
/** A voice failure or notice and the channel it concerns, shown under that channel for a while. */
const [voiceError, setVoiceError] = createSignal<{ channelId: string; message: string; notice: boolean } | null>(null);
/** How long a voice failure or notice stays shown. */
const VOICE_ERROR_MS = 5000;
/** The channel last asked to join, which a failure reported later concerns. */
let voiceAttempt: string | null = null;
let voiceErrorTimer: ReturnType<typeof setTimeout> | undefined;
const showVoiceError = (message: string, notice = false) => {
  const channelId = voiceAttempt ?? voiceChannelId();
  if (!channelId) return;
  clearTimeout(voiceErrorTimer);
  setVoiceError({ channelId, message, notice });
  voiceErrorTimer = setTimeout(() => setVoiceError(null), VOICE_ERROR_MS);
};
// Persists after disconnect so we can still show who's in the channel
const [voiceParticipantChannelId, setVoiceParticipantChannelId] = createSignal<string | null>(null);
// Per-participant mute/deafen state from relay
const [voiceMuteStates, setVoiceMuteStates] = createSignal<Map<string, { muted: boolean; deafened: boolean }>>(new Map());
// Call quality metrics from audio pipeline
const [voiceQuality, setVoiceQuality] = createSignal<VoiceQuality | null>(null);
// Per-channel voice members from mailbox WS (visible to all server members)
const [voiceChannelMembers, setVoiceChannelMembers] = createSignal<Map<string, VoiceChannelMember[]>>(new Map());

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
  voiceAttempt = channelId;
  setVoiceError(null);
  joinVoice(serverId, channelId, isMuted(), isDeafened()).catch((e) => showVoiceError(String(e)));
};

const isSpeaking = (fingerprint: string) => speakingSet().has(fingerprint);
const isInVoiceChannel = (channelId: string) => voiceChannelId() === channelId;

// --- Derived ---

const selectedServer = () => servers().find((s) => s.server_id === selectedServerId());
const selectedChannelName = () => channels().find((c) => c.channel_id === selectedChannelId())?.name ?? "";
const dms = () => servers().filter((s) => s.kind === "dm" || s.kind === "group");
const serverList = () => servers().filter((s) => s.kind === "server");

/** Fetch the members of every server for `contacts`, unless they are current. */
const loadContacts = (): Promise<void> => {
  if (!contactsStale) return Promise.resolve();
  if (contactsLoading) return contactsLoading;
  contactsLoading = (async () => {
    const results = await Promise.all(servers().map((s) => listMembers(s.server_id).catch(() => [] as Member[])));
    setAllMembers(results.flat());
    contactsStale = false;
  })().finally(() => {
    contactsLoading = null;
  });
  return contactsLoading;
};

/** Contacts are fetched again the next time they are wanted. */
const invalidateContacts = () => {
  contactsStale = true;
};

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

const refreshRoles = async () => {
  const sid = selectedServerId();
  if (!sid) { setServerRoles(null); return; }
  const roles = await getServerRoles(sid).catch(() => null);
  if (selectedServerId() === sid) setServerRoles(roles);
};

const refreshMembers = async () => {
  const sid = selectedServerId();
  if (!sid) return;
  setMembers(await listMembers(sid));
  await refreshRoles();
};

// --- Actions ---

/** Forget a server this account was removed from or stopped following, with its history, closing it if open. */
const forgetServer = async (id: string) => {
  await forgetServerCommand(id);
  if (selectedServerId() === id) {
    setSelectedServerId(null);
    setSelectedChannelId(null);
    setChannels([]);
    setMembers([]);
  }
  await refreshServers();
};

const selectServer = async (id: string | null) => {
  setDmViewActive(false);
  setSelectedServerId(id);
  setSelectedChannelId(null);
  if (!id) { setChannels([]); setMembers([]); return; }
  const [ch, mem] = await Promise.all([listChannels(id), listMembers(id)]);
  if (selectedServerId() !== id) return;
  setChannels(ch);
  setMembers(mem);
  await refreshRoles();
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


const applyRelayConnectivity = (c: Connectivity) => {
  setConnectivity(c);
  if (c.any) rebuildPresence();
};

const applyVoiceChannelMembers = ({ channel_id, members }: VoiceChannelMembers) => {
  setVoiceChannelMembers(prev => {
    const next = new Map(prev);
    if (members.length === 0) next.delete(channel_id);
    else next.set(channel_id, members);
    return next;
  });
};

const applyOnlinePresence = ({ server_id, members }: OnlinePresenceEvent) => {
  const serverMap = new Map<string, ShownPresence>();
  for (const member of members) {
    serverMap.set(member.fingerprint, { status: member.status, status_message: member.status_message });
    // Load avatar for members that have one cached but not yet loaded
    if (member.avatar_hash && !avatarUrl(member.fingerprint)) {
      loadAvatar(member.fingerprint);
    }
  }
  presenceByServer.set(server_id, serverMap);
  rebuildPresence();
};

const applyVoiceState = (s: VoiceState) => {
  setVoiceConnected(s.connected);
  setVoiceServerId(s.server_id);
  setVoiceChannelId(s.channel_id);
  setVoicePhase(s.phase);
  setVoiceMediaPath(s.media_path);
  setIsMuted(s.muted);
  setIsDeafened(s.deafened);
  if (s.channel_id) setVoiceParticipantChannelId(s.channel_id);
  const selfFp = identity()?.fingerprint;
  if (s.connected) {
    // Update self mute state in the per-participant map
    if (selfFp) {
      setVoiceMuteStates(prev => {
        const next = new Map(prev);
        next.set(selfFp, { muted: s.muted, deafened: s.deafened });
        return next;
      });
    }
  } else {
    // Remove self from participants but keep others visible
    if (selfFp) setVoiceParticipants(prev => prev.filter(fp => fp !== selfFp));
    setSpeakingSet(new Set<string>());
    setVoiceQuality(null);
  }
};

/** Show the session as the snapshot has it, rosters replaced whole. */
const applyLiveState = (live: LiveState) => {
  presenceByServer.clear();
  setVoiceChannelMembers(new Map());
  applyRelayConnectivity(live.connectivity);
  for (const event of live.online) applyOnlinePresence(event);
  for (const event of live.voice) applyVoiceChannelMembers(event);
  if (live.voice_state) applyVoiceState(live.voice_state);
  setWaitingChannels(new Set(live.waiting_channels));
  setOwnStatus(live.status);
  rebuildPresence();
  applyAlertsSnapshot(live);
};

let listeningForLiveState = false;

/** Listen for everything the session only reports as events, then read the snapshot of
 * what it reported before: once, at start, so nothing falls between the two. A new
 * session (after a relay change) resets the snapshot. */
const listenForLiveState = () => {
  if (listeningForLiveState) return;
  listeningForLiveState = true;
  listenForAccountAlerts();
  listen<Connectivity>("relay-connectivity", (event) => applyRelayConnectivity(event.payload));
  listen<OnlinePresenceEvent>("online-presence", (event) => applyOnlinePresence(event.payload));
  listen<VoiceChannelMembers>("voice-channel-members", (event) => applyVoiceChannelMembers(event.payload));
  listen<VoiceState>("voice-state", (event) => applyVoiceState(event.payload));
  listen<ChannelWaiting>("channel-waiting", (event) => applyChannelWaiting(event.payload));
  listen<OnlineStatus>("idle-transition", (event) => {
    setOwnStatus(event.payload);
    rebuildPresence();
  });
  const readSnapshot = () => liveState().then(applyLiveState).catch(() => {});
  listen("live-reset", () => {
    setConnectivity(NO_CONNECTIVITY);
    readSnapshot();
  });
  readSnapshot();
};

const initialize = async () => {
  await updateIdentity();
  await refreshServers();
  await refreshAllChannels();

  // A server changed, or the server list did. Only what is on screen is fetched again;
  // contacts are fetched when next wanted.
  listen<string>("sync", (event) => {
    const sid = event.payload;
    invalidateContacts();
    refreshServers();
    if (sid === "all") {
      refreshAllChannels();
    } else if (sid === selectedServerId()) {
      refreshChannels();
      refreshMembers();
    }
  });

  listen<string>("display-name-sync", () => {
    updateIdentity();
    refreshMembers();
    invalidateContacts();
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


  // A server this account was removed from stays, read-only, with who removed it.
  listen<string>("kicked", () => {
    refreshServers();
    refreshAllChannels();
    invalidateContacts();
  });

  // Acting in this window ends idle at once; the idle task alone notices at its next poll.
  const noteActivityIfIdle = () => {
    if (ownStatus() === "idle") noteActivity().catch(() => {});
  };
  window.addEventListener("focus", noteActivityIfIdle);
  document.addEventListener("pointerdown", noteActivityIfIdle);
  document.addEventListener("keydown", noteActivityIfIdle);

  listen<string>("voice-error", (event) => {
    console.error("voice:", event.payload);
    showVoiceError(event.payload);
  });

  listen<string>("voice-notice", (event) => {
    console.warn("voice:", event.payload);
    showVoiceError(event.payload, true);
  });

  onPttActiveChange((active) => setIsPttKeyHeld(active));
  initKeybinds().catch((e) => console.error("keybinds init failed:", e));
  getConfig().then((c) => {
    setIsPttMode(c.input_mode === "push_to_talk");
    if (c.status_message) setOwnStatusMessage(c.status_message);
    setExpiresAt(c.status_expiry);
    rebuildPresence();
  }).catch(() => {});

  // Another device of the account chose a status or a status message: the session
  // already announces it; show it here too.
  listen("sync-status", () => {
    getConfig().then((c) => {
      setOwnStatus(c.status);
      setOwnStatusMessage(c.status_message ?? "");
      setExpiresAt(c.status_expiry);
      if (!c.status_message) setSelectedExpiry(0);
      rebuildPresence();
    }).catch(() => {});
  });

  // An audio setting came from another device; the settings page refreshes itself.
  listen<string>("sync-pref", (event) => {
    if (event.payload !== "input_mode") return;
    getConfig().then((c) => {
      setIsPttMode(c.input_mode === "push_to_talk");
      setKeybindInputMode(c.input_mode);
    }).catch(() => {});
  });

  // Whether the call's mute is the one going idle applied; the mute itself follows
  // `voice-state`.
  listen<boolean>("auto-muted", (event) => setAutoMuted(event.payload));

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
  identity, servers, selectedServerId, channels, members, serverRoles, refreshRoles,
  selectedChannelId, allChannels,
  invite, moveLink, showInfo, desiredChannelKind, waitingChannels,
  selectedServer, selectedChannelName,
  dmViewActive, dms, serverList, contacts, loadContacts, invalidateContacts,
  selectServer, selectChannel, selectDm, activateDmView, forgetServer,
  updateIdentity, initialize, listenForLiveState,
  refreshServers, refreshChannels, refreshAllChannels,
  setInvite, setMoveLink, setShowInfo, setDesiredChannelKind,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  profileOpen, setProfileOpen, toggleProfile, relayConnected, connectivity, onlinePresence,
  INVISIBLE, ownStatus, setOwnStatus, ownStatusMessage, setOwnStatusMessage, selectedExpiry, setSelectedExpiry, expiresAt, setExpiresAt, rebuildPresence, autoMuted, setAutoMuted,
  isInCall, isMuted, isDeafened, isPttMode, setIsPttMode, isPttKeyHeld, pttMuteAttempt, toggleMute, toggleDeafen, endCall,
  voiceChannelId, voiceServerId, voicePhase, voiceMediaPath, voiceParticipants, speakingSet, voiceError,
  joinVoiceChannel, isSpeaking, isInVoiceChannel,
  voiceParticipantChannelId, voiceMuteStates, voiceQuality,
  voiceChannelMembers,
  avatarUrl, loadAvatar,
};
