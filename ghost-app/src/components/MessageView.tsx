import { createSignal, createEffect, createMemo, on, onCleanup, For, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Message, MessageDelivery } from "../lib/types";
import { acceptRelayState, listMessages, retryMessage, sendMessage } from "../lib/api";
import { hashGradient } from "../lib/gradients";
import { Avatar } from "./ui/avatar";
import type { AvatarStatus } from "./ui/avatar";
import { cn } from "../lib/cn";
import { ChevronDown, SendHorizonal } from "lucide-solid";
import { selectedServerId, selectedChannelId, selectedServer, channels, members, settingsOpen, onlinePresence, forgetServer, refreshServers, waitingChannels } from "../lib/store";
import { MESSAGE_TYPES } from "../lib/types";
import { ConfirmButton } from "./ui/confirm-button";
import { slideDuration } from "../lib/constants";
import { sections } from "../lib/settings-registry";
import { showTimestamps } from "./settings/AppearanceSettings";
import { enterSends } from "./settings/MessagesSettings";

const PAGE_SIZE = 50;
const SCROLL_BOTTOM_THRESHOLD = 80;

const formatTime = (ts: number) => {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

/** Under a message the relay has not taken: that it is on its way, or that it was refused and can be retried. */
function DeliveryNote(props: { message: Message; onRetry: (messageId: string) => void }) {
  return (
    <Show when={props.message.delivery !== "delivered"}>
      <div class="text-xs mt-0.5" data-testid="delivery-note">
        <Show when={props.message.delivery === "pending"}>
          <span class="text-[var(--neutral-500)]">sending...</span>
        </Show>
        <Show when={props.message.delivery === "failed"}>
          <span class="text-[var(--red-400)]">not sent</span>
          <button
            class="ml-2 text-[var(--neutral-300)] hover:text-[var(--neutral-100)] cursor-pointer"
            onClick={() => props.onRetry(props.message.message_id)}
          >
            retry
          </button>
        </Show>
      </div>
    </Show>
  );
}

export function MessageView() {
  const [messages, setMessages] = createSignal<Message[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [hasMore, setHasMore] = createSignal(true);
  const [inputText, setInputText] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [nearBottom, setNearBottom] = createSignal(true);
  const seenIds = new Set<string>();
  let initialLoad = true;

  let containerRef!: HTMLDivElement;
  let inputRef!: HTMLInputElement;

  const senderMap = createMemo(() => {
    const m = new Map<string, string>();
    for (const member of members()) {
      m.set(member.fingerprint, member.display_name);
    }
    return m;
  });

  const scrollToBottom = () => {
    if (containerRef) containerRef.scrollTop = containerRef.scrollHeight;
  };

  const updateNearBottom = () => {
    if (!containerRef) return;
    const nb = containerRef.scrollHeight - containerRef.scrollTop - containerRef.clientHeight < SCROLL_BOTTOM_THRESHOLD;
    setNearBottom(nb);
  };

  const isGrouped = (msgs: Message[], idx: number) => {
    if (idx === 0) return false;
    return msgs[idx - 1].sender_fp === msgs[idx].sender_fp;
  };

  createEffect(on(selectedChannelId, (cid) => {
    if (!cid) return;
    setMessages([]);
    seenIds.clear();
    setHasMore(true);
    initialLoad = true;

    (async () => {
      const msgs = await listMessages(cid, undefined, PAGE_SIZE);
      const loaded = msgs.reverse();
      setMessages((prev) => {
        const loadedIds = new Set(loaded.map((m) => m.message_id));
        const arrived = prev.filter((m) => !loadedIds.has(m.message_id));
        const merged = [...loaded, ...arrived];
        for (const m of merged) seenIds.add(m.message_id);
        return merged;
      });
      setHasMore(msgs.length === PAGE_SIZE);
      requestAnimationFrame(() => {
        scrollToBottom();
        initialLoad = false;
      });
    })();

    const unlisten = listen<Message>("message", (event) => {
      const msg = event.payload;
      if (msg.channel_id !== cid) return;
      if (seenIds.has(msg.message_id)) return;
      seenIds.add(msg.message_id);
      setMessages((prev) => [...prev, msg]);
      if (nearBottom()) requestAnimationFrame(scrollToBottom);
    });
    // The relay took or refused one of our messages: it stops looking pending.
    const unlistenDelivery = listen<MessageDelivery>("message-delivery", (event) => {
      const { message_id, delivery } = event.payload;
      if (!seenIds.has(message_id)) return;
      setMessages((prev) => prev.map((m) => (m.message_id === message_id ? { ...m, delivery } : m)));
    });
    onCleanup(() => {
      unlisten.then((fn) => fn());
      unlistenDelivery.then((fn) => fn());
    });
  }));

  const handleRetry = async (messageId: string) => {
    try {
      const msg = await retryMessage(messageId);
      setMessages((prev) => prev.map((m) => (m.message_id === messageId ? msg : m)));
    } catch (e: any) {
      setError(String(e));
    }
  };

  const loadMore = async () => {
    const current = messages();
    const cid = selectedChannelId();
    if (!current.length || loading() || !cid) return;
    setLoading(true);
    const oldest = current[0];
    const older = await listMessages(cid, oldest.received_at, PAGE_SIZE);
    for (const m of older) seenIds.add(m.message_id);
    setMessages([...older.reverse(), ...current]);
    setHasMore(older.length === PAGE_SIZE);
    setLoading(false);
  };

  const handleSend = async () => {
    const text = inputText().trim();
    const sid = selectedServerId();
    const cid = selectedChannelId();
    if (!text || !sid || !cid) return;
    setInputText("");
    if (inputRef) inputRef.value = "";
    setError(null);
    try {
      const msg = await sendMessage(sid, cid, text);
      seenIds.add(msg.message_id);
      setMessages((prev) => [...prev, msg]);
      requestAnimationFrame(scrollToBottom);
    } catch (e: any) {
      setError(String(e));
    }
  };

  return (
    <div class="flex-1 flex flex-col min-h-0 relative pr-1">
      <div
        ref={containerRef}
        class="scrollarea flex-1 overflow-y-auto px-4 py-2"
        onScroll={updateNearBottom}
      >
        <Show when={hasMore()}>
          <button
            class="w-full text-xs text-[var(--neutral-500)] py-2 hover:text-[var(--neutral-300)] cursor-pointer transition-colors duration-150"
            onClick={loadMore}
            disabled={loading()}
          >
            {loading() ? "loading..." : "load older messages"}
          </button>
        </Show>
        <For each={messages()}>
          {(msg, idx) => {
            const grouped = () => isGrouped(messages(), idx());
            const name = () => senderMap().get(msg.sender_fp) ?? msg.sender_fp.slice(0, 16);
            const grad = () => hashGradient(msg.sender_fp);
            if (msg.message_type === MESSAGE_TYPES.undecryptable) {
              return <UndecryptableNotice message={msg} isNew={!initialLoad && idx() === messages().length - 1} />;
            }
            if (msg.message_type === MESSAGE_TYPES.historyGap) {
              return <HistoryGapNotice message={msg} isNew={!initialLoad && idx() === messages().length - 1} />;
            }
            return (
              <div
                class={cn(
                  "group/msg -mx-2 px-2 rounded-md hover:bg-[var(--neutral-900)]",
                  grouped() ? "py-1 pl-[var(--msg-indent)]" : "mt-2 py-1.5",
                  !initialLoad && idx() === messages().length - 1 ? "msg-new" : "",
                  msg.delivery === "pending" ? "opacity-60" : "",
                )}
                data-delivery={msg.delivery}
              >
                <Show when={!grouped()}>
                  <div class="flex items-start gap-3">
                    <Avatar
                      hashKey={msg.sender_fp}
                      label={name()}
                      class="w-[var(--size-md)] h-[var(--size-md)] text-xs mt-1 transition-all duration-200 opacity-85 hover:opacity-100 hover:scale-105"
                      status={onlinePresence().get(msg.sender_fp)?.status as AvatarStatus | undefined}
                    />
                    <div class="flex-1 min-w-0">
                      <div class="flex items-baseline gap-2">
                        <span
                          class="text-sm font-medium"
                          style={{ color: grad().from }}
                        >
                          {name()}
                        </span>
                        <Show when={showTimestamps()}>
                          <span class="text-xs text-[var(--neutral-600)]">
                            {formatTime(msg.timestamp)}
                          </span>
                        </Show>
                      </div>
                      <div data-testid="message-content" class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                        {msg.content}
                      </div>
                      <DeliveryNote message={msg} onRetry={handleRetry} />
                    </div>
                  </div>
                </Show>
                <Show when={grouped()}>
                  <div data-testid="message-content" class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                    {msg.content}
                  </div>
                  <DeliveryNote message={msg} onRetry={handleRetry} />
                </Show>
              </div>
            );
          }}
        </For>
      </div>

      {/* Scroll-to-bottom */}
      <Show when={!nearBottom()}>
        <button
          class="absolute right-4 bottom-20 w-[var(--size-md)] h-[var(--size-md)] rounded-full flex items-center justify-center cursor-pointer transition-colors duration-150"
          style={{
            background: "var(--neutral-800)",
            border: "1px solid var(--neutral-700)",
          }}
          onClick={scrollToBottom}
        >
          <ChevronDown size={16} class="text-[var(--neutral-300)]" />
        </button>
      </Show>

      <Show when={error()}>
        <div class="px-4 py-1 text-xs text-[var(--red-400)]">{error()}</div>
      </Show>
      <Show when={selectedChannelId() && waitingChannels().has(selectedChannelId()!)}>
        <div role="status" data-testid="channel-waiting" class="px-4 py-1 text-xs text-[var(--neutral-400)]">
          Waiting for this server's latest changes; this channel's new messages appear once they arrive.
        </div>
      </Show>
      <div
        class="flex-shrink-0 px-4 py-3"
        style={{
          // 200vh counteracts the parent layer's translateY(-100%) and pushes below viewport
          transform: settingsOpen() ? "translateY(200vh)" : "translateY(0)",
          transition: `transform ${slideDuration(sections().length)} var(--ease-out)`,
        }}
      >
        <Show
          when={!selectedServer()?.removed && !selectedServer()?.halted}
          fallback={<Show when={selectedServer()?.removed} fallback={<HaltedNotice />}><RemovedNotice /></Show>}
        >
          <div
            class="flex items-center gap-2 rounded-lg px-3"
            style={{
              background: "var(--neutral-800)",
              border: "1px solid var(--neutral-700)",
            }}
          >
            <input
              data-testid="composer"
              ref={inputRef}
              class="flex-1 h-10 bg-transparent text-sm text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)] outline-none"
              placeholder="send a message..."
              value={inputText()}
              onInput={(e) => setInputText(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const send = enterSends() ? !e.shiftKey : e.shiftKey;
                  if (send) { e.preventDefault(); handleSend(); }
                }
              }}
            />
            <button
              class="w-7 h-7 flex items-center justify-center rounded-md cursor-pointer transition-colors duration-150"
              classList={{
                "text-[var(--purple-400)] hover:text-[var(--purple-300)] hover:bg-[var(--accent-hover)]": inputText().trim().length > 0,
                "text-[var(--neutral-600)]": inputText().trim().length === 0,
              }}
              onClick={handleSend}
            >
              <SendHorizonal size={16} />
            </button>
          </div>
        </Show>
      </div>
    </div>
  );
}

/** Stands in the history for a message this device could not decrypt. A public
 * channel's messages travel in the server's one group, so there the notice cannot say
 * which channel the message was for; a private channel has a group of its own. */
function UndecryptableNotice(props: { message: Message; isNew: boolean }) {
  const inPrivateChannel = () => channels().find((c) => c.channel_id === props.message.channel_id)?.private ?? false;
  return (
    <div role="note" data-testid="undecryptable" class={cn("-mx-2 px-2 mt-2 py-1.5 flex items-baseline gap-2", props.isNew && "msg-new")}>
      <span class="text-sm italic text-[var(--neutral-500)]">
        {inPrivateChannel() ? "a message could not be decrypted" : "a message sent somewhere in this server could not be decrypted"}
      </span>
      <Show when={showTimestamps()}>
        <span class="text-xs text-[var(--neutral-600)]">{formatTime(props.message.received_at)}</span>
      </Show>
    </div>
  );
}

/** Marks where the history skips what the relay no longer kept when this device came
 * back. As with a stand-in, a public channel's messages travel in the server's one group,
 * so there the notice cannot say which channel lost them. */
function HistoryGapNotice(props: { message: Message; isNew: boolean }) {
  const inPrivateChannel = () => channels().find((c) => c.channel_id === props.message.channel_id)?.private ?? false;
  return (
    <div role="note" data-testid="history-gap" class={cn("-mx-2 px-2 mt-2 py-1.5 flex items-baseline gap-2", props.isNew && "msg-new")}>
      <span class="text-sm italic text-[var(--neutral-500)]">
        {inPrivateChannel()
          ? "earlier messages here were not kept by the relay while this device was away"
          : "earlier messages in this server were not kept by its relay while this device was away"}
      </span>
      <Show when={showTimestamps()}>
        <span class="text-xs text-[var(--neutral-600)]">{formatTime(props.message.received_at)}</span>
      </Show>
    </div>
  );
}

/** In place of the message box on a server this device stopped following: its relay
 * accepted a change the server's rules forbid, so this copy is from before it and
 * read-only. The person takes the relay's version after all, or leaves. */
function HaltedNotice() {
  const server = () => selectedServer();
  const halt = () => server()?.halted;
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const accept = async () => {
    const id = server()?.server_id;
    if (!id) return;
    setBusy(true);
    setError(null);
    try {
      await acceptRelayState(id);
      await refreshServers();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      role="status"
      class="flex items-center gap-3 rounded-lg px-3 py-2"
      style={{ background: "var(--neutral-800)", border: "1px solid var(--neutral-700)" }}
    >
      <div class="flex-1 min-w-0 text-sm text-[var(--neutral-300)]">
        {`${server()?.name} is read-only.`}
        <span class="text-[var(--neutral-500)]">
          {` Its relay${halt()?.relay ? ` (${halt()?.relay})` : ""} accepted a change the server's rules forbid: ${halt()?.reason}. Your copy from before it is kept; newer messages show as unreadable.`}
        </span>
        <Show when={error()}>
          <div class="text-xs text-[var(--red-400)]">{error()}</div>
        </Show>
      </div>
      <ConfirmButton
        variant="outline"
        label={busy() ? "rejoining…" : "rejoin anyway"}
        confirm="take the relay's version and drop yours?"
        disabled={busy()}
        onConfirm={accept}
      />
      <ConfirmButton variant="outline" label="leave" confirm="leave it and delete its history?" onConfirm={() => server() && forgetServer(server()!.server_id)} />
    </div>
  );
}

/** In place of the message box on a server this account was removed from: who removed
 * it, why nothing can be sent, and deleting the server with its history. */
function RemovedNotice() {
  const server = () => selectedServer();
  const who = () => server()?.removed?.by;
  return (
    <div
      role="status"
      class="flex items-center gap-3 rounded-lg px-3 py-2"
      style={{ background: "var(--neutral-800)", border: "1px solid var(--neutral-700)" }}
    >
      <div class="flex-1 min-w-0 text-sm text-[var(--neutral-300)]">
        {who() ? `${who()} removed you from ${server()?.name}.` : `You were removed from ${server()?.name}.`}
        <span class="text-[var(--neutral-500)]"> You can't send messages or join calls here.</span>
      </div>
      <ConfirmButton variant="outline" label="delete" confirm="delete it and its history?" onConfirm={() => server() && forgetServer(server()!.server_id)} />
    </div>
  );
}
