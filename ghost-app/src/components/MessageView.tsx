import { createSignal, createEffect, on, onCleanup, For, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Member, Identity, Message } from "../lib/types";
import { listMessages, sendMessage } from "../lib/api";

interface Props {
  groupId: string;
  channelId: string;
  members: Member[];
  identity: Identity | null;
}

const PAGE_SIZE = 50;
const SCROLL_BOTTOM_THRESHOLD = 80;

const formatTime = (ts: number) => {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

export function MessageView(props: Props) {
  const [messages, setMessages] = createSignal<Message[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [hasMore, setHasMore] = createSignal(true);
  const [inputText, setInputText] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const seenIds = new Set<string>();

  let containerRef!: HTMLDivElement;
  let inputRef!: HTMLInputElement;

  const senderMap = () => {
    const m = new Map<string, string>();
    for (const member of props.members) {
      m.set(member.fingerprint, member.display_name);
    }
    return m;
  };

  const scrollToBottom = () => {
    if (containerRef) containerRef.scrollTop = containerRef.scrollHeight;
  };

  createEffect(on(() => props.channelId, (cid) => {
    setMessages([]);
    seenIds.clear();
    setHasMore(true);

    // Load history — merge with any relay messages that arrived during the await
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
      requestAnimationFrame(scrollToBottom);
    })();

    // Real-time messages from relay
    const unlisten = listen<Message>("message", (event) => {
      const msg = event.payload;
      if (msg.channel_id !== cid) return;
      if (seenIds.has(msg.message_id)) return;
      seenIds.add(msg.message_id);
      setMessages((prev) => [...prev, msg]);
      const el = containerRef;
      const nearBottom = el && (el.scrollHeight - el.scrollTop - el.clientHeight < SCROLL_BOTTOM_THRESHOLD);
      if (nearBottom) requestAnimationFrame(scrollToBottom);
    });
    onCleanup(() => { unlisten.then((fn) => fn()); });
  }));

  const loadMore = async () => {
    const current = messages();
    if (!current.length || loading()) return;
    setLoading(true);
    const oldest = current[0];
    const older = await listMessages(props.channelId, oldest.received_at, PAGE_SIZE);
    for (const m of older) seenIds.add(m.message_id);
    setMessages([...older.reverse(), ...current]);
    setHasMore(older.length === PAGE_SIZE);
    setLoading(false);
  };

  const handleSend = async () => {
    const text = inputText().trim();
    if (!text) return;
    setInputText("");
    if (inputRef) inputRef.value = "";
    setError(null);
    try {
      const msg = await sendMessage(props.groupId, props.channelId, text);
      seenIds.add(msg.message_id);
      setMessages((prev) => [...prev, msg]);
      requestAnimationFrame(scrollToBottom);
    } catch (e: any) {
      setError(String(e));
    }
  };

  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div ref={containerRef} class="flex-1 overflow-y-auto px-4 py-2">
        <Show when={hasMore()}>
          <button
            class="w-full text-xs text-[var(--neutral-500)] py-2 hover:text-[var(--neutral-300)] cursor-pointer"
            onClick={loadMore}
            disabled={loading()}
          >
            {loading() ? "loading..." : "load older messages"}
          </button>
        </Show>
        <For each={messages()}>
          {(msg) => (
            <div class="py-1.5">
              <div class="flex items-baseline gap-2">
                <span class="text-sm font-medium text-[var(--purple-300)]">
                  {senderMap().get(msg.sender_fp) ?? msg.sender_fp.slice(0, 16)}
                </span>
                <span class="text-xs text-[var(--neutral-600)]">
                  {formatTime(msg.timestamp)}
                </span>
              </div>
              <div class="text-sm text-[var(--neutral-200)] break-words">
                {msg.content}
              </div>
            </div>
          )}
        </For>
      </div>

      <Show when={error()}>
        <div class="px-4 py-1 text-xs text-[var(--red-400)]">{error()}</div>
      </Show>
      <div class="flex-shrink-0 px-4 py-3 border-t border-[var(--neutral-800)]">
        <input
          ref={inputRef}
          class="w-full h-9 rounded px-3 text-sm bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)] border border-[var(--neutral-700)] focus:border-[var(--purple-500)] outline-none"
          placeholder="send a message..."
          value={inputText()}
          onInput={(e) => setInputText(e.currentTarget.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
        />
      </div>
    </div>
  );
}
