import { createSignal, createEffect, on, onCleanup, For, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Message } from "../lib/types";
import { listMessages, sendMessage } from "../lib/api";
import { hashGradient } from "../lib/gradients";
import { Avatar } from "./ui/avatar";
import { cn } from "../lib/cn";
import { ChevronDown, SendHorizonal } from "lucide-solid";
import { selectedServerId, selectedChannelId, members, settingsOpen } from "../lib/store";
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

  const senderMap = () => {
    const m = new Map<string, string>();
    for (const member of members()) {
      m.set(member.fingerprint, member.display_name);
    }
    return m;
  };

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
    onCleanup(() => { unlisten.then((fn) => fn()); });
  }));

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
            return (
              <div
                class={cn(
                  "group/msg -mx-2 px-2 rounded-md hover:bg-[var(--neutral-900)]",
                  grouped() ? "py-1 pl-[var(--msg-indent)]" : "mt-2 py-1.5",
                  !initialLoad && idx() === messages().length - 1 ? "msg-new" : "",
                )}
              >
                <Show when={!grouped()}>
                  <div class="flex items-start gap-3">
                    <Avatar
                      hashKey={msg.sender_fp}
                      label={name()}
                      class="w-[var(--size-md)] h-[var(--size-md)] text-xs mt-1 transition-all duration-200 opacity-85 hover:opacity-100 hover:scale-105"
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
                      <div class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                        {msg.content}
                      </div>
                    </div>
                  </div>
                </Show>
                <Show when={grouped()}>
                  <div class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                    {msg.content}
                  </div>
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
      <div
        class="flex-shrink-0 px-4 py-3"
        style={{
          // 200vh counteracts the parent layer's translateY(-100%) and pushes below viewport
          transform: settingsOpen() ? "translateY(200vh)" : "translateY(0)",
          transition: `transform ${slideDuration(sections().length)} var(--ease-out)`,
        }}
      >
        <div
          class="flex items-center gap-2 rounded-lg px-3"
          style={{
            background: "var(--neutral-800)",
            border: "1px solid var(--neutral-700)",
          }}
        >
          <input
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
      </div>
    </div>
  );
}
