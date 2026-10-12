// A capture of the flight recorder: the last minute of what Ghost did, the main window's
// waits and frames alongside the backend's spans. The overview finds the busy moments,
// the timeline shows them span by span, and the pane below explains the selection.

import { batch, createEffect, createMemo, createSignal, For, on, Show } from "solid-js";
import { Circle } from "lucide-solid";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Popover } from "../components/ui/popover";
import { KeyBadge } from "../components/KeyBadge";
import { cn } from "../lib/cn";
import type { ProfilerData, SlowEvent } from "./data";
import { formatOffset } from "./format";
import Overview from "./Overview";
import { ModuleDot } from "./table";
import Timeline, { type Range, type View } from "./Timeline";
import TraceDetails, { type Scope } from "./TraceDetails";
import { layoutTrace, type Span, type Trace } from "./trace-model";

/** A slow event to show, in the capture taken for it. */
export interface Focus {
  trace: Trace;
  event: SlowEvent;
}

const DEFAULT_PANE_HEIGHT = 240;
const MIN_PANE_HEIGHT = 120;
/** Room the timeline keeps when the pane grows. */
const MIN_TIMELINE_HEIGHT = 160;
/** Time shown either side of a slow event. */
const FOCUS_MARGIN_US = 500_000;
const isMac = navigator.platform.toLowerCase().includes("mac");

const HELP: { keys: string[]; then?: string; does: string }[] = [
  { keys: [], then: "scroll", does: "move through the rows" },
  { keys: [isMac ? "Cmd" : "Ctrl"], then: "scroll, or pinch", does: "zoom around the pointer" },
  { keys: ["⇧"], then: "scroll, or scroll sideways", does: "pan" },
  { keys: [], then: "drag", does: "pan" },
  { keys: [], then: "drag the ruler", does: "select a stretch of time" },
  { keys: ["Enter"], does: "zoom to the selected stretch" },
  { keys: [], then: "double-click", does: "zoom to a span, or fit" },
  { keys: ["W", "S"], does: "zoom in and out" },
  { keys: ["A", "D"], does: "pan left and right" },
  { keys: ["Esc"], does: "clear the selection" },
];

function Help() {
  return (
    <Popover label="How to move around the timeline" trigger="?" triggerClass="h-7 w-7 rounded text-xs text-[var(--neutral-400)] hover:bg-[var(--hover)] cursor-pointer">
      <div class="grid items-center gap-x-4 gap-y-2" style={{ "grid-template-columns": "auto auto" }}>
        <For each={HELP}>
          {(row) => (
            <>
              <span class="flex items-center gap-1 text-[var(--neutral-300)]">
                <For each={row.keys}>{(key) => <KeyBadge value={key} size="sm" />}</For>
                <Show when={row.then}>{row.then}</Show>
              </span>
              <span class="text-[var(--neutral-400)]">{row.does}</span>
            </>
          )}
        </For>
      </div>
    </Popover>
  );
}

/** Captures the flight recorder: wherever the trace view offers it. */
function CaptureButton(props: { windowS: number; capturing: boolean; onCapture: () => void }) {
  return (
    <Button size="sm" disabled={props.capturing} onClick={props.onCapture}>
      <Circle size={10} fill="currentColor" />
      capture last {props.windowS} s
    </Button>
  );
}

export default function TraceView(props: { data: ProfilerData; focus: Focus | null; capturing: boolean; onCapture: () => void }) {
  const [view, setView] = createSignal<View>({ start: 0, end: 1 });
  const [crumbs, setCrumbs] = createSignal<View[]>([]);
  const [selected, setSelected] = createSignal<Span | null>(null);
  const [range, setRange] = createSignal<Range | null>(null);
  const [filter, setFilter] = createSignal("");
  const [hidden, setHidden] = createSignal<ReadonlySet<string>>(new Set());
  const [collapsed, setCollapsed] = createSignal<ReadonlySet<string>>(new Set());
  const [paneHeight, setPaneHeight] = createSignal(DEFAULT_PANE_HEIGHT);
  let body!: HTMLDivElement;

  const trace = () => props.data.trace();
  const layout = createMemo(() => {
    const t = trace();
    return t ? layoutTrace(t, collapsed(), hidden()) : null;
  });
  const blockingUs = () => (props.data.limits()?.blocking_ms ?? Infinity) * 1000;
  const windowS = () => Math.round((props.data.limits()?.capture_window_ms ?? 0) / 1000);

  const query = () => filter().trim().toLowerCase();
  const matches = (span: Span) => !query() || span.kind.toLowerCase().includes(query());
  const include = (span: Span) => !hidden().has(span.module.id) && matches(span);
  const dimmed = (span: Span) => !matches(span);

  const full = (t: Trace): View => ({ start: 0, end: Math.max(t.durationUs, 1) });
  createEffect(
    on(trace, (t) => {
      if (!t) return;
      batch(() => {
        setView(full(t));
        setCrumbs([full(t)]);
        setSelected(null);
        setRange(null);
      });
    }),
  );

  const toggle = (set: ReadonlySet<string>, id: string, keep?: boolean) => {
    const next = new Set(set);
    if (keep ?? !next.has(id)) next.add(id);
    else next.delete(id);
    return next;
  };

  createEffect(
    on(
      () => props.focus,
      (focus) => {
        if (!focus || focus.trace !== trace()) return;
        const t = focus.trace;
        const from = (focus.event.atUnixMs - t.startUnixMs) * 1000;
        const to = from + focus.event.durationMs * 1000;
        const span = focus.event.spanId ? t.byId.get(focus.event.spanId) ?? null : null;
        batch(() => {
          if (span) {
            setHidden((h) => toggle(h, span.module.id, false));
            setCollapsed((c) => toggle(c, span.module.id, false));
          }
          setView({ start: Math.max(0, from - FOCUS_MARGIN_US), end: Math.min(t.durationUs, to + FOCUS_MARGIN_US) });
          setSelected(span);
        });
      },
    ),
  );

  const commitRange = () => {
    const r = range();
    if (!r || r[0] === r[1]) return;
    const next = { start: Math.min(...r), end: Math.max(...r) };
    batch(() => {
      setCrumbs((c) => [...c, next]);
      setView(next);
      setRange(null);
    });
  };
  const fit = () => setView(crumbs()[crumbs().length - 1] ?? full(trace()!));
  const show = (span: Span) => {
    const pad = Math.max(span.duration * 0.25, 1);
    batch(() => {
      setSelected(span);
      setView({ start: span.start - pad, end: span.end + pad });
    });
  };

  const scope = (): Scope => {
    const r = range();
    if (r && r[0] !== r[1]) return { from: Math.min(...r), to: Math.max(...r), label: "selected range" };
    return { from: view().start, to: view().end, label: "in view" };
  };

  const resize = (e: MouseEvent) => {
    const [startY, startHeight] = [e.clientY, paneHeight()];
    const move = (event: MouseEvent) => {
      const room = body.clientHeight - MIN_TIMELINE_HEIGHT;
      setPaneHeight(Math.min(Math.max(startHeight + startY - event.clientY, MIN_PANE_HEIGHT), Math.max(room, MIN_PANE_HEIGHT)));
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  return (
    <Show
      when={trace() && layout() ? { trace: trace()!, layout: layout()! } : null}
      fallback={
        <div class="flex-1 flex items-center justify-center text-center">
          <div class="flex flex-col items-center gap-3">
            <div class="text-sm text-[var(--neutral-400)]">
              Ghost keeps the last {windowS()} s of what it did.
              <div class="text-xs text-[var(--neutral-500)] mt-1">Capture when something feels slow, or from the main window with /capture.</div>
            </div>
            <CaptureButton windowS={windowS()} capturing={props.capturing} onCapture={props.onCapture} />
          </div>
        </div>
      }
    >
      {(current) => (
        <div ref={body} class="flex-1 min-h-0 flex flex-col gap-2 px-4 pb-4">
          <div class="flex items-center gap-2 flex-wrap">
            <Input class="h-7 text-xs w-48" placeholder="filter spans" aria-label="Filter spans" value={filter()} onInput={(e) => setFilter(e.currentTarget.value)} />
            <For each={current().layout.modules}>
              {(module) => (
                <button
                  class={cn(
                    "h-6 px-2 rounded-full border border-[var(--neutral-700)] text-[11px] flex items-center gap-1.5 cursor-pointer transition-opacity",
                    hidden().has(module.id) ? "opacity-40" : "text-[var(--neutral-300)] hover:border-[var(--neutral-600)]",
                  )}
                  aria-pressed={!hidden().has(module.id)}
                  title={hidden().has(module.id) ? `Show ${module.label}` : `Hide ${module.label}`}
                  onClick={() => setHidden((h) => toggle(h, module.id))}
                >
                  <ModuleDot module={module} />
                  {module.label}
                </button>
              )}
            </For>
            <div class="flex-1" />
            <Button variant="ghost" size="sm" onClick={fit}>fit</Button>
            <Help />
            <CaptureButton windowS={windowS()} capturing={props.capturing} onCapture={props.onCapture} />
          </div>

          <div class="flex items-center gap-1.5 text-xs text-[var(--neutral-500)] h-5">
            <For each={crumbs()}>
              {(crumb, i) => (
                <>
                  <Show when={i() > 0}>›</Show>
                  <button
                    class={cn("cursor-pointer hover:text-[var(--neutral-200)]", i() === crumbs().length - 1 && "text-[var(--neutral-200)]")}
                    onClick={() => {
                      setCrumbs((c) => c.slice(0, i() + 1));
                      setView(crumb);
                    }}
                  >
                    {i() === 0 ? `whole capture, ${formatOffset(crumb.end - crumb.start)}` : `${formatOffset(crumb.start)} to ${formatOffset(crumb.end)}`}
                  </button>
                </>
              )}
            </For>
            <Show when={range() && range()![0] !== range()![1]}>
              <button class="ml-2 text-[var(--purple-400)] hover:text-[var(--purple-300)] cursor-pointer flex items-center gap-1" onClick={commitRange}>
                zoom to selection <KeyBadge value="Enter" size="sm" />
              </button>
            </Show>
            <Show when={current().trace.truncated}>
              <span class="ml-auto">the recorder was full, so this capture starts later than {windowS()} s ago</span>
            </Show>
          </div>

          <Overview trace={current().trace} view={view()} range={range()} onView={setView} />

          <Timeline
            trace={current().trace}
            layout={current().layout}
            view={view()}
            onView={setView}
            selected={selected()}
            onSelect={setSelected}
            range={range()}
            onRange={setRange}
            onCommitRange={commitRange}
            onFit={fit}
            onToggleModule={(id) => setCollapsed((c) => toggle(c, id))}
            dimmed={dimmed}
            blockingUs={blockingUs()}
          />

          <div class="h-2 -my-1 flex items-center justify-center cursor-row-resize flex-shrink-0" onMouseDown={resize} role="separator" aria-orientation="horizontal">
            <div class="w-10 h-[3px] rounded-full bg-[var(--neutral-700)]" />
          </div>

          <div class="flex-shrink-0" style={{ height: `${paneHeight()}px` }}>
            <TraceDetails
              trace={current().trace}
              scope={scope()}
              selected={selected()}
              onSelect={setSelected}
              onShow={show}
              include={include}
              blockingUs={blockingUs()}
            />
          </div>
        </div>
      )}
    </Show>
  );
}
