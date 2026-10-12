// The bottom of the trace view. Summary tells a selected span's story (how long, how much
// was its own code, what it was inside, where its time went, how it compares with its
// kind), or without one, how the backend's modules shared the stretch in view. Bottom-up
// ranks kinds of span by the own time they took there; spans lists the longest ones.

import { createMemo, createSignal, For, Match, Show, Switch } from "solid-js";
import { Card } from "../components/ui/card";
import { ScrollArea } from "../components/ui/scroll-area";
import { Tabs } from "../components/ui/tabs";
import { cn } from "../lib/cn";
import { DASH, formatOffset, formatUs, percent } from "./format";
import { moduleColor } from "./modules";
import { emptyClass, Heading, numClass, OperationName, OverBudget, rowClass, warnClass } from "./table";
import {
  ancestry,
  backendOf,
  bottomUp,
  breakdown,
  budgetUs,
  compareWithKind,
  heldThread,
  longestSpans,
  overBudget,
  timeByModule,
  type Span,
  type Trace,
} from "./trace-model";

type Tab = "summary" | "bottom-up" | "spans";
const TABS = [
  { value: "summary", label: "summary" },
  { value: "bottom-up", label: "bottom-up" },
  { value: "spans", label: "spans" },
] as const;
const LIST_LIMIT = 100;
const BOTTOM_UP_COLUMNS = "minmax(0, 1fr) 56px 76px 76px 76px";
const SPANS_COLUMNS = "minmax(0, 1fr) 72px 76px 76px 76px";

export interface Scope {
  from: number;
  to: number;
  /** "selected range" or "in view". */
  label: string;
}

const labelClass = "text-xs text-[var(--neutral-500)]";

/** A labelled bar, its length a share of `of`. */
function ShareBar(props: { label: string; us: number; of: number; color: string }) {
  return (
    <>
      <span class="truncate text-[var(--neutral-300)]">{props.label}</span>
      <span class="h-1.5 rounded-full bg-[var(--neutral-800)]">
        <span class="block h-full rounded-full" style={{ width: `${props.of > 0 ? (props.us / props.of) * 100 : 0}%`, background: props.color }} />
      </span>
      <span class={numClass}>{formatUs(props.us)}</span>
    </>
  );
}

function SpanSummary(props: { trace: Trace; span: Span; blockingUs: number; onSelect: (span: Span) => void; onShow: (span: Span) => void }) {
  const split = createMemo(() => breakdown(props.span));
  const comparison = createMemo(() => compareWithKind(props.trace, props.span));
  const backend = createMemo(() => backendOf(props.trace, props.span));
  const chain = createMemo(() => ancestry(props.span).slice(0, -1));
  const budget = () => budgetUs(props.span);
  const sizeOf = (span: Span) => `${formatUs(span.duration)}${span.open ? " so far" : ""}`;

  return (
    <div class="grid grid-cols-2 gap-6 px-4 py-3 text-xs">
      <div class="flex flex-col gap-1.5 min-w-0">
        <div class="flex items-center gap-2 flex-wrap">
          <OperationName target={props.span.target} name={props.span.name} />
          <Show when={overBudget(props.span)}>
            <OverBudget>
              {formatUs(props.span.duration)}, budget {formatUs(budget()!)}
            </OverBudget>
          </Show>
          <Show when={heldThread(props.span, props.blockingUs)}>
            <OverBudget>held its thread {formatUs(props.span.longestPoll!)}</OverBudget>
          </Show>
          <Show when={props.span.open}>
            <span class="text-[var(--neutral-400)]">still running at the capture</span>
          </Show>
          <button class="ml-auto text-[var(--purple-400)] hover:text-[var(--purple-300)] cursor-pointer" onClick={() => props.onShow(props.span)}>
            zoom to it
          </button>
        </div>
        <div class="text-[var(--neutral-500)]">
          took {sizeOf(props.span)} · started at {formatOffset(props.span.start)}
          <Show when={props.span.busy !== null}>
            {" "}· running {formatUs(props.span.busy!)}, waiting {formatUs(Math.max(0, props.span.duration - props.span.busy!))}
          </Show>
        </div>
        <Show when={chain().length > 0}>
          <div class="flex items-center gap-1 flex-wrap text-[var(--neutral-500)]">
            inside
            <For each={chain()}>
              {(outer, i) => (
                <>
                  <Show when={i() > 0}>›</Show>
                  <button class="cursor-pointer text-[var(--neutral-300)] hover:text-[var(--neutral-100)]" onClick={() => props.onSelect(outer)}>
                    {outer.name}
                  </button>
                </>
              )}
            </For>
          </div>
        </Show>
        <Show when={backend()}>
          {(b) => (
            <div class="text-[var(--neutral-500)]">
              the backend ran it in{" "}
              <button class="cursor-pointer text-[var(--neutral-300)] hover:text-[var(--neutral-100)]" onClick={() => props.onSelect(b())}>
                {formatUs(b().duration)}
              </button>
              ; the other {formatUs(Math.max(0, props.span.duration - b().duration))} went to IPC and the webview
            </div>
          )}
        </Show>
        <Show when={split().children.length > 0}>
          <div class={cn(labelClass, "mt-1.5")}>where its time went</div>
          <div class="grid items-center gap-x-3 gap-y-1.5" style={{ "grid-template-columns": "minmax(0, 180px) minmax(0, 1fr) 64px" }}>
            <For each={split().children}>
              {(share) => <ShareBar label={`${share.module.label}::${share.name}`} us={share.us} of={props.span.duration} color={moduleColor(share.module, 400)} />}
            </For>
            <ShareBar label="its own code and waits" us={split().own} of={props.span.duration} color="var(--neutral-500)" />
          </div>
        </Show>
      </div>
      <Show when={comparison().count > 1}>
        <div class="flex flex-col gap-1.5">
          <div class={labelClass}>against the {comparison().count - 1} other {props.span.name} in this capture</div>
          <div class="grid grid-cols-3 gap-2">
            <For each={[["median", comparison().medianUs], ["p95", comparison().p95Us], ["slowest", comparison().maxUs]] as const}>
              {([label, us]) => (
                <div>
                  <div class={labelClass}>{label}</div>
                  <div class="text-[var(--neutral-200)] tabular-nums">{formatUs(us)}</div>
                </div>
              )}
            </For>
          </div>
          <div class="text-[var(--neutral-500)]">slower than {percent(comparison().slowerThan * 100)} of them</div>
        </div>
      </Show>
    </div>
  );
}

const FRONTEND_COUNTS = [
  ["command", "commands"],
  ["interaction", "inputs"],
  ["frame", "long frames"],
  ["longtask", "long tasks"],
] as const;

function ScopeSummary(props: { trace: Trace; scope: Scope; include: (span: Span) => boolean }) {
  const backendOnly = (span: Span) => props.include(span) && !span.frontend;
  const modules = createMemo(() => timeByModule(props.trace, props.scope.from, props.scope.to, backendOnly));
  const largest = () => Math.max(...modules().map((m) => m.us), 1);
  /** The main window's events in the scope, by kind, and how many went over budget. */
  const frontend = createMemo(() =>
    FRONTEND_COUNTS.map(([kind, label]) => {
      const events = props.trace.spans.filter((s) => s.frontend === kind && props.include(s) && s.end >= props.scope.from && s.start <= props.scope.to);
      return { label, count: events.length, over: events.filter(overBudget).length };
    }).filter((c) => c.count > 0),
  );

  return (
    <div class="px-4 py-3 text-xs flex flex-col gap-1.5">
      <div class={labelClass}>
        {props.scope.label}, {formatOffset(props.scope.from)} to {formatOffset(props.scope.to)} ({formatUs(props.scope.to - props.scope.from)}): own time by module
      </div>
      <Show when={modules().length > 0} fallback={<div class={emptyClass}>the backend did nothing here</div>}>
        <div class="grid items-center gap-x-3 gap-y-1.5 max-w-[640px]" style={{ "grid-template-columns": "minmax(0, 140px) minmax(0, 1fr) 64px 72px" }}>
          <For each={modules()}>
            {(m) => (
              <>
                <ShareBar label={m.module.label} us={m.us} of={largest()} color={moduleColor(m.module, 400)} />
                <span class={cn(numClass, "text-[var(--neutral-500)]")}>{m.spans} spans</span>
              </>
            )}
          </For>
        </div>
        <div class="text-[var(--neutral-600)]">operations running at once each count, so modules can add up past the stretch</div>
      </Show>
      <Show when={frontend().length > 0}>
        <div class="text-[var(--neutral-500)] mt-1">
          main window:{" "}
          <For each={frontend()}>
            {(c, i) => (
              <>
                {i() > 0 ? ", " : ""}
                {c.count} {c.label}
                <Show when={c.over > 0 && c.label !== "long frames" && c.label !== "long tasks"}>
                  <span class={warnClass}> ({c.over} over budget)</span>
                </Show>
              </>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}

export default function TraceDetails(props: {
  trace: Trace;
  scope: Scope;
  selected: Span | null;
  onSelect: (span: Span) => void;
  /** Select a span and zoom to it. */
  onShow: (span: Span) => void;
  include: (span: Span) => boolean;
  blockingUs: number;
}) {
  const [tab, setTab] = createSignal<Tab>("summary");
  const kinds = createMemo(() => (tab() === "bottom-up" ? bottomUp(props.trace, props.scope.from, props.scope.to, props.include).slice(0, LIST_LIMIT) : []));
  const longest = createMemo(() => (tab() === "spans" ? longestSpans(props.trace, props.scope.from, props.scope.to, props.include, LIST_LIMIT) : []));
  const showLongestOf = (kind: string) => {
    const [span] = longestSpans(props.trace, props.scope.from, props.scope.to, (s) => s.kind === kind && props.include(s), 1);
    if (span) props.onShow(span);
  };
  const busy = (us: number | null) => (us === null ? DASH : formatUs(us));

  return (
    <Card class="h-full flex flex-col min-h-0">
      <div class="flex items-center gap-3 px-3 pt-2">
        <Tabs value={tab()} onChange={setTab} tabs={TABS} label="Details" size="sm" />
        <span class={cn(labelClass, "ml-auto")}>{tab() === "summary" && props.selected ? "selected span" : props.scope.label}</span>
      </div>
      <ScrollArea class="flex-1 min-h-0">
        <Switch>
          <Match when={tab() === "summary"}>
            <Show when={props.selected} fallback={<ScopeSummary trace={props.trace} scope={props.scope} include={props.include} />}>
              {(span) => <SpanSummary trace={props.trace} span={span()} blockingUs={props.blockingUs} onSelect={props.onSelect} onShow={props.onShow} />}
            </Show>
          </Match>
          <Match when={tab() === "bottom-up"}>
            <div class="px-4 py-2">
              <Show when={kinds().length > 0} fallback={<div class={emptyClass}>nothing here</div>}>
                <div class={rowClass} style={{ "grid-template-columns": BOTTOM_UP_COLUMNS }}>
                  <Heading label="operation" />
                  <Heading label="spans" right />
                  <Heading label="own" hint="Time not covered by operations nested inside it" right sorted />
                  <Heading label="total" hint="Time any of them was open; nested and overlapping ones count once" right />
                  <Heading label="busy" hint="Own code running, in proportion to the own time here" right />
                </div>
                <For each={kinds()}>
                  {(k) => (
                    <button class={cn(rowClass, "w-full text-left cursor-pointer hover:bg-[var(--hover)]")} style={{ "grid-template-columns": BOTTOM_UP_COLUMNS }} onClick={() => showLongestOf(k.kind)}>
                      <OperationName target={k.target} name={k.name} />
                      <span class={numClass}>{k.count}</span>
                      <span class={numClass}>{formatUs(k.ownUs)}</span>
                      <span class={numClass}>{formatUs(k.totalUs)}</span>
                      <span class={numClass}>{busy(k.busyUs)}</span>
                    </button>
                  )}
                </For>
              </Show>
            </div>
          </Match>
          <Match when={tab() === "spans"}>
            <div class="px-4 py-2">
              <Show when={longest().length > 0} fallback={<div class={emptyClass}>nothing here</div>}>
                <div class={rowClass} style={{ "grid-template-columns": SPANS_COLUMNS }}>
                  <Heading label="operation" />
                  <Heading label="started" right />
                  <Heading label="took" right sorted />
                  <Heading label="own" right />
                  <Heading label="busy" right />
                </div>
                <For each={longest()}>
                  {(span) => (
                    <button
                      class={cn(rowClass, "w-full text-left cursor-pointer hover:bg-[var(--hover)]", span === props.selected && "bg-[var(--active)]")}
                      style={{ "grid-template-columns": SPANS_COLUMNS }}
                      onClick={() => props.onShow(span)}
                    >
                      <OperationName target={span.target} name={span.name}>
                        <Show when={overBudget(span) || heldThread(span, props.blockingUs)}>
                          <span class={warnClass}>▲</span>
                        </Show>
                      </OperationName>
                      <span class={numClass}>{formatOffset(span.start)}</span>
                      <span class={cn(numClass, overBudget(span) && warnClass)}>{formatUs(span.duration)}</span>
                      <span class={numClass}>{formatUs(span.own)}</span>
                      <span class={numClass}>{busy(span.busy)}</span>
                    </button>
                  )}
                </For>
              </Show>
            </div>
          </Match>
        </Switch>
      </ScrollArea>
    </Card>
  );
}

