// Where time went since the statistics started: each command the interface waited on,
// with how much of the wait was the backend's, and each backend operation by module,
// with whether it ever held its thread.

import { createMemo, createSignal, For, Show } from "solid-js";
import { SettingGroup } from "../components/settings/controls";
import { Input } from "../components/ui/input";
import { COMMAND_BUDGET_MS } from "../lib/devtools/budgets";
import { cn } from "../lib/cn";
import type { CommandRow, ProfilerData, SpanRow } from "./data";
import { DASH, ms } from "./format";
import { COMMANDS_TARGET, moduleOf, moduleRank, type Module } from "./modules";
import { createStableOrder } from "./order";
import { emptyClass, Heading, ModuleDot, numClass, OperationName, rowClass, warnClass } from "./table";

const COMMAND_COLUMNS = "minmax(0, 1fr) 52px 64px 64px 64px 64px 72px";
const OPERATION_COLUMNS = "minmax(0, 1fr) 52px 64px 64px 64px 72px";

type CommandSort = "calls" | "avg" | "p95" | "slowest";
type OperationSort = "calls" | "avg" | "slowest" | "busy" | "poll";

const COMMAND_ORDER: Record<CommandSort, (a: CommandRow, b: CommandRow) => number> = {
  calls: (a, b) => b.calls - a.calls,
  avg: (a, b) => b.avgMs - a.avgMs,
  p95: (a, b) => b.p95Ms - a.p95Ms,
  slowest: (a, b) => b.maxMs - a.maxMs,
};

const OPERATION_ORDER: Record<OperationSort, (a: SpanRow, b: SpanRow) => number> = {
  calls: (a, b) => b.count - a.count,
  avg: (a, b) => b.wall_ms / b.count - a.wall_ms / a.count,
  slowest: (a, b) => b.max_wall_ms - a.max_wall_ms,
  busy: (a, b) => b.busy_ms - a.busy_ms,
  poll: (a, b) => b.longest_poll_ms - a.longest_poll_ms,
};

export default function StatisticsView(props: { data: ProfilerData }) {
  const [filter, setFilter] = createSignal("");
  const [commandSort, setCommandSort] = createSignal<CommandSort>("p95");
  const [operationSort, setOperationSort] = createSignal<OperationSort>("busy");
  const matches = (text: string) => text.toLowerCase().includes(filter().trim().toLowerCase());
  const blockingMs = () => props.data.limits()?.blocking_ms ?? Infinity;

  const backendByCommand = createMemo(
    () => new Map(props.data.tables.spans.filter((s) => s.target === COMMANDS_TARGET).map((s) => [s.name, s.wall_ms / s.count])),
  );
  const commands = createStableOrder(
    () => props.data.tables.commands.filter((c) => matches(c.name)),
    (c) => c.name,
    () => COMMAND_ORDER[commandSort()],
  );

  const operations = createStableOrder(
    () => props.data.tables.spans.filter((s) => s.target !== COMMANDS_TARGET && matches(s.kind)),
    (s) => s.kind,
    () => OPERATION_ORDER[operationSort()],
  );
  /** The sorted operations under their modules, busiest module first. */
  const byModule = createMemo(() => {
    const groups = new Map<string, { module: Module; rows: SpanRow[]; busyMs: number }>();
    for (const row of operations()) {
      const module = moduleOf(row.target);
      const group = groups.get(module.id) ?? { module, rows: [], busyMs: 0 };
      group.rows.push(row);
      group.busyMs += row.busy_ms;
      groups.set(module.id, group);
    }
    return [...groups.values()].sort((a, b) => b.busyMs - a.busyMs || moduleRank(a.module) - moduleRank(b.module));
  });

  const commandHeading = (label: string, sort: CommandSort, hint?: string) => (
    <Heading label={label} hint={hint} right sorted={commandSort() === sort} onSort={() => setCommandSort(sort)} />
  );
  const operationHeading = (label: string, sort: OperationSort, hint?: string) => (
    <Heading label={label} hint={hint} right sorted={operationSort() === sort} onSort={() => setOperationSort(sort)} />
  );

  return (
    <div class="px-2 pb-6">
      <div class="mx-2 mt-2">
        <Input class="h-7 text-xs w-64" placeholder="filter by name" aria-label="Filter by name" value={filter()} onInput={(e) => setFilter(e.currentTarget.value)} />
      </div>

      <SettingGroup label="commands · round trips the interface waited on">
        <Show when={commands().length > 0} fallback={<div class={emptyClass}>no commands since the statistics started</div>}>
          <div class={rowClass} style={{ "grid-template-columns": COMMAND_COLUMNS }}>
            <Heading label="command" />
            {commandHeading("calls", "calls")}
            {commandHeading("avg", "avg")}
            {commandHeading("p95", "p95")}
            {commandHeading("slowest", "slowest")}
            <Heading label="backend" hint="The backend's average time running the command" right />
            <Heading label="overhead" hint="Average round trip less the backend's time: IPC, serialization and the webview getting to it" right />
          </div>
          <For each={commands()}>
            {(c) => {
              const backend = () => backendByCommand().get(c.name);
              return (
                <div class={rowClass} style={{ "grid-template-columns": COMMAND_COLUMNS }}>
                  <OperationName target={COMMANDS_TARGET} name={c.name} />
                  <span class={numClass}>{c.calls}</span>
                  <span class={numClass}>{ms(c.avgMs)}</span>
                  <span class={cn(numClass, c.p95Ms > COMMAND_BUDGET_MS && warnClass)}>{ms(c.p95Ms)}</span>
                  <span class={cn(numClass, c.maxMs > COMMAND_BUDGET_MS && warnClass)}>{ms(c.maxMs)}</span>
                  <span class={numClass}>{backend() === undefined ? DASH : ms(backend()!)}</span>
                  <span class={numClass}>{backend() === undefined ? DASH : ms(Math.max(0, c.avgMs - backend()!))}</span>
                </div>
              );
            }}
          </For>
        </Show>
      </SettingGroup>

      <SettingGroup label="backend operations">
        <Show when={byModule().length > 0} fallback={<div class={emptyClass}>no backend operations since the statistics started</div>}>
          <div class={rowClass} style={{ "grid-template-columns": OPERATION_COLUMNS }}>
            <Heading label="operation" />
            {operationHeading("calls", "calls")}
            {operationHeading("avg", "avg")}
            {operationHeading("slowest", "slowest")}
            {operationHeading("busy", "busy", "Time its own code ran in total, not counting operations nested inside it")}
            {operationHeading("held", "poll", "The longest it ran without yielding, holding up its thread; on the async runtime, everything queued behind it waited too")}
          </div>
          <For each={byModule()}>
            {(group) => (
              <>
                <div class="flex items-center gap-2 pt-3 pb-1 text-xs border-b border-[var(--neutral-800)]">
                  <ModuleDot module={group.module} />
                  <span class="flex-1 text-[var(--neutral-400)]">{group.module.label}</span>
                  <span class="text-[var(--neutral-500)] tabular-nums">{ms(group.busyMs)} ms busy</span>
                </div>
                <For each={group.rows}>
                  {(row) => (
                    <div class={rowClass} style={{ "grid-template-columns": OPERATION_COLUMNS }}>
                      <OperationName target={row.target} name={row.name} />
                      <span class={numClass}>{row.count}</span>
                      <span class={numClass}>{ms(row.wall_ms / row.count)}</span>
                      <span class={numClass}>{ms(row.max_wall_ms)}</span>
                      <span class={numClass}>{ms(row.busy_ms)}</span>
                      <span class={cn(numClass, row.longest_poll_ms >= blockingMs() && warnClass)}>{ms(row.longest_poll_ms)}</span>
                    </div>
                  )}
                </For>
              </>
            )}
          </For>
        </Show>
      </SettingGroup>
    </div>
  );
}
