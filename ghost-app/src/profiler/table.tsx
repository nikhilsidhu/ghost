// Pieces the profiler's tables share.

import { Show, type JSX } from "solid-js";
import { Tooltip } from "../components/ui/tooltip";
import { cn } from "../lib/cn";
import { moduleColor, moduleOf, shortTarget, type Module } from "./modules";

export const rowClass = "grid items-center gap-3 py-1.5 text-xs border-b border-[var(--neutral-800)] last:border-b-0";
export const numClass = "text-right tabular-nums text-[var(--neutral-300)]";
export const warnClass = "text-[var(--amber-400)]";
export const emptyClass = "py-3 text-xs text-[var(--neutral-500)]";

/** A module's color, the key to every chart and timeline bar of it. */
export function ModuleDot(props: { module: Module }) {
  return <span class="w-[7px] h-[7px] rounded-full flex-shrink-0" style={{ background: moduleColor(props.module, 400) }} />;
}

/** Marks a figure past its budget. */
export function OverBudget(props: { children: JSX.Element }) {
  return <span class={cn(warnClass, "whitespace-nowrap")}>▲ {props.children}</span>;
}

/** A span kind: its module's color, then its full path with the name standing out. */
export function OperationName(props: { target: string; name: string; children?: JSX.Element }) {
  return (
    <span class="flex items-center gap-2 min-w-0">
      <ModuleDot module={moduleOf(props.target)} />
      <span class="truncate" title={`${props.target}::${props.name}`}>
        <span class="text-[var(--neutral-500)]">{shortTarget(props.target)}::</span>
        <span class="text-[var(--neutral-200)]">{props.name}</span>
      </span>
      {props.children}
    </span>
  );
}

/** A column heading, explained on hover where the name alone is not enough, and a sort
 * control where the table sorts by it. */
export function Heading(props: { label: string; hint?: string; right?: boolean; sorted?: boolean; onSort?: () => void }) {
  const text = () => (
    <span class={cn("text-[var(--neutral-500)] whitespace-nowrap", props.hint && "underline decoration-dotted decoration-[var(--neutral-600)] underline-offset-2")}>
      {props.label}
      <Show when={props.sorted}> ↓</Show>
    </span>
  );
  const content = () => (
    <Show when={props.onSort} fallback={text()}>
      <button class="cursor-pointer hover:text-[var(--neutral-300)]" onClick={props.onSort}>
        {text()}
      </button>
    </Show>
  );
  return (
    <span class={cn("flex", props.right && "justify-end")}>
      <Show when={props.hint} fallback={content()}>
        <Tooltip label={props.hint!} placement="top" gutter={6}>
          {content()}
        </Tooltip>
      </Show>
    </span>
  );
}
