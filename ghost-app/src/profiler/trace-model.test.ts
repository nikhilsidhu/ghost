// Laying out captures for the timeline, and what the views work out from them.

import { describe, expect, it } from "vitest";
import type { TraceCapture } from "../lib/generated/TraceCapture";
import type { TraceSpan } from "../lib/generated/TraceSpan";
import type { FrontendEvent } from "../lib/devtools/types";
import { backendOf, bottomUp, buildTrace, compareWithKind, layoutTrace, timeByModule, type Span } from "./trace-model";

const span = (id: string, target: string, name: string, start: number, duration: number, parent: string | null = null): TraceSpan => ({
  id, parent, target, name, start_us: start, duration_us: duration,
  busy_us: duration / 2, own_busy_us: duration / 4, longest_poll_us: 0, open: false,
});

const capture = (spans: TraceSpan[], duration_us = 1000): TraceCapture => ({ spans, duration_us, start_unix_ms: 10_000, truncated: false });
const none = new Set<string>();
const all = () => true;
const find = (spans: Span[], id: string) => spans.find((s) => s.id === id)!;

describe("trace model", () => {
  it("nests children under their parent and counts overlapping children once in own time", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::session", "handle_event", 0, 100),
      span("2", "ghost_core::client", "receive", 10, 40, "1"),
      span("3", "ghost_core::mls::group", "decrypt", 30, 40, "1"),
    ]), []);
    const event = find(trace.spans, "1");
    expect(event.children.map((c) => c.id)).toEqual(["2", "3"]);
    expect(event.own).toBe(40);
  });

  it("puts overlapping siblings on rows of their own below the parent", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::session", "handle_event", 0, 100),
      span("2", "ghost_core::client", "receive", 10, 40, "1"),
      span("3", "ghost_core::client", "fetch", 30, 40, "1"),
      span("4", "ghost_core::client", "store", 80, 10, "1"),
    ]), []);
    layoutTrace(trace, none, none);
    const row = (id: string) => find(trace.spans, id).row;
    expect(row("2")).toBe(row("1") + 1);
    expect(row("3")).toBe(row("1") + 2);
    expect(row("4")).toBe(row("1") + 1);
  });

  it("gathers top-level spans by module and kind, on lanes that free up", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::relay", "post_blob", 0, 50),
      span("2", "ghost_core::relay", "post_blob", 20, 50),
      span("3", "ghost_core::relay", "post_blob", 60, 10),
      span("4", "ghost_app::commands", "list_messages", 0, 5),
    ]), []);
    const layout = layoutTrace(trace, none, none);
    expect(layout.modules.map((m) => m.id)).toEqual(["commands", "relay"]);
    const row = (id: string) => find(trace.spans, id).row;
    expect(row("1")).not.toBe(row("2"));
    expect(row("3")).toBe(row("1"));
    const labels = layout.rows.map((r) => (r.type === "module" ? `[${r.module.id}]` : r.label));
    expect(labels).toEqual(["[commands]", "list_messages ×1", "[relay]", "post_blob ×3", null]);
  });

  it("shows only the header of a collapsed module and nothing of a hidden one", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::relay", "post_blob", 0, 50),
      span("2", "ghost_app::commands", "list_messages", 0, 5),
    ]), []);
    const layout = layoutTrace(trace, new Set(["relay"]), new Set(["commands"]));
    expect(layout.rows.map((r) => r.type)).toEqual(["module"]);
    expect(layout.modules.length).toBe(2);
  });

  it("treats spans whose parent closed before the capture as roots", () => {
    const trace = buildTrace(capture([span("5", "ghost_core::session", "commit", 0, 10, "gone")]), []);
    expect(trace.spans[0].parent).toBeNull();
  });

  it("splits a range's time by module without counting a child in its parent too", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::session", "handle_event", 0, 100),
      span("2", "ghost_core::client", "receive", 20, 40, "1"),
    ]), []);
    const times = Object.fromEntries(timeByModule(trace, 0, 100, all).map((t) => [t.module.id, t.us]));
    expect(times).toEqual({ session: 60, client: 40 });
  });

  it("counts a kind nested in itself once in its total", () => {
    const trace = buildTrace(capture([
      span("1", "ghost_core::client", "sync", 0, 100),
      span("2", "ghost_core::client", "sync", 20, 40, "1"),
    ]), []);
    const [sync] = bottomUp(trace, 0, 50, all);
    expect(sync.count).toBe(2);
    expect(sync.totalUs).toBe(50);
    expect(sync.ownUs).toBe(50);
    // Span 1 has 60 µs own time (0-20, 60-100), 20 of it inside; span 2 has 40, 30 inside.
    expect(sync.busyUs).toBeCloseTo(25 * 20 / 60 + 10 * 30 / 40);
  });

  it("places the main window's events on the capture's clock and finds the backend's command span", () => {
    const events: FrontendEvent[] = [
      { kind: "command", name: "send_message", startUnixMs: 10_000.1, durationMs: 0.5 },
      { kind: "frame", name: "", startUnixMs: 9_000, durationMs: 60 },
    ];
    const trace = buildTrace(capture([span("1", "ghost_app::commands", "send_message", 150, 300)]), events);
    const roundTrip = trace.spans.find((s) => s.frontend === "command")!;
    expect(roundTrip.start).toBeCloseTo(100);
    expect(roundTrip.end).toBeCloseTo(600);
    expect(trace.spans.some((s) => s.frontend === "frame")).toBe(false);
    expect(backendOf(trace, roundTrip)?.id).toBe("1");
  });

  it("compares a span with the others of its kind", () => {
    const trace = buildTrace(capture([10, 20, 30, 40].map((d, i) => span(String(i), "ghost_core::relay", "post_blob", i * 100, d))), []);
    const comparison = compareWithKind(trace, find(trace.spans, "2"));
    expect(comparison).toEqual({ count: 4, medianUs: 30, p95Us: 40, maxUs: 40, slowerThan: 2 / 3 });
  });
});
