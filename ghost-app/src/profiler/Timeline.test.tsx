// The timeline's pointer handling, against a stub canvas.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSignal } from "solid-js";
import { render } from "solid-js/web";
import Timeline, { LABEL_WIDTH, RULER_HEIGHT, type View } from "./Timeline";
import { buildTrace, layoutTrace, MODULE_ROW_HEIGHT, type Span } from "./trace-model";

let dispose: () => void = () => {};

beforeEach(() => {
  const context = new Proxy({}, { get: (_, key) => (key === "measureText" ? () => ({ width: 7 }) : () => {}), set: () => true });
  HTMLCanvasElement.prototype.getContext = (() => context) as unknown as typeof HTMLCanvasElement.prototype.getContext;
});
afterEach(() => dispose());

const trace = buildTrace(
  {
    spans: [
      { id: "1", parent: null, target: "ghost_core::session", name: "handle_event", start_us: 1000, duration_us: 4000, busy_us: 100, own_busy_us: 50, longest_poll_us: 50, open: false },
      { id: "2", parent: "1", target: "ghost_core::client", name: "receive", start_us: 1500, duration_us: 2000, busy_us: 50, own_busy_us: 50, longest_poll_us: 50, open: false },
    ],
    duration_us: 10_000,
    start_unix_ms: 0,
    truncated: false,
  },
  [],
);

/** The default size the timeline assumes before it is measured. */
const PLOT_WIDTH = 800 - LABEL_WIDTH;
const xAt = (us: number) => LABEL_WIDTH + (us / 10_000) * PLOT_WIDTH;

function mount(initial: View = { start: 0, end: 10_000 }) {
  const [view, setView] = createSignal<View>(initial);
  const [selected, setSelected] = createSignal<Span | null>(null);
  const toggled: string[] = [];
  const host = document.createElement("div");
  document.body.appendChild(host);
  dispose = render(
    () => (
      <Timeline
        trace={trace}
        layout={layoutTrace(trace, new Set(), new Set())}
        view={view()}
        onView={setView}
        selected={selected()}
        onSelect={setSelected}
        range={null}
        onRange={() => {}}
        onCommitRange={() => {}}
        onFit={() => {}}
        onToggleModule={(id) => toggled.push(id)}
        dimmed={() => false}
        blockingUs={Infinity}
      />
    ),
    host,
  );
  return { canvas: host.querySelector("canvas")!, view, selected, toggled };
}

const mouse = (target: EventTarget, type: string, clientX: number, clientY: number) =>
  target.dispatchEvent(new MouseEvent(type, { bubbles: true, button: 0, clientX, clientY }));

/** happy-dom's WheelEvent leaves out the mouse fields, so they are set on the event. */
function wheel(deltaY: number, clientX: number, metaKey = false): WheelEvent {
  const event = new WheelEvent("wheel", { bubbles: true, deltaY });
  for (const [key, value] of Object.entries({ clientX, clientY: 80, metaKey, ctrlKey: false, shiftKey: false })) {
    Object.defineProperty(event, key, { value });
  }
  return event;
}

describe("timeline", () => {
  it("pans when dragged", () => {
    const { canvas, view } = mount({ start: 2000, end: 6000 });
    mouse(canvas, "mousedown", 500, 80);
    mouse(window, "mousemove", 500 - PLOT_WIDTH / 10, 80);
    mouse(window, "mouseup", 500 - PLOT_WIDTH / 10, 80);
    expect(view().start).toBeCloseTo(2400);
    expect(view().end).toBeCloseTo(6400);
  });

  it("zooms around the pointer on a modified scroll and leaves plain scrolling to the rows", () => {
    const { canvas, view } = mount();
    canvas.dispatchEvent(wheel(100, xAt(5000)));
    expect(view()).toEqual({ start: 0, end: 10_000 });
    canvas.dispatchEvent(wheel(-200, xAt(5000), true));
    const width = view().end - view().start;
    expect(width).toBeLessThan(10_000);
    expect((5000 - view().start) / width).toBeCloseTo(0.5);
  });

  it("selects the span clicked and folds a module from its header", () => {
    const { canvas, selected, toggled } = mount();
    const firstSpanRow = RULER_HEIGHT + MODULE_ROW_HEIGHT + 4;
    mouse(canvas, "mousedown", xAt(2000), firstSpanRow);
    mouse(window, "mouseup", xAt(2000), firstSpanRow);
    expect(selected()?.id).toBe("1");
    mouse(canvas, "mousedown", 40, RULER_HEIGHT + 4);
    mouse(window, "mouseup", 40, RULER_HEIGHT + 4);
    expect(toggled).toEqual(["session"]);
  });
});
