// Live tables keep their order between re-sorts.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoot, createSignal } from "solid-js";
import { createStableOrder } from "./order";

interface Row { name: string; ms: number }
const slowestFirst = (a: Row, b: Row) => b.ms - a.ms;

describe("stable order", () => {
  afterEach(() => vi.restoreAllMocks());

  it("holds the order until the next re-sort, with new rows last", () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(0);
    createRoot((dispose) => {
      const [rows, setRows] = createSignal<Row[]>([{ name: "a", ms: 1 }, { name: "b", ms: 2 }]);
      const [compare] = createSignal(slowestFirst);
      const ordered = createStableOrder(rows, (r) => r.name, compare, 5000);
      expect(ordered().map((r) => r.name)).toEqual(["b", "a"]);

      now.mockReturnValue(1000);
      setRows([{ name: "a", ms: 9 }, { name: "b", ms: 2 }, { name: "c", ms: 5 }]);
      expect(ordered().map((r) => r.name)).toEqual(["b", "a", "c"]);
      expect(ordered()[1].ms).toBe(9);

      now.mockReturnValue(5000);
      setRows([{ name: "a", ms: 9 }, { name: "c", ms: 5 }]);
      expect(ordered().map((r) => r.name)).toEqual(["a", "c"]);
      dispose();
    });
  });

  it("re-sorts at once when the comparison changes", () => {
    vi.spyOn(Date, "now").mockReturnValue(0);
    createRoot((dispose) => {
      const [rows] = createSignal<Row[]>([{ name: "a", ms: 1 }, { name: "b", ms: 2 }]);
      const [compare, setCompare] = createSignal(slowestFirst);
      const ordered = createStableOrder(rows, (r) => r.name, compare);
      setCompare(() => (x: Row, y: Row) => x.ms - y.ms);
      expect(ordered().map((r) => r.name)).toEqual(["a", "b"]);
      dispose();
    });
  });
});
