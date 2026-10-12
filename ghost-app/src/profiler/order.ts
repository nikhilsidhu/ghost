// Row order for live tables that does not shuffle under the reader every second.

import { createMemo } from "solid-js";

/** How often a live table re-sorts by its figures. */
export const RESORT_MS = 5000;

/**
 * `rows` in the order they had at the last sort, sorting again every `everyMs` or when
 * `compare` changes (the reader picked another column). Rows that appear in between go
 * last until then.
 */
export function createStableOrder<T>(
  rows: () => readonly T[],
  key: (row: T) => string,
  compare: () => (a: T, b: T) => number,
  everyMs = RESORT_MS,
): () => T[] {
  let order: string[] = [];
  let sortedAt = -Infinity;
  let sortedWith: ((a: T, b: T) => number) | null = null;
  return createMemo(() => {
    const list = rows();
    const by = compare();
    const byKey = new Map(list.map((row) => [key(row), row]));
    const now = Date.now();
    if (by !== sortedWith || now - sortedAt >= everyMs) {
      order = [...list].sort(by).map(key);
      sortedAt = now;
      sortedWith = by;
    } else {
      const kept = new Set(order.filter((k) => byKey.has(k)));
      order = [...kept, ...list.map(key).filter((k) => !kept.has(k))];
    }
    return order.map((k) => byKey.get(k)!);
  });
}
