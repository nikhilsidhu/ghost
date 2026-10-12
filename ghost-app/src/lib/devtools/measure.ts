// Helpers both the main window and the profiler measure with.

/** Wall-clock time of a `performance.now()` reading, anchored afresh on every call so
 * the two clocks drifting apart over a long session does not misplace events. */
export const toUnixMs = (performanceMs: number) => Date.now() - (performance.now() - performanceMs);

/** Value at `fraction` (0 to 1) of the values, which need not be sorted. */
export function percentile(values: readonly number[], fraction: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(fraction * sorted.length))];
}
