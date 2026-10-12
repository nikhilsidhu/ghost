// How the profiler writes figures.

/** Shown where there is no figure, rather than a zero that reads as a measurement. */
export const DASH = "—";

/** Milliseconds to two significant digits past the point, and fewer as they grow. */
export const ms = (value: number) => (value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1) : value.toFixed(2));
export const formatMs = (value: number) => `${ms(value)} ms`;

export function formatUs(us: number): string {
  if (us >= 1_000_000) return `${(us / 1_000_000).toFixed(2)} s`;
  if (us >= 1000) return formatMs(us / 1000);
  return `${us.toFixed(0)} µs`;
}

/** A position in a capture: seconds from its start. */
export const formatOffset = (us: number) => `${(us / 1_000_000).toFixed(us < 10_000_000 ? 2 : 1)} s`;

export const percent = (value: number, digits = 0) => `${value.toFixed(digits)}%`;
/** A load, as a share of real time. */
export const load = (share: number) => percent(share * 100);

export const clockTime = (unixMs: number) => new Date(unixMs).toLocaleTimeString([], { hour12: false });

export function ago(unixMs: number, nowMs: number): string {
  const seconds = Math.max(0, Math.round((nowMs - unixMs) / 1000));
  return seconds < 60 ? `${seconds} s ago` : `${Math.floor(seconds / 60)} min ago`;
}

export const duration = (fromMs: number, toMs: number) => {
  const minutes = Math.floor((toMs - fromMs) / 60_000);
  return minutes < 1 ? "under a minute" : `${minutes} min`;
};
