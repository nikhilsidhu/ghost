// Animation timing tiers (must match --duration-* in app.css)
export const DURATION_FAST = 150;
export const DURATION_MID = 200;
export const DURATION_SLOW = 300;

// Slide-swap animation: base + per-item stagger
export const slideDuration = (count: number) => `${DURATION_FAST + count * 25}ms`;

// Channel kind prefix glyphs
export const CHANNEL_PREFIX = { text: "#", voice: "\u266a" } as const;

export function channelPrefix(kind: string): string {
  return kind === "text" ? CHANNEL_PREFIX.text : CHANNEL_PREFIX.voice;
}
