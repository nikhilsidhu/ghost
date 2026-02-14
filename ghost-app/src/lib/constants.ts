// Channel kind prefix glyphs
export const CHANNEL_PREFIX = { text: "#", voice: "\u266a" } as const;

export function channelPrefix(kind: string): string {
  return kind === "text" ? CHANNEL_PREFIX.text : CHANNEL_PREFIX.voice;
}
