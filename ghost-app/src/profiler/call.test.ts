// Per-second call figures from the backend's per-call counts.

import { describe, expect, it } from "vitest";
import type { CallFigure } from "../lib/generated/CallFigure";
import type { PeerFigure } from "../lib/generated/PeerFigure";
import { callSecond } from "./call";

const peer = (counts: Partial<PeerFigure>): PeerFigure => ({
  slot_id: 3, fingerprint: "ab", name: "Ada", depth_frames: 3, target_frames: 2,
  played: 0, recovered: 0, concealed: 0, dropped_late: 0, received_frames: 0, received_bytes: 0,
  ...counts,
});

const call = (peers: PeerFigure[], sent_bytes: number, captureFrames = 50): CallFigure => ({
  ping_ms: 40, frame_ms: 20,
  capture: { frames: captureFrames, load: 0.03, peak: 0.09 },
  playback: { frames: 100, load: 0.01, peak: 0.04 },
  sent_frames: 0, sent_bytes, peers,
});

describe("call seconds", () => {
  it("takes what changed since the last snapshot", () => {
    const previous = call([peer({ played: 100, concealed: 2, dropped_late: 1, received_bytes: 6000 })], 3000);
    const next = call([peer({ played: 148, recovered: 1, concealed: 3, dropped_late: 1, received_bytes: 9000 })], 6000);
    const second = callSecond(previous, next, 1);
    expect(second.sentKbps).toBe(24);
    expect(second.capturePeak).toBe(0.09);
    expect(second.peers.get(3)).toEqual({ depthMs: 60, targetMs: 40, concealed: 1 / 50, late: 0, receivedKbps: 24 });
  });

  it("counts a caller from zero when they first appear and leaves silence and idle threads blank", () => {
    const second = callSecond(null, call([peer({})], 0, 0), 1);
    expect(second.capturePeak).toBeNull();
    expect(second.peers.get(3)?.concealed).toBeNull();
  });
});
