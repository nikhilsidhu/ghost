// Turns the backend's per-call counts into what changed each second, stream by stream.

import type { CallFigure } from "../lib/generated/CallFigure";

/** One second of another caller's stream. */
export interface PeerSecond {
  /** Jitter buffer depth and what its delay policy aims for. */
  depthMs: number;
  targetMs: number;
  /** Share of the frames due that were concealed; null while they were silent. */
  concealed: number | null;
  late: number;
  receivedKbps: number;
}

/** One second of the call. */
export interface CallSecond {
  /** The audio threads' peak loads; null when a thread processed nothing. */
  capturePeak: number | null;
  playbackPeak: number | null;
  sentKbps: number;
  peers: Map<number, PeerSecond>;
}

const kbps = (bytes: number, seconds: number) => (bytes * 8) / seconds / 1000;

/** What changed between `previous` (null at the start of a call) and `next`, `seconds` apart. */
export function callSecond(previous: CallFigure | null, next: CallFigure, seconds: number): CallSecond {
  const before = new Map(previous?.peers.map((p) => [p.slot_id, p]));
  const peers = new Map<number, PeerSecond>();
  for (const peer of next.peers) {
    const last = before.get(peer.slot_id);
    const delta = (pick: (p: typeof peer) => number) => pick(peer) - (last ? pick(last) : 0);
    const due = delta((p) => p.played + p.recovered + p.concealed);
    peers.set(peer.slot_id, {
      depthMs: peer.depth_frames * next.frame_ms,
      targetMs: peer.target_frames * next.frame_ms,
      concealed: due > 0 ? delta((p) => p.concealed) / due : null,
      late: delta((p) => p.dropped_late),
      receivedKbps: kbps(delta((p) => p.received_bytes), seconds),
    });
  }
  return {
    capturePeak: next.capture.frames > 0 ? next.capture.peak : null,
    playbackPeak: next.playback.frames > 0 ? next.playback.peak : null,
    sentKbps: kbps(next.sent_bytes - (previous?.sent_bytes ?? 0), seconds),
    peers,
  };
}
