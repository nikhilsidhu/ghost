// The current call stream by stream, in the manner of a browser's WebRTC internals page:
// whether this device's audio threads keep up and what it sends, and for each other
// caller how deep their jitter buffer runs against its aim, how much of them was
// concealed or came too late, and what arrives. Each over the last minute.

import { For, Show, type JSX } from "solid-js";
import { SettingGroup } from "../components/settings/controls";
import { AUDIO_LOAD_BUDGET } from "../lib/devtools/budgets";
import { cn } from "../lib/cn";
import type { PeerFigure } from "../lib/generated/PeerFigure";
import type { CallSecond, PeerSecond } from "./call";
import { SERIES_POINTS, type ProfilerData } from "./data";
import { DASH, load, percent } from "./format";
import Sparkline from "./Sparkline";
import { emptyClass, warnClass } from "./table";

const ROW_COLUMNS = "minmax(0, 1fr) 220px";
/** Jitter buffer charts span at least this, so a steady buffer reads flat. */
const DEPTH_SCALE_MIN_MS = 200;
/** Characters of a fingerprint shown for a caller this device has no name for. */
const FINGERPRINT_CHARS = 8;

function StreamRow(props: { label: string; detail: string; warn?: boolean; children: JSX.Element }) {
  return (
    <div class="grid items-center gap-4 py-2.5 border-b border-[var(--neutral-800)] last:border-b-0" style={{ "grid-template-columns": ROW_COLUMNS }}>
      <div class="min-w-0">
        <div class="text-sm text-[var(--neutral-200)] truncate">{props.label}</div>
        <div class={cn("text-xs truncate", props.warn ? warnClass : "text-[var(--neutral-500)]")}>{props.detail}</div>
      </div>
      {props.children}
    </div>
  );
}

const kbps = (value: number) => `${value.toFixed(0)} kbps`;
/** A thread's peak load, or a dash when it processed nothing. */
const peak = (value: number | null | undefined) => (value === null || value === undefined ? DASH : load(value));

function peerDetail(latest: PeerSecond | undefined): string {
  if (!latest || (latest.receivedKbps === 0 && latest.concealed === null)) return "nothing received yet";
  const concealed = latest.concealed === null ? "silent" : `${percent(latest.concealed * 100, 1)} concealed`;
  return `buffer ${latest.depthMs} ms, aiming ${latest.targetMs} ms · ${concealed} · ${latest.late} late · ${kbps(latest.receivedKbps)}`;
}

export default function CallView(props: { data: ProfilerData }) {
  const call = () => props.data.snapshot()?.call ?? null;
  const series = () => props.data.callSeries();
  const latest = (): CallSecond | undefined => series()[series().length - 1];
  const peerSeries = (slot: number) => series().map((s) => s.peers.get(slot) ?? null);
  const name = (peer: PeerFigure) => peer.name ?? `slot ${peer.slot_id} · ${peer.fingerprint.slice(0, FINGERPRINT_CHARS)}`;

  return (
    <Show when={call()} fallback={<div class={cn(emptyClass, "px-4")}>not in a call</div>}>
      {(current) => (
        <div class="px-2 pb-6">
          <SettingGroup label="this device">
            <StreamRow
              label="microphone"
              detail={`capture ${load(current().capture.load)}, peak ${peak(latest()?.capturePeak)} · sending ${kbps(latest()?.sentKbps ?? 0)}`}
              warn={(latest()?.capturePeak ?? 0) >= AUDIO_LOAD_BUDGET}
            >
              <Sparkline values={series().map((s) => s.capturePeak)} points={SERIES_POINTS} min={0} max={1} budget={AUDIO_LOAD_BUDGET} color="var(--rose-400)" />
            </StreamRow>
            <StreamRow
              label="speaker"
              detail={`playback ${load(current().playback.load)}, peak ${peak(latest()?.playbackPeak)}`}
              warn={(latest()?.playbackPeak ?? 0) >= AUDIO_LOAD_BUDGET}
            >
              <Sparkline values={series().map((s) => s.playbackPeak)} points={SERIES_POINTS} min={0} max={1} budget={AUDIO_LOAD_BUDGET} color="var(--rose-400)" />
            </StreamRow>
          </SettingGroup>

          <SettingGroup label="others in the call" footer="buffer charts show jitter buffer depth; the dashed line is what it aims for">
            <Show when={current().peers.length > 0} fallback={<div class={emptyClass}>nobody else is here</div>}>
              <For each={current().peers}>
                {(peer) => {
                  const points = () => peerSeries(peer.slot_id);
                  const deepest = () => Math.max(DEPTH_SCALE_MIN_MS, ...points().map((p) => (p ? p.depthMs * 1.25 : 0)));
                  return (
                    <StreamRow label={name(peer)} detail={peerDetail(latest()?.peers.get(peer.slot_id))}>
                      <Sparkline
                        values={points().map((p) => p?.depthMs ?? null)}
                        points={SERIES_POINTS}
                        min={0}
                        max={deepest()}
                        budget={latest()?.peers.get(peer.slot_id)?.targetMs}
                        color="var(--cyan-400)"
                      />
                    </StreamRow>
                  );
                }}
              </For>
            </Show>
          </SettingGroup>
        </div>
      )}
    </Show>
  );
}
