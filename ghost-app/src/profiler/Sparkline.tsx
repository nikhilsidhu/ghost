// A minute of one figure against a fixed scale, so a flat line means steady rather than
// magnified noise, with the budget dashed where there is one and gaps where there was
// nothing to measure.

import { For, Show } from "solid-js";

const WIDTH = 240;
const HEIGHT = 28;

export default function Sparkline(props: {
  values: readonly (number | null)[];
  /** How many points the full width holds; the newest sits at the right edge. */
  points: number;
  min: number;
  max: number;
  budget?: number;
  color: string;
}) {
  const y = (value: number) => {
    const share = (Math.min(Math.max(value, props.min), props.max) - props.min) / (props.max - props.min || 1);
    return (HEIGHT - 1 - share * (HEIGHT - 2)).toFixed(1);
  };
  const x = (index: number) => (((props.points - props.values.length + index) / (props.points - 1)) * WIDTH).toFixed(1);
  /** Runs of measured points, broken where a value is missing. */
  const runs = () => {
    const all: string[] = [];
    let run: string[] = [];
    props.values.forEach((value, i) => {
      if (value === null) {
        if (run.length) all.push(run.join(" "));
        run = [];
      } else {
        run.push(`${x(i)},${y(value)}`);
      }
    });
    if (run.length) all.push(run.join(" "));
    return all;
  };

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none" class="w-full h-7 mt-1 block" aria-hidden="true">
      <Show when={props.budget !== undefined}>
        <line x1="0" x2={WIDTH} y1={y(props.budget!)} y2={y(props.budget!)} stroke="var(--neutral-600)" stroke-dasharray="3 3" vector-effect="non-scaling-stroke" />
      </Show>
      <For each={runs()}>
        {(points) => <polyline points={points} fill="none" stroke={props.color} stroke-width="1.5" vector-effect="non-scaling-stroke" />}
      </For>
    </svg>
  );
}
