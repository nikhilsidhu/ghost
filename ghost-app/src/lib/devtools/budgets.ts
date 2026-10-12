// How long things may take before people notice, shared by the main window's measuring
// and the profiler.

/** RAIL: a response within 100 ms feels immediate. */
export const COMMAND_BUDGET_MS = 100;
/** Interaction to Next Paint: 200 ms or less is good. */
export const INTERACTION_BUDGET_MS = 200;
/** A frame this long is a long animation frame, the same 50 ms as a long task: visible jank. */
export const LONG_FRAME_MS = 50;
/** Audio processing past half of real time leaves little room before audio breaks up. */
export const AUDIO_LOAD_BUDGET = 0.5;
