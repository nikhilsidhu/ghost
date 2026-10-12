// The Ghost Dev launcher profile this instance runs as (alice, bob…), to label its windows.
// Dev servers only; none for an instance started by hand.

import { createSignal } from "solid-js";
import { getDevProfile } from "./api";

const [devProfile, setDevProfile] = createSignal<string | null>(null);
if (import.meta.env.DEV) getDevProfile().then(setDevProfile).catch(() => {});

export { devProfile };
