// Failures of things the user did that would otherwise pass unseen, such as a palette
// command the backend refused after the palette closed. Shown for a while, then gone.

import { createSignal } from "solid-js";

export interface Notice {
  id: number;
  message: string;
}

const NOTICE_MS = 6000;

const [notices, setNotices] = createSignal<Notice[]>([]);
let nextId = 1;

export const dismissNotice = (id: number) => setNotices((all) => all.filter((n) => n.id !== id));

export const notify = (message: string) => {
  const id = nextId++;
  setNotices((all) => [...all, { id, message }]);
  setTimeout(() => dismissNotice(id), NOTICE_MS);
};

export { notices };
