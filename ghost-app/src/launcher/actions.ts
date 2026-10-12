// What the launcher's pages do through the page: run a command under a name (so its button
// can show it is at work, and its error is shown), and open another page.

import { createSignal } from "solid-js";

/** A page of the launcher. A process page shows one that is not a relay or profile. */
export type Page =
  | { kind: "overview" }
  | { kind: "blueprints" }
  | { kind: "relay"; name: string }
  | { kind: "profile"; name: string }
  | { kind: "process"; process: string };

/** A page's identity, for telling whether two are the same page. */
export function pageKey(page: Page): string {
  switch (page.kind) {
    case "relay":
    case "profile":
      return `${page.kind} ${page.name}`;
    case "process":
      return `process ${page.process}`;
    default:
      return page.kind;
  }
}

export interface Actions {
  run: (key: string, action: () => Promise<unknown>) => Promise<void>;
  busy: (key: string) => boolean;
  open: (page: Page) => void;
  /** The page showing `process`: its relay's or profile's, or its own. */
  openProcess: (process: string) => void;
}

/** Actions that report errors to `onError` and call `onDone` after each command. */
export function createActions(options: {
  onError: (message: string | null) => void;
  onDone: () => void;
  open: (page: Page) => void;
  pageFor: (process: string) => Page;
}): Actions {
  const [busy, setBusy] = createSignal<ReadonlySet<string>>(new Set());
  return {
    run: async (key, action) => {
      options.onError(null);
      setBusy((keys) => new Set([...keys, key]));
      try {
        await action();
      } catch (e) {
        options.onError(String(e));
      } finally {
        setBusy((keys) => new Set([...keys].filter((k) => k !== key)));
        options.onDone();
      }
    },
    busy: (key) => busy().has(key),
    open: options.open,
    openProcess: (process) => options.open(options.pageFor(process)),
  };
}
