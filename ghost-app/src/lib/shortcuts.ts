const isMac = navigator.userAgent.includes("Mac");
const mod = isMac ? "Cmd" : "Ctrl";

export interface ShortcutDef {
  id: string;
  keys: string[];
  label: string;
  match: (e: KeyboardEvent) => boolean;
}

export const shortcuts: ShortcutDef[] = [
  {
    id: "search",
    keys: [mod, "K"],
    label: "Search servers",
    match: (e) => (e.metaKey || e.ctrlKey) && e.key === "k" && !e.shiftKey,
  },
  {
    id: "commands",
    keys: [mod, "\u21e7", "K"],
    label: "Command palette",
    match: (e) => (e.metaKey || e.ctrlKey) && e.key === "k" && e.shiftKey,
  },
  {
    id: "shortcuts",
    keys: ["?"],
    label: "Keyboard shortcuts",
    match: (e) => e.key === "?" && !e.metaKey && !e.ctrlKey,
  },
];

export function findShortcut(id: string) {
  return shortcuts.find((s) => s.id === id)!;
}

export function formatHint(def: ShortcutDef): string {
  return def.keys.join("+") + " " + def.label.toLowerCase();
}
