import { createSignal } from "solid-js";

// --- Public types ---

export interface SelectOption {
  label: string;
  value: string;
  iconKey?: string;
  iconLabel?: string;
}

export interface ArgDef {
  name: string;
  placeholder: string;
  complete?: (query: string, collected: Record<string, string>) => SelectOption[];
  defaultValue?: () => string | null;
}

export interface CommandDef {
  id: string;
  command: string;
  description?: string;
  args: ArgDef[];
  execute: (args: Record<string, string>) => void | Promise<void>;
  shortcut?: string[];
  dangerous?: boolean;
}

export interface SearchResult {
  id: string;
  label: string;
  prefix?: string;
  iconKey?: string;
  iconLabel?: string;
  badge?: string;
  onSelect: () => void;
}

export type SearchProvider = (query: string) => SearchResult[];

// --- Module-level state ---

const [commands, setCommands] = createSignal<CommandDef[]>([]);
const [providers, setProviders] = createSignal<SearchProvider[]>([]);
const [triggeredCommandId, setTriggeredCommandId] = createSignal<string | null>(null);

export { commands, providers, triggeredCommandId };

// --- Registration API ---

export function registerCommand(cmd: CommandDef): () => void {
  setCommands((prev) => {
    if (prev.some((c) => c.id === cmd.id)) {
      console.warn(`registry: command "${cmd.id}" already registered, replacing`);
      return prev.map((c) => (c.id === cmd.id ? cmd : c));
    }
    return [...prev, cmd];
  });
  return () => setCommands((prev) => prev.filter((c) => c.id !== cmd.id));
}

export function registerProvider(provider: SearchProvider): () => void {
  setProviders((prev) => [...prev, provider]);
  return () => setProviders((prev) => prev.filter((p) => p !== provider));
}

export function triggerCommand(id: string) {
  setTriggeredCommandId(id);
}

export function clearTriggeredCommand() {
  setTriggeredCommandId(null);
}
