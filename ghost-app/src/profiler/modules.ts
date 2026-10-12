// The parts of Ghost that spans come from, each with a fixed color so it reads the same
// in every view and every capture.

export interface Module {
  id: string;
  label: string;
  /** Color family in the palette. */
  color: string;
}

/** Target prefix of the main window's own events in a capture. */
export const MAIN_TARGET = "main";
/** Where the app's commands are spanned, and the module they make. */
export const COMMANDS_TARGET = "ghost_app::commands";
export const COMMANDS_MODULE = "commands";

const KNOWN: Record<string, Omit<Module, "id">> = {
  [MAIN_TARGET]: { label: "main window", color: "neutral" },
  [COMMANDS_MODULE]: { label: "commands", color: "purple" },
  session: { label: "session", color: "emerald" },
  client: { label: "client", color: "cyan" },
  relay: { label: "relay", color: "violet" },
  mls: { label: "mls", color: "ember" },
  voice: { label: "voice", color: "rose" },
  media: { label: "media", color: "rose" },
};
const ORDER = Object.keys(KNOWN);

const cache = new Map<string, Module>();

/** `ghost_core::mls::group` → mls, `ghost_app::commands` → commands, `ghost_media::session`
 * → media: the core's and app's modules by name, other crates as a whole. */
export function moduleOf(target: string): Module {
  let module = cache.get(target);
  if (!module) {
    const [crate, inner] = target.split("::");
    const id = crate === MAIN_TARGET ? MAIN_TARGET : crate === "ghost_core" || crate === "ghost_app" ? (inner ?? crate) : crate.replace(/^ghost_/, "");
    module = { id, ...(KNOWN[id] ?? { label: id, color: "neutral" }) };
    cache.set(target, module);
  }
  return module;
}

/** Where a module sorts: the main window first, then from the interface down. */
export const moduleRank = (module: Module) => {
  const rank = ORDER.indexOf(module.id);
  return rank < 0 ? ORDER.length : rank;
};

/** `ghost_core::mls::group` → `core::mls::group`: the crate stays, so like-named modules of
 * two crates keep apart. */
export const shortTarget = (target: string) => target.replace(/^ghost_/, "");

export const moduleColor = (module: Module, shade: number) => `var(--${module.color}-${shade})`;
