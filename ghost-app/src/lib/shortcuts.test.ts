// Shortcut matching against the key events webviews actually send. On Linux and
// Windows, Shift or Caps Lock makes `key` the uppercase letter.

import { describe, expect, it } from "vitest";
import { findShortcut } from "./shortcuts";

const press = (key: string, mods: { ctrl?: boolean; shift?: boolean } = {}) =>
  new KeyboardEvent("keydown", { key, ctrlKey: mods.ctrl ?? false, shiftKey: mods.shift ?? false });

describe("shortcuts", () => {
  it("opens the command palette on Ctrl+Shift+K, which reports an uppercase K", () => {
    expect(findShortcut("commands").match(press("K", { ctrl: true, shift: true }))).toBe(true);
    expect(findShortcut("search").match(press("K", { ctrl: true, shift: true }))).toBe(false);
  });

  it("opens search on Ctrl+K, with or without Caps Lock", () => {
    expect(findShortcut("search").match(press("k", { ctrl: true }))).toBe(true);
    expect(findShortcut("search").match(press("K", { ctrl: true }))).toBe(true);
    expect(findShortcut("commands").match(press("k", { ctrl: true }))).toBe(false);
  });
});
