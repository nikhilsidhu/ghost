import { createSignal } from "solid-js";
import type { Component } from "solid-js";

export interface SettingsSection {
  id: string;
  label: string;
  icon: Component<{ size?: number; class?: string }>;
  order: number;
  render: Component;
}

const [sections, setSections] = createSignal<SettingsSection[]>([]);

export { sections };

export function registerSettings(section: SettingsSection): () => void {
  setSections((prev) => {
    if (prev.some((s) => s.id === section.id)) {
      console.warn(`settings: section "${section.id}" already registered, replacing`);
      return prev.map((s) => (s.id === section.id ? section : s)).sort((a, b) => a.order - b.order);
    }
    return [...prev, section].sort((a, b) => a.order - b.order);
  });
  return () => setSections((prev) => prev.filter((s) => s.id !== section.id));
}
