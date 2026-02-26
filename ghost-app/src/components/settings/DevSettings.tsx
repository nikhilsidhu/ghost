import { createSignal } from "solid-js";
import { spawnDevInstance } from "../../lib/api";
import { SettingGroup } from "./controls";
import { Plus } from "lucide-solid";

export default function DevSettings() {
  const [spawning, setSpawning] = createSignal(false);
  const [lastSpawned, setLastSpawned] = createSignal<number | null>(null);

  const handleSpawn = async () => {
    setSpawning(true);
    try {
      const n = await spawnDevInstance();
      setLastSpawned(n);
    } catch (e) {
      console.error("spawn failed:", e);
    } finally {
      setSpawning(false);
    }
  };

  return (
    <div class="pb-4">
      <SettingGroup label="dev instances">
        <div class="flex items-center gap-3 py-3">
          <button
            class="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded cursor-pointer transition-colors duration-150 text-[var(--neutral-300)] hover:text-[var(--neutral-100)] border border-[var(--neutral-700)] hover:border-[var(--neutral-600)]"
            onClick={handleSpawn}
            disabled={spawning()}
          >
            <Plus size={12} />
            {spawning() ? "spawning..." : "spawn instance"}
          </button>
          {lastSpawned() !== null && (
            <span class="text-xs text-[var(--neutral-500)]">launching</span>
          )}
        </div>
      </SettingGroup>
    </div>
  );
}
