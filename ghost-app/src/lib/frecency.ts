const STORAGE_KEY = "ghost:frecency";
const DECAY_RATE = 0.05; // per hour

interface FrecencyEntry {
  count: number;
  lastUsed: number;
}

type FrecencyStore = Record<string, FrecencyEntry>;

// Cached in memory — only read localStorage once
let cache: FrecencyStore | null = null;

function getStore(): FrecencyStore {
  if (!cache) {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      cache = raw ? JSON.parse(raw) : {};
    } catch {
      cache = {};
    }
  }
  return cache!;
}

function persist() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cache));
}

export function recordUsage(id: string) {
  const store = getStore();
  const entry = store[id] ?? { count: 0, lastUsed: 0 };
  entry.count++;
  entry.lastUsed = Date.now();
  store[id] = entry;
  persist();
}

export function frecencyScore(id: string): number {
  const entry = getStore()[id];
  if (!entry) return 0;
  const hoursSince = (Date.now() - entry.lastUsed) / (1000 * 60 * 60);
  return entry.count * Math.exp(-DECAY_RATE * hoursSince);
}
