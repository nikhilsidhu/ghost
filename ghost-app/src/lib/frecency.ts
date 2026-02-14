const STORAGE_KEY = "ghost:frecency";
const DECAY_RATE = 0.05; // per hour

interface FrecencyEntry {
  count: number;
  lastUsed: number;
}

type FrecencyStore = Record<string, FrecencyEntry>;

function load(): FrecencyStore {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function save(store: FrecencyStore) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function recordUsage(id: string) {
  const store = load();
  const entry = store[id] ?? { count: 0, lastUsed: 0 };
  entry.count++;
  entry.lastUsed = Date.now();
  store[id] = entry;
  save(store);
}

export function frecencyScore(id: string): number {
  const store = load();
  const entry = store[id];
  if (!entry) return 0;
  const hoursSince = (Date.now() - entry.lastUsed) / (1000 * 60 * 60);
  return entry.count * Math.exp(-DECAY_RATE * hoursSince);
}
