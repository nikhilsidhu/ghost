import { seedAndRefresh, startDevSession } from "../../lib/store";

export default function DevSettings() {
  return (
    <div class="px-4 flex flex-col gap-2">
      <button
        class="px-3 py-1.5 rounded text-sm bg-[var(--neutral-800)] hover:bg-[var(--neutral-700)] text-[var(--neutral-200)] transition-colors w-fit"
        onClick={startDevSession}
      >
        start dev session
      </button>
      <button
        class="px-3 py-1.5 rounded text-sm bg-[var(--neutral-800)] hover:bg-[var(--neutral-700)] text-[var(--neutral-200)] transition-colors w-fit"
        onClick={seedAndRefresh}
      >
        seed test data
      </button>
    </div>
  );
}
